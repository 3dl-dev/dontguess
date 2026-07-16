package exchange

// state_replay_windowbound_0ba_test.go — the ground-source test for
// dontguess-0ba (memory-bounded windowed Replay, state_core.go / state_put.go).
//
// BEFORE: State.Replay prefetched EVERY offloaded-put ciphertext in the whole log
// into ONE in-memory map before folding, and folded the entire log under a single
// s.mu hold. A log with N large offloaded puts held all N ciphertexts resident at
// once (O(N)) — an OOM/stall on Replay-of-many-offloaded.
//
// AFTER: Replay folds the log in replayFoldWindow-sized windows, prefetching only
// ONE window's ciphertexts off the lock at a time and discarding them before the
// next window — resident blob memory is O(window), not O(log). The lock is
// released between windows, so every replay-only fold behavior (the §6
// legacy-plaintext grandfather admission + recordFoldDenial suppression) is scoped
// to the replay msg-ID set (isReplayMsg), NOT the bare s.replaying flag, so a
// concurrent live Apply interleaving in a between-window gap is never mistaken for
// replay.
//
// These are WHITE-BOX (package exchange) tests: they use REAL secp256k1
// identities, REAL nip44.Seal/Open, REAL ChaCha20-Poly1305, and a REAL
// content-addressed MemoryBlobStore — nothing about the crypto or the fold is
// mocked. The only instrument is a BlobStore wrapper that records, at each Fetch,
// how many puts have ALREADY folded (observed via the public PendingPuts()), which
// is what proves the working set stays bounded.
//
// Proven:
//
//	(1) BOUNDED WORKING SET: over a Replay of N = 3*replayFoldWindow offloaded puts,
//	    by the time the LAST window's ciphertexts are fetched, N-window puts have
//	    already folded — so at most `window` ciphertexts are ever resident at once.
//	    The old all-at-once prefetch would fetch every blob BEFORE any fold, so this
//	    observed count would be 0; the assertion fails on the pre-0ba shape.
//	(2) FOLD CORRECTNESS UNCHANGED: all N offloaded puts fold into pendingPuts.
//	(3) ATOMICITY PRESERVED under windowing: a concurrent LIVE Apply of a team-tier
//	    plaintext put whose ID coincides with a log put-accept, interleaved into a
//	    between-window gap while s.replaying is true, is STILL fail-closed DROPPED
//	    (grandfather does not fire for it) and a concurrent live fold-guard denial in
//	    the same gap is STILL counted (not suppressed) — while a GENUINE pre-cutover
//	    legacy put that IS in the replay log still grandfathers.

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// pendingCountingBlobStore wraps a real MemoryBlobStore and records, at each
// Fetch, the number of puts that have ALREADY folded into pendingPuts (read via
// the public accessor). The prefetch runs OFF s.mu, so PendingPuts()'s RLock never
// contends with the fold. maxFoldedAtFetch is the load-bearing measurement: in a
// windowed Replay the later windows' fetches observe the earlier windows already
// folded (and their ciphertexts discarded), which is exactly the bounded-working-
// set property. In the pre-0ba all-at-once prefetch every fetch precedes every
// fold, so this stays 0.
type pendingCountingBlobStore struct {
	inner *MemoryBlobStore
	state *State

	mu               sync.Mutex
	fetches          int
	maxFoldedAtFetch int
}

func newPendingCountingBlobStore(inner *MemoryBlobStore) *pendingCountingBlobStore {
	return &pendingCountingBlobStore{inner: inner}
}

func (b *pendingCountingBlobStore) Put(content []byte) (string, error) {
	return b.inner.Put(content)
}

func (b *pendingCountingBlobStore) Fetch(pointer string) ([]byte, error) {
	folded := len(b.state.PendingPuts()) // off-lock RLock; measures fold progress
	b.mu.Lock()
	b.fetches++
	if folded > b.maxFoldedAtFetch {
		b.maxFoldedAtFetch = folded
	}
	b.mu.Unlock()
	return b.inner.Fetch(pointer)
}

// (1)+(2) A Replay of many offloaded puts keeps the prefetch working set bounded
// to one window (O(window), not O(N)) AND folds every entry.
func TestReplay_WindowedFold_BoundedPrefetchWorkingSet(t *testing.T) {
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("seller: %v", err)
	}
	operator, err := identity.Generate()
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	s := teamTierState(t, operator)

	shared := NewMemoryBlobStore()
	store := newPendingCountingBlobStore(shared)
	store.state = s
	s.SetBlobStore(store)

	// N a clean multiple of the window so the arithmetic below is exact: 3 full
	// windows. Every put is offloaded (blob_pointer envelope), so every one costs a
	// Fetch and would be resident under the old all-at-once prefetch.
	n := 3 * replayFoldWindow
	msgs := make([]Message, 0, n)
	for i := 0; i < n; i++ {
		plaintext := []byte(fmt.Sprintf("reusable offloaded artifact number %d — distinct bytes so no dedup collision", i))
		enc, _ := buildEncObjectBlob(t, seller, operator.PubKeyHex(), plaintext, shared)
		desc := fmt.Sprintf("reusable go flock contention test pattern entry %d", i)
		msgs = append(msgs, *marshalV2Put(t, seller, desc, 4242, enc))
	}

	s.Replay(msgs)

	// (2) Correctness: every offloaded put folded.
	if got := len(s.PendingPuts()); got != n {
		t.Fatalf("(2) folded %d puts, want all %d — windowed fold lost entries", got, n)
	}
	// One Fetch per distinct offloaded ciphertext.
	if store.fetches != n {
		t.Fatalf("fetched %d blobs, want %d (one per offloaded put)", store.fetches, n)
	}

	// (1) Bounded working set. With 3 windows of size W, the final window's fetches
	// observe the first two windows (2*W puts) already folded — proving that when
	// the last window's blobs were prefetched, only the remaining W puts' blobs
	// needed to be resident. The old code fetched all N blobs before any fold, so
	// this count would be 0.
	wantFolded := n - replayFoldWindow // == 2*replayFoldWindow
	if store.maxFoldedAtFetch != wantFolded {
		t.Fatalf("(1) max puts folded at any fetch = %d, want %d (= N - window): the prefetch working set is not window-bounded — "+
			"0 would mean the pre-0ba all-at-once prefetch (every blob resident before any fold, O(N))",
			store.maxFoldedAtFetch, wantFolded)
	}
}

// noopMsg is a message that carries no exchange op tag — it folds to nothing
// (applyLocked's default branch has no case for ""). Used only to fill the FIRST
// replay window so the blocking offloaded put lands in the SECOND window, i.e.
// AFTER beginReplayLocked has installed the replay scope (replaying /
// replayPutAccepts / replayMsgIDs) — the state required to exercise the dangerous
// between-window interleave.
func noopMsg(sender string, i int) Message {
	return Message{
		ID:        fmt.Sprintf("noop-%d", i),
		Sender:    sender,
		Tags:      nil,
		Timestamp: time.Now().UnixNano(),
	}
}

// forgedNonOperatorSettle is a scrip-settle from a NON-operator sender — the
// operator-only fold guard in applyScripSettle rejects it via recordFoldDenial.
func forgedNonOperatorSettle(t *testing.T, sender string) *Message {
	t.Helper()
	payload, err := json.Marshal(scrip.SettlePayload{MatchMsg: "m-forged-live"})
	if err != nil {
		t.Fatalf("marshal settle: %v", err)
	}
	return &Message{
		ID:        "forged-settle-live",
		Sender:    sender,
		Payload:   payload,
		Tags:      []string{scrip.TagScripSettle},
		Timestamp: time.Now().UnixNano(),
	}
}

// (3) A concurrent live Apply interleaved into a between-window Replay gap must be
// treated as LIVE, not replay: a live plaintext downgrade whose ID matches a log
// put-accept stays fail-closed DROPPED (grandfather withheld), and a live
// fold-guard denial is STILL counted (not suppressed). A GENUINE pre-cutover
// legacy put that IS in the replay log still grandfathers.
func TestReplay_WindowedFold_ConcurrentLiveApplyNotTreatedAsReplay(t *testing.T) {
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("seller: %v", err)
	}
	operator, err := identity.Generate()
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	s := teamTierState(t, operator)
	s.OperatorKey = operator.PubKeyHex() // arm the operator-sender fold guards

	var denials int32
	s.onFoldDenial = func(_ foldDenialReason, _ *Message) { atomic.AddInt32(&denials, 1) }

	// A genuine PRE-cutover legacy plaintext put + its operator put-accept: it IS in
	// the replay log, so it must still grandfather under windowing.
	genuine := legacyPlaintextPut(t, seller, "genuine pre-cutover grandfathered runbook migration recipe symlink bridge",
		[]byte("a real pre-migration plaintext artifact already broadcast before the cutover"), 4242)
	acceptGenuine := putAcceptMsg(t, operator.PubKeyHex(), genuine.ID)

	// The LIVE post-cutover plaintext downgrade. It is NOT in the replay log, but a
	// put-accept referencing its ID IS — the exact bait that a bare-s.replaying
	// grandfather check would re-admit. Built here only to obtain its stable ID; it
	// is applied LIVE (never placed in the replay log).
	live := legacyPlaintextPut(t, seller, "live post-cutover downgrade attempt",
		[]byte("brand-new cleartext a rogue client injects after the cutover"), 4242)
	acceptLive := putAcceptMsg(t, operator.PubKeyHex(), live.ID) // references live.ID; live itself absent from the log

	// A blocking offloaded put that PAUSES Replay mid-prefetch of the SECOND window,
	// with the replay scope already installed by the first window's beginReplayLocked.
	blob := newBlockingBlobStore()
	livePlaintextForBlob := []byte("ciphertext bytes behind a blob host that blocks until the test unblocks it")
	encQ, _ := buildEncObjectBlob(t, seller, operator.PubKeyHex(), livePlaintextForBlob, blob)
	q := marshalV2Put(t, seller, "confidential go flock contention test pattern (blocking blob)", 4242, encQ)
	s.SetBlobStore(blob)

	// Build the log so the FIRST window (replayFoldWindow msgs) is [genuine,
	// acceptGenuine, noop…] and the SECOND window is [q, acceptLive]. q's fetch
	// blocks → Replay parks in the second window's off-lock prefetch with the replay
	// scope live and s.mu FREE.
	log := make([]Message, 0, replayFoldWindow+2)
	log = append(log, *genuine, *acceptGenuine)
	for i := 0; i < replayFoldWindow-2; i++ {
		log = append(log, noopMsg(seller.PubKeyHex(), i))
	}
	log = append(log, *q, *acceptLive)

	replayDone := make(chan struct{})
	go func() {
		s.Replay(log)
		close(replayDone)
	}()

	// Wait until q's fetch is in flight — Replay is now parked in the second
	// window's prefetch, off-lock, with replaying=true and replayPutAccepts[live.ID]
	// set but live.ID absent from replayMsgIDs.
	select {
	case <-blob.started:
	case <-time.After(10 * time.Second):
		close(blob.unblock)
		<-replayDone
		t.Fatal("blocking blob fetch never started — Replay did not reach the second window")
	}

	// --- The dangerous interleave: live Apply while Replay is parked mid-window ---
	s.Apply(live)                                           // live plaintext downgrade, ID matches acceptLive
	s.Apply(forgedNonOperatorSettle(t, seller.PubKeyHex())) // live fold-guard denial

	// live plaintext put must be DROPPED — grandfather must NOT fire for it even
	// though s.replaying is true and a matching put-accept is in the log, because
	// its ID is not in replayMsgIDs (dontguess-0ba). A bare-flag check would fold it.
	if _, ok := s.GetPendingPut(live.ID); ok {
		t.Fatal("(3) live plaintext downgrade FOLDED into pendingPuts during a Replay gap — grandfather fired for a live msg (confidentiality regression)")
	}
	if e := s.GetInventoryEntry(live.ID); e != nil {
		t.Fatal("(3) live plaintext downgrade reached inventory during a Replay gap — grandfathering leaked into the live path")
	}
	// The live fold-guard denial must have been COUNTED, not suppressed by the
	// in-flight replay (the alarm-miss the bare-flag check would cause).
	if got := atomic.LoadInt32(&denials); got != 1 {
		t.Fatalf("(3) live fold-guard denials counted = %d, want 1 — a concurrent live denial was suppressed because a Replay was in flight", got)
	}

	// Let Replay finish.
	close(blob.unblock)
	<-replayDone

	// The genuine pre-cutover legacy put IS in the replay log → still grandfathered
	// under windowing (its ID is in replayMsgIDs, so the isReplayMsg gate admits it).
	eg := s.GetInventoryEntry(genuine.ID)
	if eg == nil {
		t.Fatal("(3) genuine pre-cutover legacy put was NOT grandfathered under windowed Replay — the isReplayMsg gate over-rejected")
	}
	if !eg.LegacyPlaintext {
		t.Fatal("(3) genuine grandfathered entry not marked LegacyPlaintext")
	}
	// The blocking offloaded put folded once unblocked.
	if _, ok := s.GetPendingPut(q.ID); !ok {
		t.Fatal("(3) blocking offloaded put did not fold after unblock — windowed fold lost the second window")
	}
	// live stayed out of inventory after the full replay too.
	if e := s.GetInventoryEntry(live.ID); e != nil {
		t.Fatal("(3) live plaintext downgrade appeared in inventory after Replay completed")
	}
}
