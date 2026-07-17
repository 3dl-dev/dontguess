package exchange_test

// medium_loop_oppost_race_20e_test.go is the MANDATORY enforcement test for
// dontguess-20e: the medium-loop compression-assign poster
// (Engine.PostOpenCompressionAssign, engine_buy.go) must make its check-then-act
// ATOMIC under opMu so it cannot double-post.
//
// Background (948a review of dontguess-ffb). serve.go's medium-loop goroutine
// drives pkg/pricing MediumLoop.Tick, whose PostAssign callback calls
// Engine.PostOpenCompressionAssign. That is a check-then-act: read the dedup guard
// (HasCompressedVersion / ActiveAssigns), then a compound sendOperatorMessage WRITE
// + state.Apply. opMu is the documented serializer for operator broadcasts, but
// before this item it named only the auto-accept ticker and the operator-socket
// handler — the medium loop was an unaccounted THIRD concurrent operator-broadcast
// writer that did NOT hold opMu. So two operator-broadcast compression-assign posts
// for the same entry could each read ActiveAssigns()==0 before either applied its
// post, and BOTH land — two AssignRecords for one compression unit, so two agents
// could each claim + complete + be paid task_reward for one unit of work (a scrip
// double-pay leak).
//
// The fix makes PostOpenCompressionAssign acquire opMu and RE-CHECK the guard
// atomically with the post. These tests prove that with a REAL exchange.Engine
// backed by a REAL pkg/store event log, under the race detector, with the two posts
// ACTUALLY racing (a released start barrier), not hand-serialized.

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// seedAcceptedEntryNoAssign puts a plaintext fixture entry and folds a
// settle(put-accept) DIRECTLY (the same State.applySettlePutAccept fold
// Engine.AutoAcceptPut triggers) rather than calling eng.AutoAcceptPut. AutoAcceptPut
// ALSO fires Engine.sendCompressionAssign unconditionally as a side effect (the "Hot
// compression offer" — an EXCLUSIVE-to-seller assign posted on every accept): that
// standing assign would itself count as an active assign for the entry and, post
// dontguess-20e, make PostOpenCompressionAssign atomically DEFER — suppressing the
// cold post these tests exercise. Folding put-accept directly promotes the entry to
// inventory (pendingPuts -> s.inventory) with ZERO active assigns, the exact state
// the production medium loop posts from (its own guard is len(ActiveAssigns)==0).
// Returns the entry ID (the put message ID).
func seedAcceptedEntryNoAssign(t *testing.T, h *testHarness, eng *exchange.Engine, desc string, tokenCost int64) string {
	t.Helper()
	putMsg := h.sendMessage(h.seller,
		putPayload(desc, "sha256:"+fmt.Sprintf("%064x", tokenCost), "code", tokenCost, 5000),
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)
	acceptPayload, err := json.Marshal(map[string]any{
		"phase":      "put-accept",
		"entry_id":   putMsg.ID,
		"price":      tokenCost / 2,
		"expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("seedAcceptedEntryNoAssign: encoding put-accept payload: %v", err)
	}
	h.sendMessage(h.operator, acceptPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrPutAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{putMsg.ID},
	)
	msgs, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("seedAcceptedEntryNoAssign: listing messages: %v", err)
	}
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	return putMsg.ID
}

// countActiveCompressAssigns returns the number of non-terminal compress assigns
// currently recorded for entryID, read through the same production accessor the
// engine and `dontguess assigns` use.
func countActiveCompressAssigns(eng *exchange.Engine, entryID string) int {
	n := 0
	for _, a := range eng.State().ActiveAssigns(entryID) {
		if a.TaskType == "compress" {
			n++
		}
	}
	return n
}

// TestPostOpenCompressionAssign_ConcurrentPostersYieldSingleAssign is the primary
// dontguess-20e enforcement proof. It launches many goroutines that ACTUALLY race
// on PostOpenCompressionAssign for one entry (released together off a start barrier)
// and asserts exactly ONE compress AssignRecord results. Each goroutine models an
// operator-broadcast compression-assign writer doing the medium loop's check-then-act.
//
// Without the fix, PostOpenCompressionAssign held no opMu and had no post-time guard:
// every racer's guard read saw ActiveAssigns()==0 and every racer posted, yielding N
// AssignRecords (N-way double-post -> N-way task_reward double-pay). With the fix, the
// guard read and the post are atomic under opMu, so exactly one racer posts and the
// rest observe the applied assign and defer. Run under `-race`.
func TestPostOpenCompressionAssign_ConcurrentPostersYieldSingleAssign(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	const tokenCost int64 = 20000
	entryID := seedAcceptedEntryNoAssign(t, h, eng,
		"20e concurrency fixture: race N cold compression posters", tokenCost)

	if n := countActiveCompressAssigns(eng, entryID); n != 0 {
		t.Fatalf("precondition: entry has %d active compress assign(s), want 0", n)
	}

	const workers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // hold at the barrier so all goroutines contend at once
			errs[idx] = eng.PostOpenCompressionAssign(entryID)
		}(i)
	}
	close(start) // release the whole herd simultaneously — a genuine race
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: PostOpenCompressionAssign returned error: %v", i, err)
		}
	}

	if got := countActiveCompressAssigns(eng, entryID); got != 1 {
		t.Fatalf("after %d concurrent PostOpenCompressionAssign calls, entry has %d active compress assigns, want exactly 1 — the opMu-atomic check-then-act must let exactly one post through; a stale ActiveAssigns()==0 read would let multiple post and double-pay task_reward",
			workers, got)
	}
}

// TestPostOpenCompressionAssign_ConcurrentDefersToActiveDispatchAssign proves the
// cross-writer half of the fix: a burst of medium-loop cold posters, racing against
// a compression assign an opMu-holding dispatch-loop writer already posted, adds
// ZERO — it never stacks a second AssignRecord on top of the dispatch assign.
//
// The pre-existing assign here is a REAL hot (seller-exclusive) compression assign
// posted by Engine.AutoAcceptPut — a genuine operator-broadcast dispatch-loop writer
// (autoAcceptPutLocked's hot offer, which runs under opMu). This is precisely the
// "same-tick warm/hot compression assign from the dispatch-loop" the 948a review
// flagged as double-posting against the medium loop's cold assign. The N cold posters
// then ACTUALLY race (start barrier); the surviving compress assign must still be the
// one the dispatch writer posted (exclusive to the seller), with no open/cold assign
// added. Run under `-race`.
func TestPostOpenCompressionAssign_ConcurrentDefersToActiveDispatchAssign(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	const tokenCost int64 = 20000
	putMsg := h.sendMessage(h.seller,
		putPayload("20e defer fixture: rust ownership cheatsheet",
			"sha256:"+fmt.Sprintf("%064x", 7777), "code", tokenCost, 5000),
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:rust"},
		nil,
	)
	// AutoAcceptPut promotes the entry AND fires a real hot (seller-exclusive)
	// compression assign under opMu — the dispatch-loop writer we race against.
	if err := eng.AutoAcceptPut(putMsg.ID, tokenCost/2, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	entryID := putMsg.ID

	if got := countActiveCompressAssigns(eng, entryID); got != 1 {
		t.Fatalf("precondition: after AutoAcceptPut the entry has %d active compress assign(s), want exactly 1 (the hot assign the medium loop must defer to)", got)
	}
	sellerKey := h.seller.PublicKeyHex()

	const workers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// A cold post racing the standing hot assign: the atomic guard must see
			// ActiveAssigns()>0 and skip (nil, no post). Errors would themselves be
			// a defect; the count assertion below is the real proof.
			_ = eng.PostOpenCompressionAssign(entryID)
		}()
	}
	close(start)
	wg.Wait()

	assigns := eng.State().ActiveAssigns(entryID)
	var compress []*exchange.AssignRecord
	for _, a := range assigns {
		if a.TaskType == "compress" {
			compress = append(compress, a)
		}
	}
	if len(compress) != 1 {
		t.Fatalf("after %d concurrent cold posters raced a standing dispatch (hot) assign, entry has %d active compress assigns, want exactly 1 — the medium-loop poster must never stack a second assign on an active one (double-post -> double-pay)",
			workers, len(compress))
	}
	if compress[0].ExclusiveSender != sellerKey {
		t.Errorf("surviving compress assign ExclusiveSender = %q, want the seller's hot-assign key %q — a cold (open) assign was posted on top of the dispatch assign instead of deferring",
			compress[0].ExclusiveSender, sellerKey)
	}
}
