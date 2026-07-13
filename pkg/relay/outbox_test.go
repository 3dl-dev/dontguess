package relay

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// --- Test doubles ----------------------------------------------------------

// fakePublisher records every published event id and decides accept/fail per
// event via scripted hooks. It models the relay's OK response deterministically.
type fakePublisher struct {
	mu        sync.Mutex
	published []string // ev.ID in publish order (includes re-publishes)
	// failUntil[id] > 0 means the first failUntil[id] attempts for that id return
	// a transient error; the attempt after that ACKs. Absent = ACK immediately.
	failUntil map[string]int
	attempts  map[string]int
	// reject[id] = true means the relay returns OK=false for that id forever.
	reject map[string]bool
}

func newFakePublisher() *fakePublisher {
	return &fakePublisher{
		failUntil: map[string]int{},
		attempts:  map[string]int{},
		reject:    map[string]bool{},
	}
}

func (p *fakePublisher) PublishEvent(_ context.Context, ev *identity.Event) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempts[ev.ID]++
	p.published = append(p.published, ev.ID)
	if p.reject[ev.ID] {
		return false, nil
	}
	if n := p.failUntil[ev.ID]; n > 0 && p.attempts[ev.ID] <= n {
		return false, errors.New("relay unreachable")
	}
	return true, nil
}

func (p *fakePublisher) publishedIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.published))
	copy(out, p.published)
	return out
}

// --- Helpers ---------------------------------------------------------------

// newOutboxWithStore builds an Outbox over a real on-disk store plus a fake
// publisher, returning both the store (to append records) and the cursor path.
func newOutboxWithStore(t *testing.T, pub EventPublisher, opts ...OutboxOption) (*Outbox, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	s, err := store.Open(logPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	cursorPath := logPath + ".pubcursor"
	quietOpts := append([]OutboxOption{WithOutboxLogf(func(string, ...interface{}) {})}, opts...)
	ob, err := NewOutbox(s, signer, pub, cursorPath, quietOpts...)
	if err != nil {
		t.Fatalf("NewOutbox: %v", err)
	}
	return ob, s, cursorPath
}

// localRec builds an operator-authored (Origin=local) put record. A put fully
// determines its nostr kind, so ToNostrEvent accepts it.
func localRec(id string) store.Record {
	return store.Record{
		ID:        id,
		Sender:    "0000000000000000000000000000000000000000000000000000000000000001",
		Tags:      []string{"exchange:put", "exchange:domain:test"},
		Payload:   []byte("body-" + id),
		Timestamp: 1_700_000_000_000_000_000,
		Origin:    "local",
	}
}

// relayRec builds a record that entered the log via the Intake path
// (Origin=relay). These must never be republished.
func relayRec(id string) store.Record {
	r := localRec(id)
	r.Origin = "relay"
	r.Seq = 1
	return r
}

// --- Tests -----------------------------------------------------------------

// TestOutbox_PublishesLocalRecordsAndAdvancesCursor is the happy path: fold N
// local records, tick, assert all N publish in order and the durable cursor
// reaches N with publish_lag back to zero.
func TestOutbox_PublishesLocalRecordsAndAdvancesCursor(t *testing.T) {
	pub := newFakePublisher()
	ob, s, cursorPath := newOutboxWithStore(t, pub)

	ids := []string{"a", "b", "c"}
	for _, id := range ids {
		if err := s.Append(localRec(id)); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if got := len(pub.publishedIDs()); got != 3 {
		t.Fatalf("published %d events, want 3", got)
	}
	if ob.Cursor() != 3 {
		t.Fatalf("cursor=%d, want 3", ob.Cursor())
	}
	if ob.PublishLag() != 0 {
		t.Fatalf("publish_lag=%d, want 0 after full publish", ob.PublishLag())
	}
	// Cursor is durable on disk.
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("read cursor file: %v", err)
	}
	if strings := string(data); strings != "3\n" {
		t.Fatalf("cursor file = %q, want \"3\\n\"", strings)
	}

	// A second tick with no new records is a no-op — nothing republished.
	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if got := len(pub.publishedIDs()); got != 3 {
		t.Fatalf("second tick republished; total published=%d, want 3", got)
	}
}

// TestOutbox_SkipsRelayOriginRecords proves the ping-pong guard: records with
// Origin=relay are NEVER republished, and they do not consume cursor budget
// (the cursor counts only Origin=local records).
func TestOutbox_SkipsRelayOriginRecords(t *testing.T) {
	pub := newFakePublisher()
	ob, s, _ := newOutboxWithStore(t, pub)

	// Interleave relay-origin records among local ones.
	recs := []store.Record{
		localRec("L1"),
		relayRec("R1"),
		relayRec("R2"),
		localRec("L2"),
		relayRec("R3"),
		localRec("L3"),
	}
	for _, r := range recs {
		if err := s.Append(r); err != nil {
			t.Fatalf("Append %s: %v", r.ID, err)
		}
	}

	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := pub.publishedIDs()
	// The published ids are content-hash event ids, not the record ids, so assert
	// on the COUNT and on the absence of any relay record being published by
	// verifying only 3 events (the 3 locals) went out.
	if len(got) != 3 {
		t.Fatalf("published %d events, want 3 (only the 3 local records; relay records must never be republished)", len(got))
	}
	if ob.Cursor() != 3 {
		t.Fatalf("cursor=%d, want 3 (relay records do not advance the local cursor)", ob.Cursor())
	}
	if ob.PublishLag() != 0 {
		t.Fatalf("publish_lag=%d, want 0", ob.PublishLag())
	}
}

// TestOutbox_CrashBetweenFoldAndPublish is the required test #7. It simulates a
// crash after local records are folded but before the Outbox published them (or
// after publishing some but before the cursor caught up), then restarts a fresh
// Outbox over the SAME log + cursor sidecar and asserts it republishes exactly
// the unacked tail from the durable cursor — with the relay re-ACKing the
// idempotent (content-hash id) events.
func TestOutbox_CrashBetweenFoldAndPublish(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	cursorPath := logPath + ".pubcursor"

	s, err := store.Open(logPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Fold 5 local records.
	ids := []string{"a", "b", "c", "d", "e"}
	for _, id := range ids {
		if err := s.Append(localRec(id)); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	// --- Process 1: publishes the first 2, then "crashes" (context cancelled)
	// before the rest go out. A publisher that blocks forever on the 3rd event
	// models the crash window between fold and publish. ---
	pub1 := newFakePublisher()
	blockOn3rd := &blockingPublisher{inner: pub1, blockAfter: 2}
	quiet := WithOutboxLogf(func(string, ...interface{}) {})
	ob1, err := NewOutbox(s, signer, blockOn3rd, cursorPath, quiet,
		WithPublishBackoff(Backoff{Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 0}))
	if err != nil {
		t.Fatalf("NewOutbox 1: %v", err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	tickDone := make(chan error, 1)
	go func() { tickDone <- ob1.Tick(ctx1) }()

	// Wait until 2 events have been ACKed and the cursor is durable at 2, then the
	// 3rd is blocked in-flight. Cancel to simulate the crash.
	waitFor(t, func() bool { return ob1.Cursor() == 2 && blockOn3rd.blocked() })
	cancel1()
	if err := <-tickDone; err == nil {
		t.Fatal("cancelled Tick should return an error")
	}

	if ob1.Cursor() != 2 {
		t.Fatalf("pre-crash cursor=%d, want 2 (only ACKed events advance it)", ob1.Cursor())
	}
	if pl := ob1.PublishLag(); pl != 3 {
		t.Fatalf("pre-crash publish_lag=%d, want 3 (5 folded − 2 published)", pl)
	}
	firstRun := pub1.publishedIDs()
	if len(firstRun) != 2 {
		t.Fatalf("process 1 ACKed %d events, want 2", len(firstRun))
	}

	// --- Process 2: fresh Outbox over the SAME log + cursor. It must resume from
	// the durable cursor (2) and republish exactly the unacked tail (c, d, e). ---
	pub2 := newFakePublisher()
	ob2, err := NewOutbox(s, signer, pub2, cursorPath, quiet)
	if err != nil {
		t.Fatalf("NewOutbox 2: %v", err)
	}
	if ob2.Cursor() != 2 {
		t.Fatalf("restart cursor=%d, want 2 (recovered from durable sidecar)", ob2.Cursor())
	}
	if pl := ob2.PublishLag(); pl != 0 {
		// lag is refreshed on Tick; before the first tick it is the zero-value.
		t.Logf("restart publish_lag (pre-tick) = %d", pl)
	}

	if err := ob2.Tick(context.Background()); err != nil {
		t.Fatalf("restart Tick: %v", err)
	}

	// Exactly the 3 unacked records were republished — not the 2 already ACKed.
	secondRun := pub2.publishedIDs()
	if len(secondRun) != 3 {
		t.Fatalf("restart republished %d events, want exactly 3 (the unacked tail c,d,e — NOT a,b)", len(secondRun))
	}
	// None of the restart's republished ids may be one of the first run's ACKed
	// ids — the first two are past the durable cursor and must not go out again.
	firstSet := map[string]bool{firstRun[0]: true, firstRun[1]: true}
	for _, id := range secondRun {
		if firstSet[id] {
			t.Fatalf("restart republished already-ACKed event %s (cursor recovery failed)", id)
		}
	}
	if ob2.Cursor() != 5 {
		t.Fatalf("post-recovery cursor=%d, want 5 (all folded records now published)", ob2.Cursor())
	}
	if ob2.PublishLag() != 0 {
		t.Fatalf("post-recovery publish_lag=%d, want 0", ob2.PublishLag())
	}

	_ = s.Close()
}

// TestOutbox_IdempotentReACKOnRepublish proves the content-hash id makes a
// republish idempotent from the relay's view: the SAME record, published by two
// separate Outbox runs, carries the SAME event id both times, so a relay keying
// on id re-ACKs the duplicate rather than storing a second copy.
func TestOutbox_IdempotentReACKOnRepublish(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	cursorPath := logPath + ".pubcursor"
	s, err := store.Open(logPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close() //nolint:errcheck
	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := s.Append(localRec("only")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	quiet := WithOutboxLogf(func(string, ...interface{}) {})

	// Run 1 publishes but we throw away its cursor advance by pointing run 2 at a
	// FRESH cursor path — forcing a republish of the same record.
	pub1 := newFakePublisher()
	ob1, _ := NewOutbox(s, signer, pub1, cursorPath, quiet)
	if err := ob1.Tick(context.Background()); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	pub2 := newFakePublisher()
	ob2, _ := NewOutbox(s, signer, pub2, cursorPath+".fresh", quiet)
	if err := ob2.Tick(context.Background()); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}

	id1 := pub1.publishedIDs()
	id2 := pub2.publishedIDs()
	if len(id1) != 1 || len(id2) != 1 {
		t.Fatalf("expected 1 publish per run, got %d and %d", len(id1), len(id2))
	}
	if id1[0] != id2[0] {
		t.Fatalf("republish carried a different event id (%s vs %s) — republish is NOT idempotent", id1[0], id2[0])
	}
}

// TestOutbox_PublishLagReflectsUnackedCount proves publish_lag tracks the number
// of folded-but-unpublished local records. With a publisher that rejects the 2nd
// record forever, the outbox publishes the 1st, stalls on the 2nd, and lag
// settles at the unacked count.
func TestOutbox_PublishLagReflectsUnackedCount(t *testing.T) {
	pub := newFakePublisher()
	ob, s, _ := newOutboxWithStore(t, pub,
		WithPublishBackoff(Backoff{Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 2}),
		WithLagAlarmThreshold(2))

	for _, id := range []string{"a", "b", "c"} {
		if err := s.Append(localRec(id)); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}

	// Compute the content-hash id of the 2nd record and mark it rejected so the
	// outbox stalls there after publishing the 1st.
	signer := ob.signer
	secondEv, err := ob.toSignedEvent(localRec("b"))
	if err != nil {
		t.Fatalf("toSignedEvent: %v", err)
	}
	_ = signer
	pub.mu.Lock()
	pub.reject[secondEv.ID] = true
	pub.mu.Unlock()

	// Tick will publish "a", then exhaust MaxAttempts on "b" and return an error.
	err = ob.Tick(context.Background())
	if err == nil {
		t.Fatal("Tick should return an error when a record is persistently rejected")
	}

	if ob.Cursor() != 1 {
		t.Fatalf("cursor=%d, want 1 (only 'a' ACKed)", ob.Cursor())
	}
	// 3 folded − 1 published = 2 unacked.
	if pl := ob.PublishLag(); pl != 2 {
		t.Fatalf("publish_lag=%d, want 2 (3 folded − 1 ACKed)", pl)
	}
	// The rejected record was retried (publish_retry incremented).
	if pr := ob.PublishRetry(); pr < 2 {
		t.Fatalf("publish_retry=%d, want ≥2 (the rejected 2nd record was retried)", pr)
	}
}

// TestOutbox_UnknownOriginFailsLoudly proves an unrecognised Origin is a loud
// reject, never a silent publish or silent skip (LOCKED-5).
func TestOutbox_UnknownOriginFailsLoudly(t *testing.T) {
	pub := newFakePublisher()
	ob, s, _ := newOutboxWithStore(t, pub)

	r := localRec("weird")
	r.Origin = "martian"
	if err := s.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := ob.Tick(context.Background()); err == nil {
		t.Fatal("Tick should fail loudly on an unknown Origin")
	}
	if len(pub.publishedIDs()) != 0 {
		t.Fatal("an unknown-origin record was published")
	}
}

// TestConnPublisher_SendsEventAwaitsOK exercises the production EventPublisher
// against a scripted frameConn: it encodes+sends the EVENT and reads frames
// until the matching OK, ignoring unrelated frames.
func TestConnPublisher_SendsEventAwaitsOK(t *testing.T) {
	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ev := &identity.Event{CreatedAt: 1, Kind: KindPutForTest(), Tags: [][]string{{"t", "x"}}, Content: "hi"}
	if err := identity.SignEvent(signer, ev); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}

	// The relay first emits an unrelated NOTICE and an OK for a DIFFERENT event,
	// then the real OK for our event id — the publisher must skip the noise.
	notice, _ := EncodeNotice("hello")
	otherOK, _ := EncodeOK("deadbeef", true, "")
	ourOK, _ := EncodeOK(ev.ID, true, "")
	fc := &scriptFrameConn{reads: [][]byte{notice, otherOK, ourOK}}

	pub := NewConnPublisher(fc, func(string, ...interface{}) {})
	accepted, err := pub.PublishEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("PublishEvent: %v", err)
	}
	if !accepted {
		t.Fatal("expected the relay OK to be accepted=true")
	}
	// The EVENT frame was actually sent.
	if len(fc.writes) != 1 {
		t.Fatalf("frameConn saw %d writes, want 1 (the EVENT)", len(fc.writes))
	}
	f, perr := ParseFrame(fc.writes[0])
	if perr != nil || f.Type != LabelEVENT || f.Event == nil || f.Event.ID != ev.ID {
		t.Fatalf("sent frame is not our EVENT: parsed=%v err=%v", f, perr)
	}
}

// --- more test doubles -----------------------------------------------------

// blockingPublisher wraps an inner publisher and blocks forever (until ctx is
// cancelled) starting with the (blockAfter+1)-th publish — modelling a crash
// window where the process dies mid-publish. The first blockAfter events pass
// through to the inner publisher and ACK normally.
type blockingPublisher struct {
	inner      *fakePublisher
	blockAfter int

	mu         sync.Mutex
	count      int
	blockedNow bool
}

func (b *blockingPublisher) PublishEvent(ctx context.Context, ev *identity.Event) (bool, error) {
	b.mu.Lock()
	b.count++
	n := b.count
	b.mu.Unlock()
	if n <= b.blockAfter {
		return b.inner.PublishEvent(ctx, ev)
	}
	b.mu.Lock()
	b.blockedNow = true
	b.mu.Unlock()
	<-ctx.Done() // block until the "crash" (context cancellation)
	return false, ctx.Err()
}

func (b *blockingPublisher) blocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blockedNow
}

// scriptFrameConn is an in-memory frameConn: Recv returns queued frames in
// order; Send records the written frame.
type scriptFrameConn struct {
	mu     sync.Mutex
	reads  [][]byte
	idx    int
	writes [][]byte
}

func (s *scriptFrameConn) Send(_ context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, append([]byte(nil), frame...))
	return nil
}

func (s *scriptFrameConn) Recv(_ context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx >= len(s.reads) {
		return nil, errors.New("scriptFrameConn: no more frames")
	}
	b := s.reads[s.idx]
	s.idx++
	return b, nil
}

// KindPutForTest exposes the put kind to the test without importing pkg/nostr.
func KindPutForTest() int { return 3401 }

// waitFor polls cond up to 2s, failing the test if it never becomes true.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("waitFor: condition never became true within 2s")
}
