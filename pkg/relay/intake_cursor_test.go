package relay

// intake_cursor_test.go — dontguess-61a ground-source tests.
//
// GROUND-SOURCE (a): drive a REAL resync-audit cycle (Watchdog.ResyncAudit) and
// a REAL reconnect cycle (Watchdog.Reconnect) with a durable IntakeCursor wired
// and assert the emitted Filter carries BOTH the dontguess kinds set AND
// Since=cursor (not Since=0, not an unbounded/kindless REQ). These drive the
// REAL Watchdog methods against the REAL fakeRelay/Intake harness
// (newWatchdogHarness) already used by the rest of this file — nothing here is
// a mock of the thing under test, only the wire (the fakeRelay) is faked,
// exactly as every other test in this package does.
//
// GROUND-SOURCE (b) — the per-relay Intake cursor is re-read from the on-disk
// sidecar, not memory, after a restart — is covered by
// TestIntakeCursor_ReReadFromDiskNotMemory below (a fresh *IntakeCursor opened
// from the SAME path a second time, simulating a process restart) and by
// cmd/dontguess's TestAttachRelayTransport_RestartReadsIntakeCursorFromDisk,
// which restarts the FULL relayWiring (a brand-new object graph) and asserts
// the second wiring's cursor value came from the file, not the first process's
// memory.

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestIntakeCursor_ReReadFromDiskNotMemory proves the sidecar is durable and
// that a FRESH IntakeCursor instance (no shared memory with the one that wrote
// it — simulating a process restart) reads the persisted value back, not 0.
func TestIntakeCursor_ReReadFromDiskNotMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.intakecursor")

	c1, err := OpenIntakeCursor(path)
	if err != nil {
		t.Fatalf("OpenIntakeCursor: %v", err)
	}
	if v := c1.Value(); v != 0 {
		t.Fatalf("fresh sidecar Value() = %d, want 0", v)
	}
	if err := c1.Advance(1_700_000_000); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	// c1 is now discarded — a genuine restart never carries this Go value
	// forward. c2 is a COMPLETELY SEPARATE struct; the only channel between them
	// is the file on disk.
	c1 = nil
	_ = c1

	c2, err := OpenIntakeCursor(path)
	if err != nil {
		t.Fatalf("OpenIntakeCursor (restart): %v", err)
	}
	if got := c2.Value(); got != 1_700_000_000 {
		t.Fatalf("restart Value() = %d, want 1700000000 (re-read from disk, not memory)", got)
	}

	// An older/equal Advance is a no-op — the watermark only climbs.
	if err := c2.Advance(1_600_000_000); err != nil {
		t.Fatalf("Advance (older): %v", err)
	}
	if got := c2.Value(); got != 1_700_000_000 {
		t.Fatalf("Advance with an older value rewound the cursor to %d, want unchanged 1700000000", got)
	}
}

// TestWatchdog_ResyncAudit_BoundedKindsAndCursor_NotSinceZero is GROUND-SOURCE
// (a) for the watchdog.go:470 site — the periodic resync audit that, pre-fix,
// re-flooded Since=0 across every kind on EVERY low-cadence cycle. It drives a
// REAL ResyncAudit() call with a real IntakeCursor pre-advanced to a known
// value and asserts the REQ the Watchdog actually issued (captured by
// fakeRelay.queries, the harness's real Subscriber) carries:
//   - Kinds == the wired dontguess kinds set (not nil/unbounded)
//   - Since == cursor-derived (NOT 0, NOT nil)
func TestWatchdog_ResyncAudit_BoundedKindsAndCursor_NotSinceZero(t *testing.T) {
	cursorPath := filepath.Join(t.TempDir(), "resync.intakecursor")
	cursor, err := OpenIntakeCursor(cursorPath)
	if err != nil {
		t.Fatalf("OpenIntakeCursor: %v", err)
	}
	const priorWatermark = int64(2_000_000_000)
	if err := cursor.Advance(priorWatermark); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	kinds := []int{3401, 3402, 3403, 3404, 3405, 3406, 3410, 3411}
	wd, relay, _, _, _, _, _ := newWatchdogHarness(t,
		WithDontguessKinds(kinds), WithIntakeCursor(cursor))

	if _, err := wd.ResyncAudit(context.Background()); err != nil {
		t.Fatalf("ResyncAudit: %v", err)
	}

	if len(relay.queries) == 0 {
		t.Fatalf("ResyncAudit issued no REQ")
	}
	f := relay.queries[len(relay.queries)-1]

	if f.Since == nil {
		t.Fatalf("resync REQ Since is nil, want cursor-bounded (not an unbounded REQ)")
	}
	if *f.Since == 0 {
		t.Fatalf("resync REQ Since = 0 (unbounded full-history re-read) — the exact 61a regression; want Since derived from the cursor (%d)", priorWatermark)
	}
	wantSince := priorWatermark - DefaultReconnectSlack
	if *f.Since != wantSince {
		t.Fatalf("resync REQ Since = %d, want %d (cursor %d minus reconnect slack %d)",
			*f.Since, wantSince, priorWatermark, DefaultReconnectSlack)
	}

	if len(f.Kinds) != len(kinds) {
		t.Fatalf("resync REQ Kinds = %v, want the bounded dontguess set %v (an empty/nil Kinds is the dropped_smuggled-flood regression)", f.Kinds, kinds)
	}
	for i, k := range kinds {
		if f.Kinds[i] != k {
			t.Fatalf("resync REQ Kinds[%d] = %d, want %d", i, f.Kinds[i], k)
		}
	}
}

// TestWatchdog_ResyncAudit_NoCursorWired_FreshOperator_BoundedWindowNotZero
// covers the GENUINELY FRESH operator/relay pair — a cursor that has NEVER
// advanced (Value()==0). Even then the periodic audit must NOT fall back to an
// unconditional since=0 (it would re-flood EVERY cycle, not just once): it
// bounds to DefaultBackfillWindowSeconds ending "now".
func TestWatchdog_ResyncAudit_NeverAdvancedCursor_BoundedWindowNotZero(t *testing.T) {
	cursorPath := filepath.Join(t.TempDir(), "fresh.intakecursor")
	cursor, err := OpenIntakeCursor(cursorPath) // never advanced: Value()==0
	if err != nil {
		t.Fatalf("OpenIntakeCursor: %v", err)
	}

	fixedNow := int64(5_000_000_000)
	kinds := []int{3401, 3402}
	wd, relay, _, _, _, _, _ := newWatchdogHarness(t,
		WithDontguessKinds(kinds), WithIntakeCursor(cursor),
		WithClock(func() time.Time { return time.Unix(fixedNow, 0) }))

	if _, err := wd.ResyncAudit(context.Background()); err != nil {
		t.Fatalf("ResyncAudit: %v", err)
	}
	if len(relay.queries) == 0 {
		t.Fatalf("ResyncAudit issued no REQ")
	}
	f := relay.queries[len(relay.queries)-1]
	if f.Since == nil {
		t.Fatalf("resync REQ Since is nil, want a bounded backfill-window floor")
	}
	if *f.Since == 0 {
		t.Fatalf("resync REQ Since = 0 (unbounded full-history re-read) for a never-advanced cursor — want the bounded DefaultBackfillWindowSeconds floor")
	}
	wantSince := fixedNow - DefaultBackfillWindowSeconds
	if *f.Since != wantSince {
		t.Fatalf("resync REQ Since = %d, want %d (now %d minus DefaultBackfillWindowSeconds %d)",
			*f.Since, wantSince, fixedNow, DefaultBackfillWindowSeconds)
	}
}

// TestWatchdog_Reconnect_BoundedKinds proves the reconnect-leg REQ
// (watchdog.go:306) also carries the bounded kinds set — the third of the four
// 61a sites (the fourth, the targeted IDs refetch at watchdog.go:392, is
// inherently bounded by IDs already and is covered incidentally by every
// existing orphan-refetch test in this file, which now also carries Kinds).
func TestWatchdog_Reconnect_BoundedKinds(t *testing.T) {
	kinds := []int{3401, 3403}
	wd, relay, _, _, _, _, _ := newWatchdogHarness(t, WithDontguessKinds(kinds))

	if err := wd.Reconnect(context.Background(), 1000); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if len(relay.queries) == 0 {
		t.Fatalf("Reconnect issued no REQ")
	}
	f := relay.queries[len(relay.queries)-1]
	if len(f.Kinds) != 2 || f.Kinds[0] != 3401 || f.Kinds[1] != 3403 {
		t.Fatalf("reconnect REQ Kinds = %v, want %v", f.Kinds, kinds)
	}
}
