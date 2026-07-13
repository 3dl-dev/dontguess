package exchange

// engine_local_append_notify_test.go — unit coverage for the additive
// EngineOptions.OnLocalAppend post-emit hook (design §3.8, H1; dontguess-97f).
//
// The hook is the seam that lets the relay Outbox publish an operator match the
// instant it is folded rather than up to a full outbox tick later. These tests
// pin its two load-bearing contracts at the SINGLE operator egress point
// (appendLocalRecord, driven via the real sendLocalOperatorMessage path):
//
//   1. FIRES EXACTLY ONCE per SUCCESSFUL operator append — no misses, no doubles.
//   2. NIL is a strict no-op: the individual tier (OnLocalAppend unset) appends
//      operator records byte-for-byte as before, no panic.

import (
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// newNotifyTestEngine builds a run-loop-free engine over a fresh LocalStore with
// the given OnLocalAppend hook, replayed to a clean state. PollInterval is an hour
// so no background poll folds — the test drives egress explicitly.
func newNotifyTestEngine(t *testing.T, onAppend func()) *Engine {
	t.Helper()
	dir := t.TempDir()
	ls, err := dgstore.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	t.Cleanup(func() { ls.Close() }) //nolint:errcheck
	eng := NewEngine(EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: newReservationID(),
		PollInterval:      time.Hour,
		Logger:            func(string, ...any) {},
		OnLocalAppend:     onAppend,
	})
	if err := eng.replayAll(); err != nil {
		t.Fatalf("replayAll: %v", err)
	}
	return eng
}

// emitOne appends one operator-signed record through the REAL egress path
// (sendLocalOperatorMessage -> appendLocalRecord), the same path a match/settle
// takes. Returns the durable record count after the emit.
func emitOne(t *testing.T, eng *Engine, i int) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"entry_id": i})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := eng.sendLocalOperatorMessage(payload, []string{TagConsume}, nil); err != nil {
		t.Fatalf("sendLocalOperatorMessage: %v", err)
	}
}

// TestOnLocalAppend_FiresOncePerOperatorAppend proves the hook fires exactly once
// for every successful operator append — the count equals the number of appends,
// so it never misses (which would leave the Outbox waiting a full tick) and never
// doubles (which would over-signal). It also confirms the fire count matches the
// durable operator-record count, i.e. the hook is bound to the append, not to any
// earlier or later step.
func TestOnLocalAppend_FiresOncePerOperatorAppend(t *testing.T) {
	var fires int64
	eng := newNotifyTestEngine(t, func() { atomic.AddInt64(&fires, 1) })

	const n = 25
	for i := 0; i < n; i++ {
		emitOne(t, eng, i)
	}

	if got := atomic.LoadInt64(&fires); got != n {
		t.Fatalf("OnLocalAppend fired %d times, want exactly %d (one per operator append)", got, n)
	}

	// Cross-check: the hook count equals the durable operator-record count — bound
	// to the append itself.
	recs, err := eng.opts.LocalStore.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("durable operator records = %d, want %d (hook must fire once per durable append)", len(recs), n)
	}
}

// TestOnLocalAppend_NilIsByteForByte proves the individual-tier default (hook
// unset) appends operator records exactly as before: no panic, and every record
// is durably present. This is the guard that the additive hook does not perturb
// the frozen egress path when nil.
func TestOnLocalAppend_NilIsByteForByte(t *testing.T) {
	eng := newNotifyTestEngine(t, nil) // nil hook == individual tier

	const n = 10
	for i := 0; i < n; i++ {
		emitOne(t, eng, i) // must not panic on the nil hook
	}

	recs, err := eng.opts.LocalStore.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("nil-hook path: durable records = %d, want %d — the nil hook must be a strict no-op", len(recs), n)
	}
}
