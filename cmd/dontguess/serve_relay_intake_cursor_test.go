package main

// serve_relay_intake_cursor_test.go — dontguess-61a ground-source tests for the
// wiring-level sites (serve_relay.go:711, the initial subscribe) and the
// restart-durability requirement.
//
// GROUND-SOURCE (a) for the initial-subscribe site: drives the REAL
// attachRelayTransport and captures the ACTUAL REQ frame it sends over the fake
// relay connection (fakeRelayConn.reqFilters, extended in serve_relay_test.go
// for this fix), asserting it carries the bounded dontguess kinds set and a
// Since bounded by the durable per-relay Intake cursor — never an
// unbounded/Since=0 REQ.
//
// GROUND-SOURCE (b): restarts the process by discarding the first
// *relayWiring entirely and building a COMPLETELY SEPARATE one (a fresh
// buildRelayWiring call, itself opening a fresh *dgstore.Store handle on the
// same on-disk log) against the SAME intake-cursor sidecar path, and asserts
// the second wiring's cursor value is what the FIRST wiring persisted to
// disk — there is no shared Go memory between the two; the only channel is the
// sidecar file.

import (
	"context"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/relay"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// TestAttachRelayTransport_InitialSubscribe_BoundedKindsAndCursor is
// GROUND-SOURCE (a) for serve_relay.go:711 (the fresh-operator initial
// subscribe — the exact site named in the 61a report). A cursor is pre-advanced
// on disk (as if a prior run had already ingested up to a known created_at)
// BEFORE attachRelayTransport is called, so the assertion proves the initial
// REQ resumes from that on-disk value rather than Since=0.
func TestAttachRelayTransport_InitialSubscribe_BoundedKindsAndCursor(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/events.jsonl"
	ls, err := dgstore.Open(storePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	operator, _ := identity.Generate()

	intakePath := intakeCursorPath(storePath, "wss://relay.example")
	preCursor, err := relay.OpenIntakeCursor(intakePath)
	if err != nil {
		t.Fatalf("OpenIntakeCursor: %v", err)
	}
	const priorIngest = int64(3_000_000_000)
	if err := preCursor.Advance(priorIngest); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	relayConn := newFakeRelayConn(false /* no echo */)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stop, err := attachRelayTransport(ctx, ls, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", relayConn, relayConn, time.Hour, nil, nil, nil,
		WithIntakeCursorPath(intakePath))
	if err != nil {
		t.Fatalf("attachRelayTransport: %v", err)
	}
	t.Cleanup(func() { cancel(); stop() })

	if relayConn.reqCount() == 0 {
		t.Fatalf("attachRelayTransport issued no initial REQ")
	}
	f := relayConn.reqFiltersSnapshot()[0]

	if f.Since == nil {
		t.Fatalf("initial subscribe REQ Since is nil, want cursor-bounded")
	}
	if *f.Since == 0 {
		t.Fatalf("initial subscribe REQ Since = 0 (the exact 61a fresh-operator full-history-reread regression) — a pre-advanced on-disk cursor (%d) was ignored", priorIngest)
	}
	wantSince := priorIngest - reconnectSlackSeconds
	if *f.Since != wantSince {
		t.Fatalf("initial subscribe REQ Since = %d, want %d (on-disk cursor %d minus slack %d)",
			*f.Since, wantSince, priorIngest, reconnectSlackSeconds)
	}

	if len(f.Kinds) != len(nostr.DontguessKinds) {
		t.Fatalf("initial subscribe REQ Kinds = %v, want the bounded dontguess set %v (empty/nil Kinds means the relay serves EVERY event of EVERY kind — the dropped_smuggled flood)", f.Kinds, nostr.DontguessKinds)
	}
	for i, k := range nostr.DontguessKinds {
		if f.Kinds[i] != k {
			t.Fatalf("initial subscribe REQ Kinds[%d] = %d, want %d", i, f.Kinds[i], k)
		}
	}
}

// TestAttachRelayTransport_FreshOperatorNoCursorYet_BoundedWindowNotSinceZero
// covers the GENUINELY fresh operator: no intake-cursor sidecar exists yet AND
// the local store is empty (watermark 0). Even here the initial subscribe must
// NOT emit Since=0 — it bounds to relay.DefaultBackfillWindowSeconds ending now.
func TestAttachRelayTransport_FreshOperatorNoCursorYet_BoundedWindowNotSinceZero(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/events.jsonl"
	ls, err := dgstore.Open(storePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	operator, _ := identity.Generate()
	intakePath := intakeCursorPath(storePath, "wss://relay.example") // sidecar does not exist yet

	relayConn := newFakeRelayConn(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	before := time.Now().Unix()
	stop, err := attachRelayTransport(ctx, ls, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", relayConn, relayConn, time.Hour, nil, nil, nil,
		WithIntakeCursorPath(intakePath))
	if err != nil {
		t.Fatalf("attachRelayTransport: %v", err)
	}
	t.Cleanup(func() { cancel(); stop() })
	after := time.Now().Unix()

	f := relayConn.reqFiltersSnapshot()[0]
	if f.Since == nil {
		t.Fatalf("fresh-operator initial REQ Since is nil, want a bounded backfill-window floor")
	}
	if *f.Since == 0 {
		t.Fatalf("fresh-operator initial REQ Since = 0 — the unbounded full-history-reread regression; want the bounded DefaultBackfillWindowSeconds floor")
	}
	lo := before - relay.DefaultBackfillWindowSeconds
	hi := after - relay.DefaultBackfillWindowSeconds
	if *f.Since < lo || *f.Since > hi {
		t.Fatalf("fresh-operator initial REQ Since = %d, want in [%d,%d] (now-DefaultBackfillWindowSeconds)", *f.Since, lo, hi)
	}
	if len(f.Kinds) != len(nostr.DontguessKinds) {
		t.Fatalf("fresh-operator initial REQ Kinds = %v, want %v", f.Kinds, nostr.DontguessKinds)
	}
}

// TestAttachRelayTransport_RestartReadsIntakeCursorFromDisk is GROUND-SOURCE
// (b): the per-relay Intake cursor is re-read from the on-disk sidecar, not
// memory, after a restart. It builds relayWiring TWICE against the SAME
// intake-cursor path — the second build is a COMPLETELY SEPARATE object graph
// (its own *dgstore.Store handle too), so the only way its cursor can see the
// value the first wiring persisted is by reading the file.
func TestAttachRelayTransport_RestartReadsIntakeCursorFromDisk(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/events.jsonl"
	operator, _ := identity.Generate()
	intakePath := intakeCursorPath(storePath, "wss://relay.example")

	// --- "run 1" ---
	ls1, err := dgstore.Open(storePath)
	if err != nil {
		t.Fatalf("open store (run 1): %v", err)
	}
	pub1 := newDemuxPublisher(nil)
	w1, _, err := buildRelayWiring(ls1, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", pub1, 0, nil, nil,
		WithIntakeCursorPath(intakePath))
	if err != nil {
		t.Fatalf("buildRelayWiring (run 1): %v", err)
	}
	if w1.intakeCursor == nil {
		t.Fatalf("run 1 wiring has no intake cursor wired")
	}
	const ingestedAt = int64(4_200_000_000)
	if err := w1.intakeCursor.Advance(ingestedAt); err != nil {
		t.Fatalf("advance cursor (run 1): %v", err)
	}
	_ = ls1.Close()
	// Discard run 1 entirely — no reference to w1 or ls1 survives past this
	// point. A real restart is a brand-new process; this is the closest a
	// single-process test gets to that without exec-ing a real binary.
	w1 = nil
	ls1 = nil

	// --- "run 2" (the restart) ---
	ls2, err := dgstore.Open(storePath)
	if err != nil {
		t.Fatalf("open store (run 2 / restart): %v", err)
	}
	t.Cleanup(func() { _ = ls2.Close() })
	pub2 := newDemuxPublisher(nil)
	w2, _, err := buildRelayWiring(ls2, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", pub2, 0, nil, nil,
		WithIntakeCursorPath(intakePath))
	if err != nil {
		t.Fatalf("buildRelayWiring (run 2): %v", err)
	}
	if w2.intakeCursor == nil {
		t.Fatalf("run 2 (restart) wiring has no intake cursor wired")
	}
	if got := w2.intakeCursor.Value(); got != ingestedAt {
		t.Fatalf("restart intake cursor Value() = %d, want %d (re-read from the on-disk sidecar, not memory — run 2 shares NO Go state with run 1)", got, ingestedAt)
	}
}
