package exchange

import (
	"fmt"
	"testing"
)

// TestSequencer_IngestLiveDistinctNeverArrivingFloodBoundsAllMemory is the
// wave-9 HIGH regression. A flood of N >> maxOrphans events, each referencing
// DISTINCT antecedents that NEVER arrive, must keep TOTAL sequencer memory
// bounded — not just the buffered set (which the LRU occupancy bound already
// caps) but every auxiliary index: missingWaiters, missingOf, missingCount, and
// orderElem.
//
// The bug: evictOldestLocked used to drop the evicted id from buffered /
// orderElem / missingCount but LEFT its entries in missingWaiters[a] for each
// missing antecedent `a`. Because `a` never arrives, missingWaiters[a] is never
// reclaimed (resolveArrivalLocked only fires when `a` ARRIVES), so it accumulated
// one stale entry for EVERY evicted event that ever referenced it — growing
// missingWaiters 1:1 with TOTAL events ever ingested. With the reverse-index
// (missingOf) cleanup on eviction, every auxiliary index is O(maxOrphans *
// per-event-fan-in), i.e. O(maxOrphans * MaxAntecedents) — BOUNDED under any
// flood, independent of N.
func TestSequencer_IngestLiveDistinctNeverArrivingFloodBoundsAllMemory(t *testing.T) {
	const (
		bound = 64    // maxOrphans
		fanIn = 3     // distinct never-arriving antecedents per event
		flood = 40000 // N >> bound (625x). Under the bug this would leave ~fanIn*N stale edges.
	)
	s := NewSequencer(bound)

	for i := 0; i < flood; i++ {
		antes := make([]string, fanIn)
		for k := 0; k < fanIn; k++ {
			// Distinct, never-ingested antecedent id, unique to THIS event so the
			// bug's "grows 1:1 with total events" shape is reproduced exactly.
			antes[k] = fmt.Sprintf("ante-%d-%d", i, k)
		}
		evicted, err := s.IngestLive(seqMsg(fmt.Sprintf("e%d", i), int64(i), antes...))
		if err != nil {
			t.Fatalf("IngestLive e%d: unexpected error (must never reject a well-formed event): %v", i, err)
		}
		// Once full, every admit evicts exactly one oldest orphan.
		if i >= bound && len(evicted) != 1 {
			t.Fatalf("ingest e%d evicted %v, want exactly one oldest orphan", i, evicted)
		}
	}

	// (1) Buffered occupancy is the sliding window bound — already covered by the
	// chained-flood test, re-asserted here as the anchor for the memory bound.
	if got := s.PendingCount(); got != bound {
		t.Fatalf("PendingCount = %d, want exactly the bound %d", got, bound)
	}

	// (2) Every auxiliary index is bounded by the LIVE orphan population, NOT by N.
	// With fanIn distinct antecedents per buffered event and every antecedent
	// unique to one event:
	//   - missingCount has one entry per buffered true orphan          == bound
	//   - missingOf     has one entry per buffered true orphan          == bound
	//   - missingWaiters has one key per distinct missing antecedent    == bound*fanIn
	//   - total missingWaiters edges (sum of set sizes)                 == bound*fanIn
	// trueOrphans (== len(missingCount)) is the invariant tying them together.
	if len(s.missingCount) != bound {
		t.Fatalf("len(missingCount) = %d, want %d (one per buffered true orphan, NOT O(N)=%d)", len(s.missingCount), bound, flood)
	}
	if len(s.missingOf) != bound {
		t.Fatalf("len(missingOf) = %d, want %d (one per buffered true orphan, NOT O(N))", len(s.missingOf), bound)
	}
	if s.trueOrphans != bound {
		t.Fatalf("trueOrphans = %d, want %d", s.trueOrphans, bound)
	}
	if len(s.orderElem) != bound {
		t.Fatalf("len(orderElem) = %d, want %d", len(s.orderElem), bound)
	}

	wantWaiterKeys := bound * fanIn
	if len(s.missingWaiters) != wantWaiterKeys {
		t.Fatalf("len(missingWaiters) = %d, want %d (bound*fanIn) — NOT O(N*fanIn)=%d (the stale-waiter leak)",
			len(s.missingWaiters), wantWaiterKeys, flood*fanIn)
	}
	totalEdges := 0
	for _, set := range s.missingWaiters {
		totalEdges += len(set)
	}
	if totalEdges != wantWaiterKeys {
		t.Fatalf("total missingWaiters edges = %d, want %d (== bound*fanIn) — NOT O(N)", totalEdges, wantWaiterKeys)
	}
	// The load-bearing anti-regression assertion: the missingWaiters element count
	// is O(maxOrphans*MaxAntecedents), decisively NOT O(N). N is 625x the bound
	// here; under the bug totalEdges would be ~fanIn*N == flood*fanIn.
	if totalEdges >= flood {
		t.Fatalf("total missingWaiters edges = %d grew with N (flood=%d) — the unbounded-memory DoS is NOT fixed", totalEdges, flood)
	}

	// (3) The buffer is not wedged: a brand-new well-formed event still admits
	// (evicting one oldest), and eviction cleaned its edges so the invariants hold.
	if _, err := s.IngestLive(seqMsg("fresh-root", 1_000_000)); err != nil {
		t.Fatalf("IngestLive fresh-root after flood must succeed (no wedge): %v", err)
	}
	if got := s.PendingCount(); got != bound {
		t.Fatalf("PendingCount after fresh-root = %d, want %d", got, bound)
	}
	// fresh-root has no antecedents, so it is NOT a true orphan: the flood shrank
	// by one (one evicted), so missingCount/missingOf drop by one.
	if len(s.missingCount) != bound-1 {
		t.Fatalf("len(missingCount) after fresh-root = %d, want %d", len(s.missingCount), bound-1)
	}
	if len(s.missingOf) != bound-1 {
		t.Fatalf("len(missingOf) after fresh-root = %d, want %d", len(s.missingOf), bound-1)
	}
	// fresh-root is causally ready and drains, leaving only the (bound-1) orphans.
	rel, err := s.Drain()
	if err != nil {
		t.Fatalf("Drain after fresh-root: %v", err)
	}
	if len(rel) != 1 || rel[0].Msg.ID != "fresh-root" {
		t.Fatalf("Drain released %v, want [fresh-root]", idsOf(rel))
	}
}

// TestSequencer_EvictionReclaimsMissingWaiters is the focused micro-regression
// for the HIGH fix: evicting an orphan must reclaim its membership in EVERY
// antecedent's missingWaiters set (and its missingOf entry), so a never-arriving
// antecedent's waiter set can never outlive the orphan that referenced it.
func TestSequencer_EvictionReclaimsMissingWaiters(t *testing.T) {
	const bound = 2
	s := NewSequencer(bound)

	if _, err := s.IngestLive(seqMsg("w1", 1, "never-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestLive(seqMsg("w2", 2, "never-b")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.missingWaiters["never-a"]["w1"]; !ok {
		t.Fatalf("pre-check: missingWaiters[never-a] must hold w1")
	}

	// Admit w3 at the bound → evicts oldest w1. Its edge under "never-a" and its
	// missingOf entry MUST be reclaimed (the pre-fix leak left them forever).
	ev, err := s.IngestLive(seqMsg("w3", 3, "never-c"))
	if err != nil || len(ev) != 1 || ev[0] != "w1" {
		t.Fatalf("IngestLive w3: evicted=%v err=%v, want oldest [w1] evicted", ev, err)
	}
	if _, ok := s.missingWaiters["never-a"]; ok {
		t.Fatalf("missingWaiters[never-a] survived eviction of its only waiter w1 (the unbounded-memory leak)")
	}
	if _, ok := s.missingOf["w1"]; ok {
		t.Fatalf("missingOf[w1] not cleared on eviction")
	}
	if s.trueOrphans != s.PendingCount() || len(s.missingCount) != s.trueOrphans || len(s.missingOf) != s.trueOrphans {
		t.Fatalf("index drift after eviction: occupancy=%d trueOrphans=%d missingCount=%d missingOf=%d",
			s.PendingCount(), s.trueOrphans, len(s.missingCount), len(s.missingOf))
	}
}

// TestSequencer_AntecedentArrivalClearsWaitersAndMissingOf verifies the OTHER
// exit path: when a shared antecedent finally arrives, every waiter that fully
// resolves has its missingOf entry cleared (and the shared waiter set is bulk-
// deleted), so a later eviction of a resolved event does not touch stale edges
// and the indices stay consistent.
func TestSequencer_AntecedentArrivalClearsWaitersAndMissingOf(t *testing.T) {
	const bound = 8
	s := NewSequencer(bound)

	// Two orphans share the SAME missing antecedent "shared".
	if _, err := s.IngestLive(seqMsg("w1", 1, "shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestLive(seqMsg("w2", 2, "shared")); err != nil {
		t.Fatal(err)
	}
	if got := len(s.missingWaiters["shared"]); got != 2 {
		t.Fatalf("missingWaiters[shared] size = %d, want 2 (w1,w2)", got)
	}
	if s.trueOrphans != 2 {
		t.Fatalf("trueOrphans = %d, want 2", s.trueOrphans)
	}

	// "shared" arrives as a root (room to spare, so no eviction). Both waiters
	// fully resolve: the shared set is bulk-deleted and each missingOf is cleared.
	if _, err := s.IngestLive(seqMsg("shared", 3)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.missingWaiters["shared"]; ok {
		t.Fatalf("missingWaiters[shared] not deleted after the antecedent arrived")
	}
	for _, w := range []string{"w1", "w2"} {
		if _, ok := s.missingOf[w]; ok {
			t.Fatalf("missingOf[%s] not cleared after full resolve", w)
		}
		if _, ok := s.missingCount[w]; ok {
			t.Fatalf("missingCount[%s] not cleared after full resolve", w)
		}
	}
	if s.trueOrphans != 0 {
		t.Fatalf("trueOrphans = %d after arrival, want 0", s.trueOrphans)
	}
	if len(s.missingCount) != s.trueOrphans || len(s.missingOf) != s.trueOrphans {
		t.Fatalf("index drift: missingCount=%d missingOf=%d trueOrphans=%d",
			len(s.missingCount), len(s.missingOf), s.trueOrphans)
	}

	// The now-causally-ready chain drains cleanly (shared, then w1/w2).
	rel, err := s.Drain()
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(rel) != 3 {
		t.Fatalf("Drain released %v, want all 3 (shared,w1,w2)", idsOf(rel))
	}
}
