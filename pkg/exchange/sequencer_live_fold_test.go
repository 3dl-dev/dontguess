package exchange_test

// Live-path fold determinism for the §2.5a LRU orphan buffer. The relay Intake
// drives the Sequencer through IngestLive (occupancy-bounded, LRU-evicting) then
// Drain, per event. This test proves DONE criterion (5) at the FOLD level: on a
// realistic, causally-closed exchange event set whose reorder window fits within
// the bound, the LIVE occupancy bound is INERT — no orphan is ever evicted, and
// the folded State (Layer 0-4 metrics included) is BYTE-IDENTICAL to the
// canonical SequenceForFold reference, regardless of how tight the bound is set.

import (
	"bytes"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// driveLiveFold feeds msgs through the LIVE ingest path (IngestLive + Drain per
// event, exactly as the relay Intake does), concatenates the released sequence
// across the incremental drains, folds it in ONE Replay (matching the reference,
// so the assertion isolates the released ORDER — the sequencer's output — from
// State.Replay's per-call granularity), and returns the folded State plus the
// total number of orphans the LRU bound evicted.
func driveLiveFold(t *testing.T, msgs []exchange.Message, bound int) (*exchange.State, int) {
	t.Helper()
	seq := exchange.NewSequencer(bound)
	var releasedAll []exchange.Message
	evictions := 0
	for i := range msgs {
		evicted, err := seq.IngestLive(msgs[i])
		if err != nil {
			t.Fatalf("IngestLive %s: %v", msgs[i].ID, err)
		}
		evictions += len(evicted)
		released, err := seq.Drain()
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
		for j := range released {
			releasedAll = append(releasedAll, released[j].Msg)
		}
	}
	st := exchange.NewState()
	st.Replay(releasedAll)
	return st, evictions
}

func TestSequencer_LiveFoldByteIdenticalEvictionInert(t *testing.T) {
	canonical, _ := buildCausalLog(t)
	sellerKeys := sendersOf(canonical)

	// Reference: canonical batch sequencing + fold.
	seqCanonical, err := exchange.SequenceForFold(canonical, 0)
	if err != nil {
		t.Fatalf("SequenceForFold(canonical): %v", err)
	}
	ref := exchange.NewState()
	ref.Replay(seqCanonical)
	refSnap := stateSnapshot(t, ref, sellerKeys)

	// The causally-closed set fed IN CANONICAL ORDER through the live path: each
	// event is ready on arrival, so peak occupancy is 1 and the LRU bound is
	// inert even at an aggressively small bound. Fold must byte-match the
	// reference, at both a tight and an oversized bound.
	for _, bound := range []int{2, 1000} {
		got, evictions := driveLiveFold(t, canonical, bound)
		if evictions != 0 {
			t.Fatalf("bound=%d: eviction fired %d time(s) on a causally-closed in-order set; must be inert", bound, evictions)
		}
		if snap := stateSnapshot(t, got, sellerKeys); !bytes.Equal(snap, refSnap) {
			t.Fatalf("bound=%d: live-path fold diverged from canonical reference:\n ref=%s\n got=%s", bound, refSnap, snap)
		}
	}
}
