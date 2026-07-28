package pricing_test

// compression_reachability_test.go — the compression pool must never be
// unreachable (dontguess-817, dontguess-cba).
//
// Measured on the live exchange 2026-07-28: 44 assigns issued, all 44 EXCLUSIVE,
// all 44 targets dead, none ever claimed — and the medium loop had posted ZERO
// open assigns for the exchange's entire life. Three separate repricings had tuned
// the value of an offer no agent could see or take. These pin both blockages.

import (
	"context"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/pricing"
)

// reachabilityLoop wires a medium loop over the stub state, capturing posts.
func reachabilityLoop(st *mediumStubState, posted *[]pricing.AssignSpec) *pricing.MediumLoop {
	return pricing.NewMediumLoop(pricing.MediumLoopOptions{
		State: st,
		PostAssign: func(spec pricing.AssignSpec) error {
			*posted = append(*posted, spec)
			return nil
		},
	})
}

func reachabilityEntry(id string, tokenCost int64) *exchange.InventoryEntry {
	return &exchange.InventoryEntry{EntryID: id, TokenCost: tokenCost, ContentSize: 40_000}
}

// TestColdStartGate_PostsWhenNothingMeetsTheFixedThreshold is dontguess-cba. Open
// assigns are the ONLY tier any agent may claim; a fixed 3-purchase gate keeps that
// pool permanently empty in a market that has never reached 3.
func TestColdStartGate_PostsWhenNothingMeetsTheFixedThreshold(t *testing.T) {
	st := newMediumStubState()
	st.inventory = []*exchange.InventoryEntry{reachabilityEntry("e1", 50_000)}
	st.purchaseCount["e1"] = 1 // below the default threshold of 3

	var posted []pricing.AssignSpec
	reachabilityLoop(st, &posted).Tick(context.Background())

	if len(posted) == 0 {
		t.Fatal("no open compression assign posted for the busiest entry (1 purchase, fixed threshold 3) — the only claimable tier stays empty in a cold-start market, which is why 0 of 44 assigns were ever completed")
	}
}

// TestColdStartGate_SteadyStateUnchanged proves this is not merely "lower the
// constant": once the market is deep, the configured threshold governs again and
// thin inventory is still skipped.
func TestColdStartGate_SteadyStateUnchanged(t *testing.T) {
	st := newMediumStubState()
	st.inventory = []*exchange.InventoryEntry{
		reachabilityEntry("busy", 50_000),
		reachabilityEntry("quiet", 50_000),
	}
	st.purchaseCount["busy"] = 10 // well past the threshold
	st.purchaseCount["quiet"] = 1 // still below it

	var posted []pricing.AssignSpec
	reachabilityLoop(st, &posted).Tick(context.Background())

	for _, p := range posted {
		if p.EntryID == "quiet" {
			t.Error("posted a compression assign for a 1-purchase entry while the market has entries at 10 — in a deep market the configured threshold must still gate, or the exchange spends compression effort on inventory nobody wants")
		}
	}
}

// TestExclusiveFallback_UnclaimedExclusiveDoesNotBlock is dontguess-817: an assign
// addressed to an agent that never returns must not lock the work forever.
func TestExclusiveFallback_UnclaimedExclusiveDoesNotBlock(t *testing.T) {
	st := newMediumStubState()
	st.inventory = []*exchange.InventoryEntry{reachabilityEntry("e1", 50_000)}
	st.purchaseCount["e1"] = 5
	// A hot assign was issued to the original seller, which then vanished.
	st.activeAssigns["e1"] = []*exchange.AssignRecord{{
		AssignID:        "a1",
		EntryID:         "e1",
		TaskType:        "compress",
		ExclusiveSender: "dead-seller-key",
		Status:          exchange.AssignOpen, // issued, never claimed
	}}

	var posted []pricing.AssignSpec
	reachabilityLoop(st, &posted).Tick(context.Background())

	if len(posted) == 0 {
		t.Fatal("an unclaimed EXCLUSIVE assign blocked the open assign — the work is locked to an agent that never returns and no other agent may claim it; this is the exact 44-of-44 live failure")
	}
}

// TestExclusiveFallback_ClaimedAssignStillBlocks is the other side: if someone is
// genuinely working the task, do not post a duplicate.
func TestExclusiveFallback_ClaimedAssignStillBlocks(t *testing.T) {
	st := newMediumStubState()
	st.inventory = []*exchange.InventoryEntry{reachabilityEntry("e1", 50_000)}
	st.purchaseCount["e1"] = 5
	st.activeAssigns["e1"] = []*exchange.AssignRecord{{
		AssignID:    "a1",
		EntryID:     "e1",
		TaskType:    "compress",
		ClaimantKey: "someone",
		Status:      exchange.AssignClaimed, // actively being worked
	}}

	var posted []pricing.AssignSpec
	reachabilityLoop(st, &posted).Tick(context.Background())

	if len(posted) != 0 {
		t.Errorf("posted %d duplicate assign(s) for an entry someone is already compressing — a CLAIMED assign must still block", len(posted))
	}
}
