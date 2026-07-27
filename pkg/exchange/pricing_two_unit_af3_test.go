package exchange_test

// Two-unit pricing model tests (dontguess-af3, operator ruling dontguess-96e).
//
// THE MODEL: the exchange ACQUIRES an entry in OUTPUT tokens (entry.TokenCost
// IS DEFINED AS OUTPUT TOKENS — see CLAUDE.md §Scrip and state_put.go's
// plausibility-check comment) and DELIVERS copies of it in INPUT tokens (~5x
// cheaper, outputToInputMultiplier). It therefore runs a deficit on any single
// sale and recovers that deficit only across resales of the same entry — a
// resaleAmortizationN=4 assumed resale count (ruling decision 4: no
// cold-start reuse estimator), applied through a RESIDUAL-AWARE divisor
// (resaleAmortizationDivisor, engine_pricing.go — dontguess-af3 defect 1 fix)
// so both the standard (10% residual) and high-reuse (20% residual) classes
// are net-positive at that assumed count, not just standard. computePrice's
// acquisition-scale base (PutPrice * 1.2, or TokenCost * 0.7 pre-accept) is
// divided by resaleAmortizationDivisor(entry) before it becomes the
// buyer-facing DELIVERY price.
//
// These three tests are the item's REQUIRED done condition, not decoration:
//  1. Net-positive at N=4 resales, net-negative at N=1, for BOTH the standard
//     and high-reuse reuse classes — proves the amortization is real (through
//     the actual settlement price-minus-residual math, not price*N with zero
//     residual outflow) and residual-aware, not just asserted for one class.
//     Mutation-verified: reverting resaleAmortizationDivisor to the flat
//     resaleAmortizationN for every class makes the high-reuse subtest's N=4
//     case net-NEGATIVE again, failing it.
//  2. Buyer-facing price materially below token_cost — asserts the RELATION
//     (price well under half of token_cost), not a magic pinned number.
//  3. No code path converts the OUTPUT-token acquisition figure into the
//     INPUT-token delivery figure at 1:1.

import (
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// acceptedEntryForAmortization returns an accepted (post-put-accept) STANDARD
// inventory entry with the standard 70% accept rate (RunAutoAccept's
// StandardAcceptPriceNumerator), matching the real steady state a served
// match is priced from. ContentSize=0 and PutTimestamp=0 eliminate the size
// and age multipliers so only the acquisition base and amortization are in
// play — the demand/rep/size/age/tier/density signals are exercised
// separately in compute_price_test.go / compute_price_demand_test.go /
// compute_price_density_test.go and are not this item's scope.
func acceptedEntryForAmortization(tokenCost int64) *exchange.InventoryEntry {
	return &exchange.InventoryEntry{
		TokenCost:    tokenCost,
		PutPrice:     tokenCost * 70 / 100, // what RunAutoAccept actually credits the seller
		ContentSize:  0,
		PutTimestamp: 0,
	}
}

// highReuseAcceptedEntryForAmortization returns an accepted HIGH-REUSE
// inventory entry (85% accept rate, HighReuseAcceptPriceNumerator) whose
// Description/ContentType genuinely classify via IsHighReuseArtifact — the
// same §4-class fixture description used in
// settle_highreuse_residual_test.go's ground-source residual test, so this
// package's two high-reuse fixtures can never silently drift apart.
func highReuseAcceptedEntryForAmortization(t *testing.T, tokenCost int64) *exchange.InventoryEntry {
	t.Helper()
	entry := &exchange.InventoryEntry{
		TokenCost:    tokenCost,
		PutPrice:     tokenCost * 85 / 100, // what RunAutoAccept credits a high-reuse seller
		ContentSize:  0,
		PutTimestamp: 0,
		Description:  "flock contention test pattern for Go goroutine synchronization",
		ContentType:  "code",
	}
	if !exchange.IsHighReuseArtifactForTest(entry) {
		t.Fatalf("test fixture error: entry must classify as high-reuse")
	}
	return entry
}

// TestComputePrice_AmortizationNetPositiveAtN4NetNegativeAtN1 is the item's
// required test 1: the exchange must be NET-POSITIVE on an entry sold to 4
// buyers and NET-NEGATIVE if it only ever sells to 1 — for BOTH the standard
// (10% residual) and high-reuse (20% residual) reuse classes.
//
// dontguess-af3 defect 1 (veracity-reproduced 2026-07-27): the original
// version of this test modeled revenue as price*N with ZERO residual
// outflow, which cannot see that high-reuse entries pay DOUBLE the standard
// residual rate. Revenue here is computed through the REAL settlement
// arithmetic (price - residual, correct denominator per class —
// ExchangeRevenueForTest mirrors engine_settle.go's performScripSettlement
// exactly, same residualDenominatorFor helper) so a residual-blind
// amortization regression cannot pass silently.
//
// acquisitionCost is what the exchange actually paid the seller
// (entry.PutPrice, per RunAutoAccept/applySettlePutAccept — the seller's real
// scrip credit).
//
// Mutation-verified: reverting computePrice's resaleAmortizationDivisor to
// the flat resaleAmortizationN for every class makes the high-reuse subtest's
// N=4 case net-NEGATIVE again (the exact defect this item fixes), failing it.
func TestComputePrice_AmortizationNetPositiveAtN4NetNegativeAtN1(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)

	cases := []struct {
		name  string
		entry *exchange.InventoryEntry
	}{
		{"standard", acceptedEntryForAmortization(8000)},
		{"high-reuse", highReuseAcceptedEntryForAmortization(t, 8000)}, // the CLAUDE.md/dontguess-96e live example, high-reuse variant
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acquisitionCost := tc.entry.PutPrice // actually paid to the seller
			price := eng.ComputePriceForTest(tc.entry)

			revenuePerSale := exchange.ExchangeRevenueForTest(price, tc.entry)
			revenueAt1 := revenuePerSale * 1
			revenueAt4 := revenuePerSale * 4

			if revenueAt1 >= acquisitionCost {
				t.Errorf("%s: revenue at N=1 (price=%d, post-residual=%d) = %d, want < acquisitionCost=%d (net NEGATIVE on a single sale)",
					tc.name, price, revenuePerSale, revenueAt1, acquisitionCost)
			}
			if revenueAt4 <= acquisitionCost {
				t.Errorf("%s: revenue at N=4 (price=%d, post-residual=%d) = %d, want > acquisitionCost=%d (net POSITIVE across resales, accounting for the real residual payout)",
					tc.name, price, revenuePerSale, revenueAt4, acquisitionCost)
			}
		})
	}
}

// TestComputePrice_BuyerPriceMaterialyBelowTokenCost is the item's required
// test 2: buyer-facing price for a typical (accepted) entry must be
// MATERIALLY below its token_cost — asserting the relation, not a specific
// number. The historical defect quoted price=6723 against token_cost=8000
// (84%); this asserts the fixed price is well under half of token_cost across
// a spread of token_cost magnitudes, so the assertion isn't a fluke of one
// input.
func TestComputePrice_BuyerPriceMaterialyBelowTokenCost(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)

	for _, tokenCost := range []int64{800, 8000, 80000, 8000000} {
		entry := acceptedEntryForAmortization(tokenCost)
		price := eng.ComputePriceForTest(entry)

		if price*2 >= entry.TokenCost {
			t.Errorf("computePrice(token_cost=%d) = %d, want < 50%% of token_cost (materially below, not a one-off commission)",
				entry.TokenCost, price)
		}
		// Also pin against the specific historical defect ratio: the buggy
		// price was ~84% of token_cost. The fix must land far under that.
		if price*100 >= entry.TokenCost*84 {
			t.Errorf("computePrice(token_cost=%d) = %d is still >= 84%% of token_cost — the defect this item fixes",
				entry.TokenCost, price)
		}
	}
}

// TestComputePrice_NoOneToOneUnitConversion is the item's required test 3: no
// code path may convert the OUTPUT-token acquisition figure (entry.PutPrice /
// entry.TokenCost) into the INPUT-token delivery figure (computePrice's
// return) at 1:1. Mutation-verified: removing the `price /= resaleAmortizationN`
// division (or any regression that reintroduces a straight pass-through)
// makes price >= PutPrice, failing the strict "<" checks below.
func TestComputePrice_NoOneToOneUnitConversion(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)

	for _, tokenCost := range []int64{100, 1000, 10000, 1000000} {
		entry := acceptedEntryForAmortization(tokenCost)
		price := eng.ComputePriceForTest(entry)

		if price == entry.TokenCost {
			t.Errorf("computePrice(token_cost=%d) = %d: 1:1 conversion from TokenCost (OUTPUT tokens) to delivery price", tokenCost, price)
		}
		if price == entry.PutPrice {
			t.Errorf("computePrice(token_cost=%d, put_price=%d) = %d: 1:1 conversion from PutPrice (OUTPUT-token acquisition credit) to delivery price", tokenCost, entry.PutPrice, price)
		}
		if price >= entry.PutPrice {
			t.Errorf("computePrice(token_cost=%d, put_price=%d) = %d, want strictly < PutPrice (delivery must be cheaper than acquisition — the two-unit spread)", tokenCost, entry.PutPrice, price)
		}
	}
}
