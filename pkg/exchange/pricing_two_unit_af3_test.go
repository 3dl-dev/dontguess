package exchange_test

// Two-unit pricing model tests (dontguess-af3, operator ruling dontguess-96e).
//
// THE MODEL: the exchange ACQUIRES an entry in OUTPUT tokens (entry.TokenCost
// IS DEFINED AS OUTPUT TOKENS — see CLAUDE.md §Scrip and state_put.go's
// plausibility-check comment) and DELIVERS copies of it in INPUT tokens (~5x
// cheaper, outputToInputMultiplier). It therefore runs a deficit on any single
// sale and recovers that deficit only across resales of the same entry — a
// flat resaleAmortizationN=4 assumed resale count (ruling decision 4: no
// cold-start reuse estimator). computePrice's acquisition-scale base (PutPrice
// * 1.2, or TokenCost * 0.7 pre-accept) is divided by resaleAmortizationN
// before it becomes the buyer-facing DELIVERY price (engine_pricing.go).
//
// These three tests are the item's REQUIRED done condition, not decoration:
//  1. Net-positive at N=4 resales, net-negative at N=1 — proves the
//     amortization is real, not asserted. Mutation-verified: deleting the
//     `price /= resaleAmortizationN` line in engine_pricing.go makes the N=1
//     case ALSO net-positive (PutPrice*1.2 > PutPrice), failing this test.
//  2. Buyer-facing price materially below token_cost — asserts the RELATION
//     (price well under half of token_cost), not a magic pinned number.
//  3. No code path converts the OUTPUT-token acquisition figure into the
//     INPUT-token delivery figure at 1:1.

import (
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// acceptedEntryForAmortization returns an accepted (post-put-accept) inventory
// entry with the standard 70% accept rate (RunAutoAccept's
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

// TestComputePrice_AmortizationNetPositiveAtN4NetNegativeAtN1 is the item's
// required test 1: the exchange must be NET-POSITIVE on an entry sold to 4
// buyers and NET-NEGATIVE if it only ever sells to 1.
//
// acquisitionCost is what the exchange actually paid the seller (entry.PutPrice,
// per RunAutoAccept/applySettlePutAccept — the seller's real scrip credit).
// Revenue at N sales is computePrice(entry) * N (the same per-copy price is
// charged to each of the N buyers — the ranker/match path does not know in
// advance how many resales an entry will get, per ruling decision 4's flat
// assumption).
func TestComputePrice_AmortizationNetPositiveAtN4NetNegativeAtN1(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)

	entry := acceptedEntryForAmortization(8000) // the CLAUDE.md/dontguess-96e live example
	acquisitionCost := entry.PutPrice           // 5600 — actually paid to the seller

	price := eng.ComputePriceForTest(entry)

	revenueAt1 := price * 1
	revenueAt4 := price * 4

	if revenueAt1 >= acquisitionCost {
		t.Errorf("revenue at N=1 (price=%d) = %d, want < acquisitionCost=%d (net NEGATIVE on a single sale)",
			price, revenueAt1, acquisitionCost)
	}
	if revenueAt4 <= acquisitionCost {
		t.Errorf("revenue at N=4 (price=%d) = %d, want > acquisitionCost=%d (net POSITIVE across resales)",
			price, revenueAt4, acquisitionCost)
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
