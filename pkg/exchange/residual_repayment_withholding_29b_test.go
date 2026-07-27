package exchange_test

// dontguess-29b wave-7 fix, item 2 (RESIDUAL-SIDE WITHHOLDING HAD ZERO
// COVERAGE): TestPaySellerForBuyMiss_WithholdsForOutstandingLoan
// (engine_credit_cap_test.go) proves automatic repayment withholding on the
// PUT/buy-miss path (paySellerForBuyMiss, engine_put.go). Nothing proved the
// SAME withholding on the residual/settle path
// (performScripSettlement, engine_settle.go) — replacing
// `withheld := e.repaymentAmount(sellerKey, residualGross)` at
// engine_settle.go with `withheld := int64(0)` passed the entire suite before
// this test existed.
//
// This test drives a REAL end-to-end buy -> match -> buyer-accept -> deliver
// -> settle(complete) flow (via buildSettleChainForPriceTests, the same
// helper scrip_settle_price_test.go uses) for a SELLER who carries an
// outstanding, Active deliver-on-credit loan seeded BEFORE the scrip store is
// constructed, and asserts:
//   - the seller's residual credit is LESS than the full residualGross by
//     exactly the withheld amount (creditRepaymentWithholdPct of
//     residualGross);
//   - the withheld amount is durably applied to the loan (loan.Repaid).
//
// Mutation: replace engine_settle.go's
// `withheld := e.repaymentAmount(sellerKey, residualGross)` with
// `withheld := int64(0)` — this test must fail (seller residual would be the
// full residualGross with zero withheld, and loan.Repaid would stay 0).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

func TestSettleResidual_WithholdsForOutstandingLoan(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	sellerKey := h.seller.PublicKeyHex()

	// Seed the seller with an outstanding, Active loan BEFORE constructing the
	// scrip store (mirrors addScripMintMsg/addScripLoanMintMsg's documented
	// ordering requirement so the initial Replay sees it).
	const loanPrincipal = int64(100000) // large enough that 50% of any residual here never hits the cap
	addScripLoanMintMsg(t, h, sellerKey, "loan-residual-test", loanPrincipal)

	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	// The loan-mint credited the seller's balance by loanPrincipal too — net
	// that out (simulating the borrowed scrip already spent) so the only
	// balance change observed below is the residual credit.
	ctx := context.Background()
	preBal, etag, err := cs.GetBudget(ctx, sellerKey, scrip.BalanceKey)
	if err != nil {
		t.Fatalf("GetBudget: %v", err)
	}
	if preBal != loanPrincipal {
		t.Fatalf("test setup: seller balance after loan-mint = %d, want %d", preBal, loanPrincipal)
	}
	if _, _, err := cs.DecrementBudget(ctx, sellerKey, scrip.BalanceKey, preBal, etag); err != nil {
		t.Fatalf("test setup: DecrementBudget: %v", err)
	}

	res, deliverMsg, salePrice := buildSettleChainForPriceTests(t, h, eng, cs, "Kubernetes operator scaffold generator", 8000)

	// Expected numbers, derived the same way engine_settle.go's
	// performScripSettlement does (residualDenominatorFor is not
	// high-reuse-classified for a fresh single-sale entry, so it is the
	// standard ResidualRate=10 denominator) — mirrors
	// TestSettle_PriceLockedAtBuyerAcceptTime's own expectedResidual derivation.
	expectedResidualGross := salePrice / exchange.ResidualRate
	expectedWithheld := expectedResidualGross * exchange.CreditRepaymentWithholdPctForTest / 100
	expectedNetResidual := expectedResidualGross - expectedWithheld
	if expectedWithheld <= 0 {
		t.Fatalf("test setup: expectedWithheld = %d, want > 0 (residualGross=%d too small to exercise withholding)", expectedWithheld, expectedResidualGross)
	}

	sellerBalanceBefore := cs.Balance(sellerKey)

	completePayload, _ := json.Marshal(map[string]any{
		"price":    salePrice,
		"entry_id": res.ID,
	})
	completeMsg := h.sendMessage(h.buyer, completePayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete,
		},
		[]string{deliverMsg.ID},
	)

	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	rec, err := h.st.GetMessage(completeMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if dispatchErr := eng.DispatchForTest(exchange.FromStoreRecord(rec)); dispatchErr != nil {
		t.Fatalf("dispatch settle(complete): %v", dispatchErr)
	}

	gotBalance := cs.Balance(sellerKey)
	wantBalance := sellerBalanceBefore + expectedNetResidual
	if gotBalance != wantBalance {
		t.Fatalf("seller balance after settle(complete) with outstanding debt = %d, want %d (residualGross %d minus %d%% withheld for repayment)",
			gotBalance, wantBalance, expectedResidualGross, exchange.CreditRepaymentWithholdPctForTest)
	}

	loan, ok := cs.GetLoan("loan-residual-test")
	if !ok {
		t.Fatal("expected loan-residual-test to still exist")
	}
	if loan.Repaid != expectedWithheld {
		t.Errorf("loan.Repaid after settle-residual repayment withholding = %d, want %d", loan.Repaid, expectedWithheld)
	}
	if loan.Status != scrip.LoanActive {
		t.Errorf("loan.Status after partial repayment = %v, want LoanActive (%v)", loan.Status, scrip.LoanActive)
	}
}
