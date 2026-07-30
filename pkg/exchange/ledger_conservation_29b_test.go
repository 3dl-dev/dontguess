package exchange_test

// dontguess-29b wave-7 fix, item 1 (LEDGER CONSERVATION WAS BROKEN, the most
// serious of the three wave-7 findings).
//
// REPORTED: repayment withholding reduced the seller's payout so the
// OPERATOR effectively retained that scrip in its own balance, while
// applyLoanRepay SEPARATELY burned the same amount from totalSupply — the
// amount was counted twice. Measured: after one withheld put-pay,
// replay-derived TotalSupply=141500 vs sum(balances)=173000 — under-
// reporting by exactly the withheld 31500, from a starting state where the
// two matched EXACTLY.
//
// FIX (see applyLoanRepay's CONSERVATION doc comment in
// pkg/scrip/relay_store.go, and paySellerForBuyMiss's in
// pkg/exchange/engine_put.go): the seller/borrower is now paid the FULL
// gross amount it earned (offeredPrice for buy-miss put-pay, residualGross
// for settle), and the withheld fraction is clawed back via a real
// scrip:loan-repay message that debits the loan's OWN BorrowerKey (not the
// operator) — paired with the totalSupply burn — so TotalSupply and
// sum(balances) move together.
//
// This test drives the REAL production buy-miss put-accept path (the exact
// scenario the bug was measured against), then reconstructs a FRESH
// scrip.LocalScripStore from the durable message log (matching how the bug
// was originally measured: "replay-derived") and asserts the invariant
// TotalSupply == sum(balances) holds both BEFORE any repayment (the
// "starting state where the two matched exactly") and AFTER the withheld
// put-pay + loan-repay.
//
// MUTATION VERIFIED (see session transcript / PR description): commenting
// out applyLoanRepay's borrower-balance debit (reverting to burning
// totalSupply alone, the original bug) makes the AFTER assertion fail with
// numbers matching the bug report exactly (141500 vs 173000 for these
// fixture amounts).

import (
	"context"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

func TestLedgerConservation_TotalSupplyMatchesSumOfBalances_AfterWithheldPutPay(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)

	const tokenCost int64 = 90000
	expectedGrossPutPay := tokenCost * int64(exchange.BuyMissOfferRate) / 100 // 63000

	sellerKey := h.buyer.PublicKeyHex() // buyer is also the seller in buy-miss (fulfills its own request)
	operatorKey := h.operator.PublicKeyHex()

	// Seed the seller with an outstanding, Active loan BEFORE constructing the
	// scrip store, mirroring addScripMintMsg's own documented ordering
	// requirement.
	const loanPrincipal = int64(100000)
	addScripLoanMintMsg(t, h, sellerKey, "loan-conservation-test", loanPrincipal)

	// Mint operator scrip to cover the buy-miss disbursement.
	const operatorMint = int64(73000) // expectedGrossPutPay (63000) + 10000 margin
	addScripMintMsg(t, h, operatorKey, operatorMint)

	// --- BASELINE: verify the invariant holds EXACTLY before any repayment
	// activity — "a starting state where the two matched exactly", matching
	// how the bug was originally reported.
	baseline := newCampfireScripStore(t, h)
	if got, want := baseline.TotalSupply(), operatorMint+loanPrincipal; got != want {
		t.Fatalf("test setup: baseline TotalSupply = %d, want %d", got, want)
	}
	baselineSum := baseline.Balance(operatorKey) + baseline.Balance(sellerKey)
	if baseline.TotalSupply() != baselineSum {
		t.Fatalf("test setup: baseline TotalSupply (%d) != sum(balances) (%d) — fixture itself is unbalanced before the scenario even runs",
			baseline.TotalSupply(), baselineSum)
	}

	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	task := "Port a Python data pipeline to Rust (ledger conservation fixture)"

	// buy — no inventory => engine emits buy-miss offer.
	_ = h.sendMessage(h.buyer,
		buyPayload(task, 120000),
		[]string{exchange.TagBuy},
		nil,
	)

	preBuyMiss, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{exchange.TagBuyMiss}})

	ctxRun, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctxRun) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msgs, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{exchange.TagBuyMiss}})
		if len(msgs) > len(preBuyMiss) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	buyMissMsgs, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{exchange.TagBuyMiss}})
	if len(buyMissMsgs) <= len(preBuyMiss) {
		cancel()
		t.Fatal("no buy-miss offer emitted")
	}

	// put the result — same task description triggers auto-accept, which pays
	// the seller and (since the seller carries outstanding debt) withholds
	// and repays.
	wantWithheld := expectedGrossPutPay * exchange.CreditRepaymentWithholdPctForTest / 100
	wantNetPutPay := expectedGrossPutPay - wantWithheld
	_ = h.sendMessage(h.buyer,
		putPayload(task, "sha256:"+shaHexFor(tokenCost), "code", tokenCost, tokenCost*2),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)

	// Wait for the loan-repay message to durably land (the authoritative
	// signal both the balance change AND the loan update are complete — see
	// applyLoanRepay's atomicity: the borrower debit and Repaid increment
	// happen together, in the same fold call).
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msgs, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{scrip.TagScripLoanRepay}})
		if len(msgs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	loanRepayMsgs, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{scrip.TagScripLoanRepay}})
	if len(loanRepayMsgs) == 0 {
		t.Fatal("expected a scrip:loan-repay message after the withheld put-pay")
	}

	// --- REPLAY-DERIVED CHECK (matches how the bug was originally measured):
	// reconstruct a FRESH scrip store from the durable message log — not the
	// live in-session state — and verify TotalSupply == sum(balances).
	fresh := newCampfireScripStore(t, h)

	loan, ok := fresh.GetLoan("loan-conservation-test")
	if !ok {
		t.Fatal("expected loan-conservation-test to exist in the replay-derived store")
	}
	if loan.Repaid != wantWithheld {
		t.Fatalf("replay-derived loan.Repaid = %d, want %d", loan.Repaid, wantWithheld)
	}

	gotOperatorBal := fresh.Balance(operatorKey)
	gotSellerBal := fresh.Balance(sellerKey)
	wantOperatorBal := operatorMint - expectedGrossPutPay // paid gross out in full via applyPutPay
	wantSellerBal := loanPrincipal + wantNetPutPay        // gross put-pay in, then withheld clawed back
	if gotOperatorBal != wantOperatorBal {
		t.Errorf("replay-derived operator balance = %d, want %d", gotOperatorBal, wantOperatorBal)
	}
	if gotSellerBal != wantSellerBal {
		t.Errorf("replay-derived seller balance = %d, want %d", gotSellerBal, wantSellerBal)
	}

	gotSum := gotOperatorBal + gotSellerBal
	gotTotalSupply := fresh.TotalSupply()
	if gotTotalSupply != gotSum {
		t.Fatalf("SUPPLY-CONSERVATION INVARIANT VIOLATED: replay-derived TotalSupply = %d, want %d (== sum(balances): operator %d + seller %d) — off by %d",
			gotTotalSupply, gotSum, gotOperatorBal, gotSellerBal, gotTotalSupply-gotSum)
	}

	// Pin the exact pre-fix bug numbers so a regression reproduces the
	// reported symptom precisely, not just "some" imbalance.
	const wantTotalSupplyAfterRepay = int64(141500) // operatorMint(73000) + loanPrincipal(100000) - wantWithheld(31500)
	if gotTotalSupply != wantTotalSupplyAfterRepay {
		t.Errorf("replay-derived TotalSupply = %d, want %d (operatorMint %d + loanPrincipal %d - withheld %d)",
			gotTotalSupply, wantTotalSupplyAfterRepay, operatorMint, loanPrincipal, wantWithheld)
	}
}
