package exchange_test

// dontguess-29b wave-6 fix, item 4 (CRITICAL — UNBOUNDED CREDIT).
//
// Wave 5 wired deliver-on-credit (engine_credit.go's ensureCreditForShortfall)
// with NO per-buyer cap, NO outstanding-loan check, and no wiring for
// pkg/scrip/loan.go's LoanRepay/LoanVigAccrue outside pkg/scrip itself — any
// allowlisted fleet key could mint unlimited scrip via repeated shortfall
// loans and drain inventory with no collection path.
//
// This file proves the two-part interim fail-safe:
//
//   - TestEnsureCreditForShortfall_PerBuyerCapRefusesFurtherCredit: a buyer
//     already AT creditMaxOutstandingPerBuyer outstanding principal is
//     REFUSED any further credit — ensureCreditForShortfall returns a non-nil
//     error and mints NO new scrip:loan-mint message.
//   - TestApplyRepayment_ReducesLoanOutstandingAndCanFullyRepay: a direct
//     unit test of applyRepayment/repaymentAmount proving a real
//     scrip:loan-repay emission reduces a loan's outstanding balance
//     (Principal - Repaid), and that repeated application clears the loan to
//     LoanRepaid.
//   - TestPaySellerForBuyMiss_WithholdsForOutstandingLoan: an END-TO-END test
//     driving the REAL put-accept/buy-miss production code path
//     (paySellerForBuyMiss) proving a seller with outstanding debt is
//     credited LESS than the full buy-miss payout, and the withheld amount is
//     durably applied to the loan via scrip:loan-repay — not merely proven
//     against an exported test hook.
//
// Both are verified by mutation (see the accompanying mutation runs in the
// session transcript): commenting out the cap check or emptying
// applyRepayment's loop causes the respective tests to fail.

import (
	"context"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// TestEnsureCreditForShortfall_PerBuyerCapRefusesFurtherCredit seeds a
// pre-existing Active loan for a buyer whose outstanding principal already
// equals creditMaxOutstandingPerBuyer (simulating that the borrowed scrip was
// already spent — i.e. balance is back at 0 but the debt remains), then
// verifies that even a 1-scrip shortfall request is REFUSED.
func TestEnsureCreditForShortfall_PerBuyerCapRefusesFurtherCredit(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	buyerKey := h.buyer.PublicKeyHex()

	const capAmt = exchange.CreditMaxOutstandingPerBuyerForTest
	addScripLoanMintMsg(t, h, buyerKey, "loan-precap", capAmt)

	cs := newCampfireScripStore(t, h)
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	// The pre-existing loan-mint credited the buyer's balance by `cap` too
	// (applyLoanMint). Simulate that the borrowed scrip was already spent (a
	// realistic prior hold) by decrementing it back to 0, leaving the loan's
	// full principal outstanding and unrepaid — exactly "at the cap, broke".
	ctx := context.Background()
	bal, etag, err := cs.GetBudget(ctx, buyerKey, scrip.BalanceKey)
	if err != nil {
		t.Fatalf("GetBudget: %v", err)
	}
	if bal != capAmt {
		t.Fatalf("test setup: buyer balance after loan-mint = %d, want %d (== capAmt)", bal, capAmt)
	}
	if _, _, err := cs.DecrementBudget(ctx, buyerKey, scrip.BalanceKey, bal, etag); err != nil {
		t.Fatalf("test setup: DecrementBudget: %v", err)
	}
	if got := cs.Balance(buyerKey); got != 0 {
		t.Fatalf("test setup: buyer balance after simulated spend = %d, want 0", got)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.PublicKeyHex(),
		ScripStore:        cs,
		Logger:            func(string, ...any) {},
	})

	if got, ok := eng.BorrowerOutstandingPrincipalForTest(buyerKey); !ok || got != capAmt {
		t.Fatalf("test setup: borrowerOutstandingPrincipal = (%d, %v), want (%d, true)", got, ok, capAmt)
	}

	preMintCount := len(mustListLoanMints(t, h))

	// Even a 1-scrip shortfall must now be REFUSED — outstanding (cap) + 1 > cap.
	err = eng.EnsureCreditForShortfallForTest(buyerKey, 1, "buyer-accept-over-cap", "match-over-cap")
	if err == nil {
		t.Fatal("expected ensureCreditForShortfall to REFUSE credit once buyer is at the per-buyer cap, got nil error")
	}
	t.Logf("got expected refusal error: %v", err)

	postMintCount := len(mustListLoanMints(t, h))
	if postMintCount != preMintCount {
		t.Errorf("expected NO new scrip:loan-mint message once buyer is at cap, count went from %d to %d", preMintCount, postMintCount)
	}

	// Outstanding principal must be unchanged — nothing was minted.
	if got, ok := eng.BorrowerOutstandingPrincipalForTest(buyerKey); !ok || got != capAmt {
		t.Errorf("borrowerOutstandingPrincipal after refused request = (%d, %v), want (%d, true) — unchanged", got, ok, capAmt)
	}
}

// TestEnsureCreditForShortfall_JustUnderCapStillSucceeds is the companion
// positive case: a buyer whose outstanding principal plus the new shortfall
// stays AT OR BELOW the cap must still be extended credit normally. This
// guards against an off-by-one or overly aggressive cap implementation.
func TestEnsureCreditForShortfall_JustUnderCapStillSucceeds(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	buyerKey := h.buyer.PublicKeyHex()

	const capAmt = exchange.CreditMaxOutstandingPerBuyerForTest
	const preexisting = capAmt - 100
	addScripLoanMintMsg(t, h, buyerKey, "loan-under-capAmt", preexisting)

	cs := newCampfireScripStore(t, h)
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	ctx := context.Background()
	bal, etag, err := cs.GetBudget(ctx, buyerKey, scrip.BalanceKey)
	if err != nil {
		t.Fatalf("GetBudget: %v", err)
	}
	if _, _, err := cs.DecrementBudget(ctx, buyerKey, scrip.BalanceKey, bal, etag); err != nil {
		t.Fatalf("test setup: DecrementBudget: %v", err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.PublicKeyHex(),
		ScripStore:        cs,
		Logger:            func(string, ...any) {},
	})

	// Shortfall of exactly 100 brings outstanding to exactly `cap` — must succeed.
	if err := eng.EnsureCreditForShortfallForTest(buyerKey, 100, "buyer-accept-at-capAmt", "match-at-capAmt"); err != nil {
		t.Fatalf("expected credit to succeed when outstanding+shortfall == capAmt exactly, got error: %v", err)
	}

	if got, ok := eng.BorrowerOutstandingPrincipalForTest(buyerKey); !ok || got != capAmt {
		t.Errorf("borrowerOutstandingPrincipal after successful top-up = (%d, %v), want (%d, true)", got, ok, capAmt)
	}
}

// TestApplyRepayment_ReducesLoanOutstandingAndCanFullyRepay is a direct
// unit test of the repayment wiring (repaymentAmount + applyRepayment): the
// FIRST real caller of pkg/scrip's LoanRepay outside pkg/scrip itself.
func TestApplyRepayment_ReducesLoanOutstandingAndCanFullyRepay(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	borrowerKey := h.seller.PublicKeyHex()

	const principal = int64(10000)
	addScripLoanMintMsg(t, h, borrowerKey, "loan-repay-test", principal)

	cs := newCampfireScripStore(t, h)
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.PublicKeyHex(),
		ScripStore:        cs,
		Logger:            func(string, ...any) {},
	})

	// repaymentAmount on a gross credit of 8000 with 50% withhold pct and
	// outstanding=10000 (not cap-limiting) must withhold exactly 4000.
	const grossCredit = int64(8000)
	wantWithheld := grossCredit * exchange.CreditRepaymentWithholdPctForTest / 100
	got := eng.RepaymentAmountForTest(borrowerKey, grossCredit)
	if got != wantWithheld {
		t.Fatalf("repaymentAmount(gross=%d) = %d, want %d (%d%% of gross)", grossCredit, got, wantWithheld, exchange.CreditRepaymentWithholdPctForTest)
	}

	// Apply it — must durably reduce the loan's outstanding balance.
	eng.ApplyRepaymentForTest(borrowerKey, got, "cause-msg-1")

	loanID := "loan-repay-test"
	loan, ok := cs.GetLoan(loanID)
	if !ok {
		t.Fatalf("expected loan %s to exist", loanID)
	}
	if loan.Repaid != wantWithheld {
		t.Errorf("loan.Repaid after first repayment = %d, want %d", loan.Repaid, wantWithheld)
	}
	if loan.Status != scrip.LoanActive {
		t.Errorf("loan.Status after partial repayment = %v, want LoanActive (%v)", loan.Status, scrip.LoanActive)
	}
	owedAfterFirst := loan.Principal - loan.Repaid
	if owedAfterFirst != principal-wantWithheld {
		t.Errorf("owed (Principal-Repaid) after first repayment = %d, want %d", owedAfterFirst, principal-wantWithheld)
	}

	// Fully clear the remaining debt in one more application.
	eng.ApplyRepaymentForTest(borrowerKey, owedAfterFirst, "cause-msg-2")
	loan, ok = cs.GetLoan(loanID)
	if !ok {
		t.Fatalf("expected loan %s to still exist", loanID)
	}
	if loan.Repaid != principal {
		t.Errorf("loan.Repaid after full repayment = %d, want %d (== Principal)", loan.Repaid, principal)
	}
	if loan.Status != scrip.LoanRepaid {
		t.Errorf("loan.Status after full repayment = %v, want LoanRepaid (%v)", loan.Status, scrip.LoanRepaid)
	}

	// Outstanding principal for the borrower must now be 0 — the loan is closed.
	if outstanding, ok := eng.BorrowerOutstandingPrincipalForTest(borrowerKey); !ok || outstanding != 0 {
		t.Errorf("borrowerOutstandingPrincipal after full repayment = (%d, %v), want (0, true)", outstanding, ok)
	}
}

// TestPaySellerForBuyMiss_WithholdsForOutstandingLoan drives the REAL
// production buy-miss put-accept path (not an exported test hook) and proves
// automatic repayment withholds part of the seller's payout when that seller
// carries outstanding deliver-on-credit debt, durably applying it to the loan.
func TestPaySellerForBuyMiss_WithholdsForOutstandingLoan(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)

	const tokenCost int64 = 90000
	expectedGrossPutPay := tokenCost * int64(exchange.BuyMissOfferRate) / 100 // 63000

	sellerKey := h.buyer.PublicKeyHex() // buyer is also the seller in buy-miss (fulfills its own request)

	// Seed the seller with an outstanding, Active loan BEFORE constructing the
	// scrip store, mirroring addScripMintMsg's own documented ordering
	// requirement.
	const loanPrincipal = int64(100000) // large enough that 50% of the put-pay never hits the cap
	addScripLoanMintMsg(t, h, sellerKey, "loan-putpay-test", loanPrincipal)

	// Mint operator scrip to cover the (reduced) put-pay disbursement.
	addScripMintMsg(t, h, h.operator.PublicKeyHex(), expectedGrossPutPay+10000)

	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	// The loan-mint credited the seller's balance by loanPrincipal too — net
	// that out (simulating the borrowed scrip already spent) so the only
	// balance change we observe below is the put-pay credit.
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

	task := "Translate a legacy COBOL batch job to Go (buy-miss repayment fixture)"

	// Step 1: buyer sends a buy — no inventory => engine emits buy-miss offer.
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
		t.Fatal("step 1: no buy-miss offer emitted")
	}

	// Step 2: buyer puts the result — same task description triggers auto-accept.
	_ = h.sendMessage(h.buyer,
		putPayload(task, "sha256:"+shaHexFor(tokenCost), "code", tokenCost, tokenCost*2),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)

	// Wait for the (reduced) credit to land.
	wantNetPutPay := expectedGrossPutPay - (expectedGrossPutPay * exchange.CreditRepaymentWithholdPctForTest / 100)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cs.Balance(sellerKey) == wantNetPutPay {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	gotBalance := cs.Balance(sellerKey)
	if gotBalance != wantNetPutPay {
		t.Fatalf("seller balance after buy-miss put-accept with outstanding debt = %d, want %d (gross %d minus %d%% withheld for repayment)",
			gotBalance, wantNetPutPay, expectedGrossPutPay, exchange.CreditRepaymentWithholdPctForTest)
	}

	// The withheld amount must have been durably applied to the loan.
	withheld := expectedGrossPutPay - wantNetPutPay
	loan, ok := cs.GetLoan("loan-putpay-test")
	if !ok {
		t.Fatal("expected loan-putpay-test to still exist")
	}
	if loan.Repaid != withheld {
		t.Errorf("loan.Repaid after buy-miss repayment withholding = %d, want %d", loan.Repaid, withheld)
	}
	if loan.Status != scrip.LoanActive {
		t.Errorf("loan.Status = %v, want LoanActive (%v) — not yet fully repaid", loan.Status, scrip.LoanActive)
	}

	// A durable scrip:loan-repay message must exist on the log (not just a
	// live in-memory mutation) so a fresh Replay reconstructs it.
	repayMsgs, _ := h.st.ListMessages(0, store.MessageFilter{Tags: []string{scrip.TagScripLoanRepay}})
	if len(repayMsgs) == 0 {
		t.Error("expected at least 1 durable scrip:loan-repay message, found none")
	}

	freshCS, err := scrip.NewLocalScripStore(h.st, h.operator.PublicKeyHex())
	if err != nil {
		t.Fatalf("NewCampfireScripStore (fresh): %v", err)
	}
	freshLoan, ok := freshCS.GetLoan("loan-putpay-test")
	if !ok {
		t.Fatal("expected loan-putpay-test to be reconstructed from a fresh Replay")
	}
	if freshLoan.Repaid != withheld {
		t.Errorf("replayed loan.Repaid = %d, want %d", freshLoan.Repaid, withheld)
	}
}

// mustListLoanMints returns every scrip:loan-mint message currently on the
// harness log.
func mustListLoanMints(t *testing.T, h *testHarness) []store.MessageRecord {
	t.Helper()
	msgs, err := h.st.ListMessages(0, store.MessageFilter{Tags: []string{scrip.TagScripLoanMint}})
	if err != nil {
		t.Fatalf("ListMessages(scrip:loan-mint): %v", err)
	}
	return msgs
}

// shaHexFor returns a deterministic 64-hex-char string derived from n, used
// to build a plausible-looking content hash for put fixtures in this file.
func shaHexFor(n int64) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = hexdigits[(n+int64(i))%16]
	}
	return string(b)
}
