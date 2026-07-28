package exchange_test

// assign_bounty_repayment_7e21_test.go is the enforcement proof for
// dontguess-7e21 break 2: COMPLETING A COMPRESSION MUST PAY DOWN THE WORKER'S
// DELIVER-ON-CREDIT DEBT.
//
// The loop the exchange advertises is: a buyer short of scrip is served on
// credit rather than turned away (engine_credit.go), and it clears that loan by
// doing compression work. Before this fix the second half did not exist —
// handleAssignAccept paid the bounty with a bare ScripStore.AddBudget and never
// called repaymentAmount/applyRepayment. Withholding was wired at exactly two
// sites (paySellerForBuyMiss, performScripSettlement) and assign-pay was
// neither, so a borrower could claim, compress, be paid in full, and still owe
// every scrip of the loan. There was no indirect route either:
// createCompressionDerivative credits the derivative to orig.SellerKey, so
// residuals on the compressed version flow to the ORIGINAL seller and never
// reach the compressor.
//
// The bug was invisible in production only because zero compression assigns had
// ever been completed (measured 2026-07-28: 44 assigns posted, all exclusive to
// dead ephemeral keys, 0 ever claimed), so this pay path had never once run
// against a borrower.
//
// These tests drive the REAL production ticker (RunAutoAcceptAssigns) against
// the REAL engine/LocalScripStore fixture in assign_autoaccept_test.go, with the
// loan minted by folding a REAL scrip-loan-mint message — the same message
// ensureCreditForShortfall emits on a live buy — never by poking store internals.

import (
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// mintLoanTo folds an operator-authored scrip-loan-mint for principal to the
// fixture's agent, exactly as engine_credit.go's ensureCreditForShortfall does
// on a live buy-accept (same payload type, same tag, same operator sender), and
// returns the borrower's outstanding principal as the ledger then reports it.
func mintLoanTo(t *testing.T, f *compressFixture, loanID string, principal int64) {
	t.Helper()
	payload, err := json.Marshal(scrip.LoanMintPayload{
		Borrower:   f.agent.PublicKeyHex(),
		Principal:  principal,
		VigRateBPS: 0, // operator ruling dontguess-4c1: no vig at fleet tier
		LoanID:     loanID,
	})
	if err != nil {
		t.Fatalf("marshal LoanMintPayload: %v", err)
	}
	msg := f.h.sendMessage(f.h.operator, payload, []string{scrip.TagScripLoanMint}, nil)
	replayAll(t, f.h, f.eng)
	// The exchange State replay above does not fold scrip messages; the ledger is
	// a separate store. ApplyMessage is the same seam ensureCreditForShortfall
	// uses to make a freshly minted loan visible without waiting on a Replay
	// (engine_credit.go's scripApplier), and applyMessage is idempotent by msg ID.
	f.cs.ApplyMessage(msg)

	if got := outstandingPrincipal(f); got != principal {
		t.Fatalf("outstanding principal after mint = %d, want %d — the loan did not fold", got, principal)
	}
}

// outstandingPrincipal sums (Principal - Repaid) over the agent's ACTIVE loans,
// mirroring Engine.borrowerOutstandingPrincipal.
func outstandingPrincipal(f *compressFixture) int64 {
	var total int64
	for _, id := range f.cs.LoansByBorrower(f.agent.PublicKeyHex()) {
		loan, ok := f.cs.GetLoan(id)
		if !ok || loan.Status != scrip.LoanActive {
			continue
		}
		total += loan.Principal - loan.Repaid
	}
	return total
}

// validCompression is the same valid completion the (i) case uses: same VEC_A
// marker (cosine 1.0 -> GATE2 pass), 200 bytes of 400 (50% -> GATE1 pass).
func validCompression() []byte { return []byte(padTo("VEC_A compressed ", 200)) }

// TestAssignBounty_WithheldAgainstOutstandingLoan is the core proof: a worker
// carrying deliver-on-credit debt has creditRepaymentWithholdPct of its bounty
// clawed back and applied to the loan.
//
// The withheld slice is 50% of the bounty, and the loan here (2x the bounty) is
// deliberately larger than that slice so the partial-repayment arithmetic is
// what is under test — not the "loan smaller than the withholding" clamp, which
// has its own case below.
func TestAssignBounty_WithheldAgainstOutstandingLoan(t *testing.T) {
	t.Parallel()
	f := newCompressFixture(t, true, 400)

	principal := wantAutoAcceptReward * 2
	mintLoanTo(t, f, "loan-7e21-partial", principal)

	// Minting credits the borrower's balance (that is the point of credit — the
	// scrip is spendable), so capture the pre-bounty balance rather than
	// assuming zero.
	before := f.balance()

	f.claimAndComplete(t, compressResult(validCompression()))
	f.eng.RunAutoAcceptAssigns()

	wantWithheld := wantAutoAcceptReward * 50 / 100 // creditRepaymentWithholdPct

	if got, want := f.balance(), before+wantAutoAcceptReward-wantWithheld; got != want {
		t.Fatalf("balance after paid bounty = %d, want %d (before %d + bounty %d - withheld %d).\n"+
			"If this equals %d, the bounty was paid in full and the loan was never touched — the dontguess-7e21 break 2 regression.",
			got, want, before, wantAutoAcceptReward, wantWithheld, before+wantAutoAcceptReward)
	}
	if got, want := outstandingPrincipal(f), principal-wantWithheld; got != want {
		t.Fatalf("outstanding principal after bounty = %d, want %d (principal %d - withheld %d)",
			got, want, principal, wantWithheld)
	}
	if st := assignStatus(f, f.assignID); st != exchange.AssignPaid {
		t.Fatalf("assign status = %v, want AssignPaid", st)
	}
}

// TestAssignBounty_WithholdingClampedToOutstandingDebt proves the worker is
// never over-collected: when the outstanding principal is SMALLER than the
// withholding fraction, only the remaining debt is taken, the loan reaches zero,
// and the worker keeps the rest of the bounty.
func TestAssignBounty_WithholdingClampedToOutstandingDebt(t *testing.T) {
	t.Parallel()
	f := newCompressFixture(t, true, 400)

	// A tiny loan: far less than 50% of the bounty, so the clamp is what decides.
	principal := int64(100)
	if principal >= wantAutoAcceptReward*50/100 {
		t.Fatalf("fixture assumption broken: principal %d must be below the withholding fraction %d",
			principal, wantAutoAcceptReward*50/100)
	}
	mintLoanTo(t, f, "loan-7e21-clamp", principal)
	before := f.balance()

	f.claimAndComplete(t, compressResult(validCompression()))
	f.eng.RunAutoAcceptAssigns()

	if got, want := outstandingPrincipal(f), int64(0); got != want {
		t.Fatalf("outstanding principal after bounty = %d, want %d (the loan is fully repaid)", got, want)
	}
	if got, want := f.balance(), before+wantAutoAcceptReward-principal; got != want {
		t.Fatalf("balance after paid bounty = %d, want %d — only the remaining debt (%d) may be withheld, never the full %d fraction",
			got, want, principal, wantAutoAcceptReward*50/100)
	}
}

// TestAssignBounty_NoDebtIsPaidInFull is the anti-regression guard on the other
// side: a worker with NO outstanding loan must be paid the whole bounty. Without
// it the two tests above could be satisfied by withholding unconditionally.
func TestAssignBounty_NoDebtIsPaidInFull(t *testing.T) {
	t.Parallel()
	f := newCompressFixture(t, true, 400)

	if got := outstandingPrincipal(f); got != 0 {
		t.Fatalf("agent starts with outstanding principal %d, want 0", got)
	}
	before := f.balance()

	f.claimAndComplete(t, compressResult(validCompression()))
	f.eng.RunAutoAcceptAssigns()

	if got, want := f.balance(), before+wantAutoAcceptReward; got != want {
		t.Fatalf("balance after paid bounty = %d, want %d — a debt-free worker must receive the FULL bounty", got, want)
	}
}
