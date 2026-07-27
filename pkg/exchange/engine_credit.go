package exchange

import (
	"fmt"
	"time"

	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// Deliver-on-credit (dontguess-29b, root-caused by the operator ruling
// dontguess-96e).
//
// PROBLEM MEASURED: 13 of 26 buyer-accepts (exactly half, 13-day window ending
// 2026-07-27) were rejected with reason=insufficient_scrip. The buyer had
// already found the exact entry it needed and was turned away broke — this
// destroys the sale AND the highest-signal demand event in the system at once.
//
// ROOT CAUSE: pay-to-play cannot bootstrap. Total scrip ever minted (1.25M
// across 7 hand-minted operator mints) is far short of match prices demanded
// (4.3M) — that arithmetic never closes without minting forever.
//
// THE FIX IS A WIRING JOB, NOT A NEW SUBSYSTEM: pkg/scrip/loan.go already has
// a full LoanRecord Active/Repaid/Defaulted lifecycle (LoanMint/LoanRepay/
// LoanVigAccrue, tags in pkg/scrip/messages.go) that nothing in the engine
// ever emitted. This file wires LoanMint into the buyer-accept hold path: when
// a buyer is short, mint a loan for exactly the shortfall (never the whole
// hold amount — a buyer with a partial balance should not borrow scrip it
// already has) BEFORE decAndSaveHold runs, so the existing hold logic sees a
// sufficient balance and proceeds completely unchanged.
//
// TIER GATE (SCOPE FENCE — do not widen): fleet only, never federation.
// creditTierEligible mirrors the natural boundary the engine already uses
// everywhere else in this file — ScripStore != nil means a relay-attached
// team/fleet-tier deployment (individual tier has no ScripStore and no scrip
// accounting at all, so credit is moot there).
//
// FederationGuardEnabled — NOT BrokeredMatchMode — is the real federation
// flag: engine_core.go documents BrokeredMatchMode as a matching-ROUTING
// toggle that "always coexists" with inline matching "without affecting
// either path's state machine" (it just decides whether handleBuy runs
// inline semantic matching or posts a brokered-match assign) — it says
// nothing about trust/deployment topology. FederationGuardEnabled is what
// engine_core.go calls "REQUIRED in multi-operator/federation deployments"
// and defaults false for single-operator deployments. Deliver-on-credit
// must never engage when FederationGuardEnabled is true — federation is
// where Sybil (fresh npub, buy on credit, walk) becomes a real attack, and
// that defense is explicitly OPEN, gated on dontguess-5a3. At fleet tier
// (FederationGuardEnabled=false) every borrower is one of the operator's
// allowlisted, traceable keys, so the standing ruling (Sybil defense
// premature for fleet, tier-gated elsewhere) already covers this — see
// dontguess-29b's SYBIL CAVEAT.
func (e *Engine) creditTierEligible() bool {
	return e.opts.ScripStore != nil && !e.opts.FederationGuardEnabled
}

// Credit loan defaults (dontguess-29b). These are NOT an operator ruling —
// unlike WarmCompressionBountyPct (explicitly derived and ruled on), no vig
// rate or term was specified for the deliver-on-credit rail. They are
// deliberately modest, named, and documented here as an initial default the
// medium/slow pricing loops (docs/design's three-loop model) may tune from
// observed repayment/default behavior — treat them as a tunable starting
// point, not a frozen conclusion.
const (
	// creditLoanVigRateBPS is the vig (interest) rate in basis points per hour
	// charged on an auto-minted shortfall loan. 10 bps/hour ≈ 2.4%/day — modest
	// carrying cost, not a punitive rate: the borrower is a legitimate,
	// allowlisted fleet member registering real demand, not a delinquent risk.
	creditLoanVigRateBPS = 10

	// creditLoanTermDays is the repayment term before a loan transitions to
	// Defaulted. 30 days matches the convention spec's own stated default
	// (docs/convention/exchange-scrip/loan-mint.json: "Defaults to 30 days
	// from mint time").
	creditLoanTermDays = 30

	// creditMaxOutstandingPerBuyer is a HARD ceiling on a single buyer's total
	// unpaid loan principal (Principal - Repaid, summed across every Active
	// loan) via the deliver-on-credit rail. INTERIM FAIL-SAFE (dontguess-29b
	// wave-6 fix, NOT an operator ruling — dontguess-4c1 governs the eventual
	// default/collection policy and vig rate; a cap can only be LOOSENED
	// later, so a conservative default is safe to ship without waiting on
	// that ruling). Without this cap, any allowlisted fleet key could mint
	// unlimited scrip via repeated shortfall loans and drain inventory with
	// no collection path — LoanRepay/LoanVigAccrue existed in pkg/scrip but
	// nothing in the engine ever called them, and SetDebtorScore had zero
	// production callers. 300,000 is roughly 5x the largest single hold
	// amount produced by this package's own fixtures (a ~45K-token_cost
	// entry's warm-compression bounty alone prices near 130% of token_cost
	// under the two-unit model, i.e. tens of thousands per entry) — enough
	// headroom for a legitimate buyer to complete several deliver-on-credit
	// purchases in a row before being cut off, not enough for one key to
	// drain the exchange unbounded.
	creditMaxOutstandingPerBuyer int64 = 300_000

	// creditRepaymentWithholdPct is the percentage of a borrower's FUTURE put
	// credit (paySellerForBuyMiss) or sale residual (performScripSettlement)
	// automatically withheld and applied to that borrower's outstanding loan
	// principal via a real scrip:loan-repay emission — see applyRepayment.
	// This is the first production caller of LoanRepay (dontguess-29b wave-6
	// fix): pkg/scrip/loan.go's Active/Repaid/Defaulted lifecycle existed,
	// but nothing durable ever moved a loan out of Active. INTERIM DEFAULT,
	// NOT an operator ruling (dontguess-4c1 governs the final collection
	// policy) — 50% is aggressive enough that debt actually retires instead
	// of accumulating forever, but leaves the borrower half of every future
	// credit so a legitimate borrower is never fully locked out of its own
	// earnings while repaying.
	creditRepaymentWithholdPct = 50
)

// scripLoanQuerier is the loan-query surface of a scrip store. LocalScripStore
// satisfies it (LoansByBorrower, GetLoan). The engine holds scrip.SpendingStore
// (which does not expose loan queries), so the per-buyer cap and the
// repayment withholding both type-assert to read live loan state — mirroring
// how scripApplier (engine_mint.go) type-asserts to fold live balance state.
type scripLoanQuerier interface {
	LoansByBorrower(borrowerKey string) []string
	GetLoan(loanID string) (*scrip.LoanRecord, bool)
}

// borrowerOutstandingPrincipal sums (Principal - Repaid) across every Active
// loan for borrowerKey — the total unpaid credit currently extended to that
// borrower via the deliver-on-credit rail. Returns ok=false when the
// configured ScripStore does not support loan queries (only
// scrip.LocalScripStore does in this codebase); callers must treat ok=false
// as "cannot verify" and choose their own fail-safe default rather than
// assuming zero debt.
func (e *Engine) borrowerOutstandingPrincipal(borrowerKey string) (total int64, ok bool) {
	q, ok := e.opts.ScripStore.(scripLoanQuerier)
	if !ok {
		return 0, false
	}
	for _, loanID := range q.LoansByBorrower(borrowerKey) {
		loan, exists := q.GetLoan(loanID)
		if !exists || loan.Status != scrip.LoanActive {
			continue
		}
		total += loan.Principal - loan.Repaid
	}
	return total, true
}

// repaymentAmount computes how much of a would-be credit of grossAmount to
// borrowerKey should be withheld and applied to that borrower's outstanding
// loan principal instead of paid out, per creditRepaymentWithholdPct. Returns
// 0 (no withholding) when the borrower carries no active debt, or when the
// configured ScripStore cannot be queried for loans (fail-OPEN here — unlike
// the cap check, a missed repayment opportunity is not a safety hole, only a
// slower collection; see borrowerOutstandingPrincipal's doc comment).
func (e *Engine) repaymentAmount(borrowerKey string, grossAmount int64) int64 {
	if grossAmount <= 0 {
		return 0
	}
	outstanding, ok := e.borrowerOutstandingPrincipal(borrowerKey)
	if !ok || outstanding <= 0 {
		return 0
	}
	withhold := grossAmount * creditRepaymentWithholdPct / 100
	if withhold > outstanding {
		withhold = outstanding
	}
	if withhold > grossAmount {
		withhold = grossAmount
	}
	return withhold
}

// applyRepayment durably applies amount (already computed by repaymentAmount)
// against borrowerKey's outstanding loans, oldest-first (LoansByBorrower
// returns loan IDs in mint order), emitting one scrip:loan-repay message per
// loan touched until amount is exhausted or every active loan is repaid in
// full. Each emission is folded live via scripApplier (mirrors
// ensureCreditForShortfall's own loan-mint fold) so a same-session query of
// the borrower's outstanding balance reflects the repayment immediately.
//
// Best-effort: a marshal or emit failure is logged and the loop continues to
// the next loan. This is called AFTER the caller has already reduced the
// amount credited to borrowerKey by exactly `amount` (paySellerForBuyMiss,
// performScripSettlement) — a failure here never double-charges the borrower
// (the withheld scrip was never paid out either way) and never forgives the
// debt silently (the durable log is reconciled from a later Replay once the
// underlying transient failure — e.g. a marshal func injected for another
// test — clears).
func (e *Engine) applyRepayment(borrowerKey string, amount int64, causeMsgID string) {
	if amount <= 0 {
		return
	}
	q, ok := e.opts.ScripStore.(scripLoanQuerier)
	if !ok {
		return
	}
	remaining := amount
	for _, loanID := range q.LoansByBorrower(borrowerKey) {
		if remaining <= 0 {
			break
		}
		loan, exists := q.GetLoan(loanID)
		if !exists || loan.Status != scrip.LoanActive {
			continue
		}
		owed := loan.Principal - loan.Repaid
		if owed <= 0 {
			continue
		}
		apply := remaining
		if apply > owed {
			apply = owed
		}

		payload, err := e.marshal(scrip.LoanRepayPayload{LoanID: loanID, Amount: apply})
		if err != nil {
			e.opts.log("engine: deliver-on-credit: repayment: marshal scrip-loan-repay for loan=%s: %v", shortKey(loanID), err)
			continue
		}
		msg, err := e.sendOperatorMessage(payload, []string{scrip.TagScripLoanRepay}, []string{causeMsgID})
		if err != nil {
			e.opts.log("engine: deliver-on-credit: repayment: emit scrip-loan-repay for loan=%s: %v", shortKey(loanID), err)
			continue
		}
		if applier, ok := e.opts.ScripStore.(scripApplier); ok {
			applier.ApplyMessage(msg)
		}

		remaining -= apply
		e.opts.log("engine: deliver-on-credit: repaid loan=%s amount=%d borrower=%s (remaining owed=%d)",
			shortKey(loanID), apply, shortKey(borrowerKey), owed-apply)
	}
}

// ensureCreditForShortfall tops up buyerKey's balance via the loan rail
// (scrip:loan-mint) so it can cover holdAmount, if and only if it currently
// cannot. It mints EXACTLY the shortfall (holdAmount - balance), never the
// full holdAmount, so a buyer with a partial balance is not lent scrip it
// already has.
//
// Returns nil (no-op) when:
//   - the deployment is not credit-eligible (creditTierEligible == false —
//     individual tier or FederationGuardEnabled), or
//   - the buyer's current balance already covers holdAmount.
//
// A non-nil error here is NON-FATAL to the caller (handleSettleBuyerAcceptScrip
// logs it and falls through to decAndSaveHold, which reproduces the exact
// pre-29b insufficient_scrip reject path) — INCLUDING the per-buyer cap
// refusal below, which is by design: refusing credit must degrade to the
// ordinary insufficient-scrip reject, never a distinct buyer-facing failure
// mode. This function must never be the source of a buyer-facing error
// distinct from "insufficient scrip" — it only ever makes a shortfall SMALLER
// or resolves it entirely, never worse.
func (e *Engine) ensureCreditForShortfall(buyerKey string, holdAmount int64, buyerAcceptMsgID, matchMsgID string) error {
	if !e.creditTierEligible() {
		return nil
	}
	if holdAmount <= 0 {
		return nil
	}

	ctx := e.engineCtx()
	bal, _, err := e.opts.ScripStore.GetBudget(ctx, buyerKey, scrip.BalanceKey)
	if err != nil {
		return fmt.Errorf("credit: GetBudget for buyer %s: %w", shortKey(buyerKey), err)
	}
	if bal >= holdAmount {
		return nil // no credit needed
	}
	shortfall := holdAmount - bal

	// PER-BUYER CAP (fail-safe, dontguess-29b wave-6 fix — see
	// creditMaxOutstandingPerBuyer's doc comment). Fail CLOSED: if the
	// outstanding balance cannot be verified (ScripStore does not support
	// loan queries), refuse rather than risk unbounded credit. This is
	// non-fatal to the caller (see this function's doc comment) — it falls
	// through to the ordinary insufficient-scrip reject path.
	//
	// OPERATOR-VISIBLE SIGNAL (dontguess-29b wave-7 fix, item 3): a borrower
	// who is refused here would otherwise be cut off with NOTHING
	// operator-visible beyond a log line the caller may not be watching —
	// this does not transition the loan to Defaulted, accrue vig, or write
	// DebtorScore (that collection policy is gated on dontguess-4c1); it is
	// observability only. Both refusal branches below get their OWN loud log
	// line (mirroring DegradationMetrics' documented "never collapsed into
	// one bucket" rule) and their OWN counter, queryable via
	// Engine.DegradationSnapshot (already the wire-observability path:
	// cmd/dontguess status.go / `dontguess status`).
	outstanding, capOK := e.borrowerOutstandingPrincipal(buyerKey)
	if !capOK {
		e.degradation.CreditCapUnverifiable.Add(1)
		e.opts.log("engine: CREDIT REFUSED (unverifiable): buyer=%s ScripStore does not support loan queries — cannot verify outstanding principal, refusing credit fail-closed",
			shortKey(buyerKey))
		return fmt.Errorf("credit: cannot verify outstanding principal for buyer %s (ScripStore does not support loan queries) — refusing credit", shortKey(buyerKey))
	}
	if outstanding+shortfall > creditMaxOutstandingPerBuyer {
		e.degradation.CreditCapRefused.Add(1)
		e.opts.log("engine: CREDIT REFUSED (cap): buyer=%s outstanding=%d shortfall=%d cap=%d — buyer is permanently cut off from further deliver-on-credit until existing debt is repaid",
			shortKey(buyerKey), outstanding, shortfall, creditMaxOutstandingPerBuyer)
		return fmt.Errorf("credit: buyer %s outstanding principal %d + shortfall %d would exceed per-buyer cap %d — refusing credit",
			shortKey(buyerKey), outstanding, shortfall, creditMaxOutstandingPerBuyer)
	}

	loanID := "loan-" + newReservationID()
	dueAt := time.Now().Add(creditLoanTermDays * 24 * time.Hour).UTC().Format(time.RFC3339)

	payload, err := e.marshal(scrip.LoanMintPayload{
		Borrower:   buyerKey,
		Principal:  shortfall,
		VigRateBPS: creditLoanVigRateBPS,
		DueAt:      dueAt,
		LoanID:     loanID,
		// SettlementMsgID binds the loan to the settle(buyer-accept) that
		// needed it — the "delivery" moment for this flow, since
		// AutoDeliverOnBuyerAccept fires the actual content deliver
		// immediately after this same hold succeeds.
		SettlementMsgID: buyerAcceptMsgID,
		// There is no real CommitmentToken flow wired (that mechanism in
		// pkg/scrip/loan.go is a separate, unbuilt pre-committed-price-ceiling
		// primitive) — record what actually triggered the auto-credit instead
		// of leaving this field a bare empty string.
		CommitmentTokenID: "auto-credit:" + matchMsgID,
	})
	if err != nil {
		return fmt.Errorf("credit: marshal scrip-loan-mint payload: %w", err)
	}

	msg, err := e.sendOperatorMessage(payload, []string{scrip.TagScripLoanMint}, []string{buyerAcceptMsgID})
	if err != nil {
		return fmt.Errorf("credit: emit scrip-loan-mint for buyer %s: %w", shortKey(buyerKey), err)
	}

	// Fold into live state immediately (mirrors MintScrip in engine_mint.go) so
	// the GetBudget call inside decAndSaveHold — which runs right after this
	// returns — sees the top-up without waiting on a Replay.
	if applier, ok := e.opts.ScripStore.(scripApplier); ok {
		applier.ApplyMessage(msg)
	}

	e.opts.log("engine: deliver-on-credit: minted loan=%s principal=%d for buyer=%s (shortfall on hold=%d, balance was %d)",
		shortKey(loanID), shortfall, shortKey(buyerKey), holdAmount, bal)
	return nil
}
