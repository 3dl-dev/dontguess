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
// accounting at all, so credit is moot there). BrokeredMatchMode is this
// engine's federation-mode flag; deliver-on-credit must never engage there —
// federation is where Sybil (fresh npub, buy on credit, walk) becomes a real
// attack, and that defense is explicitly OPEN, gated on dontguess-5a3. At
// fleet tier every borrower is one of the operator's allowlisted, traceable
// keys, so the standing ruling (Sybil defense premature for fleet, tier-gated
// elsewhere) already covers this — see dontguess-29b's SYBIL CAVEAT.
func (e *Engine) creditTierEligible() bool {
	return e.opts.ScripStore != nil && !e.opts.BrokeredMatchMode
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
)

// ensureCreditForShortfall tops up buyerKey's balance via the loan rail
// (scrip:loan-mint) so it can cover holdAmount, if and only if it currently
// cannot. It mints EXACTLY the shortfall (holdAmount - balance), never the
// full holdAmount, so a buyer with a partial balance is not lent scrip it
// already has.
//
// Returns nil (no-op) when:
//   - the deployment is not credit-eligible (creditTierEligible == false —
//     individual tier or federation/BrokeredMatchMode), or
//   - the buyer's current balance already covers holdAmount.
//
// A non-nil error here is NON-FATAL to the caller (handleSettleBuyerAcceptScrip
// logs it and falls through to decAndSaveHold, which reproduces the exact
// pre-29b insufficient_scrip reject path). This function must never be the
// source of a buyer-facing error distinct from "insufficient scrip" — it only
// ever makes a shortfall SMALLER or resolves it entirely, never worse.
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
