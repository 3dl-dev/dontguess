package exchange_test

// ed2-D (design docs/design/nostr-first-client-ed2.md §3.6 + §3.7) — Layer-0
// money-integrity proof that the FREE-CONTENT exploit is CLOSED.
//
// THE HOLE (verified, pre-fix): buyerAcceptToMatch[msg.ID] is folded
// UNCONDITIONALLY (state_settle.go applySettleBuyerAccept), the scrip HOLD is a
// separate dispatch handler that can fail (insufficient scrip) and be
// logged+dropped, and emitDeliverContent gated ONLY on operator authorship +
// the antecedent chain — never on a live reservation. Net: an underfunded buyer
// publishes buyer-accept (hold fails) then settle(deliver) → the operator emits
// the FULL CONTENT FREE, and at settle(complete) reservationFor(match) is empty
// so no scrip ever moves. Content moved without payment.
//
// THE FIXES (both additive, both guarded by ScripStore != nil):
//   §3.7 handleSettleDeliverContent REQUIRES a live reservationFor(match) before
//        emitDeliverContent — no reservation ⇒ no content. STILL TRUE, UNCHANGED
//        by dontguess-29b — this is the load-bearing invariant this file protects.
//   §3.6 a failed decAndSaveHold (ErrBudgetExceeded) emits a DURABLE, wire-visible
//        settle(buyer-accept-reject) (reason:"insufficient_scrip") before
//        returning — the buyer learns why instead of only timing out. STILL the
//        fallback path when credit (below) is unavailable or does not cover it.
//
// UPDATED BY dontguess-29b (deliver-on-credit): at fleet tier (ScripStore
// configured, not BrokeredMatchMode/federation), an "underfunded" buyer-accept
// no longer hits §3.6's reject — engine_credit.go's ensureCreditForShortfall
// mints exactly the shortfall via scrip:loan-mint BEFORE the hold, so the hold
// now SUCCEEDS and a reservation IS created. Content therefore DOES move for
// what was previously a §3.6 rejection — but it is NOT free: a wire-visible
// LoanRecord captures the debt (Active, principal = shortfall), and total
// scrip supply increases by EXACTLY that principal (a conscious, auditable
// mint), never silently. §3.7's reservation gate is what makes this safe: it
// still refuses to move content for ANY buyer-accept that did not produce a
// live reservation, by credit or by balance — that is the invariant this test
// now proves, in place of the old "reject, no content, conserved supply" one.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// deliverMessagesWithContent counts settle(deliver) messages on the log that
// actually carry content (or a blob pointer) — i.e. real operator content
// emissions from emitDeliverContent, NOT a bare deliver trigger.
func deliverMessagesWithContent(t *testing.T, h *testHarness) int {
	t.Helper()
	// Filter on the unique phase tag only — store.MessageFilter.Tags uses OR
	// semantics, so including TagSettle would also match every other settle phase.
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{
		Tags: []string{exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver},
	})
	n := 0
	for _, m := range msgs {
		var p struct {
			Content     string `json:"content"`
			BlobPointer string `json:"blob_pointer"`
		}
		if err := json.Unmarshal(m.Payload, &p); err != nil {
			continue
		}
		if p.Content != "" || p.BlobPointer != "" {
			n++
		}
	}
	return n
}

// buyerAcceptRejectMessages returns the settle(buyer-accept-reject) messages on
// the log (ed2-D §3.6).
func buyerAcceptRejectMessages(t *testing.T, h *testHarness) []store.MessageRecord {
	t.Helper()
	// Unique phase tag only (Tags filter is OR — see deliverMessagesWithContent).
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{
		Tags: []string{exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAcceptReject},
	})
	return msgs
}

// TestUnfundedBuyerAcceptDeliver_FleetCreditCoversHold_ed2D29b is the updated
// ed2-D proof for dontguess-29b: an underfunded FLEET-TIER buyer's buyer-accept
// no longer rejects — the credit rail (engine_credit.go) mints exactly the
// shortfall via scrip:loan-mint, the hold succeeds, a reservation is created,
// and the buyer's subsequent settle(deliver) DOES receive content. This is not
// the free-content exploit reopened: total scrip supply increases by EXACTLY
// the loan principal (a durable, wire-visible, auditable mint — never silent),
// the buyer's live balance nets to exactly 0 (funds + shortfall - holdAmount),
// and a LoanRecord captures the debt. §3.7's reservation gate (still enforced,
// unchanged) is what makes this safe: content moves ONLY because a live
// reservation now genuinely exists, by credit instead of by prior balance.
func TestUnfundedBuyerAcceptDeliver_FleetCreditCoversHold_ed2D29b(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)

	// Fund the buyer with a TINY amount — enough to exist, far below any price so
	// the buyer-accept hold is guaranteed to fail. Mint BEFORE constructing the
	// scrip store so its Replay picks up the balance.
	const buyerFunds = int64(10)
	addScripMintMsg(t, h, h.buyer.PublicKeyHex(), buyerFunds)

	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	// Seed one inventory entry (seller put → operator accept), put price 5000.
	seedInventoryEntry(t, h, eng, "underfunded free-content exploit fixture", "code", 10000, 5000)
	inv := eng.State().Inventory()
	if len(inv) == 0 {
		t.Fatal("no inventory entry seeded")
	}
	entry := inv[0]

	// Sanity: the required hold dwarfs the buyer's balance — this IS an
	// underfunded buyer, the exploit precondition.
	salePrice := eng.ComputePriceForTest(entry)
	holdAmount := salePrice + salePrice/exchange.MatchingFeeRate
	if buyerFunds >= holdAmount {
		t.Fatalf("test misconfigured: buyer funds %d >= hold %d — buyer is not underfunded", buyerFunds, holdAmount)
	}

	supplyBefore := cs.TotalSupply()

	// Drive the buy through the running engine to obtain a real match. The buy's
	// stated budget is high (the buyer LIES about willingness) — the actual scrip
	// balance is what gates the hold, and it is tiny.
	preMatch, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() { _ = eng.Start(ctx); close(done) }()
	h.sendMessage(h.buyer,
		buyPayload("query for underfunded free-content exploit fixture", salePrice+5000),
		[]string{exchange.TagBuy},
		nil,
	)
	matchMsg := waitForMatchMessage(t, h, preMatch, 2*time.Second)
	cancel()
	// Wait for the poll loop to fully exit so the buyer-accept and deliver below
	// are dispatched EXACTLY ONCE by our manual DispatchForTest — no concurrent
	// poll-loop dispatch double-firing the reject emit (which has no idempotency
	// guard, unlike the funded buyer-accept hold).
	<-done

	shortfall := holdAmount - buyerFunds

	// ── STEP 1: buyer-accept from the underfunded buyer. Credit covers it. ──
	buyerAcceptPayload, _ := json.Marshal(map[string]any{
		"phase":    "buyer-accept",
		"entry_id": entry.EntryID,
		"accepted": true,
	})
	buyerAccept := h.sendMessage(h.buyer, buyerAcceptPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchMsg.ID},
	)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	baRec, err := h.st.GetMessage(buyerAccept.ID)
	if err != nil {
		t.Fatalf("GetMessage(buyer-accept): %v", err)
	}
	dispErr := eng.DispatchForTest(exchange.FromStoreRecord(baRec))
	if dispErr != nil {
		t.Fatalf("expected buyer-accept to succeed on fleet-tier credit, got error: %v", dispErr)
	}

	// dontguess-29b: NO buyer-accept-reject — the shortfall was covered, not rejected.
	if rejects := buyerAcceptRejectMessages(t, h); len(rejects) != 0 {
		t.Fatalf("expected 0 settle(buyer-accept-reject) once credit covers the shortfall, got %d", len(rejects))
	}

	// A scrip-loan-mint message must exist for exactly the shortfall.
	loanPayload := extractLoanMintFromLog(t, h)
	if loanPayload == nil {
		t.Fatal("expected a scrip-loan-mint message covering the shortfall")
	}
	if loanPayload.Borrower != h.buyer.PublicKeyHex() {
		t.Fatalf("loan borrower = %s, want %s", loanPayload.Borrower, h.buyer.PublicKeyHex())
	}
	if loanPayload.Principal != shortfall {
		t.Fatalf("loan principal = %d, want %d (holdAmount=%d - buyerFunds=%d)",
			loanPayload.Principal, shortfall, holdAmount, buyerFunds)
	}
	loan, ok := cs.GetLoan(loanPayload.LoanID)
	if !ok || loan.Status != scrip.LoanActive {
		t.Fatalf("expected LoanRecord %s to exist and be Active, got ok=%v status=%v", loanPayload.LoanID, ok, loan)
	}

	// A scrip hold WAS durably recorded — the reservation now exists.
	resID := extractReservationIDFromLog(t, h)
	if resID == "" {
		t.Fatal("expected a scrip-buy-hold reservation after credit-covered buyer-accept, got none")
	}

	// ── STEP 2: settle(deliver). §3.7's reservation gate now passes because a ──
	// live reservation genuinely exists (credit-funded) — content moves.
	deliverTriggerPayload, _ := json.Marshal(map[string]any{
		"phase":    "deliver",
		"entry_id": entry.EntryID,
	})
	deliverTrigger := h.sendMessage(h.operator, deliverTriggerPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver,
		},
		[]string{buyerAccept.ID},
	)
	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	dtRec, err := h.st.GetMessage(deliverTrigger.ID)
	if err != nil {
		t.Fatalf("GetMessage(deliver-trigger): %v", err)
	}
	if err := eng.DispatchForTest(exchange.FromStoreRecord(dtRec)); err != nil {
		t.Fatalf("deliver dispatch returned error: %v", err)
	}

	// §3.7 STILL HOLDS: content moves because (and only because) a live
	// reservation exists. This is the credit-funded case, not a bypass.
	if n := deliverMessagesWithContent(t, h); n != 1 {
		t.Fatalf("expected exactly 1 settle(deliver) carrying content once a credit-funded reservation exists, got %d", n)
	}

	// No settle(complete) happened, so no scrip-settle yet — that is a later step.
	if n := countScripSettle(t, h); n != 0 {
		t.Fatalf("expected 0 scrip-settle before settle(complete), got %d", n)
	}
	// Buyer's live balance nets to exactly 0: funds + shortfall (loan) - holdAmount.
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != 0 {
		t.Fatalf("buyer balance after credit-covered hold: got %d, want 0 (funds=%d + shortfall=%d - hold=%d)",
			got, buyerFunds, shortfall, holdAmount)
	}
	// Total scrip supply increases by EXACTLY the loan principal — a conscious,
	// auditable mint (not silent, not more than the shortfall).
	if got := cs.TotalSupply(); got != supplyBefore+shortfall {
		t.Fatalf("total scrip supply: got %d, want %d (supplyBefore=%d + loan principal=%d)",
			got, supplyBefore+shortfall, supplyBefore, shortfall)
	}
}
