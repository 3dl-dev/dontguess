package exchange_test

// Deliver-on-credit tests (dontguess-29b).
//
// dontguess-29b wires the pre-existing, previously-unwired loan rail
// (pkg/scrip/loan.go: LoanRecord + LoanMint/LoanRepay/LoanVigAccrue) into the
// buyer-accept hold path so a buyer found insufficient at buyer-accept is
// topped up via a scrip:loan-mint instead of rejected. Measured motivation:
// 13 of 26 buyer-accepts (exactly half) were rejected insufficient_scrip.
//
// These tests use the same fleet-tier harness shape as scrip_test.go
// (ScripStore configured, FederationGuardEnabled left at its zero value =
// false) — the natural tier gate creditTierEligible relies on
// (engine_credit.go). See federation_guard_credit_test.go for the tests
// proving the gate keys on FederationGuardEnabled, not BrokeredMatchMode.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// waitForWarmCompressionAssign polls until a warm compression assign (exclusive
// to buyerKey, entry_id == entryID, task_type == "compress") appears in the
// log, returning its reward. sendWarmCompressionAssign runs synchronously
// right after the match message is appended (engine_buy.go), but on the LIVE
// eng.Start(ctx) poll-loop dispatch path (as opposed to a direct
// DispatchForTest call) there is no barrier guaranteeing it has landed by the
// time a test goroutine observes the match message — poll instead of a single
// check, and do this BEFORE cancel()/t.Fatal to avoid racing the harness's
// store-close-on-test-end against a straggler append.
func waitForWarmCompressionAssign(t *testing.T, h *testHarness, entryID, buyerKey string, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagAssign}})
		for _, am := range msgs {
			var ap struct {
				EntryID         string `json:"entry_id"`
				TaskType        string `json:"task_type"`
				Reward          int64  `json:"reward"`
				ExclusiveSender string `json:"exclusive_sender"`
			}
			if err := json.Unmarshal(am.Payload, &ap); err != nil {
				continue
			}
			if ap.EntryID == entryID && ap.TaskType == "compress" && ap.ExclusiveSender == buyerKey {
				return ap.Reward
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for warm compression assign")
	return 0
}

// extractLoanMintFromLog scans the log for the most recent scrip-loan-mint
// message and returns its parsed payload, or nil if none exists.
func extractLoanMintFromLog(t *testing.T, h *testHarness) *scrip.LoanMintPayload {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripLoanMint}})
	if len(msgs) == 0 {
		return nil
	}
	last := msgs[len(msgs)-1]
	var p scrip.LoanMintPayload
	if err := json.Unmarshal(last.Payload, &p); err != nil {
		t.Fatalf("parsing scrip-loan-mint payload: %v", err)
	}
	return &p
}

// TestDeliverOnCredit_ZeroBalanceBuyerCompletesEndToEnd is the mutation-guard
// test for dontguess-29b's MUTATION TO VERIFY: a buyer with a ZERO scrip
// balance completes a full buy -> match -> buyer-accept -> deliver -> complete
// cycle, a LoanRecord appears Active for the shortfall, and a compression
// assign is posted for the entry.
//
// Break the wiring (e.g., remove the ensureCreditForShortfall call in
// handleSettleBuyerAcceptScrip, or make it a no-op) and this test fails at the
// buyer-accept step: DispatchForTest returns scrip.ErrBudgetExceeded exactly
// as it did before dontguess-29b (see the retired
// TestBuyerAccept_InsufficientScripReturnsError assertions this test
// replaces), no scrip-loan-mint message is ever emitted, and no reservation
// is created.
func TestDeliverOnCredit_ZeroBalanceBuyerCompletesEndToEnd(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
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

	// Seed one entry. The buyer receives NO mint at all — a true zero balance,
	// not merely "less than required."
	seedInventoryEntry(t, h, eng, "Rust async runtime primer", "code", 12000, 8400)
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry, got %d", len(inv))
	}
	salePrice := eng.ComputePriceForTest(inv[0])
	fee := salePrice / exchange.MatchingFeeRate
	holdAmount := salePrice + fee

	if bal := cs.Balance(h.buyer.PublicKeyHex()); bal != 0 {
		t.Fatalf("test setup: buyer balance should start at 0, got %d", bal)
	}

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctx) }()

	h.sendMessage(h.buyer,
		buyPayload("Explain Rust's async runtime model", salePrice+5000),
		[]string{exchange.TagBuy},
		nil,
	)

	matchMsg := waitForMatchMessage(t, h, preMsgs, 2*time.Second)

	// A warm compression assign should already be posted at match time,
	// exclusive to the buyer, priced at WarmCompressionBountyPct (300%,
	// dontguess-29b) of token_cost. This is independent of the credit path
	// (it fires in handleBuy, before any buyer-accept) but is part of the
	// same outcome dontguess-29b verifies: "a compression assign is posted."
	// Poll for it (see waitForWarmCompressionAssign) BEFORE cancel(), so a
	// still-in-flight append can never race the test's teardown.
	warmReward := waitForWarmCompressionAssign(t, h, inv[0].EntryID, h.buyer.PublicKeyHex(), 2*time.Second)
	cancel()

	// PINNED LITERAL (dontguess-29b wave-6 fix): NOT computed via
	// `inv[0].TokenCost * exchange.WarmCompressionBountyPct / 100` — that
	// formula recomputes to match whatever WarmCompressionBountyPct currently
	// is, so it would still pass if the 30->300 bounty change were reverted.
	// 36000 = 12000 (this test's seeded token_cost) * 300 / 100.
	const wantWarmBounty int64 = 36000
	if warmReward != wantWarmBounty {
		t.Errorf("warm compression reward = %d, want %d (%d%% of token_cost %d)",
			warmReward, wantWarmBounty, exchange.WarmCompressionBountyPct, inv[0].TokenCost)
	}

	// buyer-accept — buyer has ZERO scrip. Pre-29b this returns
	// scrip.ErrBudgetExceeded and emits buyer-accept-reject with NO
	// reservation. Post-29b, ensureCreditForShortfall mints exactly the
	// shortfall (== holdAmount here, since balance is 0) via scrip:loan-mint
	// BEFORE decAndSaveHold runs, so this must now SUCCEED.
	buyerAcceptMsg := sendBuyerAcceptAndDispatch(t, h, eng, matchMsg.ID, inv[0].EntryID)

	// A scrip-loan-mint message must have been emitted for the buyer.
	loanPayload := extractLoanMintFromLog(t, h)
	if loanPayload == nil {
		t.Fatal("expected a scrip-loan-mint message after zero-balance buyer-accept")
	}
	if loanPayload.Borrower != h.buyer.PublicKeyHex() {
		t.Errorf("loan borrower = %s, want %s", loanPayload.Borrower, h.buyer.PublicKeyHex())
	}
	if loanPayload.Principal != holdAmount {
		t.Errorf("loan principal = %d, want %d (full holdAmount, since starting balance was 0)",
			loanPayload.Principal, holdAmount)
	}

	// The LoanRecord must exist and be Active.
	loan, ok := cs.GetLoan(loanPayload.LoanID)
	if !ok {
		t.Fatalf("expected LoanRecord %s to exist", loanPayload.LoanID)
	}
	if loan.Status != scrip.LoanActive {
		t.Errorf("loan status = %v, want LoanActive (%v)", loan.Status, scrip.LoanActive)
	}
	if loan.Principal != holdAmount {
		t.Errorf("loan.Principal = %d, want %d", loan.Principal, holdAmount)
	}
	if loan.BorrowerKey != h.buyer.PublicKeyHex() {
		t.Errorf("loan.BorrowerKey = %s, want %s", loan.BorrowerKey, h.buyer.PublicKeyHex())
	}

	// The buyer-accept must have produced a live scrip-buy-hold reservation —
	// the hold succeeded because the loan topped up the balance first.
	resID := extractReservationIDFromLog(t, h)
	if resID == "" {
		t.Fatal("expected non-empty reservation_id — buyer-accept must succeed on credit, not reject")
	}
	if _, err := cs.GetReservation(context.Background(), resID); err != nil {
		t.Errorf("expected reservation %s to exist, got: %v", resID, err)
	}

	// Buyer's live balance nets to exactly 0: minted exactly the shortfall,
	// then held exactly holdAmount.
	if bal := cs.Balance(h.buyer.PublicKeyHex()); bal != 0 {
		t.Errorf("buyer balance after credit-covered hold = %d, want 0 (topped up exactly to holdAmount, then held in full)", bal)
	}

	// deliver (antecedent = buyer-accept message) — a bare operator TRIGGER
	// (no content field), driven through the REAL engine dispatch path
	// (DispatchForTest), not hand-authored with content already attached.
	// dontguess-29b wave-6 fix: the previous version of this test fabricated
	// the deliver message's content_ref/content_size fields itself and only
	// called State().Replay directly, which folds state effects but never
	// runs handleSettleDeliverContent — so it never exercised the §3.7
	// money-integrity reservation gate or emitDeliverContent, and did not
	// actually prove content moved ON CREDIT through the engine. Driving the
	// bare trigger through DispatchForTest (mirrors
	// deliver_reservation_gate_test.go's credit-funded deliver step) runs the
	// real handler: it resolves the entry/buyer from the antecedent chain,
	// checks the live reservation the credit-funded hold created above, and
	// only then emits the content-bearing settle(deliver) via
	// emitDeliverContent. Breaking the credit wiring (no reservation) would
	// make this assert fail closed instead of proving content moved.
	deliverTriggerPayload, _ := json.Marshal(map[string]any{
		"phase":    "deliver",
		"entry_id": inv[0].EntryID,
	})
	deliverMsg := h.sendMessage(h.operator, deliverTriggerPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver,
		},
		[]string{buyerAcceptMsg.ID},
	)

	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	deliverRec, err := h.st.GetMessage(deliverMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage(deliver-trigger): %v", err)
	}
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("dispatch settle(deliver) trigger: %v", err)
	}

	// The engine must have actually emitted a content-bearing settle(deliver)
	// — proving the §3.7 reservation gate passed (credit-funded hold) and
	// content genuinely moved, not merely that a trigger message exists.
	if n := deliverMessagesWithContent(t, h); n != 1 {
		t.Fatalf("expected exactly 1 settle(deliver) carrying content after credit-funded buyer-accept, got %d", n)
	}

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	// complete (antecedent = the operator's deliver TRIGGER message, not the
	// engine-emitted content message — deliverToMatch keys off the trigger,
	// matching e2e_test.go's documented antecedent choice).
	completePayload, _ := json.Marshal(map[string]any{
		"price":    salePrice,
		"entry_id": inv[0].EntryID,
	})
	completeMsg := h.sendMessage(h.buyer, completePayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete,
		},
		[]string{deliverMsg.ID},
	)

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	rec, err := h.st.GetMessage(completeMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if err := eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Fatalf("dispatch settle(complete): %v", err)
	}

	// Reservation must be deleted after settle(complete) — the buy completed
	// end-to-end on credit exactly as it would have with a funded balance.
	if _, err := cs.GetReservation(context.Background(), resID); err == nil {
		t.Errorf("expected reservation %s to be deleted after settle(complete), still present", resID)
	}
}

// TestDeliverOnCredit_PartialBalanceOnlyBorrowsShortfall verifies that a
// buyer with SOME scrip (but not enough) is lent exactly the shortfall, never
// the full holdAmount — a buyer must never borrow scrip it already has.
func TestDeliverOnCredit_PartialBalanceOnlyBorrowsShortfall(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
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

	seedInventoryEntry(t, h, eng, "Python scraper generator", "code", 10000, 7000)
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry, got %d", len(inv))
	}
	salePrice := eng.ComputePriceForTest(inv[0])
	fee := salePrice / exchange.MatchingFeeRate
	holdAmount := salePrice + fee

	// Seed the buyer with LESS than required (but more than zero) — exactly
	// 1 scrip short, so the expected loan principal is unambiguous (1).
	addScripMintMsg(t, h, h.buyer.PublicKeyHex(), holdAmount-1)
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	buyerBalanceBefore := cs.Balance(h.buyer.PublicKeyHex())
	if buyerBalanceBefore != holdAmount-1 {
		t.Fatalf("test setup: buyer balance = %d, want %d", buyerBalanceBefore, holdAmount-1)
	}

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctx) }()

	h.sendMessage(h.buyer,
		buyPayload("Build a Python async web scraper", salePrice+5000),
		[]string{exchange.TagBuy},
		nil,
	)

	matchMsg := waitForMatchMessage(t, h, preMsgs, 2*time.Second)
	cancel()

	sendBuyerAcceptAndDispatch(t, h, eng, matchMsg.ID, inv[0].EntryID)

	loanPayload := extractLoanMintFromLog(t, h)
	if loanPayload == nil {
		t.Fatal("expected a scrip-loan-mint message after under-funded buyer-accept")
	}
	// Shortfall must be exactly 1 (holdAmount - (holdAmount-1)) — never the
	// full holdAmount, since the buyer already had holdAmount-1 of it.
	if loanPayload.Principal != 1 {
		t.Errorf("loan principal = %d, want 1 (holdAmount=%d - balance=%d)",
			loanPayload.Principal, holdAmount, buyerBalanceBefore)
	}

	if bal := cs.Balance(h.buyer.PublicKeyHex()); bal != 0 {
		t.Errorf("buyer balance after credit-covered hold = %d, want 0", bal)
	}
}
