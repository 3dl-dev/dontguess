package exchange_test

// End-to-end tests for the operator mint bootstrap (dontguess-af86, design §4).
//
// These exercise the REAL LocalScripStore wired into a real engine (no mocks):
//   - eng.MintScrip funds a balance LIVE (credits balance AND totalSupply, so
//     the running process sees it without a restart Replay) and DURABLY (a fresh
//     Replay of the log re-derives the same credit).
//   - A minted buyer completes a paid buy end-to-end: buyer -= price+fee,
//     seller += residual, operator += revenue, fee burned; the ledger conserves.
//   - An UNFUNDED buyer's buyer-accept fails LOUD with ErrBudgetExceeded — never
//     silently moves content for free.
//   - The individual tier (ScripStore == nil) rejects mint (scrip disabled).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// TestMintScrip_CreditsBalanceAndSupplyLive proves the mint bootstrap credits
// the live in-memory balance AND totalSupply (not just after a restart Replay).
func TestMintScrip_CreditsBalanceAndSupplyLive(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	const amount int64 = 42000
	if err := eng.MintScrip(h.buyer.PublicKeyHex(), amount); err != nil {
		t.Fatalf("MintScrip: %v", err)
	}

	if got := cs.Balance(h.buyer.PublicKeyHex()); got != amount {
		t.Errorf("live balance after mint: got %d, want %d", got, amount)
	}
	if got := cs.TotalSupply(); got != amount {
		t.Errorf("live totalSupply after mint: got %d, want %d (mint must add to supply, not just balance)", got, amount)
	}

	// Durable: a fresh Replay of the log re-derives the identical credit.
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != amount {
		t.Errorf("balance after Replay: got %d, want %d (durable scrip-mint must re-derive)", got, amount)
	}
	if got := cs.TotalSupply(); got != amount {
		t.Errorf("totalSupply after Replay: got %d, want %d", got, amount)
	}
}

// TestMintBootstrap_FundedBuySettlesEndToEnd mints the buyer, then drives a full
// buy -> match -> buyer-accept -> deliver -> complete and asserts the money moves:
// buyer -= price+fee, seller += residual, operator += revenue, fee burned, and the
// ledger conserves (TotalSupply == Σ balances + TotalBurned) after a resync Replay.
func TestMintBootstrap_FundedBuySettlesEndToEnd(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	seedInventoryEntry(t, h, eng, "Terraform module generator", "code", 8000, 5600)
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry, got %d", len(inv))
	}
	salePrice := eng.ComputePriceForTest(inv[0])
	fee := salePrice / exchange.MatchingFeeRate
	holdAmount := salePrice + fee

	// Bootstrap the buyer's balance via the operator mint god-button.
	const surplus int64 = 5000
	minted := holdAmount + surplus
	if err := eng.MintScrip(h.buyer.PublicKeyHex(), minted); err != nil {
		t.Fatalf("MintScrip: %v", err)
	}
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != minted {
		t.Fatalf("buyer balance after mint: got %d, want %d", got, minted)
	}

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctx) }()

	h.sendMessage(h.buyer,
		buyPayload("Generate Terraform module for S3", salePrice+5000),
		[]string{exchange.TagBuy},
		nil,
	)

	matchMsg := waitForMatchMessage(t, h, preMsgs, 2*time.Second)
	cancel()

	buyerBalanceBefore := cs.Balance(h.buyer.PublicKeyHex())
	sellerBalanceBefore := cs.Balance(h.seller.PublicKeyHex())
	operatorBalanceBefore := cs.Balance(h.operator.PublicKeyHex())

	// buyer-accept -> creates the scrip hold (buyer -= holdAmount).
	buyerAcceptMsg := sendBuyerAcceptAndDispatch(t, h, eng, matchMsg.ID, inv[0].EntryID)

	if got := cs.Balance(h.buyer.PublicKeyHex()); got != buyerBalanceBefore-holdAmount {
		t.Errorf("buyer balance after buyer-accept: got %d, want %d (hold=%d)", got, buyerBalanceBefore-holdAmount, holdAmount)
	}

	resID := extractReservationIDFromLog(t, h)
	if resID == "" {
		t.Fatal("expected non-empty reservation_id after buyer-accept scrip hold")
	}

	// deliver (antecedent = buyer-accept).
	deliverPayload, _ := json.Marshal(map[string]any{
		"phase":        "deliver",
		"entry_id":     inv[0].EntryID,
		"content_ref":  "sha256:" + fmt.Sprintf("%064x", 999),
		"content_size": int64(20000),
	})
	deliverMsg := h.sendMessage(h.operator, deliverPayload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver},
		[]string{buyerAcceptMsg.ID},
	)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	// complete (antecedent = deliver).
	completePayload, _ := json.Marshal(map[string]any{"price": salePrice, "entry_id": inv[0].EntryID})
	completeMsg := h.sendMessage(h.buyer, completePayload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete},
		[]string{deliverMsg.ID},
	)
	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	rec, err := h.st.GetMessage(completeMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage complete: %v", err)
	}
	if err := eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Fatalf("dispatch settle(complete): %v", err)
	}

	// Money moved: seller residual + operator revenue (live credits). Note the
	// engine derives price/fee/residual from the HOLD amount with integer
	// division, so a sub-unit of dust can be lost to truncation (holdAmount may
	// exceed price+fee by up to 1) — the security-critical invariant is that
	// accounting never EXCEEDS supply (no mint), not that it exactly equals it.
	enginePrice := holdAmount * exchange.MatchingFeeRate / (exchange.MatchingFeeRate + 1)
	expectedResidual := enginePrice / exchange.ResidualRate
	expectedRevenue := enginePrice - expectedResidual
	expectedBurn := enginePrice / exchange.MatchingFeeRate

	if got := cs.Balance(h.seller.PublicKeyHex()); got != sellerBalanceBefore+expectedResidual {
		t.Errorf("seller balance: got %d, want %d (residual=%d)", got, sellerBalanceBefore+expectedResidual, expectedResidual)
	}
	if got := cs.Balance(h.operator.PublicKeyHex()); got != operatorBalanceBefore+expectedRevenue {
		t.Errorf("operator balance: got %d, want %d (revenue=%d)", got, operatorBalanceBefore+expectedRevenue, expectedRevenue)
	}

	// Fee burn + ledger conservation are durable — re-derive from the log.
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := cs.TotalBurned(); got != expectedBurn {
		t.Errorf("total burned: got %d, want %d (the matching fee)", got, expectedBurn)
	}
	// No inflation: only the mint adds supply — the paid settle must never mint.
	if cs.TotalSupply() != minted {
		t.Errorf("total supply: got %d, want %d (a paid settle must not mint)", cs.TotalSupply(), minted)
	}
	// No scrip created out of thin air: accounted (balances + burned) never
	// exceeds supply. Truncation dust may leave it a hair under (see above).
	sumBalances := cs.Balance(h.buyer.PublicKeyHex()) + cs.Balance(h.seller.PublicKeyHex()) + cs.Balance(h.operator.PublicKeyHex())
	accounted := sumBalances + cs.TotalBurned()
	if accounted > cs.TotalSupply() {
		t.Errorf("ledger conservation violated (scrip minted): Σbalances(%d) + TotalBurned(%d) = %d > TotalSupply(%d)",
			sumBalances, cs.TotalBurned(), accounted, cs.TotalSupply())
	}
	if dust := cs.TotalSupply() - accounted; dust < 0 || dust > 2 {
		t.Errorf("unexpected ledger gap: TotalSupply(%d) - accounted(%d) = %d (want small truncation dust 0..2)",
			cs.TotalSupply(), accounted, dust)
	}
}

// TestMintBootstrap_UnfundedBuyerFailsLoud proves an unfunded buyer (never
// minted) hits ErrBudgetExceeded on buyer-accept — content is NOT moved for free.
func TestMintBootstrap_UnfundedBuyerFailsLoud(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	seedInventoryEntry(t, h, eng, "Python scraper generator", "code", 10000, 7000)
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry, got %d", len(inv))
	}
	salePrice := eng.ComputePriceForTest(inv[0])

	// NO mint — buyer balance is zero.
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != 0 {
		t.Fatalf("precondition: unfunded buyer must have zero balance, got %d", got)
	}

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctx) }()

	h.sendMessage(h.buyer, buyPayload("Build a Python async web scraper", salePrice+5000), []string{exchange.TagBuy}, nil)
	matchMsg := waitForMatchMessage(t, h, preMsgs, 2*time.Second)
	cancel()

	preHold, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripBuyHold}})

	buyerAcceptPayload, _ := json.Marshal(map[string]any{"phase": "buyer-accept", "entry_id": inv[0].EntryID, "accepted": true})
	buyerAcceptMsg := h.sendMessage(h.buyer, buyerAcceptPayload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept, exchange.TagVerdictPrefix + "accepted"},
		[]string{matchMsg.ID},
	)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	rec, err := h.st.GetMessage(buyerAcceptMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage buyer-accept: %v", err)
	}

	dispatchErr := eng.DispatchForTest(exchange.FromStoreRecord(rec))
	if dispatchErr == nil {
		t.Fatal("expected LOUD error from unfunded buyer-accept, got nil (content moved for free)")
	}
	if !errors.Is(dispatchErr, scrip.ErrBudgetExceeded) {
		t.Errorf("expected ErrBudgetExceeded, got %v", dispatchErr)
	}

	// No hold emitted, balance unchanged.
	afterHold, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripBuyHold}})
	if len(afterHold) > len(preHold) {
		t.Error("no scrip-buy-hold must be emitted for an unfunded buyer")
	}
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != 0 {
		t.Errorf("unfunded buyer balance changed: got %d, want 0", got)
	}
}

// TestMintScrip_IndividualTierRejected proves the individual/no-relay tier
// (ScripStore == nil) rejects mint — scrip accounting is disabled by design.
func TestMintScrip_IndividualTierRejected(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		// ScripStore intentionally nil (individual tier).
		Logger: func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	err := eng.MintScrip(h.buyer.PublicKeyHex(), 1000)
	if err == nil {
		t.Fatal("expected MintScrip to fail on the individual tier (ScripStore=nil), got nil")
	}
}

// TestMintScrip_RejectsInvalidArgs proves empty recipient / non-positive amount
// are rejected before any scrip is minted.
func TestMintScrip_RejectsInvalidArgs(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	if err := eng.MintScrip("", 1000); err == nil {
		t.Error("expected error for empty recipient")
	}
	if err := eng.MintScrip(h.buyer.PublicKeyHex(), 0); err == nil {
		t.Error("expected error for zero amount")
	}
	if err := eng.MintScrip(h.buyer.PublicKeyHex(), -5); err == nil {
		t.Error("expected error for negative amount")
	}
	if got := cs.TotalSupply(); got != 0 {
		t.Errorf("no scrip should be minted on invalid args, totalSupply=%d", got)
	}
}
