package exchange_test

// Tests for dontguess-400 (design §1.4, §4): the scrip money-integrity fixes.
//
// FIX-M1 (CRITICAL — the double-settle mint): State.matchToBuyHold[match] was
// never retired on settle, and restoreExistingHold re-saved the consumed
// reservation with NO recharge when a replayed buyer-accept found the stale
// matchToBuyHold entry — defeating performScripSettlement's ConsumeReservation
// "missing → already settled" guard. A repeated buyer-accept→complete (new msg
// IDs; completedSettlements dedups on the complete msg.ID only) re-credited
// seller+operator every loop. Unbounded self-mint if buyer==seller.
//
// The fix: retire matchToBuyHold[match] (+ matchToBuyHoldAmount) on settle AND
// add a DURABLE settled-match set (keyed on matchMsgID, rebuilt on State.Replay
// from the scrip-settle log) that gates BOTH restoreExistingHold and
// performScripSettlement.
//
// FIX-M2 (MAJOR — hold-path mutate-then-emit mint): decAndSaveHold decremented
// the buyer's balance and THEN best-effort-emitted scrip-buy-hold. On emit
// failure the debit was live but had no durable record — Replay lost the debit,
// a net mint. The fix mirrors the settle path: emit the durable scrip-buy-hold
// BEFORE mutating the balance.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// replayAndDispatch replays engine state from the full log, then dispatches the
// given already-appended message through DispatchForTest. Returns the dispatch
// error (nil on success). Mirrors the sequence the poll loop performs (fold →
// dispatch) for a single message.
func replayAndDispatch(t *testing.T, h *testHarness, eng *exchange.Engine, msg *exchange.Message) error {
	t.Helper()
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	rec, err := h.st.GetMessage(msg.ID)
	if err != nil {
		t.Fatalf("GetMessage(%s): %v", msg.ID[:8], err)
	}
	return eng.DispatchForTest(exchange.FromStoreRecord(rec))
}

func countScripSettle(t *testing.T, h *testHarness) int {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripSettle}})
	return len(msgs)
}

// lastMatchID returns the message ID of the most-recent exchange:match message.
func lastMatchID(t *testing.T, h *testHarness) string {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	if len(msgs) == 0 {
		t.Fatal("no match message on log")
	}
	return msgs[len(msgs)-1].ID
}

// sendComplete appends a settle(complete) message (antecedent = deliverMsgID)
// from the buyer and returns it.
func sendComplete(t *testing.T, h *testHarness, buyer *testAgent, deliverMsgID string) *exchange.Message {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"phase": "complete"})
	return h.sendMessage(buyer, payload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete},
		[]string{deliverMsgID},
	)
}

// TestDoubleSettleMint_ExactlyOneScripSettle is the FIX-M1 proof (design §1.4):
// accept → complete → accept → complete must emit EXACTLY ONE scrip-settle, and
// the seller/operator must be credited exactly once. Under the pre-fix code the
// second buyer-accept re-hydrated the consumed reservation (no recharge) and the
// second complete minted a second scrip-settle.
func TestDoubleSettleMint_ExactlyOneScripSettle(t *testing.T) {
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

	// Build put → accept → buy → match → buyer-accept1 → deliver. This runs the
	// first (legitimate) scrip hold and returns the deliver message.
	res, deliverMsg, salePrice := buildSettleChainForPriceTests(t, h, eng, cs, "double-settle fixture", 5000)
	matchID := lastMatchID(t, h)

	sellerBefore := cs.Balance(h.seller.PublicKeyHex())
	operatorBefore := cs.Balance(h.operator.PublicKeyHex())

	// complete1 — the legitimate settlement.
	complete1 := sendComplete(t, h, h.buyer, deliverMsg.ID)
	if err := replayAndDispatch(t, h, eng, complete1); err != nil {
		t.Fatalf("complete1 dispatch: %v", err)
	}
	if got := countScripSettle(t, h); got != 1 {
		t.Fatalf("after complete1: scrip-settle count = %d, want 1", got)
	}

	expectedResidual := salePrice / exchange.ResidualRate
	expectedRevenue := salePrice - expectedResidual
	if got := cs.Balance(h.seller.PublicKeyHex()); got != sellerBefore+expectedResidual {
		t.Fatalf("seller balance after complete1 = %d, want %d", got, sellerBefore+expectedResidual)
	}
	if got := cs.Balance(h.operator.PublicKeyHex()); got != operatorBefore+expectedRevenue {
		t.Fatalf("operator balance after complete1 = %d, want %d", got, operatorBefore+expectedRevenue)
	}

	// THE ATTACK: re-send buyer-accept for the SAME match (new msg ID). Under the
	// pre-fix code this re-hydrates the consumed reservation with no recharge.
	reAccept := sendBuyerAcceptForMatch(t, h, h.buyer, matchID, res.ID)
	if err := replayAndDispatch(t, h, eng, reAccept); err != nil {
		t.Logf("re-accept dispatch returned: %v (acceptable — must be a no-op / refusal)", err)
	}

	// complete2 (new msg ID) against the same deliver.
	complete2 := sendComplete(t, h, h.buyer, deliverMsg.ID)
	if err := replayAndDispatch(t, h, eng, complete2); err != nil {
		t.Logf("complete2 dispatch returned: %v (acceptable — must be a no-op)", err)
	}

	// The core assertion: still EXACTLY ONE scrip-settle. A second one is the mint.
	if got := countScripSettle(t, h); got != 1 {
		t.Fatalf("after re-accept + complete2: scrip-settle count = %d, want 1 "+
			"(FIX-M1 regression: double-settle mint — the second settlement was emitted)", got)
	}

	// Seller and operator must NOT have been credited a second time.
	if got := cs.Balance(h.seller.PublicKeyHex()); got != sellerBefore+expectedResidual {
		t.Fatalf("seller balance after attack = %d, want %d (double-credited = mint)", got, sellerBefore+expectedResidual)
	}
	if got := cs.Balance(h.operator.PublicKeyHex()); got != operatorBefore+expectedRevenue {
		t.Fatalf("operator balance after attack = %d, want %d (double-credited = mint)", got, operatorBefore+expectedRevenue)
	}
}

// sendBuyerAcceptForMatch appends a settle(buyer-accept) message with the given
// match as the direct antecedent (no preview path) from the given sender.
func sendBuyerAcceptForMatch(t *testing.T, h *testHarness, sender *testAgent, matchMsgID, entryID string) *exchange.Message {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"phase":    "buyer-accept",
		"entry_id": entryID,
		"accepted": true,
	})
	return h.sendMessage(sender, payload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchMsgID},
	)
}

// TestLedgerConservation_AcrossSettleAndReplay is the ledger-conservation
// invariant (design §4): at rest (after a completed settlement, no outstanding
// hold), TotalSupply == Σ balances + TotalBurned. Exercised across a full
// accept→complete flow PLUS a replayed double-settle attempt, then re-derived
// from a fresh Replay of the whole log. A minted second settle would push
// Σ balances above supply.
func TestLedgerConservation_AcrossSettleAndReplay(t *testing.T) {
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

	res, deliverMsg, _ := buildSettleChainForPriceTests(t, h, eng, cs, "conservation fixture", 6000)
	matchID := lastMatchID(t, h)

	// Legitimate settle.
	complete1 := sendComplete(t, h, h.buyer, deliverMsg.ID)
	if err := replayAndDispatch(t, h, eng, complete1); err != nil {
		t.Fatalf("complete1 dispatch: %v", err)
	}

	// Attempt the double-settle (must be refused).
	reAccept := sendBuyerAcceptForMatch(t, h, h.buyer, matchID, res.ID)
	_ = replayAndDispatch(t, h, eng, reAccept)
	complete2 := sendComplete(t, h, h.buyer, deliverMsg.ID)
	_ = replayAndDispatch(t, h, eng, complete2)

	assertLedgerConserved(t, h)
}

// assertLedgerConserved rebuilds a fresh LocalScripStore from the whole log and
// checks the conservation invariant at rest (every reservation settled/refunded,
// no scrip in escrow): Σ balances + TotalBurned must NOT EXCEED TotalSupply. A
// mint (double-settle M1, or an M2 lost-debit that rebuilds a balance too high)
// pushes Σ balances + TotalBurned strictly ABOVE supply — the exact failure this
// asserts against.
//
// The healthy case sits a hair BELOW supply: settlement recomputes price and fee
// from the escrow amount with integer division, so price+fee can be up to
// MatchingFeeRate below the escrowed hold — a benign, deflationary rounding
// remainder that stays debited from the buyer without being credited or burned.
// The check tolerates exactly that bound (per successful settlement) so a genuine
// large loss is still caught, while a mint of a whole residual+revenue never is.
func assertLedgerConserved(t *testing.T, h *testHarness) {
	t.Helper()
	fresh, err := scrip.NewLocalScripStore(h.st, h.operator.PublicKeyHex())
	if err != nil {
		t.Fatalf("fresh LocalScripStore: %v", err)
	}
	// Dedup participant keys — buyer and seller may be the same identity.
	seen := map[string]struct{}{}
	var sum int64
	for _, k := range []string{h.buyer.PublicKeyHex(), h.seller.PublicKeyHex(), h.operator.PublicKeyHex()} {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		sum += fresh.Balance(k)
	}
	accounted := sum + fresh.TotalBurned()
	supply := fresh.TotalSupply()
	maxLeak := int64(exchange.MatchingFeeRate+1) * int64(countScripSettle(t, h))
	if accounted > supply {
		t.Fatalf("ledger MINT after replay: Σbalances(%d) + TotalBurned(%d) = %d EXCEEDS TotalSupply(%d) by %d "+
			"(scrip was created from nothing — double-settle or lost-debit mint)",
			sum, fresh.TotalBurned(), accounted, supply, accounted-supply)
	}
	if supply-accounted > maxLeak {
		t.Fatalf("ledger under-accounted after replay: TotalSupply(%d) - (Σbalances(%d) + TotalBurned(%d)) = %d "+
			"exceeds the rounding-remainder bound %d (unexpected lost scrip)",
			supply, sum, fresh.TotalBurned(), supply-accounted, maxLeak)
	}
}

// TestDoubleSettleMint_BuyerEqualsSeller_ReplayCannotRaiseBalance is the
// unbounded-self-mint case (design §1.4): when buyer==seller, each extra settle
// loop is net-positive for the attacker. After the fix the durable log holds at
// most one scrip-settle, so a fresh Replay conserves supply and the attacker's
// balance cannot exceed the single-settle outcome.
func TestDoubleSettleMint_BuyerEqualsSeller_ReplayCannotRaiseBalance(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	// Collapse buyer and seller to a single identity: the attacker sells an entry
	// to the exchange and buys it back, harvesting residual on every settle.
	h.buyer = h.seller

	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        h.cfID,
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.pubKeyHex,
		ScripStore:        cs,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})

	res, deliverMsg, _ := buildSettleChainForPriceTests(t, h, eng, cs, "self-mint fixture", 7000)
	matchID := lastMatchID(t, h)

	complete1 := sendComplete(t, h, h.buyer, deliverMsg.ID)
	if err := replayAndDispatch(t, h, eng, complete1); err != nil {
		t.Fatalf("complete1 dispatch: %v", err)
	}
	attackerAfterOneSettle := cs.Balance(h.seller.PublicKeyHex())

	// Two further attack loops.
	for i := 0; i < 2; i++ {
		reAccept := sendBuyerAcceptForMatch(t, h, h.buyer, matchID, res.ID)
		_ = replayAndDispatch(t, h, eng, reAccept)
		complete2 := sendComplete(t, h, h.buyer, deliverMsg.ID)
		_ = replayAndDispatch(t, h, eng, complete2)
	}

	if got := countScripSettle(t, h); got != 1 {
		t.Fatalf("buyer==seller: scrip-settle count = %d, want 1 (unbounded self-mint)", got)
	}
	// Live balance must not have climbed past the single-settle outcome.
	if got := cs.Balance(h.seller.PublicKeyHex()); got > attackerAfterOneSettle {
		t.Fatalf("buyer==seller: attacker balance rose from %d to %d across replayed settles (self-mint)",
			attackerAfterOneSettle, got)
	}
	// And a fresh, independent rebuild of the whole log conserves supply.
	assertLedgerConserved(t, h)
}

// TestHoldEmitFailure_DoesNotMint is the FIX-M2 proof (design §4): decAndSaveHold
// must emit the durable scrip-buy-hold BEFORE decrementing the buyer's balance.
// We fail the emit (by closing the durable store after all reads are cached in
// the in-memory ScripStore) and assert the buyer's balance is UNCHANGED — no
// live debit without a durable record. Under the pre-fix ordering the balance
// was decremented first, so a failed best-effort emit left a live debit that
// Replay would silently drop (net mint on rebuild).
func TestHoldEmitFailure_DoesNotMint(t *testing.T) {
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

	// Seed one entry and a funded buyer, then drive a buy → match synchronously
	// (no Start goroutine, so nothing touches the store after we close it).
	seedInventoryEntry(t, h, eng, "emit-fail fixture", "code", 8000, 5000)
	inv := eng.State().Inventory()
	if len(inv) == 0 {
		t.Fatal("no inventory entry")
	}
	entry := inv[0]
	salePrice := eng.ComputePriceForTest(entry)
	holdAmount := salePrice + salePrice/exchange.MatchingFeeRate

	addScripMintMsg(t, h, h.buyer.PublicKeyHex(), holdAmount+5000)
	if err := cs.Replay(); err != nil {
		t.Fatalf("cs.Replay: %v", err)
	}

	buyMsg := h.sendMessage(h.buyer, buyPayload("query for emit-fail fixture", salePrice+5000),
		[]string{exchange.TagBuy}, nil)
	buyRec, _ := h.st.GetMessage(buyMsg.ID)
	eng.State().Apply(exchange.FromStoreRecord(buyRec))
	if err := eng.DispatchForTest(exchange.FromStoreRecord(buyRec)); err != nil {
		t.Fatalf("dispatch buy: %v", err)
	}
	matchID := lastMatchID(t, h)

	// Append the buyer-accept and cache its record + replay engine state BEFORE
	// closing the store; the only store access left in the buyer-accept dispatch
	// is the scrip-buy-hold emit (an Append), which we want to fail.
	acceptMsg := sendBuyerAcceptForMatch(t, h, h.buyer, matchID, entry.EntryID)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	acceptRec, err := h.st.GetMessage(acceptMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage(accept): %v", err)
	}

	balanceBefore := cs.Balance(h.buyer.PublicKeyHex())

	// Close the durable store: the scrip-buy-hold emit's Append now fails.
	if err := h.st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}

	dispatchErr := eng.DispatchForTest(exchange.FromStoreRecord(acceptRec))
	if dispatchErr == nil {
		t.Fatal("expected buyer-accept dispatch to error when the scrip-buy-hold emit fails, got nil " +
			"(FIX-M2: emit failure must be a hard error, not a best-effort warning)")
	}

	// The buyer's balance must be UNCHANGED — no live debit without a durable hold.
	if got := cs.Balance(h.buyer.PublicKeyHex()); got != balanceBefore {
		t.Fatalf("buyer balance changed from %d to %d despite a failed scrip-buy-hold emit "+
			"(FIX-M2 regression: mutate-then-emit left a live debit with no durable record → mint on Replay)",
			balanceBefore, got)
	}

	// No reservation may have been created for the match either.
	if _, err := cs.GetReservation(context.Background(), matchID); err == nil {
		t.Errorf("a reservation was created despite the failed hold emit")
	}
}
