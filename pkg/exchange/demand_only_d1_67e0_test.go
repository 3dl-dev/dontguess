package exchange_test

// Enforcement proof for the 67e0 OPERATOR RULING (dontguess-4f01): a D1-dropped
// (unfunded, zero-scrip) buyer's miss is REGISTERED AS A DEMAND-ONLY SIGNAL —
// deduped by task_hash and capped per identity — instead of being fully dropped.
//
// These tests drive the REAL engine with a REAL LocalScripStore (no mock of the
// thing under test) and assert against REAL state:
//
//	(1) N Sybil keys spamming ONE task_hash collapse to EXACTLY ONE demand-backlog
//	    entry (dedup), the entry surfaces in demand.BuildBacklog exactly once, the
//	    matching/ranking/pricing signal is UNMOVED (the load-bearing D1 invariant),
//	    and ZERO scrip moves.
//	(2) One unfunded identity flooding MANY DISTINCT task hashes is CAPPED at
//	    DemandOnlyPerSenderCap (per-identity bound).
//	(3) A FUNDED buyer's normal zero-match miss path is UNAFFECTED — it still opens
//	    a real 70%-rate funded BuyMissOffer and is NOT tagged demand-only.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/demand"
	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// dispatchBuy synchronously dispatches a buy from sender through the real engine
// (handleBuy), bypassing the poll loop for determinism — same technique the
// funded-buy signal-bound test uses (sendBuyerAcceptAndDispatch).
func dispatchBuy(t *testing.T, h *testHarness, eng *exchange.Engine, sender *testAgent, task string, budget int64) *exchange.Message {
	t.Helper()
	buyMsg := h.sendMessage(sender, buyPayload(task, budget), []string{exchange.TagBuy}, nil)
	rec, err := h.st.GetMessage(buyMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage buy: %v", err)
	}
	if err := eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Fatalf("DispatchForTest buy: %v", err)
	}
	return buyMsg
}

// demandOnlyMsgs returns the demand-only messages currently in the harness log.
func demandOnlyMsgs(t *testing.T, h *testHarness) []store.MessageRecord {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagDemandOnly}})
	return msgs
}

// buildBacklogFromLog reproduces the `dontguess demand` read path: it collects the
// buy-miss standing offers (TagBuyMiss, excluding fulfillment settle messages) and
// runs the REAL demand.BuildBacklog over them, exactly as cmd/dontguess/demand.go
// does. This proves the entry surfaces in `dontguess demand`, not just in state.
func buildBacklogFromLog(t *testing.T, h *testHarness) demand.Backlog {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagBuyMiss}})
	var miss []demand.MissMessage
	for _, m := range msgs {
		// Mirror buyMissFilter's ExcludeTags{TagSettle}: a fulfilled offer's
		// settle(put-accept) is also stamped TagBuyMiss.
		isSettle := false
		for _, tg := range m.Tags {
			if tg == exchange.TagSettle {
				isSettle = true
				break
			}
		}
		if isSettle {
			continue
		}
		miss = append(miss, demand.MissMessage{ID: m.ID, Payload: m.Payload, Timestamp: m.Timestamp})
	}
	return demand.BuildBacklog(miss)
}

// backlogHasTask reports whether the backlog contains an item with the given task.
func backlogHasTask(bl demand.Backlog, task string) int {
	n := 0
	for _, c := range bl.Clusters {
		for _, it := range c.Items {
			if it.Task == task {
				n++
			}
		}
	}
	return n
}

// TestDemandOnly_SybilFloodOneTaskHash_CollapsesToOneUnmovedEntry is the gate: N
// zero-scrip Sybil keys all buy the SAME task. The D1 bound drops each from
// matching, but each is registered demand-only. Assert EXACTLY ONE demand-only
// entry survives (dedup), it appears ONCE in demand.BuildBacklog, the seeded
// entry's price and demand count are UNMOVED, and ZERO scrip moved.
func TestDemandOnly_SybilFloodOneTaskHash_CollapsesToOneUnmovedEntry(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	// A live inventory entry whose signal must NOT move. Its description is chosen
	// NOT to semantically match the Sybil task, but the D1 drop happens before
	// matching anyway — the entry can never be surfaced by an unfunded buy.
	seedInventoryEntry(t, h, eng, "protected inventory entry alpha", "code", 4000, 2000)
	entry := eng.State().Inventory()[0]
	priceBefore := eng.ComputePriceForTest(entry)
	demandBefore := eng.State().EntryDemandCount(entry.EntryID)

	const sybilTask = "reusable engineering artifact demand signal for D1 sybil flood"

	// N distinct Sybil identities, each with ZERO scrip, all spamming ONE task.
	const nSybils = 8
	sybils := make([]*testAgent, nSybils)
	for i := range sybils {
		sybils[i] = newTestAgent(t)
	}
	for _, s := range sybils {
		dispatchBuy(t, h, eng, s, sybilTask, 100000)
		// Fire each identity twice to prove same-identity repeats also collapse.
		dispatchBuy(t, h, eng, s, sybilTask, 100000)
	}

	// (dedup) EXACTLY ONE demand-only message emitted despite 2*N misses.
	if got := len(demandOnlyMsgs(t, h)); got != 1 {
		t.Fatalf("Sybil flood on one task_hash produced %d demand-only entries, want exactly 1 (dedup broken)", got)
	}
	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != 1 {
		t.Fatalf("DemandOnlyRegistered = %d, want 1", snap.DemandOnlyRegistered)
	}
	if snap.DemandOnlyDeduped != (2*nSybils - 1) {
		t.Fatalf("DemandOnlyDeduped = %d, want %d (every repeat after the first collapses)", snap.DemandOnlyDeduped, 2*nSybils-1)
	}
	// Every miss was also withheld from matching (D1 counter still fires per miss).
	if snap.DroppedUnderfundedBuy != int64(2*nSybils) {
		t.Fatalf("DroppedUnderfundedBuy = %d, want %d", snap.DroppedUnderfundedBuy, 2*nSybils)
	}

	// (appears once in `dontguess demand`) BuildBacklog surfaces it exactly once.
	bl := buildBacklogFromLog(t, h)
	if got := backlogHasTask(bl, sybilTask); got != 1 {
		t.Fatalf("demand backlog contains the Sybil task %d times, want exactly 1", got)
	}
	// It is a demand-only entry: offered_price_rate 0, no funded standing offer.
	dm := demandOnlyMsgs(t, h)[0]
	var dp struct {
		OfferedPriceRate int    `json:"offered_price_rate"`
		DemandOnly       bool   `json:"demand_only"`
		TaskHash         string `json:"task_hash"`
	}
	if err := json.Unmarshal(dm.Payload, &dp); err != nil {
		t.Fatalf("parsing demand-only payload: %v", err)
	}
	if dp.OfferedPriceRate != 0 || !dp.DemandOnly {
		t.Fatalf("demand-only payload = %+v, want offered_price_rate 0 and demand_only true", dp)
	}
	// (NO funded BuyMissOffer) The engine opened no standing offer for this hash.
	if off := eng.State().GetBuyMissOffer(exchange.TaskDescriptionHash(sybilTask)); off != nil {
		t.Fatalf("demand-only registration wrongly opened a funded BuyMissOffer: %+v", off)
	}

	// (matching/ranking/pricing UNMOVED — the D1 invariant) The protected entry's
	// price and demand count are byte-for-byte unchanged, and no real match ever
	// surfaced it (the demand-only message has empty results by construction).
	if got := eng.ComputePriceForTest(eng.State().Inventory()[0]); got != priceBefore {
		t.Fatalf("Sybil demand-only moved price %d -> %d (D1 pricing invariant violated)", priceBefore, got)
	}
	if got := eng.State().EntryDemandCount(entry.EntryID); got != demandBefore {
		t.Fatalf("Sybil demand-only moved demand count %d -> %d (D1 ranking invariant violated)", demandBefore, got)
	}
	if id := eng.State().MatchEntryID(dm.ID); id != "" {
		t.Fatalf("demand-only message folded into matchToEntry (%s) — it must never enter matching state", id)
	}

	// (ZERO scrip movement) No scrip event was emitted, and every Sybil (plus the
	// operator) holds zero scrip.
	scripMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripBuyHold}})
	if len(scripMsgs) != 0 {
		t.Fatalf("demand-only registration moved scrip: %d scrip-buy-hold messages", len(scripMsgs))
	}
	for i, s := range sybils {
		bal, _, err := cs.GetBudget(nil, s.PublicKeyHex(), scrip.BalanceKey)
		if err != nil {
			t.Fatalf("GetBudget sybil %d: %v", i, err)
		}
		if bal != 0 {
			t.Fatalf("sybil %d balance = %d, want 0 (no scrip may move)", i, bal)
		}
	}
}

// TestDemandOnly_PerSenderCap proves the per-identity bound: ONE unfunded sender
// flooding MANY DISTINCT task hashes is capped at DemandOnlyPerSenderCap. Beyond
// the cap, registrations are refused and loudly counted as DemandOnlyCapped, so a
// single identity cannot flood the backlog for free.
func TestDemandOnly_PerSenderCap(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	flooder := newTestAgent(t)
	// Drive cap+extra DISTINCT task hashes from one identity.
	const extra = 5
	total := exchange.DemandOnlyPerSenderCap + extra
	for i := 0; i < total; i++ {
		dispatchBuy(t, h, eng, flooder, distinctTask(i), 100000)
	}

	// Exactly the cap number of demand-only entries were emitted; the rest capped.
	if got := len(demandOnlyMsgs(t, h)); got != exchange.DemandOnlyPerSenderCap {
		t.Fatalf("per-sender flood produced %d demand-only entries, want cap %d", got, exchange.DemandOnlyPerSenderCap)
	}
	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != int64(exchange.DemandOnlyPerSenderCap) {
		t.Fatalf("DemandOnlyRegistered = %d, want %d", snap.DemandOnlyRegistered, exchange.DemandOnlyPerSenderCap)
	}
	if snap.DemandOnlyCapped != int64(extra) {
		t.Fatalf("DemandOnlyCapped = %d, want %d (excess distinct-task floods refused)", snap.DemandOnlyCapped, extra)
	}
}

// distinctTask returns a distinct, non-synthetic task description for index i.
func distinctTask(i int) string {
	return "reusable engineering artifact demand signal variant " + time.Duration(i).String() + "-idx"
}

// TestDemandOnly_FundedMissPathUnaffected proves a FUNDED buyer's normal zero-match
// miss path is UNAFFECTED by the 67e0 change: it still opens a real 70%-rate funded
// BuyMissOffer and its buy-miss message is NOT tagged demand-only.
func TestDemandOnly_FundedMissPathUnaffected(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)

	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	// Fund the buyer above MinBuyBalance so it clears the D1 bound.
	addScripMintMsg(t, h, h.buyer.PublicKeyHex(), minBuyBalance+5000)
	if err := cs.Replay(); err != nil {
		t.Fatalf("scrip Replay: %v", err)
	}

	// Empty inventory => guaranteed zero-match => the FUNDED miss path (handleBuyMiss).
	const fundedTask = "funded buyer zero match miss path task"
	dispatchBuy(t, h, eng, h.buyer, fundedTask, 100000)

	// A funded buy-miss opened a real 70%-rate standing offer.
	off := eng.State().GetBuyMissOffer(exchange.TaskDescriptionHash(fundedTask))
	if off == nil {
		t.Fatalf("funded zero-match miss did NOT open a BuyMissOffer (funded path regressed)")
	}
	// It is NOT a demand-only registration.
	if got := len(demandOnlyMsgs(t, h)); got != 0 {
		t.Fatalf("funded miss emitted %d demand-only entries, want 0 (funded path must not be demand-only)", got)
	}
	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != 0 || snap.DemandOnlyDeduped != 0 || snap.DemandOnlyCapped != 0 {
		t.Fatalf("funded miss touched demand-only counters: %+v", snap)
	}
	if snap.DroppedUnderfundedBuy != 0 {
		t.Fatalf("funded buy was wrongly D1-dropped: DroppedUnderfundedBuy=%d", snap.DroppedUnderfundedBuy)
	}

	// The emitted buy-miss carries the funded 70% rate, not the demand-only 0 rate.
	missMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagBuyMiss}})
	if len(missMsgs) != 1 {
		t.Fatalf("expected exactly 1 buy-miss message, got %d", len(missMsgs))
	}
	var mp struct {
		OfferedPriceRate int `json:"offered_price_rate"`
	}
	if err := json.Unmarshal(missMsgs[0].Payload, &mp); err != nil {
		t.Fatalf("parsing buy-miss payload: %v", err)
	}
	if mp.OfferedPriceRate != exchange.BuyMissOfferRate {
		t.Fatalf("funded buy-miss offered_price_rate = %d, want %d", mp.OfferedPriceRate, exchange.BuyMissOfferRate)
	}
}
