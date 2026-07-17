package exchange_test

// Enforcement proofs for dontguess-fd3 — HARDENING the demand-only backlog
// (67e0 ruling / dontguess-4f01) against three CONFIRMED findings:
//
//	(1) HIGH  no eviction: the global demand-only cap counted entries that never
//	    expired, so an unfunded-Sybil flood of distinct task hashes could
//	    PERMANENTLY exhaust DemandOnlyGlobalCap and disable demand-only
//	    registration for all future legit unfunded buyers (irreversible free DoS).
//	(2) MED   unbounded per-sender slice: demandOnlySenderTimes[key] was append-only
//	    (filtered on read, never pruned), growing without bound for a long-lived /
//	    replayed sender.
//	(3) LOW   unnormalized hash: TaskDescriptionHash hashed the raw string, so
//	    whitespace/case variation minted DISTINCT hashes — multiplying global-cap
//	    slots and defeating dedup. The SAME hash keys the funded 909 buy-miss offer
//	    path, so normalization must keep funded-offer creation and matching aligned.
//
// Every test drives REAL engine/state (no mock of the thing under test) and uses a
// CONTROLLABLE CLOCK — folded event timestamps + the `now` argument to
// DemandOnlyTotal/HasDemandOnly/DemandOnlyCountForSender — instead of a real 24h
// sleep, so TTL eviction is proven deterministically.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// hexID returns a unique 64-char hex message ID for index i.
func hexID(i int) string { return fmt.Sprintf("%064x", i) }

// craftDemandOnly builds a demand-only message exactly as registerDemandOnly emits
// it: tags [buy-miss, match, demand-only], an operator-authored payload carrying
// task_hash / buyer_key / expires_at. sender must equal the state's OperatorKey (or
// "" for a bare NewState whose operator guard is disabled) or applyMatch drops it.
func craftDemandOnly(id, sender, buyerKey, taskHash string, expiresAt time.Time, ts int64) *exchange.Message {
	payload, _ := json.Marshal(map[string]any{
		"task_hash":          taskHash,
		"buyer_key":          buyerKey,
		"demand_only":        true,
		"offered_price_rate": 0,
		"expires_at":         expiresAt.UTC().Format(time.RFC3339),
	})
	return &exchange.Message{
		ID:          id,
		Sender:      sender,
		Payload:     payload,
		Tags:        []string{exchange.TagBuyMiss, exchange.TagMatch, exchange.TagDemandOnly},
		Antecedents: []string{},
		Timestamp:   ts,
	}
}

// ---------------------------------------------------------------------------
// Finding 1 — TTL eviction: expired entries neither count toward the global cap
// nor linger in the map.
// ---------------------------------------------------------------------------

// TestDemandOnly_ExpiredHashesDoNotCountTowardGlobalCap is the headline DoS-closed
// proof: a flood of demand-only task hashes whose TTL has elapsed must NOT count as
// LIVE, so DemandOnlyTotal(now) reports 0 and registerDemandOnly's cap gate stays
// open for a fresh legit unfunded buyer. Uses a controllable clock (folded expiry
// in the past) — no real 24h wait.
func TestDemandOnly_ExpiredHashesDoNotCountTowardGlobalCap(t *testing.T) {
	t.Parallel()
	st := exchange.NewState() // OperatorKey "" → applyMatch operator guard disabled

	now := time.Now()
	floodTs := now.Add(-2 * time.Hour).UnixNano()
	floodExp := now.Add(-time.Hour) // already expired relative to `now`

	// Fill the map to the GLOBAL CAP with EXPIRED entries. Under the pre-fix code
	// (len-based total) this would read as a fully-exhausted cap forever.
	for i := 0; i < exchange.DemandOnlyGlobalCap; i++ {
		st.Apply(craftDemandOnly(hexID(i), "", "flood-buyer", "hash-"+hexID(i), floodExp, floodTs))
	}

	if live := st.DemandOnlyTotal(now); live != 0 {
		t.Fatalf("DemandOnlyTotal(now) = %d, want 0 — expired entries must not count toward the cap (finding 1 DoS not closed)", live)
	}
	// A fresh, live hash is not deduped away by an expired prior registration.
	if st.HasDemandOnly("hash-"+hexID(0), now) {
		t.Fatalf("HasDemandOnly reported an EXPIRED registration as live — a fresh miss for the same task could never re-register")
	}
}

// TestDemandOnly_ExpiredHashesArePhysicallyEvicted proves the fold EVICTS expired
// entries (bounds memory), not merely filters them on read. It folds N entries that
// expire at T0+TTL, then folds ONE fresh entry whose event timestamp is PAST every
// prior expiry: the sweep must physically delete the N. Proof: query the total at a
// clock (T0) where the N WOULD be live if still present — the count is 1 (only the
// fresh survivor), which is impossible unless the N were physically removed.
func TestDemandOnly_ExpiredHashesArePhysicallyEvicted(t *testing.T) {
	t.Parallel()
	st := exchange.NewState()

	t0 := time.Now()
	const n = 50
	for i := 0; i < n; i++ {
		exp := t0.Add(exchange.DemandOnlyTTL) // live as of t0
		st.Apply(craftDemandOnly(hexID(i), "", "b", "hash-"+hexID(i), exp, t0.UnixNano()))
	}
	// Sanity: as of t0 all N are live.
	if live := st.DemandOnlyTotal(t0); live != n {
		t.Fatalf("precondition: DemandOnlyTotal(t0) = %d, want %d", live, n)
	}

	// One fresh fold whose timestamp is past every prior expiry → sweep evicts all N.
	freshTs := t0.Add(exchange.DemandOnlyTTL + time.Hour)
	freshExp := freshTs.Add(exchange.DemandOnlyTTL)
	st.Apply(craftDemandOnly(hexID(1_000_000), "", "b", "hash-fresh", freshExp, freshTs.UnixNano()))

	// If eviction were mere read-filtering, the N would still be PHYSICALLY present
	// and this query at t0 (where they'd be live) would return n+1. It returns 1 —
	// only the fresh survivor remains in the map.
	if got := st.DemandOnlyTotal(t0); got != 1 {
		t.Fatalf("DemandOnlyTotal(t0) after eviction = %d, want 1 — expired entries were not physically evicted (finding 1 memory leak)", got)
	}
}

// TestDemandOnly_ExpiredFloodStillAdmitsFreshRegistration is the END-TO-END DoS
// proof through the REAL engine: GlobalCap expired entries are folded into the
// engine's live state, then a fresh unfunded buyer's miss STILL registers demand-only
// (not capped). Under the pre-fix code the cap would read as exhausted and the fresh
// miss would be DemandOnlyCapped forever.
func TestDemandOnly_ExpiredFloodStillAdmitsFreshRegistration(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	now := time.Now()
	floodTs := now.Add(-2 * time.Hour).UnixNano()
	floodExp := now.Add(-time.Hour)
	op := h.operator.PublicKeyHex()
	for i := 0; i < exchange.DemandOnlyGlobalCap; i++ {
		eng.State().Apply(craftDemandOnly(hexID(i), op, "flood-buyer", "hash-"+hexID(i), floodExp, floodTs))
	}
	if live := eng.State().DemandOnlyTotal(now); live != 0 {
		t.Fatalf("engine state: DemandOnlyTotal(now) = %d, want 0 (expired flood must not count)", live)
	}

	// Fresh legit unfunded buyer → must register (cap not exhausted).
	sybil := newTestAgent(t)
	dispatchBuy(t, h, eng, sybil, "fresh legit unfunded demand after an expired sybil flood", 100000)

	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != 1 {
		t.Fatalf("DemandOnlyRegistered = %d, want 1 — a fresh miss was blocked by an expired flood (finding 1 DoS)", snap.DemandOnlyRegistered)
	}
	if snap.DemandOnlyCapped != 0 {
		t.Fatalf("DemandOnlyCapped = %d, want 0 — expired entries wrongly counted toward the global cap", snap.DemandOnlyCapped)
	}
	if got := len(demandOnlyMsgs(t, h)); got != 1 {
		t.Fatalf("emitted demand-only messages = %d, want 1 (the fresh registration)", got)
	}
}

// TestDemandOnly_LiveFloodStillCaps is the control for finding 1: the global cap
// STILL fires when the entries are LIVE. GlobalCap live entries are folded, then a
// fresh miss is refused (DemandOnlyCapped). This proves the eviction fix did not
// simply disable the backstop.
func TestDemandOnly_LiveFloodStillCaps(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	now := time.Now()
	liveExp := now.Add(exchange.DemandOnlyTTL) // live
	op := h.operator.PublicKeyHex()
	for i := 0; i < exchange.DemandOnlyGlobalCap; i++ {
		eng.State().Apply(craftDemandOnly(hexID(i), op, "flood-buyer", "hash-"+hexID(i), liveExp, now.UnixNano()))
	}
	if live := eng.State().DemandOnlyTotal(now); live != exchange.DemandOnlyGlobalCap {
		t.Fatalf("engine state: DemandOnlyTotal(now) = %d, want %d (live flood)", live, exchange.DemandOnlyGlobalCap)
	}

	sybil := newTestAgent(t)
	dispatchBuy(t, h, eng, sybil, "fresh unfunded demand against a FULL live cap", 100000)

	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != 0 {
		t.Fatalf("DemandOnlyRegistered = %d, want 0 — a full LIVE cap must refuse new registrations", snap.DemandOnlyRegistered)
	}
	if snap.DemandOnlyCapped != 1 {
		t.Fatalf("DemandOnlyCapped = %d, want 1 — the global backstop must still fire at a full live cap", snap.DemandOnlyCapped)
	}
}

// ---------------------------------------------------------------------------
// Finding 2 — per-sender slice is pruned on write, not just filtered on read.
// ---------------------------------------------------------------------------

// TestDemandOnly_PerSenderSliceBoundedOnWrite proves the per-sender timestamp slice
// is PHYSICALLY pruned to the rolling window on each write, so a long-lived /
// replayed sender key cannot grow it without bound. It folds many registrations for
// ONE buyer, each spaced beyond DemandOnlyPerSenderWindow from the last, then reads
// the count back with a window LARGE enough to include every entry IF they were
// retained. A small result proves physical pruning (not the read-side filter).
func TestDemandOnly_PerSenderSliceBoundedOnWrite(t *testing.T) {
	t.Parallel()
	st := exchange.NewState()

	const buyer = "long-lived-sender"
	const n = 200
	spacing := 2 * exchange.DemandOnlyPerSenderWindow // each fold is beyond the window
	base := time.Now().Add(-time.Duration(n) * spacing)
	var lastTs int64
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * spacing)
		lastTs = ts.UnixNano()
		exp := ts.Add(exchange.DemandOnlyTTL)
		st.Apply(craftDemandOnly(hexID(i), "", buyer, "same-hash", exp, lastTs))
	}

	// Read with a window so large the READ filter drops nothing; any bound on the
	// result therefore comes from physical pruning on write. Only entries within
	// one DemandOnlyPerSenderWindow of the final fold can survive — here just 1.
	hugeWindow := time.Duration(n+10) * spacing
	got := st.DemandOnlyCountForSender(buyer, time.Unix(0, lastTs), hugeWindow)
	if got != 1 {
		t.Fatalf("DemandOnlyCountForSender (huge window) = %d, want 1 — the per-sender slice was not pruned on write (finding 2 unbounded growth); an unpruned slice would report %d", got, n)
	}
}

// ---------------------------------------------------------------------------
// Finding 3 — normalized hash: whitespace/case variants collapse; the 909 funded
// offer path stays aligned.
// ---------------------------------------------------------------------------

// TestDemandOnly_WhitespaceCaseVariantsCollapse proves finding 3 on the demand-only
// dedup path AND re-asserts the load-bearing D1 invariant (finding-e): two unfunded
// misses whose task strings differ ONLY by whitespace and case collapse to ONE
// demand entry, move ZERO scrip, and leave pricing/ranking UNMOVED.
func TestDemandOnly_WhitespaceCaseVariantsCollapse(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	// A protected inventory entry whose price/demand must NOT move (D1 invariant).
	seedInventoryEntry(t, h, eng, "protected inventory entry for fd3", "code", 4000, 2000)
	entry := eng.State().Inventory()[0]
	priceBefore := eng.ComputePriceForTest(entry)
	demandBefore := eng.State().EntryDemandCount(entry.EntryID)

	// Same logical task, trivially varied: extra/leading/trailing whitespace + case.
	taskA := "Reusable Go flock contention test pattern for the exchange"
	taskB := "  reusable   go\tFLOCK  contention   test PATTERN for the exchange   "

	sybilA := newTestAgent(t)
	sybilB := newTestAgent(t)
	dispatchBuy(t, h, eng, sybilA, taskA, 100000)
	dispatchBuy(t, h, eng, sybilB, taskB, 100000)

	// (dedup) Exactly ONE demand-only entry despite two distinct raw strings.
	if got := len(demandOnlyMsgs(t, h)); got != 1 {
		t.Fatalf("whitespace/case variants produced %d demand-only entries, want exactly 1 (finding 3 dedup)", got)
	}
	snap := eng.DegradationSnapshot()
	if snap.DemandOnlyRegistered != 1 || snap.DemandOnlyDeduped != 1 {
		t.Fatalf("counters = {registered:%d deduped:%d}, want {1 1} (second variant must dedup)", snap.DemandOnlyRegistered, snap.DemandOnlyDeduped)
	}
	// Both hashes are identical after normalization.
	if exchange.TaskDescriptionHash(taskA) != exchange.TaskDescriptionHash(taskB) {
		t.Fatalf("TaskDescriptionHash not normalized: variants hashed differently")
	}

	// (D1 invariant re-asserted — finding e) ZERO scrip moved; price/demand unmoved.
	scripMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripBuyHold}})
	if len(scripMsgs) != 0 {
		t.Fatalf("demand-only registration moved scrip: %d scrip-buy-hold messages, want 0", len(scripMsgs))
	}
	if got := eng.ComputePriceForTest(eng.State().Inventory()[0]); got != priceBefore {
		t.Fatalf("demand-only moved price %d -> %d (D1 pricing invariant violated)", priceBefore, got)
	}
	if got := eng.State().EntryDemandCount(entry.EntryID); got != demandBefore {
		t.Fatalf("demand-only moved demand count %d -> %d (D1 ranking invariant violated)", demandBefore, got)
	}
}

// TestBuyMiss_FundedOfferMatchesWhitespaceCaseVariantPut proves finding 3 did NOT
// break the 909 funded buy-miss path: a funded buyer opens a standing offer keyed on
// its task; a seller then PUTs the result with a Description that differs from the
// original task only by whitespace and case. Normalization keeps offer creation and
// lookup aligned, so handlePut STILL matches the offer and the exchange auto-accepts
// (emits a put-accept and claims the offer).
func TestBuyMiss_FundedOfferMatchesWhitespaceCaseVariantPut(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	const minBuyBalance = 1000
	cs := newCampfireScripStore(t, h)
	eng := newSignalBoundEngine(t, h, cs, minBuyBalance)

	// Fund the buyer above MinBuyBalance so its zero-match miss opens a FUNDED offer.
	addScripMintMsg(t, h, h.buyer.PublicKeyHex(), minBuyBalance+5000)
	if err := cs.Replay(); err != nil {
		t.Fatalf("scrip Replay: %v", err)
	}

	// Empty inventory → guaranteed miss → funded BuyMissOffer opened for taskA.
	taskA := "Implement a Go Redis client with connection pooling and circuit breaker"
	dispatchBuy(t, h, eng, h.buyer, taskA, 100000)
	offerHash := exchange.TaskDescriptionHash(taskA)
	if eng.State().GetBuyMissOffer(offerHash) == nil {
		t.Fatalf("funded zero-match miss did not open a BuyMissOffer (909 path regressed)")
	}

	// Seller computes the result and PUTs it with a whitespace/case-varied Description.
	variantDesc := "  implement a GO   redis client\twith connection POOLING and circuit breaker  "
	const tokenCost int64 = 80000
	putMsg := h.sendMessage(h.seller,
		putPayload(variantDesc, "sha256:"+fmt.Sprintf("%064x", tokenCost), "code", tokenCost, tokenCost*2),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	putRec, err := h.st.GetMessage(putMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage put: %v", err)
	}
	// Fold the put incrementally (Apply, NOT Replay — Replay would wipe the
	// engine-set standing offer) so pendingPuts holds it for handlePut.
	eng.State().Apply(exchange.FromStoreRecord(putRec))

	preSettle, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagSettle}})
	if err := eng.DispatchForTest(exchange.FromStoreRecord(putRec)); err != nil {
		t.Fatalf("DispatchForTest put: %v", err)
	}

	// A put-accept must have been emitted → the variant put matched the offer.
	postSettle, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagSettle}})
	var putAccept *store.MessageRecord
	for i := range postSettle {
		for _, tag := range postSettle[i].Tags {
			if tag == "exchange:phase:put-accept" {
				putAccept = &postSettle[i]
			}
		}
	}
	if putAccept == nil {
		t.Fatalf("no put-accept emitted (%d->%d settle msgs) — funded offer did NOT match a whitespace/case-varied put (finding 3 broke the 909 path)", len(preSettle), len(postSettle))
	}
	// The offer is now claimed (single-fulfillment).
	if eng.State().GetBuyMissOffer(offerHash) != nil {
		t.Fatalf("BuyMissOffer not claimed after fulfillment — offer/put hashes did not align after normalization")
	}
}
