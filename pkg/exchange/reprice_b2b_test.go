package exchange_test

// Migration/audit-trail tests for dontguess-b2b (operator ruling dontguess-96e
// decision 2): the 166 existing entries are reinterpreted RETROACTIVELY under
// token_cost := output tokens, an operator override of the recommended
// grandfather option. The mandatory mitigation is an auditable, reversible
// repricing EVENT per entry — never an in-place price mutation.
//
// Required outcomes tested here:
//  1. Every live inventory entry gets exactly one reprice event (old_price,
//     new_price, basis, ruling ref).
//  2. A rollback reconstructs pre-ruling prices EXACTLY from the event log
//     alone — verified against an INDEPENDENTLY computed expected value (not
//     just self-consistency), so a broken rollback (e.g. returning new_price,
//     or the wrong record when an entry is repriced twice) actually fails.
//  3. Reconstruction works from a bare Replay of the raw message log, with no
//     prior in-memory state — "the event log alone".
//  4. Dedup by event ID: a relay-double-appended message does not double the
//     count or double-emit a reprice event (dontguess-8f5 hazard).
//  5. Both pre-migration envelope shapes (legacy plaintext, v2 confidential
//     envelope) are reinterpreted uniformly — no shape-based skip
//     (dontguess-5b8 hazard).
//  6. Non-operator senders cannot forge a reprice event.
//  7. Re-running the migration is idempotent (no duplicate events).

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// repriceFixtureEntry returns a deterministic accepted STANDARD inventory
// entry with all non-price signal factors neutralized (ContentSize=0,
// PutTimestamp=0, no CompressionTier/CompressedFrom, default reputation,
// fresh engine with zero demand/fast-loop history) — same pattern as
// pricing_two_unit_af3_test.go's acceptedEntryForAmortization — so the
// pre-ruling and post-ruling prices are simple, exactly-computable functions
// of tokenCost alone, independent of wall-clock or the entry's put history.
func repriceFixtureEntry(entryID string, tokenCost int64) *exchange.InventoryEntry {
	return &exchange.InventoryEntry{
		EntryID:      entryID,
		PutMsgID:     entryID,
		SellerKey:    "seller-" + entryID,
		TokenCost:    tokenCost,
		PutPrice:     tokenCost * 70 / 100, // RunAutoAccept's standard 70% accept rate
		ContentSize:  0,
		PutTimestamp: 0,
	}
}

// expectedLegacyPrice independently reproduces the pre-af3 one-off-commission
// formula for a repriceFixtureEntry: base = PutPrice * 1.2, all six signal
// factors are 1.0 (by fixture construction), no amortization division. This
// is computed WITHOUT calling any exchange package internals, so it can catch
// a genuinely broken legacyComputePrice/rollback, not just self-agreement.
func expectedLegacyPrice(tokenCost int64) int64 {
	putPrice := tokenCost * 70 / 100
	return int64(putPrice) * 12 / 10 // *1.2, matches operatorMargin
}

// repriceFixtureEntryWithSignals is repriceFixtureEntry's non-degenerate
// counterpart (finding 5): repriceFixtureEntry ALWAYS zeroes ContentSize/
// PutTimestamp, leaves CompressionTier unset, and ALWAYS sets PutPrice>0 —
// every test built on it therefore exercises legacyComputePrice with all six
// signal factors pinned at 1.0 and only ever the PutPrice*1.2 base branch. A
// mutation to age/size/tier factor handling, or to the TokenCost fallback
// branch (PutPrice<=0), would silently break and no test in this file would
// catch it. This constructor lets callers set PutPrice (0 to force the
// TokenCost fallback), age, content size, and compression tier explicitly.
func repriceFixtureEntryWithSignals(entryID string, tokenCost, putPrice int64, ageAgo time.Duration, contentSize int64, tier string) *exchange.InventoryEntry {
	var ts int64
	if ageAgo > 0 {
		ts = time.Now().Add(-ageAgo).UnixNano()
	}
	return &exchange.InventoryEntry{
		EntryID:         entryID,
		PutMsgID:        entryID,
		SellerKey:       "seller-" + entryID,
		TokenCost:       tokenCost,
		PutPrice:        putPrice,
		ContentSize:     contentSize,
		PutTimestamp:    ts,
		CompressionTier: tier,
	}
}

func TestReprice_EmitsOneAuditEventPerEntryWithCorrectOldAndNewPrice(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	entries := []*exchange.InventoryEntry{
		repriceFixtureEntry("entry-a", 8000),
		repriceFixtureEntry("entry-b", 60000),
		repriceFixtureEntry("entry-c", 140000),
	}
	for _, e := range entries {
		state.InjectInventoryEntryForTest(e)
	}

	records, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit)
	if err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	if len(records) != len(entries) {
		t.Fatalf("got %d reprice records, want %d (one per entry)", len(records), len(entries))
	}

	for _, e := range entries {
		recs := state.Reprices(e.EntryID)
		if len(recs) != 1 {
			t.Fatalf("entry %s: got %d reprice events, want exactly 1", e.EntryID, len(recs))
		}
		rec := recs[0]

		wantOld := expectedLegacyPrice(e.TokenCost)
		if rec.OldPrice != wantOld {
			t.Errorf("entry %s: OldPrice = %d, want %d (independently-computed pre-ruling price)", e.EntryID, rec.OldPrice, wantOld)
		}
		wantNew := eng.ComputePriceForTest(e)
		if rec.NewPrice != wantNew {
			t.Errorf("entry %s: NewPrice = %d, want %d (current computePrice)", e.EntryID, rec.NewPrice, wantNew)
		}
		// The whole point of the migration: the new (two-unit, amortized)
		// price must be materially lower than the old one-off-commission price.
		if rec.NewPrice >= rec.OldPrice {
			t.Errorf("entry %s: NewPrice=%d not below OldPrice=%d — amortization should have reduced it", e.EntryID, rec.NewPrice, rec.OldPrice)
		}
		if rec.Basis != exchange.RepriceBasisTwoUnit {
			t.Errorf("entry %s: Basis = %q, want %q", e.EntryID, rec.Basis, exchange.RepriceBasisTwoUnit)
		}
		if rec.RulingRef != exchange.RepriceRulingRef96e {
			t.Errorf("entry %s: RulingRef = %q, want %q", e.EntryID, rec.RulingRef, exchange.RepriceRulingRef96e)
		}
	}
}

// TestReprice_BothEnvelopeShapesReinterpretedUniformly is the dontguess-5b8
// data hazard test: legacy plaintext entries and v2 envelope entries were put
// under the SAME undefined token_cost semantic, so the migration must reprice
// both — no shape-based skip.
func TestReprice_BothEnvelopeShapesReinterpretedUniformly(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	legacy := repriceFixtureEntry("legacy-entry", 15000)
	legacy.LegacyPlaintext = true

	v2 := repriceFixtureEntry("v2-entry", 15000)
	v2.WrappedCEKOperator = "wrapped-cek-example-base64"
	v2.CiphertextHash = "sha256:deadbeef"

	state.InjectInventoryEntryForTest(legacy)
	state.InjectInventoryEntryForTest(v2)

	records, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit)
	if err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d reprice records, want 2 (one per envelope shape)", len(records))
	}

	if len(state.Reprices("legacy-entry")) != 1 {
		t.Errorf("legacy-plaintext entry was not repriced")
	}
	if len(state.Reprices("v2-entry")) != 1 {
		t.Errorf("v2-envelope entry was not repriced")
	}
}

// TestReprice_DedupByEventID is the dontguess-8f5 data hazard test: the store
// double-appends relay-origin events (~6% inflation on raw counts). Simulate
// the SAME reprice message id landing twice (as the store re-ingest bug would
// produce) and assert it folds to exactly one recorded event, not two.
func TestReprice_DedupByEventID(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	entry := repriceFixtureEntry("dup-entry", 8000)
	state.InjectInventoryEntryForTest(entry)

	records, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit)
	if err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	// Re-derive the exact reprice message the engine just appended and re-Apply
	// it — modeling a relay double-append of the identical event id, the root
	// cause dontguess-8f5 identified (no event-id idempotency at store append).
	msgs := findMessagesForTest(t, eng, exchange.TagReprice)
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 reprice message on the log, got %d", len(msgs))
	}
	dupMsg := msgs[0]
	eng.State().Apply(&dupMsg)
	eng.State().Apply(&dupMsg) // apply a third time for good measure

	recs := state.Reprices("dup-entry")
	if len(recs) != 1 {
		t.Fatalf("after re-applying the same message id twice more, got %d recorded events, want 1 (dedup by event id)", len(recs))
	}
}

// TestReprice_IdempotentAcrossReruns verifies that running the migration
// driver twice for the same ruling ref does not emit duplicate audit events —
// required so a partial-failure re-run (or an accidental second invocation)
// is safe.
func TestReprice_IdempotentAcrossReruns(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	state.InjectInventoryEntryForTest(repriceFixtureEntry("rerun-a", 8000))
	state.InjectInventoryEntryForTest(repriceFixtureEntry("rerun-b", 60000))

	first, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit)
	if err != nil {
		t.Fatalf("first RepriceInventoryForRuling: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first run: got %d records, want 2", len(first))
	}

	second, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit)
	if err != nil {
		t.Fatalf("second RepriceInventoryForRuling: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second run: got %d NEW records, want 0 (idempotent — already repriced under this ruling)", len(second))
	}

	if len(state.Reprices("rerun-a")) != 1 || len(state.Reprices("rerun-b")) != 1 {
		t.Fatalf("expected exactly 1 reprice event per entry after two runs")
	}
}

// TestReprice_NonOperatorSenderRejected proves a forged reprice event from a
// non-operator sender is dropped and alarmed, never folded — the same
// operator-only guard every other settlement fold enforces.
func TestReprice_NonOperatorSenderRejected(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	entry := repriceFixtureEntry("forged-entry", 8000)
	state.InjectInventoryEntryForTest(entry)

	payload, err := json.Marshal(map[string]any{
		"entry_id":   "forged-entry",
		"old_price":  99999,
		"new_price":  1,
		"basis":      "attacker-forged",
		"ruling_ref": exchange.RepriceRulingRef96e,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	forged := &exchange.Message{
		ID:          "forged-msg-id",
		Sender:      "not-the-operator",
		Payload:     payload,
		Tags:        []string{exchange.TagReprice},
		Antecedents: []string{"forged-entry"},
		Timestamp:   1,
	}
	state.Apply(forged)

	recs := state.Reprices("forged-entry")
	if len(recs) != 0 {
		t.Fatalf("forged non-operator reprice event was folded: %+v", recs)
	}
}

// TestReprice_RollbackScopedToRulingRefNotGloballyOldest is the item's
// REQUIRED mutation-verified test for finding 3 (wave-5 rejection): a prior
// version of RollbackReprice took no rulingRef and always returned an
// entry's globally OLDEST reprice record — so only the very first reprice an
// entry ever received could be rolled back, and a LATER, independent
// re-interpretation under a DIFFERENT ruling was unrecoverable (its own
// old_price could never be read back out).
//
// This test reprices roll-a TWICE, under two DIFFERENT ruling refs, in an
// order that makes the bug observable: an EARLIER, unrelated ruling first
// (old_price=111, a value that looks nothing like the real pre-96e price),
// THEN the real dontguess-96e migration reprice. A rollback that ignores
// rulingRef and just returns recs[0] would return 111 for
// RollbackReprice(RepriceRulingRef96e) — wrong, because ruling 96e's own
// old_price was computed independently as expectedLegacyPrice(8000). Scoping
// by rulingRef is what makes RollbackReprice(RepriceRulingRef96e) return the
// 96e event's own old_price regardless of what earlier events exist, and
// RollbackReprice("dontguess-earlier-ruling") return 111 and ONLY 111 (no
// stray roll-b entry, since roll-b was never touched by that ruling).
func TestReprice_RollbackScopedToRulingRefNotGloballyOldest(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	const earlierRuling = "dontguess-earlier-ruling"

	entries := []*exchange.InventoryEntry{
		repriceFixtureEntry("roll-a", 8000),
		repriceFixtureEntry("roll-b", 140000),
	}
	for _, e := range entries {
		state.InjectInventoryEntryForTest(e)
	}

	// An EARLIER, unrelated reprice for roll-a only, under a DIFFERENT ruling,
	// with an old_price that cannot be confused with the real 96e value.
	if _, err := eng.EmitReprice("roll-a", 111, 222, "earlier unrelated reinterpretation", earlierRuling); err != nil {
		t.Fatalf("EmitReprice (earlier ruling): %v", err)
	}

	// THEN the real dontguess-96e migration reprice, for both entries.
	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	if got := len(state.Reprices("roll-a")); got != 2 {
		t.Fatalf("roll-a: got %d reprice events, want 2 (earlier + 96e)", got)
	}

	// True, independently-computed pre-96e prices (same fixture math as
	// expectedLegacyPrice above — computed WITHOUT calling any exchange
	// package internals).
	want96e := map[string]int64{
		"roll-a": expectedLegacyPrice(8000),
		"roll-b": expectedLegacyPrice(140000),
	}

	got96e := state.RollbackReprice(exchange.RepriceRulingRef96e)
	for entryID, want := range want96e {
		if got96e[entryID] != want {
			t.Errorf("RollbackReprice(96e)[%s] = %d, want %d (the 96e event's own old_price, not the earlier ruling's)", entryID, got96e[entryID], want)
		}
	}
	if len(got96e) != 2 {
		t.Fatalf("RollbackReprice(96e) returned %d entries, want 2", len(got96e))
	}

	gotEarlier := state.RollbackReprice(earlierRuling)
	if len(gotEarlier) != 1 {
		t.Fatalf("RollbackReprice(earlier) returned %d entries, want 1 (only roll-a was ever touched by this ruling)", len(gotEarlier))
	}
	if gotEarlier["roll-a"] != 111 {
		t.Errorf("RollbackReprice(earlier)[roll-a] = %d, want 111", gotEarlier["roll-a"])
	}

	// A ruling ref that never touched anything must return an empty map, not
	// fall back to some other ruling's data.
	if got := state.RollbackReprice("dontguess-never-happened"); len(got) != 0 {
		t.Errorf("RollbackReprice(unknown ruling) = %v, want empty", got)
	}
}

// TestReprice_RollbackFromBareReplayNoLiveState proves the "event log alone"
// property literally: a fresh State object with ZERO prior in-memory data
// (no InjectInventoryEntryForTest, no engine, no prior Apply calls) must
// reconstruct the correct pre-ruling price by replaying nothing but the raw
// reprice message.
//
// The expected value is computed INDEPENDENTLY of the engine (expectedLegacyPrice,
// the same closed-form helper used throughout this file) — NOT by calling
// state.RollbackReprice() on the live, already-populated state and comparing
// the fresh replay against that. A prior version of this test committed
// exactly that self-comparison bug: both the "live" and "fresh" sides called
// the SAME (possibly broken) RollbackReprice implementation, so an
// identically-broken rollback would still agree with itself and pass. Also,
// fresh.OperatorKey is seeded from the harness's REAL configured operator
// identity (state.OperatorKey) rather than from repriceMsgs[0].Sender — using
// the message-under-test's own sender field to authorize replaying that same
// message is a second self-referential shortcut this test must not take.
func TestReprice_RollbackFromBareReplayNoLiveState(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	const tokenCost = int64(60000)
	entry := repriceFixtureEntry("replay-entry", tokenCost)
	state.InjectInventoryEntryForTest(entry)

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}

	// Independently computed expected value — no call to RollbackReprice on
	// the live state anywhere in this test.
	wantOld := expectedLegacyPrice(tokenCost)

	repriceMsgs := findMessagesForTest(t, eng, exchange.TagReprice)
	if len(repriceMsgs) != 1 {
		t.Fatalf("expected 1 reprice message on the log, got %d", len(repriceMsgs))
	}

	// Fresh State, built from NOTHING but the reprice message — no
	// InjectInventoryEntryForTest, no engine, no prior Apply calls.
	// OperatorKey is seeded from the REAL harness-configured operator
	// identity, not from the message under test's own Sender field.
	fresh := exchange.NewState()
	fresh.OperatorKey = state.OperatorKey
	if fresh.OperatorKey == "" {
		t.Fatalf("setup: harness operator key is empty")
	}
	fresh.Replay(repriceMsgs)

	got := fresh.RollbackReprice(exchange.RepriceRulingRef96e)
	if got["replay-entry"] != wantOld {
		t.Errorf("bare-Replay RollbackReprice(96e)[replay-entry] = %d, want %d (independently-computed pre-ruling price, recovered from event log alone)", got["replay-entry"], wantOld)
	}
}

// TestReprice_ReplayTwiceOnUnchangedLogPreservesExactlyOneEventPerEntry is
// the mutation guard for beginReplayLocked (state_core.go): repriceEvents and
// repriceCounted MUST be reset TOGETHER on every Replay. Both individually
// (reset repriceEvents but not repriceCounted, or vice versa) previously
// survived the full test suite, yet rebuildAndDispatchGapLocal calls Replay
// on an already-populated State on EVERY observed log growth — the hot path
// the real migration passes through.
//
// This models exactly that: Replay the SAME (unchanged) raw message log
// against one State object multiple times in a row, as rebuildAndDispatchGapLocal
// would when polled repeatedly with no new messages in between.
//
//   - If repriceEvents is reset but repriceCounted is NOT: on replay #2
//     repriceCounted still remembers the message id from replay #1, so the
//     per-message dedup guard in applyReprice sees a "dup" and skips the
//     fold — but repriceEvents was just wiped to empty, so the record is
//     PERMANENTLY LOST (0 events after replay #2).
//   - If repriceCounted is reset but repriceEvents is NOT: on replay #2
//     repriceCounted is empty, so the dedup guard does NOT block the
//     re-fold — but repriceEvents still holds the record from replay #1, so
//     the SAME message is appended a second time (2 events after replay #2).
//
// Only resetting both together reproduces exactly 1 event on every replay.
func TestReprice_ReplayTwiceOnUnchangedLogPreservesExactlyOneEventPerEntry(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	const tokenCost = int64(60000)
	entry := repriceFixtureEntry("replay-twice-entry", tokenCost)
	state.InjectInventoryEntryForTest(entry)

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	wantOld := expectedLegacyPrice(tokenCost)

	repriceMsgs := findMessagesForTest(t, eng, exchange.TagReprice)
	if len(repriceMsgs) != 1 {
		t.Fatalf("expected 1 reprice message on the log, got %d", len(repriceMsgs))
	}

	fresh := exchange.NewState()
	fresh.OperatorKey = state.OperatorKey

	// Replay the identical, unchanged log three times in a row — the
	// rebuildAndDispatchGapLocal hot path.
	for i := 1; i <= 3; i++ {
		fresh.Replay(repriceMsgs)
		recs := fresh.Reprices("replay-twice-entry")
		if len(recs) != 1 {
			t.Fatalf("after Replay #%d: got %d reprice events, want exactly 1 (repriceEvents/repriceCounted must reset TOGETHER in beginReplayLocked)", i, len(recs))
		}
		if recs[0].OldPrice != wantOld {
			t.Errorf("after Replay #%d: OldPrice = %d, want %d", i, recs[0].OldPrice, wantOld)
		}
		got := fresh.RollbackReprice(exchange.RepriceRulingRef96e)
		if got["replay-twice-entry"] != wantOld {
			t.Errorf("after Replay #%d: RollbackReprice(96e) = %d, want %d", i, got["replay-twice-entry"], wantOld)
		}
	}
}

// TestReprice_PutPriceZeroUsesTokenCostFallback exercises legacyComputePrice's
// ELSE branch (finding 5): repriceFixtureEntry always sets PutPrice>0, so the
// `if entry.PutPrice > 0` branch is the only one any other test in this file
// ever reaches. A put that has no put-accept price recorded yet has
// PutPrice==0, and legacyComputePrice must fall back to
// TokenCost*sellerShareFactor (0.7), NOT the PutPrice*1.2 formula.
func TestReprice_PutPriceZeroUsesTokenCostFallback(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	const tokenCost = int64(8000)
	entry := repriceFixtureEntryWithSignals("putprice-zero-entry", tokenCost, 0, 0, 0, "")
	state.InjectInventoryEntryForTest(entry)

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}

	recs := state.Reprices("putprice-zero-entry")
	if len(recs) != 1 {
		t.Fatalf("got %d reprice events, want 1", len(recs))
	}

	// Independently computed: base = TokenCost * 0.7 (sellerShareFactor), no
	// operatorMargin (that only applies when PutPrice > 0). All other signal
	// factors are 1.0 by fixture construction, so this is the base alone.
	wantOld := tokenCost * 70 / 100
	if recs[0].OldPrice != wantOld {
		t.Errorf("OldPrice = %d, want %d (TokenCost fallback branch, sellerShareFactor=0.7)", recs[0].OldPrice, wantOld)
	}
	// This must NOT equal what the PutPrice>0 branch would have produced for
	// the same tokenCost — proving the fallback branch actually ran, rather
	// than the operatorMargin branch coincidentally producing the same number.
	if wrongBranch := expectedLegacyPrice(tokenCost); recs[0].OldPrice == wrongBranch {
		t.Fatalf("OldPrice = %d matches the operatorMargin branch's output for the same tokenCost — the two branches are indistinguishable with these numbers; fix the fixture", recs[0].OldPrice)
	}
}

// TestReprice_NonDegenerateAgeSizeTierSignalsAffectOldPrice exercises the
// age/size/tier factors legacyComputePrice shares with computePrice (finding
// 5): repriceFixtureEntry always zeroes ContentSize/PutTimestamp and leaves
// CompressionTier unset, so ageFactor/sizeFactor/tierFactor are ALWAYS 1.0 in
// every other test in this file — a mutation that broke any one of those
// three factor computations INSIDE legacyComputePrice specifically (as
// opposed to computePrice, which compute_price_test.go covers separately for
// the same helpers) would not be caught here. This entry sets all three to
// non-degenerate, independently-computed values simultaneously.
func TestReprice_NonDegenerateAgeSizeTierSignalsAffectOldPrice(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	const tokenCost = int64(100000)
	const putPrice = int64(70000) // tokenCost * 70 / 100, exact
	entry := repriceFixtureEntryWithSignals(
		"signals-entry", tokenCost, putPrice,
		90*24*time.Hour, // > 60-day window -> ageFactor = 0.5 (floor)
		102400,          // 100 KB -> sizeFactor = 1.30 (cap)
		"hot",           // -> tierFactor = 1.5
	)
	state.InjectInventoryEntryForTest(entry)

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}

	recs := state.Reprices("signals-entry")
	if len(recs) != 1 {
		t.Fatalf("got %d reprice events, want 1", len(recs))
	}

	// Independently computed (no exchange package internals called):
	//   base = putPrice * 1.2 = 84000
	//   * ageFactor 0.5  (floor — entry is 90 days old, past the 60-day window)
	//   * sizeFactor 1.30 (100KB is exactly at the size-bonus cap)
	//   * tierFactor 1.5  (hot)
	// = 84000 * 0.5 * 1.30 * 1.5 = 81900, exact (no rounding ambiguity — the
	// same size-factor composition is independently pinned to an exact
	// integer by TestComputePrice_ContentSize_LargerContentHigherPrice).
	const wantOld = int64(81900)
	if recs[0].OldPrice != wantOld {
		t.Errorf("OldPrice = %d, want %d (age=0.5 * size=1.30 * tier=1.5 applied to legacyComputePrice)", recs[0].OldPrice, wantOld)
	}

	// Sanity: this must differ from the fully-neutral fixture's price for the
	// same tokenCost/putPrice, proving the signals actually moved the number.
	if neutral := expectedLegacyPrice(tokenCost); recs[0].OldPrice == neutral {
		t.Fatalf("OldPrice = %d equals the fully-neutral fixture's price %d — age/size/tier signals had no effect", recs[0].OldPrice, neutral)
	}
}

// TestReprice_ResidualMathOnAlreadySoldCopyIsReconstructible is dontguess-b2b's
// third mandatory mitigation — "residual math on any already-sold copy must
// be reconstructible" — which previously had NO test at all (finding 7). It
// runs a REAL completed sale through the full settle pipeline (put -> accept
// -> buy -> match -> buyer-accept -> deliver -> complete), producing a
// genuine PriceRecord in state.PriceHistory(). It THEN reprices the SAME
// (already-sold) entry under the dontguess-96e ruling and proves:
//
//  1. The settled sale's PriceRecord is completely UNTOUCHED by the reprice
//     event — EmitReprice never writes to priceHistory, only to the
//     independent repriceEvents log.
//  2. The residual actually owed on that already-sold copy — computed via
//     the SAME real settlement formula performScripSettlement uses
//     (ExchangeRevenueForTest, which wraps residualDenominatorFor) — is
//     therefore STILL exactly reconstructible from the untouched
//     PriceRecord alone, regardless of the later reprice.
//  3. The reprice event's Timestamp is observably AFTER the sale's
//     PriceRecord.Timestamp, so replaying the combined log lets an auditor
//     determine that THIS sale settled under the PRE-ruling price regime.
func TestReprice_ResidualMathOnAlreadySoldCopyIsReconstructible(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	matchMsg, entryID := setupMatchedOrder(t, h, eng)

	buyerAcceptMsg := h.sendMessage(h.buyer, buyerAcceptPayloadFor(entryID),
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchMsg.ID},
	)
	deliverMsg := h.sendMessage(h.operator, deliverPayloadFor(entryID),
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver,
		},
		[]string{buyerAcceptMsg.ID},
	)
	const salePrice = int64(4200)
	h.sendMessage(h.buyer, completePayloadFor(entryID, salePrice),
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{deliverMsg.ID},
	)

	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	before := eng.State().PriceHistory()
	if len(before) != 1 {
		t.Fatalf("setup: price history = %d records, want 1", len(before))
	}
	sold := before[0]
	if sold.EntryID != entryID || sold.SalePrice != salePrice {
		t.Fatalf("setup: unexpected price record %+v", sold)
	}

	soldEntry := eng.State().GetInventoryEntry(entryID)
	if soldEntry == nil {
		t.Fatalf("setup: entry %s not found in inventory", entryID)
	}
	// Residual = SalePrice - ExchangeRevenueForTest(SalePrice, entry) — the
	// same real settlement math performScripSettlement uses.
	preRepriceResidual := sold.SalePrice - exchange.ExchangeRevenueForTest(sold.SalePrice, soldEntry)

	// Now reprice the SAME (already-sold) entry under the ruling.
	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}

	after := eng.State().PriceHistory()
	if len(after) != 1 {
		t.Fatalf("price history after reprice = %d records, want 1 (reprice must never touch priceHistory)", len(after))
	}
	if after[0].EntryID != sold.EntryID || after[0].SalePrice != sold.SalePrice ||
		after[0].PutPrice != sold.PutPrice || after[0].Timestamp != sold.Timestamp {
		t.Errorf("price record mutated by reprice: before=%+v after=%+v", sold, after[0])
	}

	postRepriceResidual := after[0].SalePrice - exchange.ExchangeRevenueForTest(after[0].SalePrice, eng.State().GetInventoryEntry(entryID))
	if postRepriceResidual != preRepriceResidual {
		t.Errorf("residual on the already-sold copy changed after reprice: before=%d after=%d — not reconstructible", preRepriceResidual, postRepriceResidual)
	}

	recs := eng.State().Reprices(entryID)
	if len(recs) != 1 {
		t.Fatalf("expected exactly 1 reprice event for the entry, got %d", len(recs))
	}
	if recs[0].Timestamp <= sold.Timestamp {
		t.Errorf("reprice event Timestamp=%d is not after the sale's PriceRecord Timestamp=%d — cannot reconstruct that this sale settled under the pre-ruling regime", recs[0].Timestamp, sold.Timestamp)
	}
}

// findMessagesForTest scans the engine's underlying campfire-free event log
// (EngineOptions.LocalStore) for messages carrying the given tag. Used to
// retrieve the actual reprice message(s) the engine appended, for
// dedup/replay tests that need to re-feed or re-Apply the real wire message
// rather than reconstructing one by hand.
func findMessagesForTest(t *testing.T, eng *exchange.Engine, tag string) []exchange.Message {
	t.Helper()
	ls := eng.LocalStore()
	if ls == nil {
		t.Fatalf("engine has no LocalStore configured")
	}
	recs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("LocalStore.ReadAll: %v", err)
	}
	msgs := exchange.FromStoreRecords(recs)
	var out []exchange.Message
	for _, m := range msgs {
		for _, tg := range m.Tags {
			if tg == tag {
				out = append(out, m)
				break
			}
		}
	}
	return out
}
