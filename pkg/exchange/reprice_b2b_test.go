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

// TestReprice_RollbackRecoversExactPreRulingPricesFromEventLogAlone is the
// item's REQUIRED mutation-verified test: roll the repricing back FROM THE
// EVENT LOG ALONE and recover the pre-ruling prices EXACTLY.
//
// It deliberately reprices the SAME entry a second time under a DIFFERENT
// ruling ref with DIFFERENT (wrong-looking) old/new prices, simulating a
// later re-interpretation. RollbackReprice must still return the FIRST
// (true, original) pre-ruling price, not the second event's — this is what
// actually exercises "from the event log alone" rather than trivially
// checking self-consistency of a single write. A rollback implementation
// that (bug) picks the LATEST record instead of the OLDEST, or that
// (bug) returns NewPrice instead of OldPrice, fails this test.
func TestReprice_RollbackRecoversExactPreRulingPricesFromEventLogAlone(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	entries := []*exchange.InventoryEntry{
		repriceFixtureEntry("roll-a", 8000),
		repriceFixtureEntry("roll-b", 140000),
	}
	for _, e := range entries {
		state.InjectInventoryEntryForTest(e)
	}

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}

	// True, original pre-ruling prices, computed independently of the engine's
	// internal formula (same fixture math as expectedLegacyPrice above).
	wantPreRuling := map[string]int64{
		"roll-a": expectedLegacyPrice(8000),
		"roll-b": expectedLegacyPrice(140000),
	}

	// Simulate a LATER, DIFFERENT re-interpretation event for roll-a only,
	// under a different ruling ref, with prices that must NOT be mistaken for
	// the true original pre-ruling price.
	if _, err := eng.EmitReprice("roll-a", 424242, 1, "later re-interpretation, unrelated", "dontguess-later-ruling"); err != nil {
		t.Fatalf("EmitReprice (second event): %v", err)
	}
	if got := len(state.Reprices("roll-a")); got != 2 {
		t.Fatalf("roll-a: got %d reprice events, want 2 (original + later)", got)
	}

	got := state.RollbackReprice()
	for entryID, want := range wantPreRuling {
		if got[entryID] != want {
			t.Errorf("RollbackReprice()[%s] = %d, want %d (the TRUE original pre-ruling price, not a later re-interpretation's value)", entryID, got[entryID], want)
		}
	}
	// roll-b was only ever repriced once — sanity check the map has no stray
	// entries and the single-event case behaves identically to the multi-event one.
	if len(got) != 2 {
		t.Fatalf("RollbackReprice() returned %d entries, want 2", len(got))
	}
}

// TestReprice_RollbackFromBareReplayNoLiveState proves the "event log alone"
// property literally: build the raw message log (put-accept-equivalent
// inventory injection is NOT log-derived, so this test drives the reprice
// event purely through Apply/Replay of messages — a fresh State object with
// zero prior in-memory data must reconstruct the exact same rollback map by
// replaying nothing but the message log).
func TestReprice_RollbackFromBareReplayNoLiveState(t *testing.T) {
	t.Parallel()
	eng := newMinimalEngine(t)
	state := eng.State()

	entry := repriceFixtureEntry("replay-entry", 60000)
	state.InjectInventoryEntryForTest(entry)

	if _, err := eng.RepriceInventoryForRuling(exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit); err != nil {
		t.Fatalf("RepriceInventoryForRuling: %v", err)
	}
	want := state.RollbackReprice()
	if want["replay-entry"] == 0 {
		t.Fatalf("setup failed: no reprice recorded for replay-entry")
	}

	repriceMsgs := findMessagesForTest(t, eng, exchange.TagReprice)
	if len(repriceMsgs) != 1 {
		t.Fatalf("expected 1 reprice message on the log, got %d", len(repriceMsgs))
	}

	// Fresh State, built from NOTHING but the reprice message — no
	// InjectInventoryEntryForTest, no engine, no prior Apply calls.
	fresh := exchange.NewState()
	fresh.OperatorKey = repriceMsgs[0].Sender
	fresh.Replay(repriceMsgs)

	got := fresh.RollbackReprice()
	if got["replay-entry"] != want["replay-entry"] {
		t.Errorf("bare-Replay RollbackReprice()[replay-entry] = %d, want %d (recovered from event log alone)", got["replay-entry"], want["replay-entry"])
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
