package exchange

// engine_relay_ingest_cursor_e2a3_test.go — deterministic ground-source proofs
// for dontguess-e2a3 (ratified Design A): the offloaded/relay-ingest cursor
// mis-attribution race.
//
// THE BUG. appendLocalRecord (operator egress) used to advance localSeen /
// localDispatched with a RELATIVE `++`, correct ONLY when localSeen == len(store)
// at append time. The TEAM/relay tier violates that: relay events are
// BatchAppend'd to the SAME LocalStore OUTSIDE localMu (pkg/relay/intake.go),
// growing len(store) without touching the cursor. So when an operator record was
// emitted while a relay buy sat un-folded at index == localSeen, the `++`
// mis-attributed the relay buy's slot — the relay buy was marked folded+dispatched
// without ever reaching handleBuy (HARM 1: a permanently-skipped match — the 7ae3
// confidentiality flaky), and the operator record beyond localSeen was re-folded
// (HARM 2: a double-processed operator record — the scrip double-burn class).
//
// THE FIX (Design A). appendLocalRecord no longer advances the cursors; the
// absolute poll/rebuild/replay paths fold EVERY record in physical order and SKIP
// dispatch for operator-self-applied records (Sender == OperatorKey,
// dispatchLocalGap). The skip is a pure function of the log, so it survives a
// process restart with no in-memory suppress-set.
//
// These tests drive the REAL, unmodified fold/dispatch path (pollLocalStore /
// replayAllLocal / foldAndDispatchLocalSnapshot) with no goroutines, no timing,
// and no mocks — the exact interleave the bug requires, expressed as an explicit
// call sequence.

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// hasTagE2A3 reports whether tags contains tag (local to package exchange; the
// exchange_test hasTag lives in the external test package and is not visible here).
func hasTagE2A3(tags []string, tag string) bool {
	for _, tg := range tags {
		if tg == tag {
			return true
		}
	}
	return false
}

// countMatchesForBuy returns how many exchange:match records on the log carry
// buyID as their first antecedent — i.e. how many times handleBuy dispatched
// that buy and emitted a match. Exactly 1 == dispatched exactly once.
func countMatchesForBuy(t *testing.T, ls *dgstore.Store, buyID string) int {
	t.Helper()
	all, err := ls.Replay()
	if err != nil {
		t.Fatalf("replay for match count: %v", err)
	}
	n := 0
	for i := range all {
		if !hasTagE2A3(all[i].Tags, TagMatch) {
			continue
		}
		if len(all[i].Antecedents) > 0 && all[i].Antecedents[0] == buyID {
			n++
		}
	}
	return n
}

// countConsumeRecords returns how many exchange:consume records for entryID are
// on the log (durable cross-check that only one was ever emitted).
func countConsumeRecords(t *testing.T, ls *dgstore.Store, entryID string) int {
	t.Helper()
	all, err := ls.Replay()
	if err != nil {
		t.Fatalf("replay for consume count: %v", err)
	}
	n := 0
	for i := range all {
		if !hasTagE2A3(all[i].Tags, TagConsume) {
			continue
		}
		var p struct {
			EntryID string `json:"entry_id"`
		}
		if json.Unmarshal(all[i].Payload, &p) == nil && p.EntryID == entryID {
			n++
		}
	}
	return n
}

// seedMatchableEntry appends a put and auto-accepts it, returning the accepted
// entry ID and its seller key. After it returns, a poll has NOT necessarily run;
// callers poll to bring the cursors fully current.
func seedMatchableEntry(t *testing.T, eng *Engine, ls *dgstore.Store, desc string) (entryID, seller string) {
	t.Helper()
	seller = newReservationID()
	putID := newReservationID()
	if err := ls.Append(dgstore.Record{
		ID:         putID,
		CampfireID: "local",
		Sender:     seller,
		Payload:    localBuyDropPutPayload(t, desc, 8000),
		Tags:       []string{TagPut, "exchange:content-type:code", "exchange:domain:go"},
		Timestamp:  time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("append put: %v", err)
	}
	if err := eng.AutoAcceptPut(putID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	for _, e := range eng.State().Inventory() {
		if e.PutMsgID == putID {
			return e.EntryID, seller
		}
	}
	t.Fatalf("seeded put %s not in inventory after accept", putID)
	return "", ""
}

// TestRelayBuyDispatchedExactlyOnce_OperatorEmitInterleave_e2a3 is ground-source
// (b): it forces the EXACT bug interleave — a relay buy BatchAppend'd at
// index == localSeen, then an operator record emitted while that buy is still
// un-folded, then a poll — and asserts:
//
//   - the relay buy DISPATCHES EXACTLY ONCE (handleBuy ran → exactly one match
//     record, and State marks the order matched) — HARM 1 fixed; and
//   - the operator record FOLDS EXACTLY ONCE (no double-count) — HARM 2 fixed.
//
// The operator record used is an exchange:consume, an operator-self-applied
// record whose fold effect (entryConsumeCount) is DIRECTLY OBSERVABLE — the same
// operator-egress cursor path a scrip-burn takes, but with a State-visible
// accumulator (scrip-burn's fold is a State no-op, so it cannot be observed via
// State; the consume accumulator is its faithful "processed exactly once" proxy,
// exactly as fold_double_apply_f86_test.go uses DeliverCount).
//
// Pre-fix the operator emit's relative `++` mis-attributes the relay buy's slot:
// the buy is never dispatched (IsOrderMatched == false, zero match records) — this
// test fails. Post-fix both invariants hold.
func TestRelayBuyDispatchedExactlyOnce_OperatorEmitInterleave_e2a3(t *testing.T) {
	dir := t.TempDir()
	ls, err := dgstore.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	t.Cleanup(func() { ls.Close() }) //nolint:errcheck

	operatorKey := newReservationID()
	eng := NewEngine(EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: operatorKey,
		PollInterval:      time.Hour, // folds are driven explicitly below
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})
	if err := eng.replayAll(); err != nil {
		t.Fatalf("initial replayAll: %v", err)
	}

	entryID, _ := seedMatchableEntry(t, eng, ls, "Go HTTP handler unit test generator")

	// Bring both cursors fully current so the next relay append lands EXACTLY at
	// index == localSeen (the precise slot the bug requires).
	if err := eng.pollLocalStore(); err != nil {
		t.Fatalf("sync poll: %v", err)
	}
	all, err := ls.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	L := len(all)
	if got := eng.LocalSeenForTest(); got != L {
		t.Fatalf("precondition: localSeen = %d, want len(store) = %d", got, L)
	}
	if got := eng.LocalDispatchedForTest(); got != L {
		t.Fatalf("precondition: localDispatched = %d, want len(store) = %d", got, L)
	}

	// (1) RELAY BatchAppend a buy at index == localSeen — the exact intake path
	// (pkg/relay/intake.go BatchAppend, Origin="relay"), which does NOT touch the
	// engine cursor. The buy task matches the seeded entry so handleBuy emits a
	// match we can observe.
	relayBuyID := newReservationID()
	buyer := newReservationID()
	if err := ls.BatchAppend([]dgstore.Record{{
		ID:         relayBuyID,
		CampfireID: "local",
		Sender:     buyer,
		Payload:    localBuyDropBuyPayload(t, "Generate unit tests for a Go HTTP handler", 50000),
		Tags:       []string{TagBuy},
		Timestamp:  time.Now().UnixNano(),
		Origin:     "relay",
	}}); err != nil {
		t.Fatalf("relay BatchAppend buy: %v", err)
	}
	if got := eng.LocalSeenForTest(); got != L {
		t.Fatalf("relay BatchAppend must NOT advance the fold cursor: localSeen = %d, want %d", got, L)
	}

	// (2) The operator emits a record (exchange:consume) while the relay buy sits
	// un-folded at index L. This is the append that, pre-fix, mis-attributed the
	// buy's slot via the relative `++`. The emitter applies it to State directly
	// (mirroring emitConsumeSignal's trailing state.Apply).
	consumePayload, _ := json.Marshal(map[string]any{"entry_id": entryID})
	consumeMsg, err := eng.sendLocalOperatorMessage(consumePayload, []string{TagConsume}, nil)
	if err != nil {
		t.Fatalf("operator emit consume: %v", err)
	}
	eng.state.Apply(consumeMsg)

	// (3) Poll: fold [L:L+2] (buy + consume, consume idempotently deduped) and
	// dispatch [L:L+2] skipping the operator consume.
	if err := eng.pollLocalStore(); err != nil {
		t.Fatalf("poll after interleave: %v", err)
	}

	// --- HARM 1: the relay buy was dispatched EXACTLY once. ---
	if !eng.State().IsOrderMatched(relayBuyID) {
		t.Fatalf("relay buy %s was never dispatched — handleBuy did not run "+
			"(dontguess-e2a3 HARM 1: the operator emit's relative `++` mis-attributed the "+
			"un-folded relay buy's slot, permanently skipping it)", relayBuyID[:8])
	}
	if n := countMatchesForBuy(t, ls, relayBuyID); n != 1 {
		t.Fatalf("relay buy has %d match records, want exactly 1 (dispatched-exactly-once)", n)
	}

	// --- HARM 2: the operator record folded EXACTLY once (no double-count). ---
	if cc := eng.State().AllEntryBehavioralSignals()[entryID].ConsumeCount; cc != 1 {
		t.Fatalf("entry %s ConsumeCount = %d, want exactly 1 — the operator consume was "+
			"double-folded (the scrip double-burn class, dontguess-e2a3 HARM 2)", entryID, cc)
	}
	if n := countConsumeRecords(t, ls, entryID); n != 1 {
		t.Fatalf("found %d durable consume records for entry %s, want exactly 1", n, entryID)
	}

	// --- Cursor consistency: a quiescent poll leaves fold == dispatch == len. ---
	if err := eng.pollLocalStore(); err != nil {
		t.Fatalf("quiescent poll: %v", err)
	}
	final, _ := ls.Replay()
	if s, d := eng.LocalSeenForTest(), eng.LocalDispatchedForTest(); s != len(final) || d != len(final) {
		t.Fatalf("cursors not caught up: localSeen=%d localDispatched=%d len(store)=%d", s, d, len(final))
	}
}

// TestOperatorSkipSurvivesRestart_e2a3 is ground-source (c): the operator-self
// dispatch-skip is derived from the LOG (Sender == OperatorKey), so it holds
// across a full replayAllLocal on a FRESH engine that never saw the original
// emits — no in-memory suppress-set. It proves:
//
//   - replaying a log containing operator records folds each EXACTLY once and
//     RE-dispatches none of them (no duplicate match, no double consume); and
//   - after the restart, a NEWLY appended operator record is still skipped and a
//     NEWLY appended member buy is still dispatched — the skip decision needs
//     nothing but the record's Sender.
func TestOperatorSkipSurvivesRestart_e2a3(t *testing.T) {
	dir := t.TempDir()
	ls, err := dgstore.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	t.Cleanup(func() { ls.Close() }) //nolint:errcheck

	operatorKey := newReservationID()

	// --- Engine 1: build a log with a matched member buy + an operator consume. ---
	eng1 := NewEngine(EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: operatorKey,
		PollInterval:      time.Hour,
		Logger:            func(format string, args ...any) { t.Logf("[eng1] "+format, args...) },
	})
	if err := eng1.replayAll(); err != nil {
		t.Fatalf("eng1 replayAll: %v", err)
	}
	entryID, _ := seedMatchableEntry(t, eng1, ls, "Go HTTP handler unit test generator")
	if err := eng1.pollLocalStore(); err != nil {
		t.Fatalf("eng1 sync poll: %v", err)
	}

	buyID := newReservationID()
	buyer := newReservationID()
	if err := ls.Append(dgstore.Record{
		ID:         buyID,
		CampfireID: "local",
		Sender:     buyer,
		Payload:    localBuyDropBuyPayload(t, "Generate unit tests for a Go HTTP handler", 50000),
		Tags:       []string{TagBuy},
		Timestamp:  time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("append buy: %v", err)
	}
	consumePayload, _ := json.Marshal(map[string]any{"entry_id": entryID})
	cMsg, err := eng1.sendLocalOperatorMessage(consumePayload, []string{TagConsume}, nil)
	if err != nil {
		t.Fatalf("eng1 operator consume: %v", err)
	}
	eng1.state.Apply(cMsg)
	if err := eng1.pollLocalStore(); err != nil {
		t.Fatalf("eng1 poll: %v", err)
	}
	if !eng1.State().IsOrderMatched(buyID) {
		t.Fatalf("precondition: buy not matched on eng1")
	}
	matchesBeforeRestart := countMatchesForBuy(t, ls, buyID)
	if matchesBeforeRestart != 1 {
		t.Fatalf("precondition: %d match records before restart, want 1", matchesBeforeRestart)
	}

	// --- Engine 2: a FRESH engine replays the SAME log (process restart). ---
	eng2 := NewEngine(EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: operatorKey,
		PollInterval:      time.Hour,
		Logger:            func(format string, args ...any) { t.Logf("[eng2] "+format, args...) },
	})
	// StartupReplayForTest = the exact synchronous startup body of Start: replay
	// the full log (folding every operator record), seed localDispatched=localSeen,
	// then dispatchPendingOrders (active-but-unmatched buys only).
	if err := eng2.StartupReplayForTest(); err != nil {
		t.Fatalf("eng2 StartupReplayForTest: %v", err)
	}

	// The operator consume folded EXACTLY once during replay (guards reset then
	// repopulate in log order) — not doubled.
	if cc := eng2.State().AllEntryBehavioralSignals()[entryID].ConsumeCount; cc != 1 {
		t.Fatalf("after restart replay, ConsumeCount = %d, want 1 (operator record folded exactly once)", cc)
	}
	// The already-matched buy was NOT re-dispatched (it is not an active order, and
	// the operator match record is never dispatched) — no duplicate match emitted.
	if n := countMatchesForBuy(t, ls, buyID); n != matchesBeforeRestart {
		t.Fatalf("restart re-dispatched an operator/settled record: match count %d → %d", matchesBeforeRestart, n)
	}

	// --- Post-restart LIVE: the Sender-derived skip still holds with no state. ---
	// A new operator consume (must be skipped at dispatch) and a new member buy
	// (must be dispatched) are appended and polled on the FRESH engine, which never
	// observed eng1's emits.
	newBuyID := newReservationID()
	if err := ls.BatchAppend([]dgstore.Record{{
		ID:         newBuyID,
		CampfireID: "local",
		Sender:     newReservationID(),
		Payload:    localBuyDropBuyPayload(t, "Generate unit tests for a Go HTTP handler", 50000),
		Tags:       []string{TagBuy},
		Timestamp:  time.Now().UnixNano(),
		Origin:     "relay",
	}}); err != nil {
		t.Fatalf("post-restart relay buy: %v", err)
	}
	newConsumePayload, _ := json.Marshal(map[string]any{"entry_id": entryID})
	ncMsg, err := eng2.sendLocalOperatorMessage(newConsumePayload, []string{TagConsume}, nil)
	if err != nil {
		t.Fatalf("eng2 operator consume: %v", err)
	}
	eng2.state.Apply(ncMsg)
	if err := eng2.pollLocalStore(); err != nil {
		t.Fatalf("eng2 post-restart poll: %v", err)
	}

	if !eng2.State().IsOrderMatched(newBuyID) {
		t.Fatalf("post-restart member buy %s was not dispatched — Sender-derived skip mis-classified it", newBuyID[:8])
	}
	if n := countMatchesForBuy(t, ls, newBuyID); n != 1 {
		t.Fatalf("post-restart buy has %d match records, want exactly 1", n)
	}
	// The second consume folds once more (distinct message ID) → total 2 records,
	// ConsumeCount == 2; the point is it was FOLDED (not double), and NOT dispatched.
	if cc := eng2.State().AllEntryBehavioralSignals()[entryID].ConsumeCount; cc != 2 {
		t.Fatalf("after second consume, ConsumeCount = %d, want 2 (each distinct consume folded exactly once)", cc)
	}
}
