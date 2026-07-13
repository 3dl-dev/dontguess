package exchange_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// TestConsumeSignal_ZeroAntecedents verifies that emitConsumeSignal returns an
// error (and does NOT panic) when the settle:complete message has no antecedents.
//
// After fe7, emitConsumeSignal calls state.Apply on the emitted consume message.
// A zero-antecedent complete must fail before reaching sendOperatorMessage so
// that entryConsumeCount is NOT incremented and AllEntryBehavioralSignals is
// not corrupted.
//
// Real path: real engine (DispatchForTest), real campfire fs transport, real state.
// No mocks of the path under test.
func TestConsumeSignal_ZeroAntecedents(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	// Seed one inventory entry (not strictly needed for the error path, but keeps
	// the harness alive and ensures no nil-pointer surprises in dispatch).
	putMsg := h.sendMessage(h.seller,
		putPayload("Go flock contention error path test", "sha256:"+fmt.Sprintf("%064x", 4001), "code", 10000, 20000),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	if err := eng.AutoAcceptPut(putMsg.ID, 7000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	// Record consume count before dispatch.
	sigsBefore := eng.State().AllEntryBehavioralSignals()
	consumeCountBefore := 0
	for _, sig := range sigsBefore {
		consumeCountBefore += sig.ConsumeCount
	}

	// Build a settle:complete message with EMPTY antecedents.
	// emitConsumeSignal must return an error for this message.
	completePayload, _ := json.Marshal(map[string]any{
		"phase": exchange.SettlePhaseStrComplete,
	})
	noAntecedentComplete := h.sendMessage(h.buyer, completePayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete,
		},
		nil, // empty antecedents — the broken case
	)

	// Replay state so the complete message is visible.
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	// dispatch must NOT panic. The engine logs the emitConsumeSignal error but
	// swallows it (best-effort). DispatchForTest returns nil (the outer
	// handleSettle returns nil after logging; it does not propagate the error).
	dispatchErr := eng.DispatchForTest(noAntecedentComplete)
	// No panic is the key assertion. Return value is nil (engine swallows the
	// emitConsumeSignal error and proceeds).
	_ = dispatchErr // either nil or error; must not panic

	// entryConsumeCount must be UNCHANGED — no consume signal must have been emitted.
	sigsAfter := eng.State().AllEntryBehavioralSignals()
	consumeCountAfter := 0
	for _, sig := range sigsAfter {
		consumeCountAfter += sig.ConsumeCount
	}
	if consumeCountAfter != consumeCountBefore {
		t.Errorf("entryConsumeCount changed after zero-antecedent complete: before=%d after=%d; consume signal must NOT be emitted on broken chain",
			consumeCountBefore, consumeCountAfter)
	}
}

// TestConsumeSignal_BrokenDeliverMatchChain verifies that emitConsumeSignal
// returns an error (and does NOT panic) when the antecedent chain is broken:
// the complete message references a deliver message ID that has no corresponding
// match chain in state (deliverToMatch lookup fails).
//
// This exercises the second error branch in emitConsumeSignal:
//
//	deliverMsgID := completeMsg.Antecedents[0]
//	settledEntry, ok := e.state.EntryForDeliver(deliverMsgID)
//	if !ok { return error }
//
// Assertions:
//   - No panic.
//   - entryConsumeCount unchanged (no consume signal emitted).
//   - AllEntryBehavioralSignals not corrupted.
func TestConsumeSignal_BrokenDeliverMatchChain(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	// Seed inventory so the engine has a real entry to reference.
	putMsg := h.sendMessage(h.seller,
		putPayload("broken chain consume signal test entry", "sha256:"+fmt.Sprintf("%064x", 4002), "code", 12000, 24000),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	if err := eng.AutoAcceptPut(putMsg.ID, 8400, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	inv := eng.State().Inventory()
	if len(inv) == 0 {
		t.Fatal("expected inventory entry after auto-accept")
	}

	// Record signals before dispatch.
	sigsBefore := eng.State().AllEntryBehavioralSignals()
	consumeCountBefore := 0
	for _, sig := range sigsBefore {
		consumeCountBefore += sig.ConsumeCount
	}

	// Build a deliver message with a fake ID — NOT wired into the state chain.
	// This means deliverToMatch[fakeDeliverID] will be empty → EntryForDeliver fails.
	fakeDeliverID := "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

	// Build a settle:complete that points at the fake deliver ID.
	completePayload, _ := json.Marshal(map[string]any{
		"phase": exchange.SettlePhaseStrComplete,
	})
	// The buyer antecedent must reference a non-empty, non-existing deliver.
	brokenChainComplete := h.sendMessage(h.buyer, completePayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrComplete,
		},
		[]string{fakeDeliverID}, // deliver ID not in state → broken chain
	)

	// Replay state (no chain maps populated for fakeDeliverID).
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	// Must NOT panic. The engine logs the error and swallows it.
	dispatchErr := eng.DispatchForTest(brokenChainComplete)
	_ = dispatchErr // must not panic; return value is nil (swallowed)

	// entryConsumeCount must be unchanged.
	sigsAfter := eng.State().AllEntryBehavioralSignals()
	consumeCountAfter := 0
	for _, sig := range sigsAfter {
		consumeCountAfter += sig.ConsumeCount
	}
	if consumeCountAfter != consumeCountBefore {
		t.Errorf("entryConsumeCount changed after broken-chain complete: before=%d after=%d; no consume signal must be emitted",
			consumeCountBefore, consumeCountAfter)
	}

	// AllEntryBehavioralSignals must not be corrupted: if it was non-empty before
	// it must remain structurally identical (same entry keys).
	for entryID, beforeSig := range sigsBefore {
		afterSig, ok := sigsAfter[entryID]
		if !ok {
			t.Errorf("entry %s disappeared from AllEntryBehavioralSignals after broken-chain dispatch", entryID)
			continue
		}
		if beforeSig.ConsumeCount != afterSig.ConsumeCount {
			t.Errorf("entry %s ConsumeCount changed: %d → %d", entryID, beforeSig.ConsumeCount, afterSig.ConsumeCount)
		}
		if beforeSig.DeliverCount != afterSig.DeliverCount {
			t.Errorf("entry %s DeliverCount changed: %d → %d", entryID, beforeSig.DeliverCount, afterSig.DeliverCount)
		}
	}
}
