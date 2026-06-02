package exchange

// TestFullReplay_DeliverAndConsumeCountsMatchApply verifies that calling
// Replay(msgs) on a synthetic message log with a full chain:
//
//	exchange:match → exchange:settle/buyer-accept → exchange:settle/deliver
//	→ exchange:consume
//
// produces identical entryDeliverCount[X] and entryConsumeCount[X] values
// as incremental Apply calls processing the same messages in order.
//
// This closes dontguess-2f4 (full-log Replay for deliver + consume counts).
//
// White-box test (package exchange) — accesses unexported state maps following
// the established pattern in false_positive_signals_test.go / behavioral_signals_test.go.
//
// Real paths tested:
//   - applyMatch (populates matchToBuyer, matchToEntry, matchedOrders)
//   - applySettleBuyerAccept (populates buyerAcceptToMatch)
//   - applySettleDeliver (populates deliverToMatch, increments entryDeliverCount)
//   - applyConsume (increments entryConsumeCount)
//   - Replay (resets all maps and replays from scratch)
//
// No mocks — same code path as production.

import (
	"encoding/json"
	"testing"
	"time"
)

// buildReplayChain constructs a minimal but complete message chain for Replay testing.
//
// Chain for one entry X with two deliveries and one consume:
//  1. exchange:put for entry X (seed put so inventory entry exists)
//  2. exchange:settle/put-accept (makes entry live in inventory)
//  3. exchange:buy (creates an active order)
//  4. exchange:match (references buy, carries entry_id X in results payload)
//  5. exchange:settle/buyer-accept (references match)
//  6. exchange:settle/deliver (references buyer-accept, increments entryDeliverCount)
//  7. exchange:buy #2 (second order)
//  8. exchange:match #2 (references buy #2, same entry X)
//  9. exchange:settle/buyer-accept #2
// 10. exchange:settle/deliver #2 (second delivery, increments entryDeliverCount again)
// 11. exchange:consume (references entry X, increments entryConsumeCount)
//
// Returns the slice of messages (in order) ready for Replay, plus:
//   - entryID (the entry being tracked)
//   - operatorKey (set on State.OperatorKey to pass sender gates)
//   - buyerKey (used as Sender on buyer messages)
type replayChainResult struct {
	msgs      []Message
	entryID   string
	operatorKey string
	buyerKey  string
}

func buildReplayChain() replayChainResult {
	const operatorKey = "replay-operator-key-0001"
	const sellerKey  = "replay-seller-key-0001"
	const buyerKey   = "replay-buyer-key-0001"

	ts := time.Now().UnixNano()
	tick := func() int64 {
		ts += 1000
		return ts
	}

	// Build unique IDs.
	putMsgID       := "replay-put-0000000000000001"
	putAcceptMsgID := "replay-putaccept-000000001"
	entryID        := putMsgID // convention: entryID == putMsgID
	buyMsgID1      := "replay-buy-0000000000000001"
	matchMsgID1    := "replay-match-000000000000001"
	baAcceptMsgID1 := "replay-ba-0000000000000001"
	deliverMsgID1  := "replay-deliver-000000000001"
	buyMsgID2      := "replay-buy-0000000000000002"
	matchMsgID2    := "replay-match-000000000000002"
	baAcceptMsgID2 := "replay-ba-0000000000000002"
	deliverMsgID2  := "replay-deliver-000000000002"
	consumeMsgID1  := "replay-consume-000000000001"

	// 1. exchange:put
	putPayloadBytes, _ := json.Marshal(map[string]any{
		"description":  "Go flock contention test pattern — full replay fixture",
		"content":      "dGVzdA==", // base64("test") — minimal valid content
		"token_cost":   int64(1000),
		"content_type": "code",
		"domains":      []string{"go"},
	})
	putMsg := Message{
		ID:        putMsgID,
		Sender:    sellerKey,
		Tags:      []string{TagPut, "exchange:content-type:code"},
		Payload:   putPayloadBytes,
		Timestamp: tick(),
	}

	// 2. exchange:settle/put-accept (makes the entry live in inventory)
	putAcceptPayloadBytes, _ := json.Marshal(map[string]any{
		"phase":    SettlePhaseStrPutAccept,
		"entry_id": entryID,
		"price":    int64(700),
	})
	putAcceptMsg := Message{
		ID:          putAcceptMsgID,
		Sender:      operatorKey,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrPutAccept, TagVerdictPrefix + "accepted"},
		Payload:     putAcceptPayloadBytes,
		Antecedents: []string{putMsgID},
		Timestamp:   tick(),
	}

	// 3. exchange:buy #1
	buyPayloadBytes1, _ := json.Marshal(map[string]any{
		"task":    "flock contention pattern Go",
		"budget":  int64(5000),
	})
	buyMsg1 := Message{
		ID:        buyMsgID1,
		Sender:    buyerKey,
		Tags:      []string{TagBuy},
		Payload:   buyPayloadBytes1,
		Timestamp: tick(),
	}

	// 4. exchange:match #1 (antecedent = buy #1; payload carries entry_id)
	matchPayloadBytes1, _ := json.Marshal(map[string]any{
		"results": []map[string]any{
			{"entry_id": entryID, "price": int64(700), "confidence": 0.85},
		},
	})
	matchMsg1 := Message{
		ID:          matchMsgID1,
		Sender:      operatorKey,
		Tags:        []string{TagMatch},
		Payload:     matchPayloadBytes1,
		Antecedents: []string{buyMsgID1},
		Timestamp:   tick(),
	}

	// 5. exchange:settle/buyer-accept #1 (antecedent = match #1)
	baPayload1, _ := json.Marshal(map[string]any{
		"phase":    SettlePhaseStrBuyerAccept,
		"entry_id": entryID,
		"accepted": true,
	})
	baMsg1 := Message{
		ID:          baAcceptMsgID1,
		Sender:      buyerKey,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrBuyerAccept, TagVerdictPrefix + "accepted"},
		Payload:     baPayload1,
		Antecedents: []string{matchMsgID1},
		Timestamp:   tick(),
	}

	// 6. exchange:settle/deliver #1 (antecedent = buyer-accept #1)
	deliverPayload1, _ := json.Marshal(map[string]any{
		"phase":    SettlePhaseStrDeliver,
		"entry_id": entryID,
	})
	deliverMsg1 := Message{
		ID:          deliverMsgID1,
		Sender:      operatorKey,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrDeliver},
		Payload:     deliverPayload1,
		Antecedents: []string{baAcceptMsgID1},
		Timestamp:   tick(),
	}

	// 7. exchange:buy #2
	buyPayloadBytes2, _ := json.Marshal(map[string]any{
		"task":   "contention flock go test pattern",
		"budget": int64(5000),
	})
	buyMsg2 := Message{
		ID:        buyMsgID2,
		Sender:    buyerKey,
		Tags:      []string{TagBuy},
		Payload:   buyPayloadBytes2,
		Timestamp: tick(),
	}

	// 8. exchange:match #2 (antecedent = buy #2; same entry_id)
	matchPayloadBytes2, _ := json.Marshal(map[string]any{
		"results": []map[string]any{
			{"entry_id": entryID, "price": int64(700), "confidence": 0.82},
		},
	})
	matchMsg2 := Message{
		ID:          matchMsgID2,
		Sender:      operatorKey,
		Tags:        []string{TagMatch},
		Payload:     matchPayloadBytes2,
		Antecedents: []string{buyMsgID2},
		Timestamp:   tick(),
	}

	// 9. exchange:settle/buyer-accept #2 (antecedent = match #2)
	baPayload2, _ := json.Marshal(map[string]any{
		"phase":    SettlePhaseStrBuyerAccept,
		"entry_id": entryID,
		"accepted": true,
	})
	baMsg2 := Message{
		ID:          baAcceptMsgID2,
		Sender:      buyerKey,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrBuyerAccept, TagVerdictPrefix + "accepted"},
		Payload:     baPayload2,
		Antecedents: []string{matchMsgID2},
		Timestamp:   tick(),
	}

	// 10. exchange:settle/deliver #2 (antecedent = buyer-accept #2)
	deliverPayload2, _ := json.Marshal(map[string]any{
		"phase":    SettlePhaseStrDeliver,
		"entry_id": entryID,
	})
	deliverMsg2 := Message{
		ID:          deliverMsgID2,
		Sender:      operatorKey,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrDeliver},
		Payload:     deliverPayload2,
		Antecedents: []string{baAcceptMsgID2},
		Timestamp:   tick(),
	}

	// 11. exchange:consume #1 (operator-emitted, entry_id derived from entry)
	consumePayload1, _ := json.Marshal(map[string]any{
		"entry_id":  entryID,
		"buyer_key": buyerKey,
	})
	consumeMsg1 := Message{
		ID:          consumeMsgID1,
		Sender:      operatorKey, // must be operator for applyConsume gate
		Tags:        []string{TagConsume},
		Payload:     consumePayload1,
		Antecedents: []string{deliverMsgID1}, // antecedent chain (informational)
		Timestamp:   tick(),
	}

	return replayChainResult{
		msgs: []Message{
			putMsg,
			putAcceptMsg,
			buyMsg1,
			matchMsg1,
			baMsg1,
			deliverMsg1,
			buyMsg2,
			matchMsg2,
			baMsg2,
			deliverMsg2,
			consumeMsg1,
		},
		entryID:     entryID,
		operatorKey: operatorKey,
		buyerKey:    buyerKey,
	}
}

// TestFullReplay_DeliverAndConsumeCountsMatchApply is the ground-source Replay
// convergence test: Apply and Replay must produce identical deliver and consume
// counts for the same message sequence.
func TestFullReplay_DeliverAndConsumeCountsMatchApply(t *testing.T) {
	t.Parallel()

	chain := buildReplayChain()

	// --- Apply path: process messages one by one ---
	stApply := NewState()
	stApply.OperatorKey = chain.operatorKey
	for i := range chain.msgs {
		stApply.Apply(&chain.msgs[i])
	}

	stApply.mu.RLock()
	applyDeliverCount := stApply.entryDeliverCount[chain.entryID]
	applyConsumeCount := stApply.entryConsumeCount[chain.entryID]
	stApply.mu.RUnlock()

	// --- Replay path: fresh state, process all messages at once ---
	stReplay := NewState()
	stReplay.OperatorKey = chain.operatorKey
	stReplay.Replay(chain.msgs)

	stReplay.mu.RLock()
	replayDeliverCount := stReplay.entryDeliverCount[chain.entryID]
	replayConsumeCount := stReplay.entryConsumeCount[chain.entryID]
	stReplay.mu.RUnlock()

	// --- Assertion 1: Apply produces expected counts ---
	// 2 deliver messages in the chain → deliverCount=2
	if applyDeliverCount != 2 {
		t.Errorf("Apply: entryDeliverCount[%q] = %d, want 2", chain.entryID, applyDeliverCount)
	}
	// 1 consume message in the chain → consumeCount=1
	if applyConsumeCount != 1 {
		t.Errorf("Apply: entryConsumeCount[%q] = %d, want 1", chain.entryID, applyConsumeCount)
	}

	// --- Assertion 2: Replay matches Apply ---
	if replayDeliverCount != applyDeliverCount {
		t.Errorf("Replay: entryDeliverCount[%q] = %d, want %d (must match Apply)",
			chain.entryID, replayDeliverCount, applyDeliverCount)
	}
	if replayConsumeCount != applyConsumeCount {
		t.Errorf("Replay: entryConsumeCount[%q] = %d, want %d (must match Apply)",
			chain.entryID, replayConsumeCount, applyConsumeCount)
	}

	// --- Assertion 3: AllEntryBehavioralSignals also converges ---
	applySignals := stApply.AllEntryBehavioralSignals()
	replaySignals := stReplay.AllEntryBehavioralSignals()

	applyEntry := applySignals[chain.entryID]
	replayEntry := replaySignals[chain.entryID]

	if applyEntry.DeliverCount != replayEntry.DeliverCount {
		t.Errorf("AllEntryBehavioralSignals DeliverCount: Apply=%d Replay=%d (must match)",
			applyEntry.DeliverCount, replayEntry.DeliverCount)
	}
	if applyEntry.ConsumeCount != replayEntry.ConsumeCount {
		t.Errorf("AllEntryBehavioralSignals ConsumeCount: Apply=%d Replay=%d (must match)",
			applyEntry.ConsumeCount, replayEntry.ConsumeCount)
	}

	t.Logf("PASS: Apply=Replay: deliverCount=%d consumeCount=%d", replayDeliverCount, replayConsumeCount)
}

// TestFullReplay_ResetClearsOldCounts verifies that Replay resets prior deliver
// and consume counts before processing the new message log. If a state had
// accumulated counts from a previous Apply run, Replay must not add to those
// counts — it must rebuild from scratch.
func TestFullReplay_ResetClearsOldCounts(t *testing.T) {
	t.Parallel()

	chain := buildReplayChain()

	st := NewState()
	st.OperatorKey = chain.operatorKey

	// Apply all messages once (counts = 2 deliver, 1 consume).
	for i := range chain.msgs {
		st.Apply(&chain.msgs[i])
	}

	// Verify pre-Replay counts.
	st.mu.RLock()
	preDeliverCount := st.entryDeliverCount[chain.entryID]
	preConsumeCount := st.entryConsumeCount[chain.entryID]
	st.mu.RUnlock()

	if preDeliverCount != 2 {
		t.Fatalf("pre-Replay: expected deliverCount=2, got %d", preDeliverCount)
	}

	// Replay the SAME messages. Counts must be identical (not doubled).
	st.Replay(chain.msgs)

	st.mu.RLock()
	postDeliverCount := st.entryDeliverCount[chain.entryID]
	postConsumeCount := st.entryConsumeCount[chain.entryID]
	st.mu.RUnlock()

	if postDeliverCount != preDeliverCount {
		t.Errorf("Replay doubled deliver count: before=%d after=%d (Replay must reset, not accumulate)",
			preDeliverCount, postDeliverCount)
	}
	if postConsumeCount != preConsumeCount {
		t.Errorf("Replay doubled consume count: before=%d after=%d (Replay must reset, not accumulate)",
			preConsumeCount, postConsumeCount)
	}

	t.Logf("PASS: Replay reset: deliverCount=%d consumeCount=%d (unchanged after re-Replay)",
		postDeliverCount, postConsumeCount)
}
