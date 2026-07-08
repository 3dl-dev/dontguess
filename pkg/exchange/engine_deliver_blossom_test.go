package exchange_test

// Engine-level round-trip tests for the Blossom deliver path (dontguess-7783).
//
// Covered:
//   - Full flow: oversize put (offloaded to Blossom) -> put-accept -> buy ->
//     match -> operator deliver trigger -> engine fetches the full content
//     from the blob store, verifies it against the content-hash, and emits a
//     settle(deliver) message whose content sha256 matches the ORIGINAL full
//     content the seller put (not the inline preview slice).
//   - Tampered blob: if the bytes resolvable via the entry's BlobPointer no
//     longer match its ContentHash, the engine refuses to deliver — no
//     content-bearing settle(deliver) message is emitted.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/campfire-net/campfire/cf-protocol/store"

	"github.com/campfire-net/dontguess/pkg/exchange"
)

// buildOversizeDeliverableState mirrors buildDeliverableState (settle_deliver_test.go)
// but uses content large enough to trigger Blossom offload, with a blob store
// configured on the engine's state before any put is processed.
func buildOversizeDeliverableState(t *testing.T, h *testHarness, eng *exchange.Engine, blobStore exchange.BlobStore) (
	deliverMsg *exchange.Message,
	originalContent []byte,
) {
	t.Helper()

	eng.State().SetBlobStore(blobStore)

	// 64 KiB of line-structured pseudo-code — exceeds BlossomOffloadThreshold
	// (32 KiB). Line-structured (not a flat byte pattern) so PreviewAssembler's
	// boundary-snapping behaves normally (see buildLargePutPayload doc).
	var buf []byte
	for len(buf) < 64*1024 {
		buf = append(buf, []byte("func handler_"+string(rune('a'+(len(buf)/64)%26))+"(w, r) { return doWork(w, r) }\n")...)
	}
	originalContent = buf[:64*1024]

	desc := "Large cached analysis document for TestEngineDeliverBlossom round trip"
	putPayloadBytes, _ := json.Marshal(map[string]any{
		"description":  desc,
		"content":      base64.StdEncoding.EncodeToString(originalContent),
		"token_cost":   int64(2000000),
		"content_type": "analysis",
		"domains":      []string{"go", "testing"},
	})

	putMsg := h.sendMessage(h.seller, putPayloadBytes,
		[]string{exchange.TagPut, "exchange:content-type:analysis"},
		nil,
	)

	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.AutoAcceptPut(putMsg.ID, 1400000, time.Now().Add(168*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	inv := eng.State().Inventory()
	if len(inv) == 0 {
		t.Fatal("expected inventory entry after put-accept")
	}
	entryID := inv[0].EntryID
	if inv[0].BlobPointer == "" {
		t.Fatal("expected oversize entry to have a BlobPointer after put-accept")
	}

	buyMsg := h.sendMessage(h.buyer,
		buyPayload("Find a large cached analysis document for testing round trips", 50000000),
		[]string{exchange.TagBuy},
		nil,
	)
	buyRec, _ := h.st.GetMessage(buyMsg.ID)
	eng.State().Apply(exchange.FromStoreRecord(buyRec))
	if err := eng.DispatchForTest(exchange.FromStoreRecord(buyRec)); err != nil {
		t.Fatalf("DispatchForTest buy: %v", err)
	}

	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	matchMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	if len(matchMsgs) == 0 {
		t.Fatal("no match message emitted")
	}
	matchRec := matchMsgs[len(matchMsgs)-1]

	// Buyer accepts directly (skip preview — not the concern of this test).
	buyerAcceptPayloadBytes, _ := json.Marshal(map[string]any{
		"phase":    "buyer-accept",
		"entry_id": entryID,
		"accepted": true,
	})
	buyerAcceptMsg := h.sendMessage(h.buyer, buyerAcceptPayloadBytes,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchRec.ID},
	)

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	deliverTriggerPayload, _ := json.Marshal(map[string]any{
		"phase":    "deliver",
		"entry_id": entryID,
	})
	deliverMsg = h.sendMessage(h.operator, deliverTriggerPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver,
		},
		[]string{buyerAcceptMsg.ID},
	)

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	return deliverMsg, originalContent
}

// findDeliverContentMessage scans settle messages for the operator-emitted
// deliver message carrying a content field, same predicate used by
// TestSettleDeliver_ContentDelivered.
func findDeliverContentMessage(h *testHarness) *store.MessageRecord {
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagSettle}})
	for i := range msgs {
		m := &msgs[i]
		if m.Sender != h.operator.PublicKeyHex() {
			continue
		}
		hasDeliverPhase := false
		for _, tag := range m.Tags {
			if tag == exchange.TagPhasePrefix+exchange.SettlePhaseStrDeliver {
				hasDeliverPhase = true
				break
			}
		}
		if !hasDeliverPhase {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(m.Payload, &payload); err != nil {
			continue
		}
		if _, hasContent := payload["content"]; !hasContent {
			continue
		}
		return m
	}
	return nil
}

// TestEngineDeliverBlossom_FetchesFullContentAndVerifies verifies that for an
// oversize (Blossom-offloaded) entry, the deliver path fetches the FULL
// content from the blob store (not the inline preview slice) and its sha256
// matches what the seller originally put.
func TestEngineDeliverBlossom_FetchesFullContentAndVerifies(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	blobStore := exchange.NewMemoryBlobStore()
	deliverMsg, originalContent := buildOversizeDeliverableState(t, h, eng, blobStore)

	deliverRec, _ := h.st.GetMessage(deliverMsg.ID)
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("DispatchForTest deliver: %v", err)
	}

	contentMsg := findDeliverContentMessage(h)
	if contentMsg == nil {
		t.Fatal("engine did not emit a settle(deliver) message with content field")
	}

	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(contentMsg.Payload, &payload); err != nil {
		t.Fatalf("unmarshal deliver content payload: %v", err)
	}
	deliveredBytes, err := base64.StdEncoding.DecodeString(payload.Content)
	if err != nil {
		t.Fatalf("base64-decode delivered content: %v", err)
	}

	if len(deliveredBytes) != len(originalContent) {
		t.Fatalf("delivered content length = %d, want %d (full content, not the inline preview slice)",
			len(deliveredBytes), len(originalContent))
	}

	originalHash := sha256.Sum256(originalContent)
	deliveredHash := sha256.Sum256(deliveredBytes)
	if originalHash != deliveredHash {
		t.Errorf("delivered content hash mismatch:\n  got  sha256:%x\n  want sha256:%x",
			deliveredHash, originalHash)
	}
}

// TestEngineDeliverBlossom_TamperedBlobRefusesDelivery verifies that if the
// blob resolvable via the entry's BlobPointer does not match its recorded
// ContentHash (simulated tamper/corruption), the engine does NOT emit a
// content-bearing settle(deliver) message.
func TestEngineDeliverBlossom_TamperedBlobRefusesDelivery(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	// A blob store double whose Fetch always returns content that does NOT
	// match whatever hash the caller expects — simulates a compromised or
	// corrupted Blossom host serving the wrong bytes for a pointer.
	tamperingStore := &tamperingBlobStore{inner: exchange.NewMemoryBlobStore()}

	deliverMsg, _ := buildOversizeDeliverableState(t, h, eng, tamperingStore)

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagSettle}})
	preCount := len(preMsgs)

	deliverRec, _ := h.st.GetMessage(deliverMsg.ID)
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("DispatchForTest deliver: %v", err)
	}

	// No new content-bearing deliver message should have been emitted.
	if contentMsg := findDeliverContentMessage(h); contentMsg != nil {
		t.Fatal("engine emitted a content-bearing deliver message for a tampered blob — hash verification did not stop delivery")
	}

	postMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagSettle}})
	if len(postMsgs) > preCount {
		t.Fatalf("expected no new settle messages after a tamper-detected deliver, got %d new", len(postMsgs)-preCount)
	}
}

// tamperingBlobStore wraps a real BlobStore but returns corrupted bytes from
// Fetch (Put still stores the real content, so the corruption is only
// observable via the hash-mismatch it causes on Fetch — modeling a blob host
// that serves the wrong bytes for a given pointer).
type tamperingBlobStore struct {
	inner exchange.BlobStore
}

func (t *tamperingBlobStore) Put(content []byte) (string, error) {
	return t.inner.Put(content)
}

func (t *tamperingBlobStore) Fetch(pointer string) ([]byte, error) {
	content, err := t.inner.Fetch(pointer)
	if err != nil {
		return nil, err
	}
	// Corrupt: flip the first byte if present.
	if len(content) > 0 {
		content[0] ^= 0xFF
	}
	return content, nil
}
