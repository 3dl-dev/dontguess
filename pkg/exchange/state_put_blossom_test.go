package exchange_test

// Tests for the applyPut Blossom-offload path (dontguess-7783).
//
// Covered:
//   - Oversize put (> BlossomOffloadThreshold) with a blob store configured
//     produces a pending entry with a non-empty BlobPointer and Content that
//     is NOT the full raw bytes (only the small inline preview slice) — the
//     full content is never inlined.
//   - The full content is retrievable and verifies via
//     State.FetchAndVerifyBlob against the entry's ContentHash.
//   - Oversize put with NO blob store configured falls back to legacy
//     behavior: full content inlined (regression safety — existing tests/
//     callers that never configure a blob store are unaffected).
//   - Content at/below the threshold is never offloaded even when a blob
//     store is configured (small-content path unchanged).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// buildLargePutPayload constructs an exchange:put JSON payload with content
// large enough to exceed BlossomOffloadThreshold.
//
// Content is generated as line-structured pseudo-code (not a flat byte
// pattern): PreviewAssembler snaps chunk boundaries to structural markers
// (newlines, function keywords), and content with no such markers degenerates
// to only two boundaries {0, len}, causing pathological (oversized,
// overlapping) chunk selection. Realistic code always has line breaks, so
// tests use realistic content shape to exercise the normal preview path.
func buildLargePutPayload(t *testing.T, desc string, tokenCost int64, size int) (payload []byte, content []byte) {
	t.Helper()
	var buf []byte
	for len(buf) < size {
		buf = append(buf, []byte("func handler_"+string(rune('a'+(len(buf)/64)%26))+"(w, r) { return doWork(w, r) }\n")...)
	}
	content = buf[:size]
	p, err := json.Marshal(map[string]any{
		"description":  desc,
		"content":      base64.StdEncoding.EncodeToString(content),
		"token_cost":   tokenCost,
		"content_type": "code",
		"domains":      []string{"go"},
	})
	if err != nil {
		t.Fatalf("marshal put payload: %v", err)
	}
	return p, content
}

func TestApplyPut_OversizeContentOffloadedToBlossom(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()

	blobStore := exchange.NewMemoryBlobStore()
	eng.State().SetBlobStore(blobStore)

	// BlossomOffloadThreshold is 32 KiB; use 64 KiB of content to exceed it.
	size := 64 * 1024
	payload, fullContent := buildLargePutPayload(t, "Large cached analysis document exceeding the inline threshold", 100000, size)

	putMsg := h.sendMessage(h.seller, payload,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	pending := eng.State().PendingPuts()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending put, got %d", len(pending))
	}
	entry := pending[0]

	if entry.BlobPointer == "" {
		t.Fatal("expected oversize entry to have a non-empty BlobPointer")
	}
	if len(entry.Content) >= size {
		t.Fatalf("expected inline Content to be much smaller than full content (%d bytes); got %d bytes — oversize content was inlined", size, len(entry.Content))
	}
	// Inline preview should be roughly 15-25% of the full content (this
	// project's preview target), and strictly less than the full size.
	if len(entry.Content) == 0 {
		t.Fatal("expected a non-empty inline preview for the oversize entry")
	}

	// ContentHash must be computed from the FULL content, not the preview.
	sum := sha256.Sum256(fullContent)
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if entry.ContentHash != wantHash {
		t.Fatalf("entry.ContentHash = %q, want %q (hash of full content)", entry.ContentHash, wantHash)
	}

	// Full content must be fetchable and verify against ContentHash.
	got, err := eng.State().FetchAndVerifyBlob(entry)
	if err != nil {
		t.Fatalf("FetchAndVerifyBlob: %v", err)
	}
	if len(got) != len(fullContent) {
		t.Fatalf("fetched blob length = %d, want %d", len(got), len(fullContent))
	}
	for i := range got {
		if got[i] != fullContent[i] {
			t.Fatalf("fetched blob content mismatch at byte %d", i)
		}
	}

	// putMsg is referenced only to keep this test self-documenting about which
	// message produced the entry (EntryID == PutMsgID).
	if entry.PutMsgID != putMsg.ID {
		t.Fatalf("entry.PutMsgID = %q, want %q", entry.PutMsgID, putMsg.ID)
	}
}

func TestApplyPut_OversizeContentWithoutBlobStoreStaysInline(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()
	// No SetBlobStore call — legacy behavior must be preserved.

	size := 64 * 1024
	payload, fullContent := buildLargePutPayload(t, "Large cached analysis document with no blob store configured", 100000, size)

	h.sendMessage(h.seller, payload,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	pending := eng.State().PendingPuts()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending put, got %d", len(pending))
	}
	entry := pending[0]

	if entry.BlobPointer != "" {
		t.Fatalf("expected empty BlobPointer with no blob store configured, got %q", entry.BlobPointer)
	}
	if len(entry.Content) != len(fullContent) {
		t.Fatalf("expected full content inlined (legacy behavior) when no blob store is configured: got %d bytes, want %d", len(entry.Content), len(fullContent))
	}
}

func TestApplyPut_SmallContentNeverOffloadedEvenWithBlobStore(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng := h.newEngine()
	eng.State().SetBlobStore(exchange.NewMemoryBlobStore())

	// Well under BlossomOffloadThreshold (32 KiB).
	size := 1024
	payload, fullContent := buildLargePutPayload(t, "Small cached snippet well under the offload threshold", 5000, size)

	h.sendMessage(h.seller, payload,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	pending := eng.State().PendingPuts()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending put, got %d", len(pending))
	}
	entry := pending[0]

	if entry.BlobPointer != "" {
		t.Fatalf("expected empty BlobPointer for small content, got %q", entry.BlobPointer)
	}
	if len(entry.Content) != len(fullContent) {
		t.Fatalf("expected full small content inlined: got %d bytes, want %d", len(entry.Content), len(fullContent))
	}
}
