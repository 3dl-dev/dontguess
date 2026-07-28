package relay

// outbox_egress_294_test.go — content-indexed egress fence (dontguess-294).
//
// The regression these guard: WithClimbFence is POSITION-indexed. It seeds the
// publish cursor past the pre-climb corpus and does nothing for anything above it,
// so a plaintext record appended AFTER the climb published normally. Nine artifacts
// reached a production relay through exactly that window and are permanently public.
// WithEgressFilter must hold such a record back wherever it sits in the log.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// plaintextFence mirrors the production predicate: a v2 record with a non-null
// "enc" carries only ciphertext and is safe; anything with a non-empty "content"
// inlines cleartext and must stay local.
func plaintextFence(rec store.Record) bool {
	payload := rec.Payload
	var p struct {
		V       int             `json:"v"`
		Content string          `json:"content"`
		Enc     json.RawMessage `json:"enc"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return true // unparseable: favour no-leak
	}
	enc := strings.TrimSpace(string(p.Enc))
	if p.V >= 2 && enc != "" && enc != "null" {
		return false
	}
	return p.Content != ""
}

type capturePublisher struct{ published []*identity.Event }

func (c *capturePublisher) PublishEvent(_ context.Context, ev *identity.Event) (bool, string, error) {
	c.published = append(c.published, ev)
	return true, "", nil
}

func newEgressTestOutbox(t *testing.T, opts ...OutboxOption) (*store.Store, *capturePublisher, *Outbox) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	ls, err := store.Open(logPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	pub := &capturePublisher{}
	ob, err := NewOutbox(ls, signer, pub, logPath+".pubcursor", opts...)
	if err != nil {
		t.Fatalf("new outbox: %v", err)
	}
	return ls, pub, ob
}

func appendLocal(t *testing.T, ls *store.Store, id string, payload string) {
	t.Helper()
	if err := ls.Append(store.Record{
		ID:      id,
		Origin:  "local",
		Tags:    []string{"exchange:put"},
		Payload: []byte(payload),
	}); err != nil {
		t.Fatalf("append %s: %v", id, err)
	}
}

// TestEgressFilter_HoldsPlaintextAboveTheWatermark is the exact 2026-07-16 shape:
// a plaintext record appended AFTER the climb. The position fence cannot see it;
// the content fence must.
func TestEgressFilter_HoldsPlaintextAboveTheWatermark(t *testing.T) {
	ls, pub, ob := newEgressTestOutbox(t,
		WithClimbFence(0), // nothing fenced by position — this record is "post-climb"
		WithEgressFilter(plaintextFence))

	appendLocal(t, ls, "plain-1", `{"description":"leaky","content":"aGVsbG8gd29ybGQ="}`)
	appendLocal(t, ls, "enc-1", `{"v":2,"description":"safe","enc":{"ciphertext":"deadbeef"}}`)

	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if len(pub.published) != 1 {
		t.Fatalf("published %d events, want 1 (the encrypted one only)", len(pub.published))
	}
	for _, ev := range pub.published {
		if strings.Contains(ev.Content, "aGVsbG8gd29ybGQ=") {
			t.Fatalf("PLAINTEXT EGRESSED: a record inlining cleartext content was published -- this is the dontguess-294 regression")
		}
	}
}

// TestEgressFilter_AdvancesPastFencedRecord proves a held record does not wedge the
// cursor. Without the advance, the Outbox would retry it every tick forever and
// nothing behind it would ever publish.
func TestEgressFilter_AdvancesPastFencedRecord(t *testing.T) {
	ls, pub, ob := newEgressTestOutbox(t, WithEgressFilter(plaintextFence))

	appendLocal(t, ls, "plain-1", `{"content":"c2VjcmV0"}`)
	appendLocal(t, ls, "enc-1", `{"v":2,"enc":{"ciphertext":"aa"}}`)
	appendLocal(t, ls, "enc-2", `{"v":2,"enc":{"ciphertext":"bb"}}`)

	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(pub.published) != 2 {
		t.Fatalf("published %d, want 2 -- a fenced record must not block the records behind it", len(pub.published))
	}
	// A second tick must not re-emit anything: the cursor advanced past all three.
	before := len(pub.published)
	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if len(pub.published) != before {
		t.Errorf("second tick published %d more events, want 0 -- the fenced record is being retried forever", len(pub.published)-before)
	}
}

// TestEgressFilter_NilIsDropIn pins that omitting the filter is exactly the prior
// behaviour, so every existing caller is unaffected.
func TestEgressFilter_NilIsDropIn(t *testing.T) {
	ls, pub, ob := newEgressTestOutbox(t) // no filter

	appendLocal(t, ls, "plain-1", `{"content":"c2VjcmV0"}`)
	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(pub.published) != 1 {
		t.Errorf("published %d with no filter, want 1 -- the filter must be opt-in", len(pub.published))
	}
}
