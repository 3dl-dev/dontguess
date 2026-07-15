package main

// serve_relay_climb_fence_e18d_test.go — the dontguess-e18d / ADV-18 done-gate
// (design §6 + §9 Gate A/P4): the solo→fleet CLIMB egress fence.
//
// The individual (solo) tier stores content as PLAINTEXT (legal there, §541 §6),
// and the relay Outbox tails the SAME events.jsonl the operator folds from. The
// instant a solo operator climbs to fleet (`up --relay`), a fresh Outbox with a
// zero cursor would tail that log and RE-BROADCAST the entire pre-climb plaintext
// corpus to the relay in cleartext — a mass confidentiality exfiltration (ADV-18).
//
// The fix fences Outbox egress at the climb watermark (the count of pre-climb
// Origin=local records) so those records stay LOCAL-ONLY and are NEVER
// republished, while every post-climb record (a v2-encrypted team put, or a
// DELIBERATE per-entry re-put-as-encrypted, which appends a NEW record above the
// watermark) publishes normally. Re-put-as-encrypted is a per-entry choice, never
// automatic republication.
//
// This drives the REAL serve-path publish leg (buildRelayWiring → relay.Outbox)
// deterministically (direct Tick, no goroutine/timing) with a recording publisher
// standing in for the relay wire — the "passive REQ over all kinds" observer that
// captures every event the Outbox emits. It asserts:
//
//	(1) FENCE HOLDS: after the climb, ZERO of the N pre-climb plaintext puts reach
//	    the wire (the secret plaintext appears in NO published event).
//	(2) POST-CLIMB EGRESS UNBLOCKED: a record appended ABOVE the watermark IS
//	    published — the fence blocks only the pre-climb corpus, not the fleet.
//	(3) LOAD-BEARING: a twin Outbox WITHOUT the fence republishes ALL N puts,
//	    plaintext and all — proving assertion (1) is a real fence, not a vacuous
//	    empty-log pass.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// recordingPublisher is the passive relay-wire observer: it records every event
// the Outbox publishes and always ACKs, so the publish loop advances its cursor
// exactly as a real relay would. It is the "passive REQ over all kinds" surface.
type recordingPublisher struct {
	mu     sync.Mutex
	events []*identity.Event
}

func (p *recordingPublisher) PublishEvent(_ context.Context, ev *identity.Event) (bool, error) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
	return true, nil
}

func (p *recordingPublisher) snapshot() []*identity.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*identity.Event, len(p.events))
	copy(out, p.events)
	return out
}

func TestClimbEgressFence_PreClimbPlaintextNeverRepublished(t *testing.T) {
	dir := t.TempDir()
	operator, err := identity.Generate()
	if err != nil {
		t.Fatalf("operator identity: %v", err)
	}

	const secret = "SECRET-E18D-PRECLIMB-CORPUS"
	const n = 5

	ls, err := dgstore.Open(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	// Seed the store with N PRE-CLIMB PLAINTEXT puts (Origin=local ⇒ Outbox
	// publish candidates). The secret marker rides in the cleartext `description`
	// field of each put payload, so a single published event carrying it is a
	// provable plaintext leak.
	for i := 0; i < n; i++ {
		rec := dgstore.Record{
			ID:         randomLocalMsgID(t),
			CampfireID: "local",
			Sender:     operator.PubKeyHex(),
			Payload:    localPutPayload(secret+" pre-climb plaintext put variant", 8000+int64(i)),
			Tags:       []string{exchange.TagPut, "exchange:content-type:code"},
			Timestamp:  time.Now().UnixNano() + int64(i),
			Origin:     "local",
		}
		if err := ls.Append(rec); err != nil {
			t.Fatalf("append pre-climb put %d: %v", i, err)
		}
	}

	// The climb watermark: the count of operator-authored records now present.
	// Mirrors establishClimbWatermark's first-attach computation.
	recs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var watermark int64
	for i := range recs {
		if isOperatorOrigin(recs[i].Origin) {
			watermark++
		}
	}
	if watermark != n {
		t.Fatalf("climb watermark = %d, want %d (the pre-climb corpus size)", watermark, n)
	}

	ctx := context.Background()

	// ── CLIMB: build the FENCED Outbox (fresh cursor sidecar ⇒ the climb fence
	//    seeds the cursor to the watermark). This is exactly what the serve-path
	//    relay attach wires via WithClimbWatermark → relay.WithClimbFence.
	pub := &recordingPublisher{}
	fenced, _, err := buildRelayWiring(ls, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", pub, 0, nil, nil,
		WithClimbWatermark(watermark))
	if err != nil {
		t.Fatalf("buildRelayWiring (fenced): %v", err)
	}
	if got := fenced.outbox.Cursor(); got != watermark {
		t.Fatalf("climb fence did not seed the cursor: Cursor()=%d, want the watermark %d", got, watermark)
	}

	// One full publish pass. With the fence engaged, it must publish NOTHING.
	if err := fenced.outbox.Tick(ctx); err != nil {
		t.Fatalf("fenced Tick: %v", err)
	}
	if got := len(pub.snapshot()); got != 0 {
		t.Fatalf("CLIMB EGRESS FENCE BREACH: %d pre-climb event(s) republished to the relay, want 0 (ADV-18: the solo plaintext corpus must stay local-only on the climb)", got)
	}
	// Belt-and-suspenders: the secret plaintext is nowhere on the wire.
	for _, ev := range pub.snapshot() {
		if strings.Contains(ev.Content, secret) {
			t.Fatalf("CONFIDENTIALITY LEAK: pre-climb plaintext (%q) appeared in a published event (kind %d)", secret, ev.Kind)
		}
	}

	// ── POST-CLIMB EGRESS UNBLOCKED: append ONE operator record ABOVE the
	//    watermark (a fleet-era emission). It MUST publish — the fence blocks only
	//    the pre-climb corpus, never post-climb egress.
	postRec := dgstore.Record{
		ID:         randomLocalMsgID(t),
		CampfireID: "local",
		Sender:     operator.PubKeyHex(),
		Payload:    []byte(`{"buy_id":"b1","entry_id":"e1"}`),
		Tags:       []string{exchange.TagMatch},
		Timestamp:  time.Now().UnixNano() + 1_000,
		Origin:     "local",
	}
	if err := ls.Append(postRec); err != nil {
		t.Fatalf("append post-climb record: %v", err)
	}
	if err := fenced.outbox.Tick(ctx); err != nil {
		t.Fatalf("fenced Tick after post-climb append: %v", err)
	}
	post := pub.snapshot()
	if len(post) != 1 {
		t.Fatalf("post-climb egress: want exactly 1 published record (the emission above the watermark), got %d — the fence must not block post-climb egress", len(post))
	}
	if post[0].Kind != nostr.KindMatch {
		t.Fatalf("post-climb published event kind = %d, want KindMatch %d", post[0].Kind, nostr.KindMatch)
	}

	// ── LOAD-BEARING TWIN: same store + corpus, NO fence (fresh cursor, no
	//    watermark). It republishes ALL N pre-climb puts, secret plaintext and all —
	//    proving the fence assertion above is real, not a vacuous empty-log pass.
	twinPub := &recordingPublisher{}
	twin, _, err := buildRelayWiring(ls, operator, operator.PubKeyHex(),
		dir+"/twin.pubcursor", twinPub, 0, nil, nil)
	if err != nil {
		t.Fatalf("buildRelayWiring (twin): %v", err)
	}
	if err := twin.outbox.Tick(ctx); err != nil {
		t.Fatalf("twin Tick: %v", err)
	}
	twinEvents := twinPub.snapshot()
	var twinPuts, twinSecretHits int
	for _, ev := range twinEvents {
		if ev.Kind == nostr.KindPut {
			twinPuts++
		}
		if strings.Contains(ev.Content, secret) {
			twinSecretHits++
		}
	}
	if twinPuts != n {
		t.Fatalf("twin (no fence): republished %d put event(s), want %d — the fence assertion is not load-bearing unless the un-fenced twin leaks the corpus", twinPuts, n)
	}
	if twinSecretHits != n {
		t.Fatalf("twin (no fence): the secret plaintext appeared in %d event(s), want %d — the fixture must carry plaintext for the leak to be real", twinSecretHits, n)
	}
}
