package nostr_test

// etag_fixed_size_6d2_test.go — dontguess-6d2.
//
// A NIP-01 "e" tag value MUST be a 32-byte event id. Campfire-era records carry
// 16-byte antecedent ids, and the adapter emitted them verbatim, producing
// ["e", "<32 hex chars>", "", "reply"]. Every NIP-01 relay rejects that with
// "invalid: unexpected size for fixed-size tag: e".
//
// Because the rejected event is immutable (its id is a content hash) it could
// never become valid, and the outbox retried it forever — so one such record sat
// at the head of the publish queue and stranded EVERY later operator message
// behind it. Measured on the live exchange: operator egress stopped dead at
// 04:30:52 and 29 messages, including buy-miss answers owed to real buyers,
// never reached the relay while the operator reported itself healthy.
//
// This is the same defect dontguess-7d5 already fixed for the "p" tag. The "e"
// tag has the identical fixed-size rule and was missed.

import (
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/proto"
)

// legacyAnte is a real campfire-era antecedent from the live event log: 32 hex
// characters (16 bytes), half the length a nostr event id requires. This exact
// value produced the relay rejection that wedged the exchange.
const legacyAnte = "c50d41055706d5d9054f46f8fec2f5a2"

const validAnte = "7d9bc4beafcc9ccd3ad9dd92386be2476f203ffb220d8dead885965dac29be93"
const validAnte2 = "6edf1b5f179f9d9231e4ab61ef3cf6e6ad44d7c6ce8a789368a50a6648705a51"

func msgWithAntecedents(antes ...string) *proto.Message {
	return &proto.Message{
		ID:          "08199d6c8eff0000",
		Sender:      "6c74c7bb0f0acb9ee4820f63b52f4209490eaef6fba7d1d2c34c2622413498f1",
		Tags:        []string{exchange.TagAssignExpire},
		Antecedents: antes,
		Payload:     []byte(`{"assign_id":"x"}`),
		Timestamp:   1785299940078211969,
	}
}

func eTagValues(t *testing.T, tags [][]string) []string {
	t.Helper()
	var out []string
	for _, tg := range tags {
		if len(tg) >= 2 && tg[0] == "e" {
			out = append(out, tg[1])
		}
	}
	return out
}

// TestNoUndersizedETagEmitted is the regression proper.
func TestNoUndersizedETagEmitted(t *testing.T) {
	t.Parallel()
	ev, err := nostr.ToNostrEvent(msgWithAntecedents(legacyAnte))
	if err != nil {
		t.Fatalf("ToNostrEvent: %v", err)
	}
	for _, v := range eTagValues(t, ev.Tags) {
		if len(v) != 64 {
			t.Fatalf("emitted an e-tag of %d hex chars (%q); a NIP-01 fixed-size e-tag MUST be 64. Every relay rejects this with \"invalid: unexpected size for fixed-size tag: e\", and because the event id is a content hash it can never become valid — the outbox then retries it forever and strands every later operator message behind it (dontguess-6d2)", len(v), v)
		}
	}
}

// TestLegacyAntecedentPreservedLosslessly proves the guard drops nothing: the
// causal chain must survive even though it cannot ride in an e-tag.
func TestLegacyAntecedentPreservedLosslessly(t *testing.T) {
	t.Parallel()
	orig := msgWithAntecedents(legacyAnte, validAnte)
	ev, err := nostr.ToNostrEvent(orig)
	if err != nil {
		t.Fatalf("ToNostrEvent: %v", err)
	}

	var dgAnt string
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == "dg_ant" {
			dgAnt = tg[1]
		}
	}
	if dgAnt == "" {
		t.Fatal("no dg_ant tag emitted — the legacy antecedent was silently DROPPED, losing the causal chain")
	}
	if got := strings.Split(dgAnt, ","); len(got) != 2 || got[0] != legacyAnte || got[1] != validAnte {
		t.Fatalf("dg_ant = %q, want the full ordered antecedent list", dgAnt)
	}

	back, err := nostr.FromNostrEvent(ev)
	if err != nil {
		t.Fatalf("FromNostrEvent: %v", err)
	}
	if len(back.Antecedents) != 2 || back.Antecedents[0] != legacyAnte || back.Antecedents[1] != validAnte {
		t.Fatalf("round-trip Antecedents = %v, want [%s %s] in order", back.Antecedents, legacyAnte, validAnte)
	}
}

// TestConformingAntecedentsUnchanged pins that the guard is narrow — the normal
// all-valid case must keep its NIP-01 reply threading and emit no dg_ant.
func TestConformingAntecedentsUnchanged(t *testing.T) {
	t.Parallel()
	ev, err := nostr.ToNostrEvent(msgWithAntecedents(validAnte, validAnte2))
	if err != nil {
		t.Fatalf("ToNostrEvent: %v", err)
	}
	got := eTagValues(t, ev.Tags)
	if len(got) != 2 || got[0] != validAnte || got[1] != validAnte2 {
		t.Fatalf("e-tags = %v, want both valid antecedents in order", got)
	}
	for _, tg := range ev.Tags {
		if len(tg) >= 1 && tg[0] == "dg_ant" {
			t.Fatal("dg_ant emitted for an all-conforming antecedent list — the fallback must stay off the normal path")
		}
	}
	// The NIP-01 reply marker must still be on the first e-tag.
	for _, tg := range ev.Tags {
		if len(tg) >= 4 && tg[0] == "e" && tg[1] == validAnte && tg[3] != "reply" {
			t.Errorf("first e-tag lost its reply marker: %v", tg)
		}
	}

	back, err := nostr.FromNostrEvent(ev)
	if err != nil {
		t.Fatalf("FromNostrEvent: %v", err)
	}
	if len(back.Antecedents) != 2 || back.Antecedents[0] != validAnte {
		t.Fatalf("round-trip Antecedents = %v", back.Antecedents)
	}
}
