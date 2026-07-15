package exchange_test

// climb_fence_grandfather_e2e_9d1_test.go — the E2E ground-source for dontguess-9d1
// (climb egress fence — match/hash leg), driven on a REAL relay-attached/team engine
// (OperatorSigner + ScripStore ⇒ encryptedRequired) with a GENUINELY grandfathered
// pre-climb plaintext entry produced by a real mixed-log Replay — not a hand-set flag.
//
// It builds the exact solo→fleet climb condition: a pre-migration legacy plaintext
// put (v<2, base64 "content", no "enc") that was accepted+broadcast before the
// cutover, plus its operator put-accept. StartupReplayForTest folds the mixed log
// the way `Start` does — s.replaying=true + encryptedRequired ⇒ the legacy put is
// GRANDFATHERED into ACTIVE inventory (LegacyPlaintext=true) AND indexed in the
// semantic match index. Then a real relay buyer's buy is dispatched and we assert:
//
//	(1) NO exchange:match result references the grandfathered entry — the buyer gets
//	    a buy-miss instead (the entry is in the match index, so the miss is caused by
//	    the findCandidates fence, NOT an empty index — a non-vacuous proof);
//	(2) NO message on the wire (match, buy-miss, or any other) carries the entry's
//	    sha256(pre-climb plaintext) — the §4.4 A1/P1 plaintext-hash oracle stays off
//	    the exchange:match wire.
//
// Uses the REAL secp256k1 team-tier engine harness (newTeamTierEngine) — nothing
// about the operator identity, fold, grandfather, or dispatch is mocked.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/store"
)

func legacyPlaintextPutPayload(t *testing.T, desc string, plaintext []byte, tokenCost int64) []byte {
	t.Helper()
	p, err := json.Marshal(map[string]any{
		"description":  desc,
		"content":      base64.StdEncoding.EncodeToString(plaintext),
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
	})
	if err != nil {
		t.Fatalf("marshal legacy put: %v", err)
	}
	return p
}

func operatorPutAcceptPayload(t *testing.T) []byte {
	t.Helper()
	// Empty expires_at ⇒ the grandfathered entry keeps its default
	// LegacyGrandfatherTTL fold-time expiry (still fresh here → live).
	p, err := json.Marshal(map[string]any{"price": int64(100), "expires_at": ""})
	if err != nil {
		t.Fatalf("marshal put-accept: %v", err)
	}
	return p
}

// TestClimbFence_E2E_GrandfatheredNeverMatchedNorHashLeaked drives the full
// grandfather→buy path on a real team-tier engine and proves the fence holds
// end to end.
func TestClimbFence_E2E_GrandfatheredNeverMatchedNorHashLeaked(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng, _, _, _ := newTeamTierEngine(t, h)

	const desc = "reusable go flock file-lock contention test pattern for concurrent access"
	plaintext := []byte("a pre-migration plaintext artifact already broadcast before the cutover: hold the flock, spin a second goroutine that blocks on the same lock, assert serialized ordering under concurrent access.")
	plainHashHex := hex.EncodeToString(func() []byte { s := sha256.Sum256(plaintext); return s[:] }())

	// --- Build the mixed historical log in the store: legacy plaintext put + its
	//     operator put-accept (the pre-climb, pre-cutover accepted+broadcast entry).
	putMsg := h.sendMessage(h.seller,
		legacyPlaintextPutPayload(t, desc, plaintext, 4242),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	h.sendMessage(h.operator,
		operatorPutAcceptPayload(t),
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrPutAccept},
		[]string{putMsg.ID},
	)

	// --- Replay the mixed log exactly as Start does: fold (grandfather) + rebuild
	//     the match index.
	if err := eng.StartupReplayForTest(); err != nil {
		t.Fatalf("StartupReplayForTest: %v", err)
	}

	// SETUP SANITY: the entry is genuinely grandfathered (LegacyPlaintext=true) and
	// present in ACTIVE inventory — the exact condition the fence must neutralize.
	var gf *exchange.InventoryEntry
	for _, e := range eng.State().Inventory() {
		if e.EntryID == putMsg.ID {
			gf = e
		}
	}
	if gf == nil {
		t.Fatal("precondition: legacy plaintext put was not grandfathered into inventory (mixed-log Replay did not fold it)")
	}
	if !gf.LegacyPlaintext {
		t.Fatal("precondition: entry is in inventory but not marked LegacyPlaintext — not a grandfathered entry")
	}
	if gf.WrappedCEKOperator != "" {
		t.Fatal("precondition: grandfathered entry unexpectedly carries a CEK wrap")
	}
	// NON-VACUITY: the grandfathered entry IS in the semantic match index, so a
	// subsequent buy-miss is caused by the findCandidates fence, not an empty index.
	if n := eng.MatchIndexLen(); n != 1 {
		t.Fatalf("precondition: match index len = %d, want 1 (the grandfathered entry must be indexed so the miss is a real fence, not an empty index)", n)
	}

	// --- A real relay buyer buys with a task semantically identical to the entry.
	buyMsg := h.sendMessage(h.buyer,
		mustBuyPayload(t, "go flock contention test pattern for concurrent lock access", 50000),
		[]string{exchange.TagBuy},
		nil,
	)
	buyRec, _ := h.st.GetMessage(buyMsg.ID)
	eng.State().Apply(exchange.FromStoreRecord(buyRec))
	if err := eng.DispatchForTest(exchange.FromStoreRecord(buyRec)); err != nil {
		t.Fatalf("DispatchForTest buy: %v", err)
	}

	// --- (1) NO exchange:match result references the grandfathered entry. The buy
	//     must have produced a buy-miss (proving it was processed, not silently lost).
	allMatchTagged, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	sawBuyMiss := false
	for i := range allMatchTagged {
		m := &allMatchTagged[i]
		if containsTagE2E(m.Tags, exchange.TagBuyMiss) {
			sawBuyMiss = true
			continue
		}
		var parsed struct {
			Results []struct {
				EntryID string `json:"entry_id"`
			} `json:"results"`
		}
		if err := json.Unmarshal(m.Payload, &parsed); err != nil {
			continue
		}
		for _, r := range parsed.Results {
			if r.EntryID == gf.EntryID {
				t.Fatalf("(1) a relay buyer MATCHED the grandfathered pre-climb plaintext entry %q — the climb fence is dead", gf.EntryID)
			}
		}
	}
	if !sawBuyMiss {
		t.Fatal("(1) the buy produced neither a match for the grandfathered entry nor a buy-miss — the buy was not processed (test would be vacuous)")
	}

	// --- (2) The OPERATOR never EGRESSES the entry's sha256(pre-climb plaintext)
	//     nor its plaintext. The original seller put (authored by the seller) is
	//     pre-migration history that was already public before the cutover and
	//     legitimately still carries the plaintext — the fence is about the
	//     operator not RE-emitting it via match/deliver/assign, so scope the leak
	//     check to operator-authored egress.
	operatorHex := h.operator.PublicKeyHex()
	plainB64 := base64.StdEncoding.EncodeToString(plaintext)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	sawOperatorEgress := false
	for i := range allMsgs {
		if allMsgs[i].Sender != operatorHex {
			continue
		}
		sawOperatorEgress = true
		if strings.Contains(string(allMsgs[i].Payload), plainHashHex) {
			t.Fatalf("(2) operator EGRESSED sha256(pre-climb plaintext) (tags=%v) — the §4.4 A1/P1 plaintext-hash oracle leaked", allMsgs[i].Tags)
		}
		if strings.Contains(string(allMsgs[i].Payload), plainB64) {
			t.Fatalf("(2) operator EGRESSED the pre-climb plaintext (base64) (tags=%v) — plaintext egressed", allMsgs[i].Tags)
		}
	}
	if !sawOperatorEgress {
		t.Fatal("(2) operator emitted no egress at all — the buy path did not run (test would be vacuous)")
	}
}

func mustBuyPayload(t *testing.T, task string, budget int64) []byte {
	t.Helper()
	p, err := json.Marshal(map[string]any{"task": task, "budget": budget, "max_results": 3})
	if err != nil {
		t.Fatalf("marshal buy: %v", err)
	}
	return p
}

func containsTagE2E(tags []string, want string) bool {
	for _, tg := range tags {
		if tg == want {
			return true
		}
	}
	return false
}
