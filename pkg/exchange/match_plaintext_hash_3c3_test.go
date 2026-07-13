package exchange_test

// match_plaintext_hash_3c3_test.go — the regression gate for dontguess-3c3, the
// high-severity confidentiality leak the dontguess-541 security sweep found:
// several PUBLIC operator wire emissions re-broadcast entry.ContentHash =
// sha256(DECRYPTED plaintext) for a v2 (encrypted) entry. That unsalted
// plaintext hash is the exact guess-confirmation + cross-entry-correlation
// oracle §4.4 (A1/P1) removed from the put — a passive relay reader can hash a
// guessed plaintext and confirm it for free, defeating the AEAD.
//
// This extends the dontguess-2f7 canary (which searched only for plaintext /
// base64(plaintext) fragments) to the plaintext-DERIVED hash: it asserts the
// "sha256:<hex>" (and bare hex) of a v2 entry's plaintext appears in NONE of the
// operator's public emissions across the entry's whole lifecycle
// (put-accept → match → compression assign). It runs the REAL engine handlers
// (AutoAcceptPut → sendCompressionAssign, DispatchForTest buy → emitMatchResponse)
// over REAL secp256k1 identities + REAL nip44 + ChaCha20-Poly1305 — nothing
// crypto is mocked. See engine_buy.go (match content_hash omit for v2 +
// skipCompressionForV2).
//
// Individual-tier / legacy plaintext entries (WrappedCEKOperator == "") keep
// content_hash on the match and still receive a compression assign, byte-for-byte
// — proven in the same run so the fix is provably v2-specific, not a blanket
// removal.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// matchResult3c3 is the subset of the exchange:match result object the leak
// assertions inspect. content_hash is `omitempty` on the wire for a v2 entry,
// so a captured v2 result decodes to the empty string here.
type matchResult3c3 struct {
	EntryID     string `json:"entry_id"`
	ContentHash string `json:"content_hash"`
}

type matchPayload3c3 struct {
	Results []matchResult3c3 `json:"results"`
}

// operatorMessages3c3 returns every message the operator emitted, newest last.
func operatorMessages3c3(t *testing.T, h *testHarness) []store.MessageRecord {
	t.Helper()
	all, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	out := make([]store.MessageRecord, 0, len(all))
	for _, m := range all {
		if m.Sender == h.operator.PublicKeyHex() {
			out = append(out, m)
		}
	}
	return out
}

// matchResultFor3c3 drives a buy for task, dispatches it through the real engine
// handler, and returns the match result object for wantEntryID from the emitted
// exchange:match. Fails if no match result references wantEntryID.
func matchResultFor3c3(t *testing.T, h *testHarness, eng *exchange.Engine, task, wantEntryID string) matchResult3c3 {
	t.Helper()
	buyMsg := h.sendMessage(h.buyer, buyPayload(task, 1_000_000), []string{exchange.TagBuy}, nil)
	buyRec, err := h.st.GetMessage(buyMsg.ID)
	if err != nil {
		t.Fatalf("get buy: %v", err)
	}
	eng.State().Apply(exchange.FromStoreRecord(buyRec))
	if derr := eng.DispatchForTest(exchange.FromStoreRecord(buyRec)); derr != nil {
		t.Fatalf("dispatch buy %q: %v", task, derr)
	}
	all, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(all))

	matchMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	// Scan newest-first so we read the match this buy just produced.
	for i := len(matchMsgs) - 1; i >= 0; i-- {
		if len(matchMsgs[i].Antecedents) == 0 || matchMsgs[i].Antecedents[0] != buyMsg.ID {
			continue
		}
		var mp matchPayload3c3
		if json.Unmarshal(matchMsgs[i].Payload, &mp) != nil {
			continue
		}
		for _, r := range mp.Results {
			if r.EntryID == wantEntryID {
				return r
			}
		}
		t.Fatalf("match for buy %q carried no result for entry %s (results=%+v)", task, wantEntryID[:8], mp.Results)
	}
	t.Fatalf("no exchange:match emitted for buy %q (entry %s)", task, wantEntryID[:8])
	return matchResult3c3{}
}

// TestMatch_V2_PlaintextHashNeverOnPublicWire is the dontguess-3c3 done-gate.
func TestMatch_V2_PlaintextHashNeverOnPublicWire(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, seller, _ := useSecpIdentities(t, h)

	// OperatorSigner set (no ScripStore) ⇒ encryptedRequired == false: BOTH a v2
	// put (decrypt-then-fold) and a legacy plaintext put fold into the SAME
	// engine, so the v2-specific fix and the unchanged legacy behavior are proven
	// on one operator wire.
	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
	})

	// ── v2 confidential entry: a high-entropy plaintext disjoint from its public
	//    description, so a hash match is a REAL leak, never a metadata coincidence.
	const v2Desc = "kubernetes operator reconcile loop backoff jitter tuning recipe"
	v2Plain := []byte("SECRET-3C3-V2-" + strings.Repeat("reconcile-backoff-jitter-", 8) + "END")
	sum := sha256.Sum256(v2Plain)
	v2HashHex := hex.EncodeToString(sum[:])          // the load-bearing 64-char oracle value
	v2HashPrefixed := "sha256:" + v2HashHex          // the on-entry ContentHash form
	v2PutPayload, _ := buildV2PutPayload(t, seller, operator.PubKeyHex(), v2Desc, v2Plain, 9000)
	v2Put := h.sendMessage(h.seller, v2PutPayload,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	// ── legacy plaintext (individual-tier) entry: distinct domain + plaintext.
	const legacyDesc = "rust serde zero-copy deserialization borrow lifetime guide"
	legacyPut := h.sendMessage(h.seller,
		putPayload(legacyDesc, "sha256:"+fmt.Sprintf("%064x", 7), "code", 8000, 4096),
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	all, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(all))

	if err := eng.AutoAcceptPut(v2Put.ID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut v2: %v", err)
	}
	if err := eng.AutoAcceptPut(legacyPut.ID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut legacy: %v", err)
	}

	var v2Entry, legacyEntry *exchange.InventoryEntry
	for _, e := range eng.State().Inventory() {
		switch e.PutMsgID {
		case v2Put.ID:
			ee := e
			v2Entry = ee
		case legacyPut.ID:
			ee := e
			legacyEntry = ee
		}
	}
	if v2Entry == nil || legacyEntry == nil {
		t.Fatalf("expected both entries in inventory (v2=%v legacy=%v)", v2Entry != nil, legacyEntry != nil)
	}
	// Preconditions that make the assertions non-vacuous.
	if v2Entry.WrappedCEKOperator == "" {
		t.Fatal("v2 entry has no WrappedCEKOperator — it did not fold as a confidential entry; the whole test is vacuous")
	}
	if v2Entry.ContentHash != v2HashPrefixed {
		t.Fatalf("v2 entry.ContentHash = %q, want operator-local sha256(plaintext) %q (the oracle value we assert is off-wire)", v2Entry.ContentHash, v2HashPrefixed)
	}
	if legacyEntry.WrappedCEKOperator != "" {
		t.Fatal("legacy entry unexpectedly has WrappedCEKOperator — it is not an individual-tier plaintext entry")
	}
	if !strings.HasPrefix(legacyEntry.ContentHash, "sha256:") {
		t.Fatalf("legacy entry.ContentHash = %q, want a sha256: dedup hash", legacyEntry.ContentHash)
	}

	// ── MATCH: v2 result OMITS content_hash; legacy result KEEPS it (unchanged). ──
	v2Match := matchResultFor3c3(t, h, eng,
		"kubernetes operator reconcile backoff jitter tuning recipe", v2Entry.EntryID)
	if v2Match.ContentHash != "" {
		t.Fatalf("LEAK: v2 exchange:match result carried content_hash=%q — sha256(plaintext) must be OMITTED for a v2 entry (§4.4 A1/P1)", v2Match.ContentHash)
	}
	legacyMatch := matchResultFor3c3(t, h, eng,
		"rust serde zero-copy deserialization borrow lifetime guide", legacyEntry.EntryID)
	if legacyMatch.ContentHash != legacyEntry.ContentHash {
		t.Fatalf("REGRESSION: legacy match content_hash = %q, want the entry's %q (individual-tier behavior must be byte-for-byte unchanged)", legacyMatch.ContentHash, legacyEntry.ContentHash)
	}

	// ── THE CANARY: the v2 plaintext hash appears in NONE of the operator's
	//    public emissions (put-accept, match, any compression assign). ──
	opMsgs := operatorMessages3c3(t, h)
	if len(opMsgs) == 0 {
		t.Fatal("no operator messages captured — the wire canary would be vacuous")
	}
	for _, m := range opMsgs {
		raw := string(m.Payload)
		if strings.Contains(raw, v2HashHex) {
			t.Fatalf("CONFIDENTIALITY LEAK: sha256(v2 plaintext) hex appeared on a public operator emission (tags=%v). A passive reader can now confirm a guessed plaintext for free — §4.4 A1/P1 oracle reopened.", m.Tags)
		}
		if strings.Contains(raw, string(v2Plain)) {
			t.Fatalf("CONFIDENTIALITY LEAK: the v2 plaintext itself appeared on a public operator emission (tags=%v)", m.Tags)
		}
	}

	// ── COMPRESSION GATE: no exchange:assign references the v2 entry (a compressor
	//    cannot compress ciphertext and the assign would leak the plaintext hash),
	//    while the legacy entry DID get a compression assign — proving the gate is
	//    v2-specific, not a blanket disable. ──
	var sawLegacyAssign bool
	for _, m := range opMsgs {
		if !hasTag(m.Tags, exchange.TagAssign) {
			continue
		}
		var ap struct {
			EntryID  string `json:"entry_id"`
			TaskType string `json:"task_type"`
		}
		if json.Unmarshal(m.Payload, &ap) != nil {
			continue
		}
		if ap.EntryID == v2Entry.EntryID {
			t.Fatalf("LEAK/NONSENSE: a compression assign (task_type=%q) was posted for the v2 entry — it embeds sha256(plaintext) and orders impossible ciphertext compression", ap.TaskType)
		}
		if ap.EntryID == legacyEntry.EntryID && ap.TaskType == "compress" {
			sawLegacyAssign = true
		}
	}
	if !sawLegacyAssign {
		t.Fatal("expected a compression assign for the legacy entry — the v2 gate must not disable compression for individual-tier entries (assertion would be vacuous otherwise)")
	}
}
