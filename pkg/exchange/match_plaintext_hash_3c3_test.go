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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
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
//
// TWO-ENGINE STRUCTURE (post-ADV-7 / design §6): pre-decoupling this test folded
// BOTH a v2 put and a legacy plaintext put into ONE OperatorSigner-without-
// ScripStore engine, relying on `encryptedRequired == false` (scrip ANDed with
// signer) to accept the plaintext. dontguess-e18d decoupled encryptedRequired
// from scrip — a relay-attached (OperatorSigner != nil) engine is now fail-closed
// against plaintext regardless of ScripStore — so that single engine now REJECTS
// the legacy plaintext put. The v2 arm therefore runs on a team-tier engine
// (OperatorSigner) and the legacy arm on a SEPARATE individual-tier engine (no
// signer). Every original assertion is preserved: v2 omits content_hash + no
// compression assign + no plaintext-hash on the wire; legacy keeps content_hash +
// gets a compression assign. The two tiers use separate harness stores so their
// operator wires stay isolated (the team engine would otherwise drop the plaintext
// put, and a shared log could grandfather it — both avoided by isolation).
func TestMatch_V2_PlaintextHashNeverOnPublicWire(t *testing.T) {
	t.Parallel()

	// ── v2 confidential arm: TEAM-tier engine (OperatorSigner ⇒ encryptedRequired
	//    after ADV-7). A high-entropy plaintext disjoint from its public
	//    description, so a hash match is a REAL leak, never a metadata coincidence.
	h := newTestHarness(t)
	operator, seller, _ := useSecpIdentities(t, h)
	engTeam := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
	})

	const v2Desc = "kubernetes operator reconcile loop backoff jitter tuning recipe"
	v2Plain := []byte("SECRET-3C3-V2-" + strings.Repeat("reconcile-backoff-jitter-", 8) + "END")
	sum := sha256.Sum256(v2Plain)
	v2HashHex := hex.EncodeToString(sum[:]) // the load-bearing 64-char oracle value
	v2HashPrefixed := "sha256:" + v2HashHex // the on-entry ContentHash form
	v2PutPayload, _ := buildV2PutPayload(t, seller, operator.PubKeyHex(), v2Desc, v2Plain, 9000)
	v2Put := h.sendMessage(h.seller, v2PutPayload,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	all, _ := h.st.ListMessages(h.cfID, 0)
	engTeam.State().Replay(exchange.FromStoreRecords(all))
	if err := engTeam.AutoAcceptPut(v2Put.ID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut v2: %v", err)
	}

	var v2Entry *exchange.InventoryEntry
	for _, e := range engTeam.State().Inventory() {
		if e.PutMsgID == v2Put.ID {
			ee := e
			v2Entry = ee
		}
	}
	if v2Entry == nil {
		t.Fatal("expected the v2 entry in the team-tier inventory")
	}
	// Preconditions that make the assertions non-vacuous.
	if v2Entry.WrappedCEKOperator == "" {
		t.Fatal("v2 entry has no WrappedCEKOperator — it did not fold as a confidential entry; the whole test is vacuous")
	}
	if v2Entry.ContentHash != v2HashPrefixed {
		t.Fatalf("v2 entry.ContentHash = %q, want operator-local sha256(plaintext) %q (the oracle value we assert is off-wire)", v2Entry.ContentHash, v2HashPrefixed)
	}

	// ── legacy plaintext (individual-tier) arm: a SEPARATE individual-tier engine
	//    (no OperatorSigner ⇒ encryptedRequired == false) folds a legacy plaintext
	//    entry, proving the v2 content_hash omission + compression skip are
	//    v2-SPECIFIC, not a blanket removal — individual-tier behavior is
	//    byte-for-byte unchanged. Distinct domain + plaintext.
	h2 := newTestHarness(t)
	op2, _, _ := useSecpIdentities(t, h2)
	engIndiv := h2.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = op2.PubKeyHex()
	})

	const legacyDesc = "rust serde zero-copy deserialization borrow lifetime guide"
	legacyPut := h2.sendMessage(h2.seller,
		putPayload(legacyDesc, "sha256:"+fmt.Sprintf("%064x", 7), "code", 8000, 4096),
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	all2, _ := h2.st.ListMessages(h2.cfID, 0)
	engIndiv.State().Replay(exchange.FromStoreRecords(all2))
	if err := engIndiv.AutoAcceptPut(legacyPut.ID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut legacy: %v", err)
	}

	var legacyEntry *exchange.InventoryEntry
	for _, e := range engIndiv.State().Inventory() {
		if e.PutMsgID == legacyPut.ID {
			ee := e
			legacyEntry = ee
		}
	}
	if legacyEntry == nil {
		t.Fatal("expected the legacy entry in the individual-tier inventory")
	}
	if legacyEntry.WrappedCEKOperator != "" {
		t.Fatal("legacy entry unexpectedly has WrappedCEKOperator — it is not an individual-tier plaintext entry")
	}
	if !strings.HasPrefix(legacyEntry.ContentHash, "sha256:") {
		t.Fatalf("legacy entry.ContentHash = %q, want a sha256: dedup hash", legacyEntry.ContentHash)
	}

	// ── MATCH: v2 result OMITS content_hash; legacy result KEEPS it (unchanged). ──
	v2Match := matchResultFor3c3(t, h, engTeam,
		"kubernetes operator reconcile backoff jitter tuning recipe", v2Entry.EntryID)
	if v2Match.ContentHash != "" {
		t.Fatalf("LEAK: v2 exchange:match result carried content_hash=%q — sha256(plaintext) must be OMITTED for a v2 entry (§4.4 A1/P1)", v2Match.ContentHash)
	}
	legacyMatch := matchResultFor3c3(t, h2, engIndiv,
		"rust serde zero-copy deserialization borrow lifetime guide", legacyEntry.EntryID)
	if legacyMatch.ContentHash != legacyEntry.ContentHash {
		t.Fatalf("REGRESSION: legacy match content_hash = %q, want the entry's %q (individual-tier behavior must be byte-for-byte unchanged)", legacyMatch.ContentHash, legacyEntry.ContentHash)
	}

	// ── THE CANARY: the v2 plaintext hash appears in NONE of the team operator's
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
	//    cannot compress ciphertext and the assign would leak the plaintext hash) on
	//    the team wire, while the legacy entry DID get a compression assign on the
	//    individual wire — proving the gate is v2-specific, not a blanket disable. ──
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
	}
	var sawLegacyAssign bool
	for _, m := range operatorMessages3c3(t, h2) {
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
		if ap.EntryID == legacyEntry.EntryID && ap.TaskType == "compress" {
			sawLegacyAssign = true
		}
	}
	if !sawLegacyAssign {
		t.Fatal("expected a compression assign for the legacy entry — the v2 gate must not disable compression for individual-tier entries (assertion would be vacuous otherwise)")
	}
}

// TestBuyMissScripPay_V2_UsesCiphertextHashNotPlaintext is the second dontguess-3c3
// leak site the audit found: paySellerForBuyMiss emits a scrip-put-pay (kind 3411,
// a PUBLIC relay event) carrying result_hash = pending.ContentHash. On the team
// tier (ScripStore != nil && OperatorSigner != nil ⇒ encryptedRequired) every
// folded put is v2, so ContentHash = sha256(plaintext) — the §4.4 A1/P1 oracle
// would leak on every buy-miss payout. The fix uses the already-public
// CiphertextHash instead (sha256(ciphertext), random per entry). The scrip ledger
// fold (applyPutPay) reads only Seller+Amount, so result_hash is audit metadata —
// changing it cannot affect balances.
func TestBuyMissScripPay_V2_UsesCiphertextHashNotPlaintext(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, _, buyer := useSecpIdentities(t, h)

	cs := newCampfireScripStore(t, h)
	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
		o.ScripStore = cs
	})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	h.startEngine(eng, ctx, cancel)

	// The buyer requests a task the exchange has no inventory for ⇒ buy-miss offer.
	const task = "postgres logical replication slot lag alerting runbook with worked queries"
	_ = h.sendMessage(h.buyer, buyPayload(task, 500000), []string{exchange.TagBuy}, nil)

	taskHash := exchange.TaskDescriptionHash(task)
	waitForCond3c3(t, 3*time.Second, "buy-miss offer recorded", func() bool {
		return eng.State().GetBuyMissOffer(taskHash) != nil
	})

	// The buyer computed the result themselves and PUTs it as a v2 confidential
	// entry (description == task so the offer's task-hash matches; wrapped from the
	// buyer, the put sender, to the operator).
	v2Plain := []byte("SECRET-3C3-BUYMISS-" + strings.Repeat("replication-slot-lag-", 6) + "END")
	sum := sha256.Sum256(v2Plain)
	plaintextHashHex := hex.EncodeToString(sum[:])
	putPayload3c3, _ := buildV2PutPayload(t, buyer, operator.PubKeyHex(), task, v2Plain, 40000)
	put := h.sendMessage(h.buyer, putPayload3c3,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	// Wait for the operator's scrip-put-pay for this fulfillment.
	var payMsg *store.MessageRecord
	waitForCond3c3(t, 4*time.Second, "scrip-put-pay emitted", func() bool {
		msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripPutPay}})
		for i := len(msgs) - 1; i >= 0; i-- {
			if msgs[i].Sender == operator.PubKeyHex() {
				m := msgs[i]
				payMsg = &m
				return true
			}
		}
		return false
	})
	cancel()

	// Locate the folded v2 entry to read its two DISTINCT hashes.
	all, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(all))
	var entry *exchange.InventoryEntry
	for _, e := range eng.State().Inventory() {
		if e.PutMsgID == put.ID {
			ee := e
			entry = ee
		}
	}
	if entry == nil {
		t.Fatalf("v2 buy-miss put %s did not fold into inventory", put.ID[:8])
	}
	if entry.WrappedCEKOperator == "" {
		t.Fatal("folded entry is not v2 — the leak-path precondition is not met (test vacuous)")
	}
	if entry.ContentHash != "sha256:"+plaintextHashHex {
		t.Fatalf("entry.ContentHash = %q, want sha256(plaintext) %q", entry.ContentHash, "sha256:"+plaintextHashHex)
	}
	if entry.CiphertextHash == "" || entry.CiphertextHash == entry.ContentHash {
		t.Fatalf("entry.CiphertextHash = %q must be non-empty and distinct from ContentHash", entry.CiphertextHash)
	}

	var pp scrip.PutPayPayload
	if err := json.Unmarshal(payMsg.Payload, &pp); err != nil {
		t.Fatalf("unmarshal scrip-put-pay: %v", err)
	}
	if strings.Contains(string(payMsg.Payload), plaintextHashHex) {
		t.Fatalf("CONFIDENTIALITY LEAK: sha256(plaintext) hex appeared on the public scrip-put-pay (kind 3411) — §4.4 A1/P1 oracle reopened on the buy-miss payout path")
	}
	if pp.ResultHash != entry.CiphertextHash {
		t.Fatalf("scrip-put-pay result_hash = %q, want the public ciphertext_hash %q for a v2 entry", pp.ResultHash, entry.CiphertextHash)
	}
}

// waitForCond3c3 polls cond until true or the deadline elapses, failing the test
// with label on timeout.
func waitForCond3c3(t *testing.T, d time.Duration, label string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout after %s waiting for: %s", d, label)
}
