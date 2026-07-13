package exchange_test

// deliver_confidentiality_9e8_test.go — the done-gate for dontguess-9e8
// (operator re-wraps the CEK to the paying buyer at deliver, §3.1(5)/§3.4/§4.5
// of docs/design/content-confidentiality-envelope-541.md).
//
// The DELIVER-side confidentiality fix: emitDeliverContent used to inline the
// full plaintext into the settle(deliver) — the last deliver-side leak. It now
// emits the §3.4 v2 payload carrying NO content and NO ciphertext: a reference
// to the already-public put-event ciphertext + ciphertext_hash + the CEK
// re-wrapped to the paying buyer.
//
// These are BLACK-BOX (package exchange_test) tests driving the REAL engine
// handler (handleSettleDeliverContent → emitDeliverContent) over a REAL
// secp256k1 operator/seller/buyer and REAL nip44 + ChaCha20-Poly1305 — NOTHING
// crypto is mocked. The v2 put is built EXACTLY as buildPutMessage builds it on
// the wire (mirrors put_confidentiality_4bed's buildEncObject), so these prove
// the operator can consume what the seller emits AND re-wrap it to the buyer.
//
// Proven (each an assertion the veracity pass challenges):
//
//	(a) the emitted deliver payload's key_wrap.recipient == the ANTECEDENT-chain
//	    MatchBuyerKey — NOT the decoy pubkey planted in the trigger payload — and
//	    the payload carries NO content and NO ciphertext field (§3.4);
//	(b) the paying buyer (holding buyerPriv) can nip44.Open the wrapped CEK and it
//	    equals the ORIGINAL CEK the seller generated (round-trip);
//	(c) a DIFFERENT buyer key CANNOT nip44.Open the wrapped CEK — a captured
//	    deliver replayed toward a different (unfunded) buyer is undecryptable by
//	    them. The recipient key IS the anti-replay binding (§4.5.4);
//	(d) team tier (ScripStore != nil) with NO live reservation ⇒ the operator
//	    emits NO deliver at all — the existing money-integrity gate is intact and
//	    fires before the re-wrap.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nip44"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// v2KeyWrap is the §3.4 key_wrap object on an emitted deliver payload.
type v2KeyWrap struct {
	Alg       string `json:"alg"`
	Recipient string `json:"recipient"`
	Wrapped   string `json:"wrapped"`
}

// v2DeliverPayload is the full §3.4 deliver wire shape the operator emits for a
// team-tier confidential entry. Content/Ciphertext are declared ONLY so the
// tests can assert they are ABSENT (empty) — deliver must never carry them.
type v2DeliverPayload struct {
	Phase          string          `json:"phase"`
	V              int             `json:"v"`
	EntryID        string          `json:"entry_id"`
	ContentAlg     string          `json:"content_alg"`
	CiphertextRef  json.RawMessage `json:"ciphertext_ref"`
	CiphertextHash string          `json:"ciphertext_hash"`
	KeyWrap        v2KeyWrap       `json:"key_wrap"`
	// Leak canaries — must stay empty on the wire.
	Content    string `json:"content"`
	Ciphertext string `json:"ciphertext"`
}

// buildV2PutPayload builds the kind-3401 v2 confidential put payload EXACTLY the
// way buildPutMessage does (a real CEK, real AEAD, CEK NIP-44-wrapped to the
// operator), and returns the marshaled payload plus the raw CEK so a test can
// prove the re-wrapped-to-buyer CEK round-trips to that same value.
func buildV2PutPayload(t *testing.T, seller identity.Signer, operatorPubHex, desc string, plaintext []byte, tokenCost int64) (payload []byte, cek []byte) {
	t.Helper()
	cek = make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("gen CEK: %v", err)
	}
	aead, err := chacha20poly1305.New(cek)
	if err != nil {
		t.Fatalf("init AEAD: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("gen nonce: %v", err)
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	sum := sha256.Sum256(ciphertext)
	wrapped, err := nip44.Seal(seller, operatorPubHex, cek)
	if err != nil {
		t.Fatalf("wrap CEK to operator: %v", err)
	}
	payload, err = json.Marshal(map[string]any{
		"v":            2,
		"description":  desc,
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
		"enc": map[string]any{
			"content_alg":     "chacha20poly1305",
			"ciphertext_hash": "sha256:" + hex.EncodeToString(sum[:]),
			"ciphertext":      base64.StdEncoding.EncodeToString(ciphertext),
			"key_wrap": map[string]any{
				"alg":       "nip44-v2-secp256k1",
				"recipient": operatorPubHex,
				"wrapped":   wrapped,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal v2 put: %v", err)
	}
	return payload, cek
}

// useSecpIdentities swaps the harness's ed25519 operator/seller/buyer for REAL
// secp256k1 identities so the NIP-44 wrap/unwrap path is exercised end-to-end.
// The operator's private signer is what the engine must be given via
// OperatorSigner; the buyer's is what the buyer uses to unwrap the CEK.
func useSecpIdentities(t *testing.T, h *testHarness) (operator, seller, buyer identity.Signer) {
	t.Helper()
	var err error
	if operator, err = identity.Generate(); err != nil {
		t.Fatalf("operator identity: %v", err)
	}
	if seller, err = identity.Generate(); err != nil {
		t.Fatalf("seller identity: %v", err)
	}
	if buyer, err = identity.Generate(); err != nil {
		t.Fatalf("buyer identity: %v", err)
	}
	h.operator = &testAgent{pubKeyHex: operator.PubKeyHex()}
	h.seller = &testAgent{pubKeyHex: seller.PubKeyHex()}
	h.buyer = &testAgent{pubKeyHex: buyer.PubKeyHex()}
	return operator, seller, buyer
}

// driveV2Deliver runs the full put→accept→buy→match→buyer-accept→deliver-trigger
// chain for a v2 confidential entry and returns the operator's deliver TRIGGER
// message (ready to DispatchForTest) plus the entry id and the original CEK. A
// DECOY pubkey is planted in the deliver trigger's "buyer" field: the emitted
// recipient must come from the antecedent chain (MatchBuyerKey), never this
// field, so the decoy must be IGNORED.
func driveV2Deliver(t *testing.T, h *testHarness, eng *exchange.Engine, seller, operator identity.Signer, decoyBuyerPubHex string) (deliverTrigger *exchange.Message, entryID string, cek []byte) {
	t.Helper()

	const desc = "reusable go flock file-lock contention test pattern for concurrent access"
	plaintext := []byte("distilled artifact: hold the flock, spin a second goroutine that blocks on the same lock, assert serialized ordering — the wire must never expose this plaintext under encryption.")
	putPayload, cek := buildV2PutPayload(t, seller, operator.PubKeyHex(), desc, plaintext, 4242)

	putMsg := h.sendMessage(h.seller, putPayload,
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.AutoAcceptPut(putMsg.ID, 2100, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	inv := eng.State().Inventory()
	if len(inv) == 0 {
		t.Fatal("v2 put did not fold into inventory after accept — decrypt-then-gate failed")
	}
	entryID = inv[0].EntryID
	if inv[0].WrappedCEKOperator == "" {
		t.Fatal("inventory entry has no WrappedCEKOperator — deliver cannot re-derive the CEK")
	}

	// Buyer publishes a buy semantically close to the entry; operator matches.
	buyMsg := h.sendMessage(h.buyer,
		buyPayload("go flock contention test pattern for concurrent lock access", 50000),
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
		t.Fatal("no match message emitted for the v2 entry")
	}
	matchRec := matchMsgs[len(matchMsgs)-1]

	// Buyer accepts directly (skip preview).
	buyerAcceptPayload, _ := json.Marshal(map[string]any{
		"phase":    "buyer-accept",
		"entry_id": entryID,
		"accepted": true,
	})
	buyerAcceptMsg := h.sendMessage(h.buyer, buyerAcceptPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchRec.ID},
	)

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	// Operator deliver trigger — with a DECOY buyer field that must be ignored.
	deliverTriggerPayload, _ := json.Marshal(map[string]any{
		"phase":    "deliver",
		"entry_id": entryID,
		"buyer":    decoyBuyerPubHex, // DECOY — must NOT become the wrap recipient
	})
	deliverTrigger = h.sendMessage(h.operator, deliverTriggerPayload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver,
		},
		[]string{buyerAcceptMsg.ID},
	)

	allMsgs, _ = h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	return deliverTrigger, entryID, cek
}

// findV2DeliverPayload returns the operator-emitted deliver message carrying a
// key_wrap (the §3.4 confidential shape), parsed. Nil if none was emitted.
func findV2DeliverPayload(t *testing.T, h *testHarness) *v2DeliverPayload {
	t.Helper()
	msgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{
		Tags: []string{exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver},
	})
	for i := range msgs {
		m := &msgs[i]
		if m.Sender != h.operator.PublicKeyHex() {
			continue
		}
		var p v2DeliverPayload
		if err := json.Unmarshal(m.Payload, &p); err != nil {
			continue
		}
		if p.KeyWrap.Wrapped != "" {
			return &p
		}
	}
	return nil
}

// TestDeliver_V2_ReWrapsCEKToAntecedentBuyer_NotPayloadDecoy is the primary
// done-gate: the emitted deliver re-wraps the CEK to the ANTECEDENT-chain buyer
// (assertions a + b), NOT to the decoy pubkey planted in the trigger, and never
// carries content/ciphertext.
func TestDeliver_V2_ReWrapsCEKToAntecedentBuyer_NotPayloadDecoy(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, seller, buyer := useSecpIdentities(t, h)

	// A different key used ONLY as the decoy in the trigger payload.
	decoy, err := identity.Generate()
	if err != nil {
		t.Fatalf("decoy identity: %v", err)
	}

	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
	})

	deliverTrigger, entryID, cek := driveV2Deliver(t, h, eng, seller, operator, decoy.PubKeyHex())

	deliverRec, _ := h.st.GetMessage(deliverTrigger.ID)
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("DispatchForTest deliver: %v", err)
	}

	p := findV2DeliverPayload(t, h)
	if p == nil {
		t.Fatal("operator emitted no v2 (key_wrap) deliver payload")
	}

	// ── (a) recipient == antecedent MatchBuyerKey, NOT the decoy; no leak fields ──
	if p.KeyWrap.Recipient != buyer.PubKeyHex() {
		t.Fatalf("key_wrap.recipient = %q, want antecedent buyer %q", p.KeyWrap.Recipient, buyer.PubKeyHex())
	}
	if p.KeyWrap.Recipient == decoy.PubKeyHex() {
		t.Fatal("key_wrap.recipient == the DECOY payload pubkey — the wrap bound to a payload field, not the antecedent chain (§4.5.4 broken)")
	}
	if p.Content != "" {
		t.Fatalf("deliver payload carries a content field (%d bytes) — the deliver-side plaintext leak is NOT closed", len(p.Content))
	}
	if p.Ciphertext != "" {
		t.Fatal("deliver payload carries a ciphertext field — deliver must reference the public put-event ciphertext, never carry it")
	}
	if p.V != 2 || p.ContentAlg != "chacha20poly1305" || p.KeyWrap.Alg != "nip44-v2-secp256k1" {
		t.Fatalf("deliver envelope shape wrong: v=%d content_alg=%q key_wrap.alg=%q", p.V, p.ContentAlg, p.KeyWrap.Alg)
	}
	if p.EntryID != entryID {
		t.Fatalf("deliver entry_id = %q, want %q", p.EntryID, entryID)
	}
	// ciphertext_ref must point at the put event (inline Phase-1 path).
	var ref struct {
		PutEvent    string `json:"put_event"`
		BlobPointer string `json:"blob_pointer"`
	}
	if err := json.Unmarshal(p.CiphertextRef, &ref); err != nil {
		t.Fatalf("unmarshal ciphertext_ref: %v", err)
	}
	if ref.PutEvent == "" {
		t.Fatalf("ciphertext_ref.put_event empty — buyer cannot locate the inline ciphertext; ref=%s", p.CiphertextRef)
	}

	// ── (b) the paying buyer unwraps the SAME CEK the seller generated ──
	got, err := nip44.Open(buyer, operator.PubKeyHex(), p.KeyWrap.Wrapped)
	if err != nil {
		t.Fatalf("paying buyer could NOT unwrap the delivered CEK: %v", err)
	}
	if string(got) != string(cek) {
		t.Fatalf("unwrapped CEK != original CEK\n got  %x\n want %x", got, cek)
	}
}

// TestDeliver_V2_ReplayToOtherBuyerIsUndecryptable is the anti-replay binding
// proof (assertion c): the SAME emitted wrap, replayed toward a DIFFERENT buyer
// key, is undecryptable by that other buyer — the recipient key is the binding.
func TestDeliver_V2_ReplayToOtherBuyerIsUndecryptable(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, seller, buyer := useSecpIdentities(t, h)

	// A different (unfunded) buyer who intercepts the deliver and tries to open it.
	otherBuyer, err := identity.Generate()
	if err != nil {
		t.Fatalf("other buyer identity: %v", err)
	}

	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
	})

	deliverTrigger, _, cek := driveV2Deliver(t, h, eng, seller, operator, otherBuyer.PubKeyHex())
	deliverRec, _ := h.st.GetMessage(deliverTrigger.ID)
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("DispatchForTest deliver: %v", err)
	}

	p := findV2DeliverPayload(t, h)
	if p == nil {
		t.Fatal("operator emitted no v2 deliver payload")
	}

	// The wrap was sealed to the paying buyer, so the paying buyer CAN open it …
	if got, err := nip44.Open(buyer, operator.PubKeyHex(), p.KeyWrap.Wrapped); err != nil || string(got) != string(cek) {
		t.Fatalf("sanity: paying buyer must be able to open the wrap (err=%v)", err)
	}
	// … but the OTHER buyer, doing ECDH with their own key, derives a different
	// conversation key ⇒ the HMAC verify fails ⇒ Open returns an error. This is
	// the anti-replay binding: capturing the deliver and pointing it at a
	// different (unfunded) buyer yields ciphertext they cannot decrypt.
	if got, err := nip44.Open(otherBuyer, operator.PubKeyHex(), p.KeyWrap.Wrapped); err == nil {
		t.Fatalf("REPLAY-TO-OTHER-BUYER BROKEN: a different buyer opened the wrapped CEK and got %x — the recipient key is not binding", got)
	}
}

// TestDeliver_V2_NoReservation_NoDeliver is assertion (d): on team tier
// (ScripStore != nil) with NO live scrip reservation, the operator emits NO
// deliver at all. The existing money-integrity gate (engine_settle.go:994-1000)
// fires BEFORE the re-wrap, so an unfunded buyer never receives a wrapped CEK.
func TestDeliver_V2_NoReservation_NoDeliver(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, seller, buyer := useSecpIdentities(t, h)

	// Team tier: fund the buyer with a TINY amount, far below any price, so the
	// buyer-accept hold fails and NO reservation is ever saved. Mint BEFORE the
	// scrip store is constructed so its Replay sees the balance.
	addScripMintMsg(t, h, buyer.PubKeyHex(), 10)
	cs := newCampfireScripStore(t, h)

	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
		o.ScripStore = cs
	})

	deliverTrigger, _, _ := driveV2Deliver(t, h, eng, seller, operator, buyer.PubKeyHex())

	// Snapshot settle-count before the deliver dispatch: the gate must add none.
	preDelivers := findV2DeliverPayload(t, h)
	if preDelivers != nil {
		t.Fatal("a v2 deliver was emitted before the deliver dispatch — unexpected")
	}

	deliverRec, _ := h.st.GetMessage(deliverTrigger.ID)
	if err := eng.DispatchForTest(exchange.FromStoreRecord(deliverRec)); err != nil {
		t.Fatalf("DispatchForTest deliver: %v", err)
	}

	// No reservation ⇒ NO deliver (no key_wrap payload, no content).
	if p := findV2DeliverPayload(t, h); p != nil {
		t.Fatal("FREE-CEK LEAK: operator emitted a wrapped-CEK deliver for a buyer with NO live reservation (§3.7 gate bypassed)")
	}
}
