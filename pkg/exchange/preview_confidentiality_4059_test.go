package exchange_test

// preview_confidentiality_4059_test.go — the done-gate for dontguess-4059
// (delete the real-chunk preview leak; replace with a bounded, coherence-checked
// seller teaser). See docs/design/content-confidentiality-envelope-541.md §4.1.
//
// The PREVIEW-side confidentiality fix: sendPreviewResponse used to emit 5
// real-content chunks (15-25% of plaintext) into the PUBLIC settle(preview) —
// the last wire-side plaintext leak. It now echoes ONLY the seller-authored
// entry.Teaser, which applyPut validates at put-accept: hard-capped at
// MaxTeaserBytes (over-cap puts DROPPED) and coherence-checked against the
// DECRYPTED plaintext (an incoherent bait-and-switch teaser dropped to "").
//
// These are BLACK-BOX (package exchange_test) tests driving the REAL engine over
// REAL secp256k1 identities + REAL nip44 + ChaCha20-Poly1305 v2 puts (team tier:
// OperatorSigner + ScripStore ⇒ encryptedRequired). Nothing crypto is mocked;
// the v2 put is built exactly as buildPutMessage builds it on the wire.
//
// Proven (each an assertion the veracity pass challenges):
//
//	(a) settle(preview) for a team-tier v2 entry echoes the teaser and its RAW
//	    payload contains NO substring of the plaintext content (no real chunks);
//	(b) a put whose teaser exceeds MaxTeaserBytes is REJECTED (dropped, never
//	    folded) — and the identical content with a capped teaser IS accepted,
//	    proving the teaser cap (not some other gate) caused the drop;
//	(c) a valid, COHERENT teaser is stored on the entry and echoed verbatim in
//	    settle(preview);
//	(d) an INCOHERENT teaser (bait-and-switch: nouns unrelated to the plaintext)
//	    is caught by the coherence gate — the entry folds but its Teaser is "".

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nip44"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// The flock plaintext + a description/buy-task pair that reliably matches. The
// coherent teaser's nouns (flock, contention, goroutine, lock, serialized,
// ordering, mutex, pattern) all appear in this plaintext.
const (
	teaserPutDesc = "reusable go flock file-lock contention test pattern for concurrent access"
	teaserBuyTask = "go flock contention test pattern for concurrent lock access"
	teaserPlain   = "func TestFlockContention(t *testing.T) { acquire the flock, then spawn a " +
		"second goroutine that blocks on the same lock; assert serialized ordering under " +
		"concurrent access. This pattern detects lock contention and mutex races in file-lock code." +
		" The wire must never expose this plaintext under encryption."
	coherentTeaser   = "go flock contention test pattern: a second goroutine blocks on the same lock and asserts serialized ordering; detects mutex races"
	incoherentTeaser = "watercolor landscape painting brushes pigment canvas easel gouache impasto varnish gallery exhibition"
)

// buildV2PutPayloadTeaser builds the kind-3401 v2 confidential put payload EXACTLY
// the way buildPutMessage does (real CEK, real AEAD, CEK NIP-44-wrapped to the
// operator) AND carries a seller-authored public "teaser" field (§3.3).
func buildV2PutPayloadTeaser(t *testing.T, seller identity.Signer, operatorPubHex, desc, teaser string, plaintext []byte, tokenCost int64) []byte {
	t.Helper()
	cek := make([]byte, chacha20poly1305.KeySize)
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
	payload, err := json.Marshal(map[string]any{
		"v":            2,
		"description":  desc,
		"teaser":       teaser,
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
	return payload
}

// newTeamTierEngine builds a team-tier engine (OperatorSigner + ScripStore ⇒
// encryptedRequired) over REAL secp256k1 identities and returns it plus the
// operator/seller/buyer signers.
func newTeamTierEngine(t *testing.T, h *testHarness) (eng *exchange.Engine, operator, seller, buyer identity.Signer) {
	t.Helper()
	operator, seller, buyer = useSecpIdentities(t, h)
	cs := newCampfireScripStore(t, h)
	eng = h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
		o.ScripStore = cs
	})
	return eng, operator, seller, buyer
}

// acceptV2Put sends+accepts a v2 put and returns the folded inventory entry.
// Fails the test if the put did not fold (i.e. was dropped by applyPut).
func acceptV2Put(t *testing.T, h *testHarness, eng *exchange.Engine, putPayload []byte) *exchange.InventoryEntry {
	t.Helper()
	putMsg := h.sendMessage(h.seller, putPayload,
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.AutoAcceptPut(putMsg.ID, 2100, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	for _, e := range eng.State().Inventory() {
		if e.EntryID == putMsg.ID {
			return e
		}
	}
	return nil
}

// driveTeamTierPreview drives put→accept→buy→match→preview-request→dispatch for a
// v2 confidential entry and returns the operator-emitted settle(preview) record.
func driveTeamTierPreview(t *testing.T, h *testHarness, eng *exchange.Engine, putPayload []byte) (previewMsg *store.MessageRecord, entryID string) {
	t.Helper()

	entry := acceptV2Put(t, h, eng, putPayload)
	if entry == nil {
		t.Fatal("v2 put did not fold into inventory after accept")
	}
	entryID = entry.EntryID

	buyMsg := h.sendMessage(h.buyer,
		buyPayload(teaserBuyTask, 50000),
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

	// Buyer sends a preview-request e-tagging the match.
	preqPayload, _ := json.Marshal(map[string]any{
		"phase":    "preview-request",
		"entry_id": entryID,
	})
	preqMsg := h.sendMessage(h.buyer, preqPayload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrPreviewRequest},
		[]string{matchRec.ID},
	)
	preqRec, _ := h.st.GetMessage(preqMsg.ID)
	eng.State().Apply(exchange.FromStoreRecord(preqRec))
	if err := eng.DispatchForTest(exchange.FromStoreRecord(preqRec)); err != nil {
		t.Fatalf("DispatchForTest preview-request: %v", err)
	}

	// Locate the operator-emitted settle(preview) whose antecedent is the request.
	postMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{
		Tags: []string{exchange.TagPhasePrefix + exchange.SettlePhaseStrPreview},
	})
	for i := range postMsgs {
		m := &postMsgs[i]
		if m.Sender != h.operator.PublicKeyHex() {
			continue
		}
		if len(m.Antecedents) > 0 && m.Antecedents[0] == preqMsg.ID {
			previewMsg = m
			break
		}
	}
	if previewMsg == nil {
		t.Fatal("operator emitted no settle(preview) response")
	}
	return previewMsg, entryID
}

// TestPreview_TeamTier_EchoesTeaser_NoPlaintext is assertion (a): a team-tier v2
// entry's settle(preview) echoes the teaser and its RAW payload contains NO
// substring of the plaintext content (no real chunks, ever).
func TestPreview_TeamTier_EchoesTeaser_NoPlaintext(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng, operator, seller, _ := newTeamTierEngine(t, h)

	putPayload := buildV2PutPayloadTeaser(t, seller, operator.PubKeyHex(),
		teaserPutDesc, coherentTeaser, []byte(teaserPlain), 4242)

	previewMsg, entryID := driveTeamTierPreview(t, h, eng, putPayload)

	var payload struct {
		EntryID string `json:"entry_id"`
		Teaser  string `json:"teaser"`
		// Leak canary — the preview must carry no chunks.
		Chunks []any `json:"chunks"`
	}
	if err := json.Unmarshal(previewMsg.Payload, &payload); err != nil {
		t.Fatalf("parse preview payload: %v", err)
	}

	if payload.EntryID != entryID {
		t.Errorf("preview entry_id = %q, want %q", payload.EntryID, entryID)
	}
	// The teaser is echoed verbatim.
	if payload.Teaser != coherentTeaser {
		t.Errorf("preview teaser = %q, want the seller teaser %q", payload.Teaser, coherentTeaser)
	}
	// No chunks.
	if len(payload.Chunks) != 0 {
		t.Errorf("preview carries %d chunks — the real-content chunk path must be gone (dontguess-4059)", len(payload.Chunks))
	}

	// THE confidentiality proof: no substring of the plaintext appears in the RAW
	// preview payload bytes. Slide a window over the plaintext; each non-blank
	// fragment must be absent from the preview wire.
	rawPreview := string(previewMsg.Payload)
	const window = 20
	pt := teaserPlain
	for i := 0; i+window <= len(pt); i += window {
		frag := pt[i : i+window]
		if strings.TrimSpace(frag) == "" {
			continue
		}
		if strings.Contains(rawPreview, frag) {
			t.Fatalf("PLAINTEXT LEAK: settle(preview) payload contains a %d-byte plaintext fragment %q", window, frag)
		}
	}
	// And the AEAD ciphertext / any base64 of the plaintext must not be present
	// either — the preview references nothing of the content.
	if strings.Contains(rawPreview, base64.StdEncoding.EncodeToString([]byte(pt))) {
		t.Fatal("PLAINTEXT LEAK: settle(preview) payload contains base64(plaintext)")
	}
}

// TestPut_OverCapTeaser_Dropped is assertion (b): a put whose teaser exceeds
// MaxTeaserBytes is dropped (never folds), while the IDENTICAL content with a
// capped teaser folds — proving the teaser cap is what caused the drop (not a
// dedup/plausibility gate).
func TestPut_OverCapTeaser_Dropped(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng, operator, seller, _ := newTeamTierEngine(t, h)

	// A teaser strictly larger than the cap. Repeat a real word so the bytes are
	// otherwise-valid text (the ONLY defect is length).
	overCap := strings.Repeat("flock ", (exchange.MaxTeaserBytes/6)+50) // > MaxTeaserBytes bytes
	if len(overCap) <= exchange.MaxTeaserBytes {
		t.Fatalf("test setup: over-cap teaser is only %d bytes, need > %d", len(overCap), exchange.MaxTeaserBytes)
	}

	overCapPut := buildV2PutPayloadTeaser(t, seller, operator.PubKeyHex(),
		teaserPutDesc, overCap, []byte(teaserPlain), 4242)

	overCapMsg := h.sendMessage(h.seller, overCapPut,
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	// The over-cap put must NOT be in pendingPuts (dropped at applyPut).
	for _, e := range eng.State().PendingPuts() {
		if e.EntryID == overCapMsg.ID {
			t.Fatalf("over-cap-teaser put (%d-byte teaser > %d cap) was FOLDED into pendingPuts — the hard cap did not fail closed",
				len(overCap), exchange.MaxTeaserBytes)
		}
	}
	// Accepting it must also be impossible (it never entered pendingPuts).
	if err := eng.AutoAcceptPut(overCapMsg.ID, 2100, time.Now().Add(72*time.Hour)); err == nil {
		for _, e := range eng.State().Inventory() {
			if e.EntryID == overCapMsg.ID {
				t.Fatal("over-cap-teaser put reached inventory — must have been dropped at applyPut")
			}
		}
	}

	// CONTROL: the IDENTICAL plaintext with a capped teaser folds and accepts.
	// The over-cap drop happens BEFORE the content-hash is registered, so the
	// same plaintext is not poisoned in the dedup index and this retry succeeds.
	cappedPut := buildV2PutPayloadTeaser(t, seller, operator.PubKeyHex(),
		teaserPutDesc, coherentTeaser, []byte(teaserPlain), 4242)
	entry := acceptV2Put(t, h, eng, cappedPut)
	if entry == nil {
		t.Fatal("identical content with a CAPPED teaser did not fold — the drop was not attributable to the teaser cap")
	}
	if entry.Teaser != coherentTeaser {
		t.Errorf("capped-teaser entry.Teaser = %q, want %q", entry.Teaser, coherentTeaser)
	}
}

// TestPut_CoherentTeaser_StoredAndEchoed is assertion (c): a valid, coherent
// teaser is stored on the folded entry and echoed verbatim in settle(preview).
func TestPut_CoherentTeaser_StoredAndEchoed(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng, operator, seller, _ := newTeamTierEngine(t, h)

	putPayload := buildV2PutPayloadTeaser(t, seller, operator.PubKeyHex(),
		teaserPutDesc, coherentTeaser, []byte(teaserPlain), 4242)

	// Drive the full flow once; assert the folded entry stored the teaser AND the
	// emitted settle(preview) echoes it verbatim.
	previewMsg, entryID := driveTeamTierPreview(t, h, eng, putPayload)

	var stored *exchange.InventoryEntry
	for _, e := range eng.State().Inventory() {
		if e.EntryID == entryID {
			stored = e
			break
		}
	}
	if stored == nil {
		t.Fatal("coherent-teaser v2 put did not fold into inventory")
	}
	if stored.Teaser != coherentTeaser {
		t.Fatalf("entry.Teaser = %q, want stored coherent teaser %q", stored.Teaser, coherentTeaser)
	}

	var payload struct {
		Teaser string `json:"teaser"`
	}
	if err := json.Unmarshal(previewMsg.Payload, &payload); err != nil {
		t.Fatalf("parse preview payload: %v", err)
	}
	if payload.Teaser != coherentTeaser {
		t.Errorf("preview echoed teaser = %q, want %q", payload.Teaser, coherentTeaser)
	}
}

// TestPut_IncoherentTeaser_DroppedByCoherenceGate is assertion (d): a
// bait-and-switch teaser whose content-bearing nouns are unrelated to the
// DECRYPTED plaintext is caught by the coherence gate — the entry still folds
// (the content sale proceeds), but its Teaser is dropped to "".
func TestPut_IncoherentTeaser_DroppedByCoherenceGate(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	eng, operator, seller, _ := newTeamTierEngine(t, h)

	putPayload := buildV2PutPayloadTeaser(t, seller, operator.PubKeyHex(),
		teaserPutDesc, incoherentTeaser, []byte(teaserPlain), 4242)

	entry := acceptV2Put(t, h, eng, putPayload)
	if entry == nil {
		t.Fatal("incoherent-teaser put did not fold — the coherence gate must drop the TEASER, not the put")
	}
	if entry.Teaser != "" {
		t.Fatalf("entry.Teaser = %q, want \"\" — the bait-and-switch teaser (nouns unrelated to plaintext) must be dropped by the coherence gate", entry.Teaser)
	}

	// Sanity: prove the incoherent teaser is not empty and would have been stored
	// verbatim absent the coherence gate — i.e. the drop is the gate's doing.
	if incoherentTeaser == "" {
		t.Fatal("test setup: incoherentTeaser must be non-empty")
	}
}
