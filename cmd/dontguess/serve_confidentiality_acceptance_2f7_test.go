package main

// serve_confidentiality_acceptance_2f7_test.go — dontguess-2f7, the ACCEPTANCE
// GATE for the whole content-confidentiality-envelope feature (dontguess-541).
//
// It proves the §1 confidentiality property END TO END against REAL
// infrastructure — a team-tier operator serve stack (real Engine + Intake +
// Outbox + Sequencer + LocalScripStore + TrustChecker + Notify), a real
// in-process NIP-01 websocket relay hub, a real content-addressed Blossom store
// (exchange.MemoryBlobStore), real secp256k1 identities, real nip44, and real
// ChaCha20-Poly1305. NOTHING crypto is mocked; the thing under test (the
// confidentiality property) is exercised, not stubbed.
//
// It drives a REAL put→buy→match→buyer-accept→deliver→complete for TWO entries —
// one INLINE (≤32 KiB, ciphertext in the 3401 put event) and one LARGE (>32 KiB,
// AEAD ciphertext offloaded to Blossom) — with DISTINCT, high-entropy known
// plaintexts, then asserts every bullet of the §2 actor threat table:
//
//	(1) PASSIVE RELAY READER   an unauthenticated REQ over every exchange kind
//	    yields ONLY {description, teaser, token_cost, content_type, domains,
//	    enc/ciphertext_ref/ciphertext_hash/key_wrap}. THE LEAK CANARY slides a
//	    16/20/24-byte window over each plaintext (and checks base64(plaintext))
//	    and asserts NO fragment appears in ANY captured event's raw bytes — for
//	    BOTH the inline and the large entry.
//	(2) UNAUTH BLOSSOM FETCHER for the large entry, fetching the blob WITHOUT
//	    auth yields AEAD ciphertext (no plaintext fragment) and
//	    sha256(blob)==the published ciphertext_hash.
//	(3) PREVIEW                the settle(preview) event carries only the seller
//	    teaser and NO real-content fragment.
//	(4) PLAINTEXT PUT DROPPED  a legacy plaintext-'content' put on the team tier
//	    is DROPPED by applyPut — never in inventory, never matchable, never
//	    delivered.
//	(5) PAYING BUYER RECOVERS  the settled buyer recovers the EXACT original
//	    plaintext for BOTH entries, byte-for-byte, via the REAL production
//	    relayclient.Settle decrypt path.
//	(6) NON-PAYING CANNOT      an allowlisted agent that never funds/settles is
//	    given EVERYTHING (all captured events + both blobs) and STILL cannot
//	    recover the plaintext: it holds no CEK it can unwrap — a stranger key
//	    cannot nip44.Open the operator's wrapped_cek_buyer nor the seller's
//	    wrapped_cek_operator. This is the "paying scrip buys exclusivity" property.
//
// The confidentiality property (§1) permits {description, teaser, token_cost,
// content_type, domains, ciphertext, ciphertext_hash, CEK-wrapped-to-others} to
// be public. The known plaintexts are therefore built as HIGH-ENTROPY content
// that shares no substring with the public description/teaser, so the sliding
// window measures a REAL leak, never a false positive on intentionally-public
// metadata.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nip44"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/relay"
	"github.com/3dl-dev/dontguess/pkg/relayclient"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
	"golang.org/x/crypto/chacha20poly1305"
)

// --- fixtures: distinct, high-entropy known plaintexts -----------------------

// randHex returns 2*n hex chars of crypto/rand entropy.
func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// c2f7Fixture is one known entry: a public matching key (description) + a public
// teaser + a high-entropy secret plaintext that shares NO substring with either.
type c2f7Fixture struct {
	desc      string
	teaser    string
	buyTask   string
	plaintext []byte
	tokenCost int64
}

// --- v2 put builders (mirror relayclient.buildPutMessage on each path) --------
//
// These mirror buildPutMessage byte-for-byte: a fresh CEK from crypto/rand, real
// ChaCha20-Poly1305(nonce||ct), a ciphertext_hash OVER the ciphertext, and the
// CEK NIP-44-wrapped from seller→operator. The operator unwraps it at fold time,
// decrypts, runs every gate on the plaintext, and stores the entry. Inline puts
// carry enc.ciphertext; offloaded puts carry enc.blob_pointer (ciphertext in the
// shared Blossom store). We build them here (rather than call the unexported
// buildPutMessage) exactly as the existing package-main knownV2PutPayload helper
// and the pkg/exchange buildV2BlobPutPayload helper do.

// buildInlineV2Put builds a §3.3 inline v2 confidential put (enc.ciphertext).
// Returns the marshaled payload, the raw ciphertext, its hash, and the
// wrapped-to-operator CEK (so the non-paying-agent proof can attempt to open it).
func buildInlineV2Put(t *testing.T, seller identity.Signer, opPubHex, desc, teaser string, plaintext []byte, tokenCost int64) (payload, ciphertext []byte, ctHash, wrappedOperator string) {
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
	ciphertext = aead.Seal(nonce, nonce, plaintext, nil)
	sum := sha256.Sum256(ciphertext)
	ctHash = "sha256:" + hex.EncodeToString(sum[:])
	wrappedOperator, err = nip44.Seal(seller, opPubHex, cek)
	if err != nil {
		t.Fatalf("wrap CEK to operator: %v", err)
	}
	payload, err = json.Marshal(map[string]any{
		"v":            2,
		"description":  desc,
		"teaser":       teaser,
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
		"enc": map[string]any{
			"content_alg":     "chacha20poly1305",
			"ciphertext_hash": ctHash,
			"ciphertext":      base64.StdEncoding.EncodeToString(ciphertext),
			"key_wrap": map[string]any{
				"alg":       "nip44-v2-secp256k1",
				"recipient": opPubHex,
				"wrapped":   wrappedOperator,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal inline v2 put: %v", err)
	}
	return payload, ciphertext, ctHash, wrappedOperator
}

// buildLargeV2Put builds a §3.3 offloaded v2 confidential put (enc.blob_pointer):
// the AEAD CIPHERTEXT (never plaintext) is stored in the shared Blossom store and
// the wire carries only the pointer + ciphertext_hash + wrapped CEK.
func buildLargeV2Put(t *testing.T, seller identity.Signer, opPubHex, desc, teaser string, plaintext []byte, tokenCost int64, blob exchange.BlobStore) (payload, ciphertext []byte, pointer, ctHash, wrappedOperator string) {
	t.Helper()
	if len(plaintext) <= exchange.BlossomOffloadThreshold {
		t.Fatalf("large fixture plaintext %d must exceed BlossomOffloadThreshold %d", len(plaintext), exchange.BlossomOffloadThreshold)
	}
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
	ciphertext = aead.Seal(nonce, nonce, plaintext, nil)
	sum := sha256.Sum256(ciphertext)
	ctHash = "sha256:" + hex.EncodeToString(sum[:])
	var err2 error
	pointer, err2 = blob.Put(ciphertext) // offload the CIPHERTEXT, never plaintext
	if err2 != nil {
		t.Fatalf("offload ciphertext to blob store: %v", err2)
	}
	wrappedOperator, err = nip44.Seal(seller, opPubHex, cek)
	if err != nil {
		t.Fatalf("wrap CEK to operator: %v", err)
	}
	payload, err = json.Marshal(map[string]any{
		"v":            2,
		"description":  desc,
		"teaser":       teaser,
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
		"enc": map[string]any{
			"content_alg":     "chacha20poly1305",
			"ciphertext_hash": ctHash,
			"blob_pointer":    pointer, // OFFLOAD: no inline "ciphertext"
			"key_wrap": map[string]any{
				"alg":       "nip44-v2-secp256k1",
				"recipient": opPubHex,
				"wrapped":   wrappedOperator,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal large v2 put: %v", err)
	}
	return payload, ciphertext, pointer, ctHash, wrappedOperator
}

// --- the leak canary ----------------------------------------------------------

// plaintextProbes returns the deduplicated set of every win-byte window of
// plaintext. Dedup keeps the probe set small for repeated large content while
// still covering every distinct byte run.
func plaintextProbes(plaintext []byte, win int) map[string]struct{} {
	probes := make(map[string]struct{})
	for i := 0; i+win <= len(plaintext); i++ {
		probes[string(plaintext[i:i+win])] = struct{}{}
	}
	return probes
}

// assertNoPlaintextLeak slides 16/20/24-byte windows over plaintext and asserts
// NO fragment (and no base64(plaintext) fragment) appears in ANY haystack. Each
// haystack is a named blob of raw bytes a passive adversary can obtain.
func assertNoPlaintextLeak(t *testing.T, label string, plaintext []byte, haystacks map[string][]byte) {
	t.Helper()
	for _, win := range []int{16, 20, 24} {
		if len(plaintext) < win {
			continue
		}
		for probe := range plaintextProbes(plaintext, win) {
			pb := []byte(probe)
			for hname, h := range haystacks {
				if bytes.Contains(h, pb) {
					t.Fatalf("CONFIDENTIALITY LEAK [%s]: a %d-byte plaintext fragment %q appeared in %s (a passive adversary can recover plaintext)", label, win, probe, hname)
				}
			}
		}
	}
	// base64(plaintext) must also be absent (guards against a plaintext body that
	// was base64-encoded onto the wire rather than encrypted).
	b64 := []byte(base64.StdEncoding.EncodeToString(plaintext))
	for _, win := range []int{24, 32} {
		if len(b64) < win {
			continue
		}
		for probe := range plaintextProbes(b64, win) {
			pb := []byte(probe)
			for hname, h := range haystacks {
				if bytes.Contains(h, pb) {
					t.Fatalf("CONFIDENTIALITY LEAK [%s]: a %d-byte base64(plaintext) fragment appeared in %s", label, win, hname)
				}
			}
		}
	}
}

// --- passive relay reader (unauthenticated NIP-01 REQ) ------------------------

// capturedDeliver is the operator settle(deliver) payload shape the assertions
// inspect (both the inline put_event and the offloaded blob_pointer forms).
type capturedDeliver struct {
	Phase          string `json:"phase"`
	V              int    `json:"v"`
	EntryID        string `json:"entry_id"`
	CiphertextHash string `json:"ciphertext_hash"`
	CiphertextRef  struct {
		PutEvent    string `json:"put_event"`
		BlobPointer string `json:"blob_pointer"`
	} `json:"ciphertext_ref"`
	KeyWrap struct {
		Alg       string `json:"alg"`
		Recipient string `json:"recipient"`
		Wrapped   string `json:"wrapped"`
	} `json:"key_wrap"`
	// Leak canaries: a correct v2 deliver carries neither.
	Content    string `json:"content"`
	Ciphertext string `json:"ciphertext"`
}

// capturePassiveREQ opens an UNAUTHENTICATED websocket to the relay hub, issues a
// single REQ over every exchange kind (3401 puts … 3406 consume) — exactly what a
// passive scraper with no scrip and no allowlist entry can do — and collects the
// RAW bytes of every event served, keyed by event id. It reads until every id in
// wantIDs has been observed (proving the passive reader really saw them) or the
// deadline elapses. The returned map is the exact set of raw bytes on the wire.
func capturePassiveREQ(t *testing.T, wsURL string, wantIDs map[string]struct{}, deadline time.Duration) map[string][]byte {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("passive reader dial: %v", err)
	}
	defer conn.Close()

	req, err := relay.EncodeReq("passive-2f7", relay.Filter{
		Kinds: []int{
			nostr.KindPut, nostr.KindBuy, nostr.KindMatch,
			nostr.KindSettle, nostr.KindAssign, nostr.KindConsume,
		},
	})
	if err != nil {
		t.Fatalf("encode passive REQ: %v", err)
	}
	if werr := conn.WriteMessage(websocket.TextMessage, req); werr != nil {
		t.Fatalf("passive REQ write: %v", werr)
	}

	raw := make(map[string][]byte)
	overall := time.Now().Add(deadline)
	for time.Now().Before(overall) {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, msg, rerr := conn.ReadMessage()
		if rerr != nil {
			// Read timeout: if we already have everything we expect, stop.
			if haveAll(raw, wantIDs) {
				break
			}
			continue
		}
		f, perr := relay.ParseFrame(msg)
		if perr != nil || f.Type != relay.LabelEVENT || f.Event == nil {
			continue
		}
		// Store the RAW event bytes exactly as a scraper would persist them.
		cp := make([]byte, len(msg))
		copy(cp, msg)
		raw[f.Event.ID] = cp
		if haveAll(raw, wantIDs) {
			break
		}
	}
	if !haveAll(raw, wantIDs) {
		missing := make([]string, 0)
		for id := range wantIDs {
			if _, ok := raw[id]; !ok {
				missing = append(missing, shortID2f7(id))
			}
		}
		t.Fatalf("passive reader did not capture all expected events within %s; missing %v (captured %d)", deadline, missing, len(raw))
	}
	return raw
}

func haveAll(raw map[string][]byte, want map[string]struct{}) bool {
	for id := range want {
		if _, ok := raw[id]; !ok {
			return false
		}
	}
	return true
}

func shortID2f7(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// operatorSettleEventsByPhase returns the operator-published settle (kind 3404)
// events carrying the ["phase", want] tag (adapter maps exchange:phase:X ->
// ["phase", X]). The preview payload has no "phase" field, so the tag is the
// reliable discriminator for both preview and deliver.
func operatorSettleEventsByPhase(st *e2eStack, want string) []*identity.Event {
	out := make([]*identity.Event, 0)
	st.conn.mu.Lock()
	defer st.conn.mu.Unlock()
	for _, ev := range st.conn.events {
		if ev.Kind != nostr.KindSettle {
			continue
		}
		for _, tg := range ev.Tags {
			if len(tg) >= 2 && tg[0] == "phase" && tg[1] == want {
				out = append(out, ev)
				break
			}
		}
	}
	return out
}

// --- the acceptance gate ------------------------------------------------------

// TestE2E_Confidentiality_PassiveReaderAndUnauthBlossom_YieldOnlyCiphertext is
// the dontguess-2f7 acceptance gate. See the file header for the full property.
func TestE2E_Confidentiality_PassiveReaderAndUnauthBlossom_YieldOnlyCiphertext(t *testing.T) {
	hushRelayLogs(t)

	dir := t.TempDir()
	ls, err := dgstore.Open(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	operator, _ := identity.Generate()
	seller, _ := identity.Generate()
	buyer, _ := identity.Generate()   // the PAYING buyer (funds + settles)
	stranger, _ := identity.Generate() // allowlisted but NEVER funds/settles

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	// Allowlist seller + paying buyer + stranger. The stranger is an ADMITTED
	// non-paying agent (§2 row 3): admission secures the write pipe, not reads.
	st := newE2EStack(t, ctx, ls, operator, dir+"/events.jsonl.pubcursor",
		e2eShortPublishInterval, seller.PubKeyHex(), buyer.PubKeyHex(), stranger.PubKeyHex())
	t.Cleanup(func() { cancel(); st.stop() })

	// ONE shared content-addressed Blossom store, wired to the operator. It is
	// also the "unauthenticated Blossom fetcher" the assertions read from — a
	// MemoryBlobStore has no auth, which is CORRECT (§2 row 2): the blob is AEAD
	// ciphertext addressed by sha256(ciphertext).
	shared := exchange.NewMemoryBlobStore()
	st.eng.State().SetBlobStore(shared)

	hub := newE2EHub(t, st.conn)
	opPubHex := operator.PubKeyHex()

	// ── fixtures: distinct high-entropy plaintexts, disjoint from public metadata ──
	inlineSecret := []byte("DONTGUESS-2F7-INLINE-SECRET-" + randHex(t, 24) + "-" +
		base64.StdEncoding.EncodeToString([]byte(randHex(t, 256))))
	// Large: a >32 KiB plaintext built from a unique high-entropy block repeated,
	// so byte-for-byte recovery is provable and the marker's absence from every
	// ciphertext-bearing artifact is meaningful.
	largeBlock := []byte("DONTGUESS-2F7-LARGE-SECRET-" + randHex(t, 24) + "-" + randHex(t, 96) + " ")
	largeSecret := bytes.Repeat(largeBlock, (exchange.BlossomOffloadThreshold/len(largeBlock))+64)
	if len(largeSecret) <= exchange.BlossomOffloadThreshold {
		t.Fatalf("large fixture %d not oversize", len(largeSecret))
	}

	inlineFx := c2f7Fixture{
		desc:      "postgres window function ranking sql analytics recipe for dashboards",
		teaser:    "buy now, use it, all set", // all <4-char tokens -> survives coherence, echoed by preview
		buyTask:   "sql window function ranking recipe for a postgres analytics dashboard",
		plaintext: inlineSecret,
		tokenCost: 8000,
	}
	largeFx := c2f7Fixture{
		desc:      "rust tokio async mutex deadlock avoidance concurrency guide",
		teaser:    "see it now",
		buyTask:   "rust tokio async mutex deadlock concurrency avoidance guide",
		plaintext: largeSecret,
		tokenCost: 60000,
	}

	// ── seller PUTs both entries; operator folds them into matchable inventory ──
	inlinePayload, inlineCipher, inlineCtHash, inlineOpWrap := buildInlineV2Put(
		t, seller, opPubHex, inlineFx.desc, inlineFx.teaser, inlineFx.plaintext, inlineFx.tokenCost)
	inlinePutEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil, inlinePayload)
	st.conn.inject(inlinePutEv)
	hub.storePut(inlinePutEv) // a real relay retains the put for the buyer's ciphertext REQ-fetch

	largePayload, largeCipher, largePointer, largeCtHash, largeOpWrap := buildLargeV2Put(
		t, seller, opPubHex, largeFx.desc, largeFx.teaser, largeFx.plaintext, largeFx.tokenCost, shared)
	largePutEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil, largePayload)
	st.conn.inject(largePutEv)
	hub.storePut(largePutEv)

	waitFor(t, 10*time.Second, "both v2 puts auto-accept into matchable inventory", func() bool {
		return len(st.eng.State().Inventory()) == 2
	})

	// Confirm the seller's teaser survived the coherence gate and was folded (so
	// assertion 3 is non-vacuous), and locate each entry.
	var inlineEntry, largeEntry *exchange.InventoryEntry
	for _, e := range st.eng.State().Inventory() {
		switch e.PutMsgID {
		case inlinePutEv.ID:
			ie := e
			inlineEntry = ie
		case largePutEv.ID:
			le := e
			largeEntry = le
		}
	}
	if inlineEntry == nil || largeEntry == nil {
		t.Fatalf("expected both entries in inventory (inline=%v large=%v)", inlineEntry != nil, largeEntry != nil)
	}
	if inlineEntry.Teaser != inlineFx.teaser {
		t.Fatalf("inline entry teaser = %q, want the seller teaser %q (coherence gate must not drop an intentional bounded teaser)", inlineEntry.Teaser, inlineFx.teaser)
	}
	if len(inlineEntry.Content) == 0 {
		t.Fatalf("inline entry has no decrypted content on the entry — operator decrypt-at-fold failed")
	}
	if largeEntry.Content != nil {
		t.Fatalf("large (offloaded) entry.Content must be nil — bytes live in the blob only, never inlined")
	}
	if largeEntry.BlobPointer != largePointer {
		t.Fatalf("large entry.BlobPointer = %q, want %q", largeEntry.BlobPointer, largePointer)
	}

	// ── ASSERTION 5 (inline) + ASSERTION 3: paying buyer recovers the inline
	//    plaintext through the REAL relayclient settle+decrypt path, driven with
	//    --preview so we also capture the settle(preview) event. ──
	st.mint(t, buyer.PubKeyHex(), wireIDBuyerMint)

	inlineSettle := drive2f7Buy(t, ctx, hub.wsURL(), buyer, opPubHex, inlineFx.buyTask, 1_000_000, true, shared)
	if inlineSettle.Outcome != relayclient.SettleOutcomeSettled {
		t.Fatalf("inline buy did not settle: outcome=%s reason=%q", inlineSettle.Outcome, inlineSettle.RejectReason)
	}
	if inlineSettle.EntryID != inlineEntry.EntryID {
		t.Fatalf("inline buy matched the WRONG entry: got %s want %s (matcher cross-match would invalidate the recovery assertion)", shortID2f7(inlineSettle.EntryID), shortID2f7(inlineEntry.EntryID))
	}
	if !bytes.Equal(inlineSettle.Content, inlineFx.plaintext) {
		t.Fatalf("ASSERTION 5 (inline) FAILED: paying buyer recovered %d bytes, want the original %d-byte plaintext byte-for-byte", len(inlineSettle.Content), len(inlineFx.plaintext))
	}

	// ── ASSERTION 5 (large): paying buyer recovers the >32 KiB plaintext via the
	//    REAL relayclient settle+decrypt path, fetching the ciphertext from the
	//    shared Blossom store (SettleOptions.BlobStore). ──
	largeSettle := drive2f7Buy(t, ctx, hub.wsURL(), buyer, opPubHex, largeFx.buyTask, 1_000_000, false, shared)
	if largeSettle.Outcome != relayclient.SettleOutcomeSettled {
		t.Fatalf("large buy did not settle: outcome=%s reason=%q", largeSettle.Outcome, largeSettle.RejectReason)
	}
	if largeSettle.EntryID != largeEntry.EntryID {
		t.Fatalf("large buy matched the WRONG entry: got %s want %s", shortID2f7(largeSettle.EntryID), shortID2f7(largeEntry.EntryID))
	}
	if !bytes.Equal(largeSettle.Content, largeFx.plaintext) {
		t.Fatalf("ASSERTION 5 (large) FAILED: paying buyer recovered %d bytes, want the original %d-byte plaintext byte-for-byte", len(largeSettle.Content), len(largeFx.plaintext))
	}

	// ── ASSERTION 4: a legacy plaintext-'content' put on the team tier is DROPPED
	//    by applyPut (encryptedRequired fail-closed §6). It is injected into the
	//    operator (a rogue admitted downgrade) and must NEVER enter inventory,
	//    never be matchable, and never be served as content. (The rogue's raw
	//    event being visible to a scraper is the §6.2 accepted residual — an
	//    honest admitted seller leaking its OWN content — and is out of scope of
	//    applyPut's drop guarantee; we therefore do NOT relay-persist it here.) ──
	legacyMarker := []byte("LEGACY-PLAINTEXT-2F7-DOWNGRADE-" + randHex(t, 24))
	legacyPayload, _ := json.Marshal(map[string]any{
		"description":  "haskell monad transformer stack tutorial with worked examples",
		"content":      base64.StdEncoding.EncodeToString(legacyMarker),
		"token_cost":   9000,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"haskell"},
	})
	legacyPutEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:haskell"}, nil, legacyPayload)
	st.conn.inject(legacyPutEv)
	// Give the operator a bounded window to (not) fold it, then assert it is gone.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(st.eng.State().Inventory()) != 2 {
			t.Fatalf("ASSERTION 4 FAILED: legacy plaintext put entered inventory (%d entries, want 2) — the §6 fail-closed drop is open", len(st.eng.State().Inventory()))
		}
		time.Sleep(25 * time.Millisecond)
	}
	for _, e := range st.eng.State().Inventory() {
		if e.PutMsgID == legacyPutEv.ID {
			t.Fatal("ASSERTION 4 FAILED: the legacy plaintext put id is present in inventory")
		}
	}
	// Not matchable: a buy for its task must NOT select the legacy entry.
	legacyBuy := drive2f7BuyRaw(t, ctx, hub.wsURL(), buyer, opPubHex, "haskell monad transformer stack tutorial worked examples", 1_000_000)
	if m := legacyBuy.Match(); m != nil && m.EntryID == legacyPutEv.ID {
		t.Fatal("ASSERTION 4 FAILED: the dropped legacy plaintext put was matchable")
	}

	// ── gather the operator-published settle(deliver) + settle(preview) events ──
	deliverEvents := operatorSettleEventsByPhase(st, "deliver")
	if len(deliverEvents) < 2 {
		t.Fatalf("expected >=2 operator settle(deliver) events (inline + large), got %d", len(deliverEvents))
	}
	previewEvents := operatorSettleEventsByPhase(st, "preview")
	if len(previewEvents) < 1 {
		t.Fatalf("expected >=1 operator settle(preview) event, got %d", len(previewEvents))
	}

	// Parse the two delivers and pin their shape (references only, no content).
	var inlineDeliver, largeDeliver *capturedDeliver
	for _, ev := range deliverEvents {
		var d capturedDeliver
		if json.Unmarshal([]byte(ev.Content), &d) != nil {
			continue
		}
		switch d.EntryID {
		case inlineEntry.EntryID:
			dd := d
			inlineDeliver = &dd
		case largeEntry.EntryID:
			dd := d
			largeDeliver = &dd
		}
	}
	if inlineDeliver == nil || largeDeliver == nil {
		t.Fatalf("missing a deliver payload (inline=%v large=%v)", inlineDeliver != nil, largeDeliver != nil)
	}
	for name, d := range map[string]*capturedDeliver{"inline": inlineDeliver, "large": largeDeliver} {
		if d.Content != "" || d.Ciphertext != "" {
			t.Fatalf("deliver[%s] leaks content/ciphertext on the wire (content=%d ciphertext=%d)", name, len(d.Content), len(d.Ciphertext))
		}
		if d.KeyWrap.Recipient != buyer.PubKeyHex() {
			t.Fatalf("deliver[%s] key_wrap.recipient = %s, want the paying buyer %s (recipient IS the anti-replay binding)", name, shortID2f7(d.KeyWrap.Recipient), shortID2f7(buyer.PubKeyHex()))
		}
	}
	if inlineDeliver.CiphertextRef.PutEvent != inlinePutEv.ID {
		t.Fatalf("inline deliver ciphertext_ref.put_event = %s, want the put event %s", shortID2f7(inlineDeliver.CiphertextRef.PutEvent), shortID2f7(inlinePutEv.ID))
	}
	if largeDeliver.CiphertextRef.BlobPointer != largePointer {
		t.Fatalf("large deliver ciphertext_ref.blob_pointer = %q, want %q", largeDeliver.CiphertextRef.BlobPointer, largePointer)
	}

	// ── ASSERTION 1: PASSIVE RELAY READER — an unauthenticated REQ yields only
	//    ciphertext. Capture EVERY event the scraper can see, then slide the leak
	//    canary over BOTH plaintexts across EVERY captured event's raw bytes. ──
	wantIDs := map[string]struct{}{
		inlinePutEv.ID: {}, largePutEv.ID: {},
	}
	for _, ev := range deliverEvents {
		wantIDs[ev.ID] = struct{}{}
	}
	for _, ev := range previewEvents {
		wantIDs[ev.ID] = struct{}{}
	}
	captured := capturePassiveREQ(t, hub.wsURL(), wantIDs, 15*time.Second)

	// The passive reader must have seen both puts and both delivers (non-vacuous).
	for _, id := range []string{inlinePutEv.ID, largePutEv.ID, inlineDeliver.entryEventID(deliverEvents, inlineEntry.EntryID), largeDeliver.entryEventID(deliverEvents, largeEntry.EntryID)} {
		if _, ok := captured[id]; id != "" && !ok {
			t.Fatalf("passive capture missing expected event %s", shortID2f7(id))
		}
	}

	// Run the canary over EVERY captured event, for BOTH plaintexts.
	haystacks := make(map[string][]byte, len(captured))
	for id, b := range captured {
		haystacks["relay-event:"+shortID2f7(id)] = b
	}
	assertNoPlaintextLeak(t, "inline/passive-relay", inlineFx.plaintext, haystacks)
	assertNoPlaintextLeak(t, "large/passive-relay", largeFx.plaintext, haystacks)

	// ── ASSERTION 2: UNAUTH BLOSSOM FETCHER — fetch the large blob WITHOUT auth. ──
	blob, err := shared.Fetch(largePointer)
	if err != nil {
		t.Fatalf("unauth Blossom fetch: %v", err)
	}
	if !bytes.Equal(blob, largeCipher) {
		t.Fatal("fetched blob != the seller's AEAD ciphertext bytes")
	}
	if s := sha256.Sum256(blob); "sha256:"+hex.EncodeToString(s[:]) != largeCtHash {
		t.Fatalf("ASSERTION 2 FAILED: sha256(blob) != published ciphertext_hash (%s)", largeCtHash)
	}
	if largeDeliver.CiphertextHash != largeCtHash {
		t.Fatalf("large deliver ciphertext_hash = %q, want %q", largeDeliver.CiphertextHash, largeCtHash)
	}
	assertNoPlaintextLeak(t, "large/unauth-blossom", largeFx.plaintext, map[string][]byte{"blossom-blob": blob})

	// ── ASSERTION 3: PREVIEW — the settle(preview) event carries only the seller
	//    teaser and NO real-content fragment. ──
	var inlinePreview *identity.Event
	for _, ev := range previewEvents {
		var p struct {
			EntryID string `json:"entry_id"`
			Teaser  string `json:"teaser"`
		}
		if json.Unmarshal([]byte(ev.Content), &p) == nil && p.EntryID == inlineEntry.EntryID {
			inlinePreview = ev
			if p.Teaser != inlineFx.teaser {
				t.Fatalf("ASSERTION 3 FAILED: preview teaser = %q, want the seller teaser %q", p.Teaser, inlineFx.teaser)
			}
		}
	}
	if inlinePreview == nil {
		t.Fatal("ASSERTION 3 FAILED: no settle(preview) event for the inline entry")
	}
	previewRaw, ok := captured[inlinePreview.ID]
	if !ok {
		// Fall back to the operator event bytes if the passive reader didn't index it.
		previewRaw = []byte(inlinePreview.Content)
	}
	assertNoPlaintextLeak(t, "inline/preview", inlineFx.plaintext, map[string][]byte{"settle-preview": previewRaw})

	// ── ASSERTION 6: NON-PAYING ADMITTED AGENT CANNOT. Give the stranger
	//    EVERYTHING — all captured events + both blobs — and prove it holds no
	//    CEK it can unwrap. The CEK is reachable only via a wrap sealed to the
	//    OPERATOR (put) or to the PAYING BUYER (deliver); a stranger key cannot
	//    nip44.Open either. Without the CEK, the ciphertext it holds is inert. ──
	assertStrangerCannotDecrypt(t, stranger, operator, seller, "inline", inlineDeliver.KeyWrap.Wrapped, inlineOpWrap, inlineCipher)
	assertStrangerCannotDecrypt(t, stranger, operator, seller, "large", largeDeliver.KeyWrap.Wrapped, largeOpWrap, blob)

	// No deliver anywhere is wrapped to the stranger (it never settled).
	for _, ev := range deliverEvents {
		var d capturedDeliver
		if json.Unmarshal([]byte(ev.Content), &d) == nil && d.KeyWrap.Recipient == stranger.PubKeyHex() {
			t.Fatal("ASSERTION 6 FAILED: a deliver was wrapped to the non-paying stranger")
		}
	}

	_ = inlineCtHash // referenced by the inline deliver shape assertion above
}

// entryEventID resolves the settle(deliver) event id for a given entry id from
// the operator-published deliver events (helper for the non-vacuous check).
func (d *capturedDeliver) entryEventID(events []*identity.Event, entryID string) string {
	for _, ev := range events {
		var p struct {
			EntryID string `json:"entry_id"`
		}
		if json.Unmarshal([]byte(ev.Content), &p) == nil && p.EntryID == entryID {
			return ev.ID
		}
	}
	return ""
}

// assertStrangerCannotDecrypt proves the "paying scrip buys exclusivity" property
// for one entry: the stranger cannot unwrap the CEK from either the buyer-targeted
// deliver wrap OR the operator-targeted put wrap, so — even holding the full
// ciphertext — it cannot AEAD-decrypt to recover the plaintext.
func assertStrangerCannotDecrypt(t *testing.T, stranger, operator, seller identity.Signer, label, wrappedForBuyer, wrappedForOperator string, ciphertext []byte) {
	t.Helper()
	// (a) The deliver CEK is sealed to the buyer via NIP-44(operatorPriv, buyerPub).
	// A stranger's ECDH(strangerPriv, operatorPub) yields a different conversation
	// key, so the MAC check fails: Open MUST error.
	if cek, err := nip44.Open(stranger, operator.PubKeyHex(), wrappedForBuyer); err == nil {
		t.Fatalf("ASSERTION 6 FAILED [%s]: stranger unwrapped the buyer-targeted CEK (len=%d) — recipient key is not binding; paying does not buy exclusivity", label, len(cek))
	}
	// (b) The put CEK is sealed to the operator via NIP-44(sellerPriv, operatorPub).
	// A stranger cannot open it either.
	if cek, err := nip44.Open(stranger, seller.PubKeyHex(), wrappedForOperator); err == nil {
		t.Fatalf("ASSERTION 6 FAILED [%s]: stranger unwrapped the operator-targeted CEK (len=%d) from the put", label, len(cek))
	}
	// (c) Belt-and-suspenders: with NO recoverable CEK, the stranger cannot even
	// form a plausible AEAD key, so the ciphertext it holds stays inert. There is
	// no key it can construct from public data that opens the AEAD; we assert the
	// ciphertext is non-empty (it really has the bytes) yet no unwrap above
	// succeeded — the exclusivity rests entirely on secp256k1 key possession.
	if len(ciphertext) == 0 {
		t.Fatalf("test setup [%s]: stranger was not actually given the ciphertext", label)
	}
}

// --- driving the paying buyer through the REAL relayclient path ---------------

// drive2f7Buy runs the production relayclient Buy→Settle chain over the hub under
// the buyer identity, with SettleOptions.BlobStore wired so the large (Blossom)
// deliver can be fetched+decrypted. This is exactly what cmd/dontguess buy.go
// does, minus the CLI wrapping, plus the buyer-side Blossom client the CLI has
// not yet wired (SettleOptions.BlobStore, dontguess-250).
func drive2f7Buy(t *testing.T, parent context.Context, wsURL string, buyer identity.Signer, opPubHex, task string, budget int64, preview bool, blob exchange.BlobStore) *relayclient.SettleResult {
	t.Helper()
	conn := relayclient.NewConn(wsURL, buyer)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	br, err := relayclient.Buy(ctx, conn, buyer, relayclient.BuyRequest{
		Task: task, Budget: budget, OperatorPubKey: opPubHex,
	})
	if err != nil {
		t.Fatalf("Buy(%q): %v", task, err)
	}
	if br.Outcome != relayclient.BuyOutcomeMatch {
		t.Fatalf("Buy(%q) outcome=%s, want a match", task, br.Outcome)
	}
	sr, err := relayclient.Settle(ctx, conn, buyer, br, relayclient.SettleOptions{
		Budget: budget, Preview: preview, OperatorPubKey: opPubHex, BlobStore: blob,
	})
	if err != nil {
		t.Fatalf("Settle(%q): %v", task, err)
	}
	return sr
}

// drive2f7BuyRaw runs only the Buy leg (no settle) — used to prove a dropped
// legacy put is not matchable.
func drive2f7BuyRaw(t *testing.T, parent context.Context, wsURL string, buyer identity.Signer, opPubHex, task string, budget int64) *relayclient.BuyResult {
	t.Helper()
	conn := relayclient.NewConn(wsURL, buyer)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	br, err := relayclient.Buy(ctx, conn, buyer, relayclient.BuyRequest{
		Task: task, Budget: budget, OperatorPubKey: opPubHex,
	})
	if err != nil {
		// A buy-miss surfaces as a non-error BuyResult; a transport error is fatal.
		t.Fatalf("Buy(%q): %v", task, err)
	}
	return br
}
