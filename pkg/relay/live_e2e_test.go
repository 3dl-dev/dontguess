package relay_test

// live_e2e_test.go — dontguess-13f: the LIVE M2 end-to-end proof that the merged
// relay transport works over the wire against a REAL strfry relay.
//
// It is ENV-GATED exactly like ready's live relay tests: it t.Skip()s unless
// DONTGUESS_LIVE_RELAY=1, so normal CI (which cannot reach the relay) skips it
// cleanly. Run it live with:
//
//	export DONTGUESS_LIVE_RELAY=1
//	go test ./pkg/relay/ -run LiveRelay -v
//
// Config (env, with defaults):
//
//	DONTGUESS_LIVE_RELAY      "1" to run; anything else skips
//	DONTGUESS_LIVE_RELAY_URL  relay ws:// URL   (default ws://192.168.2.40:7777)
//	DONTGUESS_LIVE_RELAY_KEY  operator priv-hex (default ~/.dontguess/nostr-operator.key)
//
// WHAT IT PROVES (docs/design/relay-transport.md §2.3/§2.4/§2.4a/§2.5):
//
// Two nodes share ONE real relay, using ONLY the admitted operator key for
// writes (the relay's writePolicy allowlist admits exactly that pubkey):
//
//   - NODE A = the operator. A real exchange.Engine (WriteClient=nil + a
//     LocalStore) drives a full put -> put-accept -> buy -> match ->
//     buyer-accept(scrip hold) -> deliver loop. Seller/buyer events are INJECTED
//     locally at A (Origin="relay") — they are NOT written to the relay (only the
//     operator key is allowlisted). The merged Outbox publish leg then re-signs
//     and publishes A's operator-authored records to the REAL relay.
//
//   - NODE B = a FRESH receiver: a new exchange.Sequencer + a fresh LocalStore +
//     the merged Intake ingest leg. B SUBSCRIBES to the relay, ingests A's
//     published operator events straight off the wire, and folds them. B
//     RECONSTRUCTS the operator's authoritative decisions from the relay stream:
//     the MATCH exists, the SETTLE(deliver) delivered the content, and SCRIP
//     MOVED (the buyer's scrip-buy-hold). Because the relay write-allowlist bars
//     the seller/buyer events from the wire, B seeds its Sequencer with those
//     locally-injected antecedent ids (exactly Sequencer.MarkEmitted's
//     checkpoint-recovery purpose) so the operator events' causal chain closes.
//
//   - PHYSICAL LANDING: a fresh REQ ["ids", …] re-fetches A's published event ids
//     from the relay and confirms every one comes back — proving the events
//     physically traversed the relay, not a local-only path.
//
// INTEROP: strfry OFFERS NIP-42 AUTH but does not REQUIRE it for writes (it gates
// writes by BIP-340 sig + a writePolicy author allowlist and pushes no AUTH
// challenge). The default relay.Conn handshake blocks forever waiting for that
// challenge, so both connections use relay.WithoutClientAuth() — the interop
// switch added for this item. It weakens nothing on the fold path: the Intake's
// §2.4a universal signature floor and operator-authorship gate stay fully
// enforced below (B verifies every event it ingests).

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/relay"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// --- config / gating ---------------------------------------------------------

func liveRelayConfig(t *testing.T) (url string, signer identity.Signer) {
	t.Helper()
	if os.Getenv("DONTGUESS_LIVE_RELAY") != "1" {
		t.Skip("DONTGUESS_LIVE_RELAY != 1 — skipping live relay e2e (normal CI cannot reach the strfry relay)")
	}
	url = os.Getenv("DONTGUESS_LIVE_RELAY_URL")
	if url == "" {
		url = "ws://192.168.2.40:7777"
	}
	keyPath := os.Getenv("DONTGUESS_LIVE_RELAY_KEY")
	if keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home dir: %v", err)
		}
		keyPath = filepath.Join(home, ".dontguess", "nostr-operator.key")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read operator key %s: %v", keyPath, err)
	}
	signer, err = identity.FromPrivHex(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("load operator identity from %s: %v", keyPath, err)
	}
	return url, signer
}

// --- small helpers -----------------------------------------------------------

func waitForRec(t *testing.T, ls *dgstore.Store, what string, timeout time.Duration, pred func(dgstore.Record) bool) dgstore.Record {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		recs, err := ls.ReadAll()
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		for _, r := range recs {
			if pred(r) {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
	return dgstore.Record{}
}

func waitForState(t *testing.T, what string, timeout time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

func hasTag(r dgstore.Record, tag string) bool {
	for _, tg := range r.Tags {
		if tg == tag {
			return true
		}
	}
	return false
}

// signedIDOf re-derives the SIGNED nostr content-hash id of a persisted operator
// record via the exact ToNostrEvent->SignEvent path the Outbox publishes with.
// The id is a content hash (nonce-independent), so this derivation is byte-equal
// to the id the Outbox stamped on the wire — that is what lets Node B re-fetch
// the record by id and what makes the re-fetch a real physical-landing proof.
func signedIDOf(t *testing.T, rec dgstore.Record, signer identity.Signer) string {
	t.Helper()
	msg := rec.ToMessage()
	nev, err := nostr.ToNostrEvent(&msg)
	if err != nil {
		t.Fatalf("ToNostrEvent(%s): %v", rec.ID, err)
	}
	ev := &identity.Event{ID: nev.ID, PubKey: nev.PubKey, CreatedAt: nev.CreatedAt, Kind: nev.Kind, Tags: nev.Tags, Content: nev.Content}
	if err := identity.SignEvent(signer, ev); err != nil {
		t.Fatalf("SignEvent(%s): %v", rec.ID, err)
	}
	return ev.ID
}

// toNostr copies a wire identity.Event (carrying the genuine on-wire Schnorr sig)
// into the structurally identical nostr.Event the Intake pipeline verifies and
// folds. The Sig is carried verbatim so the Intake's universal signature floor
// checks the REAL relay-delivered signature.
func toNostr(ev *identity.Event) *nostr.Event {
	return &nostr.Event{ID: ev.ID, PubKey: ev.PubKey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: ev.Tags, Content: ev.Content, Sig: ev.Sig}
}

func livePutPayload(t *testing.T, desc string, tokenCost int64) []byte {
	t.Helper()
	size := int(tokenCost/exchange.MaxTokensPerByte) + 1024
	content := make([]byte, size)
	prefix := []byte("cached inference result: " + desc + " ")
	copy(content, prefix)
	for i := len(prefix); i < size; i++ {
		content[i] = byte('a' + i%26)
	}
	p, err := json.Marshal(map[string]any{
		"description":  desc,
		"content":      base64.StdEncoding.EncodeToString(content),
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
	})
	if err != nil {
		t.Fatalf("marshal put payload: %v", err)
	}
	return p
}

// --- the live e2e ------------------------------------------------------------

func TestLiveRelay_FullExchangeLoop_OverRealRelay(t *testing.T) {
	url, operator := liveRelayConfig(t)
	t.Logf("live relay = %s  operator = %s", url, operator.PubKeyHex())

	seller, _ := identity.Generate()
	buyer, _ := identity.Generate()

	dir := t.TempDir()
	lsA, err := dgstore.Open(filepath.Join(dir, "nodeA.jsonl"))
	if err != nil {
		t.Fatalf("open node A store: %v", err)
	}
	t.Cleanup(func() { _ = lsA.Close() })

	// Node A scrip store (campfire-free, LocalStore-backed) + mint the buyer enough
	// scrip to cover the hold. Minting via AddBudget keeps mint off the relay (only
	// operator match/settle events need to traverse the wire).
	scripStore, err := scrip.NewLocalScripStore(lsA, operator.PubKeyHex())
	if err != nil {
		t.Fatalf("NewLocalScripStore: %v", err)
	}
	if _, _, err := scripStore.AddBudget(context.Background(), buyer.PubKeyHex(), scrip.BalanceKey, 10_000_000, ""); err != nil {
		t.Fatalf("mint buyer scrip: %v", err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        "local",
		LocalStore:        lsA,
		OperatorPublicKey: operator.PubKeyHex(),
		ScripStore:        scripStore,
		PollInterval:      5 * time.Millisecond,
		Logger:            func(string, ...any) {},
	})

	// injectForeign appends a seller/buyer-authored record to A's local log marked
	// Origin="relay" — the marker for "not operator-authored, never republish". The
	// engine still folds+dispatches it; the Outbox skips it (it is not on the
	// allowlist and must not reach the relay).
	injectForeign := func(id, sender string, payload []byte, tags, antecedents []string) {
		if err := lsA.Append(dgstore.Record{
			ID: id, CampfireID: "local", Sender: sender, Payload: payload,
			Tags: tags, Antecedents: antecedents, Timestamp: time.Now().UnixNano(), Origin: "relay",
		}); err != nil {
			t.Fatalf("inject foreign %s: %v", id, err)
		}
	}

	// --- Step 1: seller put (injected locally) + operator put-accept. ---
	putID := newHexID(t)
	injectForeign(putID, seller.PubKeyHex(),
		livePutPayload(t, "Go HTTP handler unit test generator", 8000),
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil)

	if err := eng.AutoAcceptPut(putID, 5600, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry after put-accept, got %d", len(inv))
	}
	entryID := inv[0].EntryID

	// Start the engine: it now folds+dispatches injected buys (-> match) and settle
	// phases (-> scrip hold, deliver) off the local log.
	ctx, cancel := context.WithCancel(context.Background())
	engDone := make(chan struct{})
	go func() { defer close(engDone); _ = eng.Start(ctx) }()

	// --- Step 2: buyer buy (injected) -> operator MATCH. ---
	buyID := newHexID(t)
	injectForeign(buyID, buyer.PubKeyHex(),
		mustJSON(t, map[string]any{"task": "Generate unit tests for a Go HTTP handler accepting JSON POST", "budget": 50000, "max_results": 3}),
		[]string{exchange.TagBuy}, nil)

	// Gate on STATE, not just the log: the match must be APPLIED to engine state
	// before the buyer-accept is injected, or ResolveMatchFromAntecedent silently
	// drops the buyer-accept ("unknown match") with no retry (a match-in-log-but-
	// not-in-state race). IsOrderMatched flips only after the match is folded.
	waitForState(t, "buy order matched in engine state", 20*time.Second, func() bool {
		return eng.State().IsOrderMatched(buyID)
	})
	matchRec := waitForRec(t, lsA, "operator match record", 20*time.Second, func(r dgstore.Record) bool {
		return r.Origin != "relay" && hasTag(r, exchange.TagMatch)
	})
	t.Logf("A emitted match (store id %s)", matchRec.ID)

	// --- Step 3: buyer-accept (injected, references the match) -> scrip HOLD. ---
	buyerAcceptID := newHexID(t)
	injectForeign(buyerAcceptID, buyer.PubKeyHex(),
		mustJSON(t, map[string]any{"phase": exchange.SettlePhaseStrBuyerAccept, "entry_id": entryID, "accepted": true}),
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept, "exchange:verdict:accepted"},
		[]string{matchRec.ID})

	holdRec := waitForRec(t, lsA, "operator scrip-buy-hold record", 20*time.Second, func(r dgstore.Record) bool {
		return r.Origin != "relay" && hasTag(r, scrip.TagScripBuyHold)
	})
	var holdPayload scrip.BuyHoldPayload
	if err := json.Unmarshal(holdRec.Payload, &holdPayload); err != nil {
		t.Fatalf("parse scrip-buy-hold payload: %v", err)
	}
	if holdPayload.Amount <= 0 {
		t.Fatalf("scrip-buy-hold amount = %d, want > 0 (scrip must have moved)", holdPayload.Amount)
	}
	t.Logf("A held scrip: amount=%d reservation=%s", holdPayload.Amount, holdPayload.ReservationID)

	// --- Step 4: operator DELIVER (operator-authored -> published). ---
	contentRef := "sha256:" + fmt.Sprintf("%064x", sha256.Sum256([]byte("delivered-content-"+entryID)))
	deliverID := newHexID(t)
	if err := lsA.Append(dgstore.Record{
		ID: deliverID, CampfireID: "local", Sender: operator.PubKeyHex(),
		Payload: mustJSON(t, map[string]any{
			"phase": exchange.SettlePhaseStrDeliver, "entry_id": entryID,
			"content_ref": contentRef, "content_size": 20000,
		}),
		Tags:        []string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrDeliver},
		Antecedents: []string{buyerAcceptID},
		Timestamp:   time.Now().UnixNano(), Origin: "local",
	}); err != nil {
		t.Fatalf("append operator deliver: %v", err)
	}
	deliverRec := waitForRec(t, lsA, "operator deliver record in log", 5*time.Second, func(r dgstore.Record) bool {
		return r.ID == deliverID
	})

	// Freeze A's log: stop the engine so the Outbox tails a stable set.
	cancel()
	<-engDone

	// --- Step 5: A's Outbox PUBLISHES operator records to the REAL relay. ---
	connA := relay.New(url, operator, relay.WithoutClientAuth())
	t.Cleanup(func() { _ = connA.Close() })
	pub := relay.NewConnPublisher(connA, func(string, ...interface{}) {})
	outbox, err := relay.NewOutbox(lsA, operator, pub, filepath.Join(dir, "nodeA.jsonl.pubcursor"))
	if err != nil {
		t.Fatalf("NewOutbox: %v", err)
	}

	pubCtx, pubCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer pubCancel()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := outbox.Tick(pubCtx); err != nil {
			t.Fatalf("outbox.Tick (publishing operator records to real relay): %v", err)
		}
		if outbox.PublishLag() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox did not drain to the relay: publish_lag=%d after 30s", outbox.PublishLag())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if outbox.Cursor() == 0 {
		t.Fatalf("outbox cursor = 0 — nothing was published+ACKed to the real relay")
	}
	t.Logf("A published+ACKed %d operator record(s) to %s", outbox.Cursor(), url)

	// The three operator records B must reconstruct, keyed by the SIGNED id the
	// Outbox published them under (re-derived deterministically). Each references
	// only a locally-injected foreign antecedent (put/buy/buyer-accept), so B can
	// fold them once those ids are seeded. (The engine's own full-content deliver
	// echo references the injected deliver by store id — an operator->operator edge
	// that a fresh receiver cannot resolve — so B does not fetch it; the injected
	// deliver above already proves "settle delivered the content".)
	matchSignedID := signedIDOf(t, matchRec, operator)
	holdSignedID := signedIDOf(t, holdRec, operator)
	deliverSignedID := signedIDOf(t, deliverRec, operator)
	wantIDs := []string{matchSignedID, holdSignedID, deliverSignedID}

	// --- Step 6: NODE B — fresh receiver folds A's events off the relay. ---
	lsB, err := dgstore.Open(filepath.Join(dir, "nodeB.jsonl"))
	if err != nil {
		t.Fatalf("open node B store: %v", err)
	}
	t.Cleanup(func() { _ = lsB.Close() })

	seqB := exchange.NewSequencer(0)
	// Seed the locally-injected foreign antecedents (barred from the relay by the
	// write-allowlist) so the operator events' causal chain closes at B. This is
	// exactly Sequencer.MarkEmitted's checkpoint-recovery contract.
	seqB.MarkEmitted(putID, buyID, buyerAcceptID)
	metricsB := &relay.IntakeMetrics{}
	intakeB := relay.NewIntake(seqB, lsB, operator.PubKeyHex(), metricsB, func(class string, err error, ev *nostr.Event) {
		t.Logf("B intake drop class=%s err=%v", class, err)
	})

	connB := relay.New(url, operator, relay.WithoutClientAuth())
	t.Cleanup(func() { _ = connB.Close() })
	subEvents := reqByIDs(t, connB, "dg-B-fold", wantIDs, 20*time.Second)
	if len(subEvents) == 0 {
		t.Fatalf("B received no events from its subscription — the operator events did not arrive over the relay")
	}
	for _, ev := range subEvents {
		if err := intakeB.HandleEvent(toNostr(ev)); err != nil {
			// Loud but non-fatal per event: the pipeline counts+alarms each drop.
			t.Logf("B intake HandleEvent(%s) returned: %v", ev.ID, err)
		}
	}
	if got := metricsB.Persisted.Load(); got == 0 {
		t.Fatalf("B persisted 0 records from the relay stream — nothing folded (received=%d)", metricsB.Received.Load())
	}
	t.Logf("B received=%d persisted=%d from the relay stream", metricsB.Received.Load(), metricsB.Persisted.Load())

	// --- B RECONSTRUCTS the operator's authoritative state from the wire. ---
	recsB, err := lsB.ReadAll()
	if err != nil {
		t.Fatalf("B ReadAll: %v", err)
	}
	var foldedMatch, foldedDeliver, foldedHold *dgstore.Record
	for i := range recsB {
		r := recsB[i]
		if r.Origin != "relay" {
			t.Fatalf("B record %s has Origin=%q, want relay (all of B's state came off the wire)", r.ID, r.Origin)
		}
		switch {
		case hasTag(r, exchange.TagMatch):
			foldedMatch = &recsB[i]
		case hasTag(r, scrip.TagScripBuyHold):
			foldedHold = &recsB[i]
		case hasTag(r, exchange.TagSettle) && hasTag(r, exchange.TagPhasePrefix+exchange.SettlePhaseStrDeliver):
			foldedDeliver = &recsB[i]
		}
	}

	// (a) MATCH exists, authored by the operator, and re-fetched under its signed id.
	if foldedMatch == nil {
		t.Fatalf("B did not reconstruct the MATCH from the relay stream")
	}
	if foldedMatch.ID != matchSignedID {
		t.Fatalf("B match id = %s, want signed id %s (must fold under the on-wire content-hash id)", foldedMatch.ID, matchSignedID)
	}
	if foldedMatch.Sender != operator.PubKeyHex() {
		t.Fatalf("B match author = %s, want operator %s", foldedMatch.Sender, operator.PubKeyHex())
	}

	// (b) SETTLE(deliver) delivered the content: the deliver record carries a
	//     content reference reconstructed from the wire.
	if foldedDeliver == nil {
		t.Fatalf("B did not reconstruct the SETTLE(deliver) from the relay stream")
	}
	var dp struct {
		Phase       string `json:"phase"`
		ContentRef  string `json:"content_ref"`
		ContentSize int64  `json:"content_size"`
	}
	if err := json.Unmarshal(foldedDeliver.Payload, &dp); err != nil {
		t.Fatalf("B parse deliver payload: %v", err)
	}
	if dp.ContentRef != contentRef {
		t.Fatalf("B deliver content_ref = %q, want %q (content reference must survive the wire)", dp.ContentRef, contentRef)
	}

	// (c) SCRIP MOVED: the buyer's scrip-buy-hold, with the same amount A held.
	if foldedHold == nil {
		t.Fatalf("B did not reconstruct the SCRIP-BUY-HOLD from the relay stream")
	}
	var bp scrip.BuyHoldPayload
	if err := json.Unmarshal(foldedHold.Payload, &bp); err != nil {
		t.Fatalf("B parse scrip-buy-hold payload: %v", err)
	}
	if bp.Amount != holdPayload.Amount {
		t.Fatalf("B scrip-buy-hold amount = %d, want %d (scrip movement must survive the wire)", bp.Amount, holdPayload.Amount)
	}
	t.Logf("B reconstructed: match=%s deliver.content_ref=%s scrip_held=%d", foldedMatch.ID, dp.ContentRef, bp.Amount)

	// --- Step 7: PHYSICAL-LANDING PROOF — fresh REQ ["ids", …] re-fetch. ---
	connC := relay.New(url, operator, relay.WithoutClientAuth())
	t.Cleanup(func() { _ = connC.Close() })
	refetched := reqByIDs(t, connC, "dg-refetch", wantIDs, 20*time.Second)
	got := map[string]bool{}
	for _, ev := range refetched {
		got[ev.ID] = true
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Fatalf("re-fetch: event %s NOT returned by the relay — it did not physically land", id)
		}
	}
	t.Logf("re-fetch OK: all %d published operator event ids physically present on %s", len(wantIDs), url)
}

// --- wire helpers ------------------------------------------------------------

// reqByIDs issues one REQ over conn filtered to the given event ids and returns
// every EVENT delivered before EOSE (or before the timeout). It drives the SAME
// relay.Conn the production transport uses (with WithoutClientAuth), so a strfry
// that offers-but-does-not-require AUTH is subscribed against exactly as it is in
// production.
func reqByIDs(t *testing.T, conn *relay.Conn, subID string, ids []string, timeout time.Duration) []*identity.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	frame, err := relay.EncodeReq(subID, relay.Filter{IDs: ids})
	if err != nil {
		t.Fatalf("EncodeReq: %v", err)
	}
	if err := conn.Send(ctx, frame); err != nil {
		t.Fatalf("send REQ: %v", err)
	}
	var out []*identity.Event
	for {
		raw, err := conn.Recv(ctx)
		if err != nil {
			// Timeout/deadline ends the read; return what we have so callers assert.
			t.Logf("reqByIDs(%s) recv stopped: %v", subID, err)
			return out
		}
		f, perr := relay.ParseFrame(raw)
		if perr != nil {
			continue // tolerate NOTICE/AUTH/other non-EVENT frames
		}
		switch f.Type {
		case relay.LabelEVENT:
			if f.Event != nil {
				out = append(out, f.Event)
			}
		case relay.LabelEOSE:
			return out
		}
	}
}

func newHexID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
