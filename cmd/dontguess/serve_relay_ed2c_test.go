package main

// serve_relay_ed2c_test.go — the MONEY + H3 PROOF for dontguess-008 (ed2-C, the
// CLIENT settle chain). These package-main tests drive the REAL team stack
// end-to-end THROUGH THE CLIENT: the actual `dontguess buy` RunE (and the
// relayclient.Buy+Settle it calls) publishes a buy over a REAL in-process nostr
// websocket relay to the exact serve-path operator wiring (engine + Intake + Outbox
// + Sequencer + LocalScripStore + wire->store alias + AutoDeliverOnBuyerAccept), and
// drives buyer-accept -> (operator auto-deliver) -> complete to move scrip and
// receive content — in ONE invocation under ONE identity.
//
// Because it is package-main, any edit to buy.go / relayclient wiring invalidates
// the test cache (the H7 cache-gap closure the ed2 design mandates).
//
// The relay hub (ed2cRelayHub) BRIDGES a genuine websocket CLIENT (the production
// relayclient dialer) to the operator's in-process fakeRelayConn: a client EVENT is
// injected into the operator's subscription and ACKed; operator publishes are
// forwarded to each client subscription whose NIP-01 filter MATCHES. That faithful
// #e filter matching is what makes assertion (2) a real H3 proof: settle(deliver)
// and settle(buyer-accept-reject) e-tag the BUYER-ACCEPT wire id, NOT buyID, so a
// client that (wrongly) subscribed #e:[buyID] would receive NEITHER and time out.
// The client subscribes #e:[buyer-accept] per §3.5, so it receives them.
//
// What is REAL vs faked: scrip moves through the REAL exchange engine + REAL
// LocalScripStore (a genuine hold at buyer-accept, a genuine residual credit at
// complete, IsMatchSettled flips durably). Nothing is stubbed but the websocket
// wire itself, exactly as the precedent serve_relay_test.go / serve_relay_wireid_test.go.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/campfire-net/dontguess/pkg/identity"
	"github.com/campfire-net/dontguess/pkg/relay"
	"github.com/campfire-net/dontguess/pkg/relayclient"
	dgstore "github.com/campfire-net/dontguess/pkg/store"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

// setBuyFlags sets cobra flags on a buy command instance (mirrors setPutFlags).
func setBuyFlags(t *testing.T, cmd *cobra.Command, vals map[string]string) {
	t.Helper()
	for k, v := range vals {
		if err := cmd.Flags().Set(k, v); err != nil {
			t.Fatalf("set flag %s=%q: %v", k, v, err)
		}
	}
}

// newClientConn builds a production team-tier client conn (WithoutClientAuth default)
// dialing the hub's ws URL via the real gorilla dialer — the exact path runBuy uses.
func newClientConn(t *testing.T, url string, signer identity.Signer) *relay.Conn {
	t.Helper()
	return relayclient.NewConn(url, signer)
}

// relayclientBuy runs the real client Buy for the ed2c fixture task.
func relayclientBuy(ctx context.Context, conn *relay.Conn, signer identity.Signer) (*relayclient.BuyResult, error) {
	return relayclient.Buy(ctx, conn, signer, relayclient.BuyRequest{
		Task:       ed2cBuyTask,
		Budget:     1_000_000,
		MaxResults: 3,
	})
}

// relayclientSettle runs the real client Settle for the ed2c fixture.
func relayclientSettle(ctx context.Context, conn *relay.Conn, signer identity.Signer, buy *relayclient.BuyResult, preview bool) (*relayclient.SettleResult, error) {
	return relayclient.Settle(ctx, conn, signer, buy, relayclient.SettleOptions{
		Budget:  1_000_000,
		Preview: preview,
	})
}

func assertClientMatch(t *testing.T, buy *relayclient.BuyResult) {
	t.Helper()
	if buy.Outcome != relayclient.BuyOutcomeMatch {
		t.Fatalf("buy outcome = %s, want match", buy.Outcome)
	}
	if buy.MatchMsgID == "" {
		t.Fatalf("match result carries no match wire id")
	}
}

// --- the websocket relay hub (client <-> operator bridge) --------------------

// ed2cClientConn is one live websocket client connection into the hub. It holds the
// client's active NIP-01 subscriptions (subID -> filter) and a per-(subID,eventID)
// forwarded set so an operator publish is delivered to a matching subscription
// exactly once. Two goroutines write to the ws (the read loop's OK acks + the pump's
// forwarded events), so every write is serialised by writeMu.
type ed2cClientConn struct {
	ws        *websocket.Conn
	writeMu   sync.Mutex
	mu        sync.Mutex
	filters   map[string]relay.Filter
	forwarded map[string]bool
	done      chan struct{}
}

func (c *ed2cClientConn) write(frame []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.WriteMessage(websocket.TextMessage, frame)
}

// ed2cRelayHub is a real in-process NIP-01 websocket relay bridging team-tier
// CLIENTS to an in-process OPERATOR stack (opConn — the fakeRelayConn
// attachRelayTransport reads/writes).
type ed2cRelayHub struct {
	srv    *httptest.Server
	opConn *fakeRelayConn
}

// newEd2cRelayHub starts the hub bridging clients to opConn (the operator's transport).
func newEd2cRelayHub(t *testing.T, opConn *fakeRelayConn) *ed2cRelayHub {
	t.Helper()
	h := &ed2cRelayHub{opConn: opConn}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.serveWS)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *ed2cRelayHub) wsURL() string { return wsURL(h.srv.URL) }

// serveWS handles one client websocket: it injects client EVENTs into the operator's
// subscription (ACKing each with OK), registers the client's REQ filters, and runs a
// pump forwarding matching operator publishes back to this client.
func (h *ed2cRelayHub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	c := &ed2cClientConn{
		ws:        conn,
		filters:   map[string]relay.Filter{},
		forwarded: map[string]bool{},
		done:      make(chan struct{}),
	}
	defer close(c.done)
	go h.pump(c)

	for {
		_, raw, rerr := conn.ReadMessage()
		if rerr != nil {
			return
		}
		f, perr := relay.ParseFrame(raw)
		if perr != nil {
			continue
		}
		switch f.Type {
		case relay.LabelEVENT:
			if f.Event == nil {
				continue
			}
			// Deliver the client's signed event into the operator's subscription
			// (exactly as the precedent test's inject() does), then ACK with OK.
			h.opConn.inject(f.Event)
			ok, _ := relay.EncodeOK(f.Event.ID, true, "")
			c.write(ok)
		case relay.LabelREQ:
			if len(f.Filters) > 0 {
				c.mu.Lock()
				c.filters[f.SubID] = f.Filters[0]
				c.mu.Unlock()
			}
		case relay.LabelCLOSE:
			c.mu.Lock()
			delete(c.filters, f.SubID)
			c.mu.Unlock()
		}
	}
}

// pump forwards every operator publish (recorded in opConn.events) matching a live
// client filter to that client subscription, once per (subID,eventID). It handles
// both live delivery and REQ-time replay (a filter registered after an event was
// published still receives it on the next tick) — the strfry historical-replay the
// client's subscribe-first/re-subscribe discipline relies on.
func (h *ed2cRelayHub) pump(c *ed2cClientConn) {
	tk := time.NewTicker(2 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-tk.C:
		}
		h.opConn.mu.Lock()
		evs := make([]*identity.Event, len(h.opConn.events))
		copy(evs, h.opConn.events)
		h.opConn.mu.Unlock()

		c.mu.Lock()
		filters := make(map[string]relay.Filter, len(c.filters))
		for k, v := range c.filters {
			filters[k] = v
		}
		c.mu.Unlock()

		for _, ev := range evs {
			for subID, f := range filters {
				key := subID + "|" + ev.ID
				c.mu.Lock()
				already := c.forwarded[key]
				c.mu.Unlock()
				if already {
					continue
				}
				if ed2cMatchFilter(f, ev) {
					c.mu.Lock()
					c.forwarded[key] = true
					c.mu.Unlock()
					frame, ferr := relay.EncodeSubEvent(subID, ev)
					if ferr == nil {
						c.write(frame)
					}
				}
			}
		}
	}
}

// ed2cMatchFilter is a faithful NIP-01 filter match for the subset the client uses
// (kinds + generic single-letter tag filters + Since). It is DELIBERATELY faithful:
// the H3 proof depends on a #e:[buyID] filter NOT matching an operator event that
// e-tags only the buyer-accept id.
func ed2cMatchFilter(f relay.Filter, ev *identity.Event) bool {
	if len(f.Kinds) > 0 {
		ok := false
		for _, k := range f.Kinds {
			if k == ev.Kind {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for name, vals := range f.Tags {
		matched := false
		for _, tg := range ev.Tags {
			if len(tg) >= 2 && tg[0] == name {
				for _, v := range vals {
					if tg[1] == v {
						matched = true
						break
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.Since != nil && ev.CreatedAt < *f.Since {
		return false
	}
	return true
}

// --- fixture -----------------------------------------------------------------

const ed2cPutDesc = "Go HTTP handler unit test generator"
const ed2cBuyTask = "Generate unit tests for a Go HTTP handler"
const ed2cTokenCost = int64(8000)

// ed2cContent is the KNOWN, byte-exact content the seller puts and the buyer must
// receive verbatim over the settle chain (inline, well under BlossomOffloadThreshold).
var ed2cContent = []byte("package main\n\nfunc TestHandler(t *testing.T) {\n\t// generated table-driven unit tests for the HTTP handler\n}\n")

// knownPutPayload builds a put payload with an EXPLICIT content body so a test can
// assert the delivered content byte-for-byte (unlike the generated localPutPayload).
func knownPutPayload(desc string, content []byte, tokenCost int64) []byte {
	p, _ := json.Marshal(map[string]any{
		"description":  desc,
		"content":      base64.StdEncoding.EncodeToString(content),
		"token_cost":   tokenCost,
		"content_type": "exchange:content-type:code",
		"domains":      []string{"go"},
	})
	return p
}

type ed2cFixture struct {
	st       *wireIDStack
	hub      *ed2cRelayHub
	seller   identity.Signer
	operator identity.Signer
	ls       *dgstore.Store
}

// newEd2cFixture stands up the full operator team stack (engine + relay wiring +
// LocalScripStore + AutoDeliverOnBuyerAccept), injects an allowlisted seller's put
// (fixture), waits for it to auto-accept into inventory, and starts the websocket
// hub. It does NOT mint the buyer — each test mints (or deliberately does not) its
// own buyer agent.
func newEd2cFixture(t *testing.T) *ed2cFixture {
	t.Helper()
	hushRelayLogs(t)
	dir := t.TempDir()
	ls, err := dgstore.Open(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	operator, _ := identity.Generate()
	seller, _ := identity.Generate()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	st := newWireIDStack(t, ctx, ls, operator, dir+"/events.jsonl.pubcursor")
	t.Cleanup(func() { cancel(); st.stop() })

	putEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil,
		knownPutPayload(ed2cPutDesc, ed2cContent, ed2cTokenCost))
	st.conn.inject(putEv)
	waitFor(t, 8*time.Second, "seller put auto-accepts into inventory", func() bool {
		return len(st.eng.State().Inventory()) == 1
	})

	hub := newEd2cRelayHub(t, st.conn)
	return &ed2cFixture{st: st, hub: hub, seller: seller, operator: operator, ls: ls}
}

// newBuyerAgent creates an agent identity home, points AGENT_CF_HOME at it, and
// returns the loaded signer — the identity `dontguess buy` RunE signs with.
func newBuyerAgent(t *testing.T) identity.Signer {
	t.Helper()
	agentHome := t.TempDir()
	id, _, err := identity.LoadOrCreate(agentHome)
	if err != nil {
		t.Fatalf("LoadOrCreate buyer agent: %v", err)
	}
	t.Setenv("AGENT_CF_HOME", agentHome)
	return id
}

// matchStoreID reads the operator's local log and returns the STORE id of the first
// operator-authored match record (the key IsMatchSettled is keyed by). The client
// only ever sees the WIRE id; the test reads the store id from the operator's log.
func (f *ed2cFixture) matchStoreID(t *testing.T) string {
	t.Helper()
	recs, _ := f.ls.ReadAll()
	rec, ok := firstLocalRecordWithTags(recs, exchange.TagMatch)
	if !ok {
		t.Fatalf("no operator match record persisted in local log")
	}
	return rec.ID
}

// --- (1) HAPPY PATH via RunE: content in hand byte-exact + scrip moved --------

// TestEd2C_RunBuy_TeamHit_SettlesContentAndMovesScrip drives the ACTUAL `dontguess
// buy` RunE on a MINTED buyer against the full stack. On the hit the client drives
// buyer-accept (e-tag match WIRE id) -> operator auto-deliver -> complete (e-tag
// deliver WIRE id), ending with the content IN HAND (byte-exact on stdout) and REAL
// scrip moved through the engine: buyer debited price+fee, seller credited residual,
// IsMatchSettled true.
func TestEd2C_RunBuy_TeamHit_SettlesContentAndMovesScrip(t *testing.T) {
	fx := newEd2cFixture(t)
	buyer := newBuyerAgent(t)
	fx.st.mintBuyer(t, buyer)
	if got := fx.st.scrip.Balance(buyer.PubKeyHex()); got != wireIDBuyerMint {
		t.Fatalf("buyer balance before buy = %d, want minted %d", got, wireIDBuyerMint)
	}

	cmd := newBuyCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	setBuyFlags(t, cmd, map[string]string{
		"task":    ed2cBuyTask,
		"budget":  "1000000",
		"relay":   fx.hub.wsURL(),
		"timeout": "30s",
	})
	if err := runBuy(cmd, nil); err != nil {
		t.Fatalf("runBuy (team hit) returned error: %v\nstderr:\n%s", err, stderr.String())
	}

	// (a) content IN HAND, byte-exact, on the pipeable stdout channel.
	if !bytes.Equal(stdout.Bytes(), ed2cContent) {
		t.Fatalf("delivered content mismatch.\n got (%d bytes): %q\nwant (%d bytes): %q",
			stdout.Len(), stdout.String(), len(ed2cContent), string(ed2cContent))
	}
	if !strings.Contains(stderr.String(), "SETTLED") {
		t.Fatalf("stderr does not surface the SETTLED outcome:\n%s", stderr.String())
	}

	// (b) REAL scrip moved through the engine.
	waitFor(t, 8*time.Second, "buyer debited a real price+fee hold", func() bool {
		return fx.st.scrip.Balance(buyer.PubKeyHex()) < wireIDBuyerMint
	})
	matchStore := fx.matchStoreID(t)
	waitFor(t, 8*time.Second, "match settles (durable scrip-settle) on the client's complete", func() bool {
		return fx.st.eng.State().IsMatchSettled(matchStore)
	})
	waitFor(t, 8*time.Second, "seller credited the residual", func() bool {
		return fx.st.scrip.Balance(fx.seller.PubKeyHex()) > 0
	})
	if got := fx.st.scrip.Balance(buyer.PubKeyHex()); got >= wireIDBuyerMint {
		t.Fatalf("buyer not debited: balance=%d, want < %d", got, wireIDBuyerMint)
	}
}

// --- (2) UNDERFUNDED via RunE: reject RECEIVED via the per-phase filter (H3) ---

// TestEd2C_RunBuy_UnderfundedBuyer_ReceivesRejectViaPerPhaseFilter proves the H3
// correctness point: an UNMINTED buyer's client RECEIVES + surfaces the operator's
// durable settle(buyer-accept-reject) (reason:insufficient_scrip) — a DISTINGUISHED
// LOUD outcome, NOT a bare timeout.
//
// This is the H3 proof BY CONSTRUCTION: the reject e-tags the buyer-accept WIRE id,
// never buyID. The hub's ed2cMatchFilter is a faithful #e matcher, so the ONLY way
// the client sees the reject is its per-phase #e:[buyer-accept] subscription (§3.5).
// A client that subscribed #e:[buyID] for the settle chain would receive NOTHING and
// this test would FAIL with an ambiguous timeout instead of the insufficient_scrip
// reject asserted below.
func TestEd2C_RunBuy_UnderfundedBuyer_ReceivesRejectViaPerPhaseFilter(t *testing.T) {
	fx := newEd2cFixture(t)
	buyer := newBuyerAgent(t) // deliberately NOT minted
	if got := fx.st.scrip.Balance(buyer.PubKeyHex()); got != 0 {
		t.Fatalf("unminted buyer balance = %d, want 0", got)
	}

	cmd := newBuyCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	setBuyFlags(t, cmd, map[string]string{
		"task":    ed2cBuyTask,
		"budget":  "1000000",
		"relay":   fx.hub.wsURL(),
		"timeout": "30s",
	})
	err := runBuy(cmd, nil)
	if err == nil {
		t.Fatalf("expected a LOUD underfunded error; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	// The reject was RECEIVED (not a timeout): the error + stderr carry the operator's
	// insufficient_scrip reason and the actionable mint instruction.
	if !strings.Contains(err.Error(), "insufficient_scrip") {
		t.Fatalf("error %q does not surface the RECEIVED insufficient_scrip reject (H3: was the per-phase #e:[buyer-accept] filter used?)\nstderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(err.Error(), "dontguess mint") {
		t.Fatalf("error %q does not surface the actionable mint instruction", err)
	}
	if !strings.Contains(stderr.String(), "UNDERFUNDED") {
		t.Fatalf("stderr does not surface the distinguished UNDERFUNDED outcome (not a bare timeout):\n%s", stderr.String())
	}
	// No content was delivered, and no scrip moved.
	if stdout.Len() != 0 {
		t.Fatalf("underfunded buyer received content on stdout (%d bytes): %q", stdout.Len(), stdout.String())
	}
	if got := fx.st.scrip.Balance(fx.seller.PubKeyHex()); got != 0 {
		t.Fatalf("seller credited %d on an underfunded buy — no scrip should have moved", got)
	}
}

// --- (3) PREVIEW path via the client Settle against the full stack ------------

// TestEd2C_PreviewPath_RequestPreviewThenBuyerAccept drives the real client
// relayclient.Buy + Settle{Preview:true} against the full operator stack and proves
// item requirement (4) — the "preview-request -> preview -> buyer-accept" path:
//
//  1. the client publishes settle(preview-request) e-tagging the match WIRE id;
//  2. it RECEIVES the FREE operator settle(preview) via its per-phase
//     #e:[preview-request] subscription (SettleResult.PreviewMsgID is populated —
//     a real operator round-trip, no scrip charged); and
//  3. it publishes settle(buyer-accept) e-tagging the PREVIEW WIRE id per design §3.5
//     (SettleResult.BuyerAcceptID is populated).
//
// KNOWN OPERATOR BOUNDARY (flagged upstream, NOT this item's scope): the operator's
// AUTO-DELIVER on a buyer-accept that e-tags the PREVIEW wire id does not fire
// in-session, so the chain does not reach settle(deliver) here. Root cause is
// OPERATOR-side and outside ed2-C's "client-only, do not touch the engine" scope:
// the operator's own settle(preview) response is NOT applied to state in-session
// (engine sendPreviewResponse lacks the send-then-Apply that emitMatchResponse /
// autoDeliverOnBuyerAccept / emitConsumeSignal all perform), so previewToMatch stays
// unpopulated within the session and ResolveMatchFromAntecedent(previewWire) misses
// (empirically: found=false for the preview wire id, found=true for the match wire
// id). 55c fixed the MATCH-wire-id auto-deliver path (proven by the happy-path test
// above) but never covered the PREVIEW-wire-id path. This test therefore asserts the
// client milestones requirement (4) names and deliberately does NOT assert the
// operator-blocked deliver; it stays forward-compatible (still passes once the
// one-line operator send-then-Apply lands). See the escalation/followup in the
// item's structured output.
func TestEd2C_PreviewPath_RequestPreviewThenBuyerAccept(t *testing.T) {
	fx := newEd2cFixture(t)
	buyer := newBuyerAgent(t)
	fx.st.mintBuyer(t, buyer)

	// One bounded ctx for the whole buy->settle (the watchdog that unblocks a
	// stalled Recv is bound to the dial ctx of the first Send). The buy + preview
	// round (preview-request -> preview -> buyer-accept) complete in well under a
	// second; the remainder is the operator-blocked deliver the client awaits (the
	// known boundary above), so this bound doubles as the test duration. The
	// asserted milestones (PreviewMsgID / BuyerAcceptID) are set before it expires.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn := newClientConn(t, fx.hub.wsURL(), buyer)
	defer conn.Close()

	buyRes, err := relayclientBuy(ctx, conn, buyer)
	if err != nil {
		t.Fatalf("relayclient.Buy: %v", err)
	}
	assertClientMatch(t, buyRes)

	settleRes, err := relayclientSettle(ctx, conn, buyer, buyRes, true /* preview */)
	if err != nil {
		t.Fatalf("relayclient.Settle(preview): %v", err)
	}
	// (2) the FREE operator preview was RECEIVED via #e:[preview-request].
	if settleRes.PreviewMsgID == "" {
		t.Fatalf("preview path did not record a preview wire id — the free preview round did not happen")
	}
	// (3) the client published buyer-accept e-tagging the PREVIEW wire id (§3.5).
	if settleRes.BuyerAcceptID == "" {
		t.Fatalf("preview path did not publish a buyer-accept after the preview")
	}
	// The FREE preview must not have moved any scrip.
	if got := fx.st.scrip.Balance(fx.seller.PubKeyHex()); got != 0 {
		t.Fatalf("seller credited %d after a FREE preview — the preview must charge nothing", got)
	}
}
