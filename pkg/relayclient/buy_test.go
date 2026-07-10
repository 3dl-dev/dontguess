package relayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/campfire-net/dontguess/pkg/identity"
	"github.com/campfire-net/dontguess/pkg/nostr"
	"github.com/campfire-net/dontguess/pkg/proto"
	"github.com/campfire-net/dontguess/pkg/relay"
)

// --- buy test fixtures -------------------------------------------------------

// signOperatorEvent builds a genuinely signed operator response event (match /
// buy-miss / assign) of the wire shape the engine emits, by routing a
// proto.Message through the SAME production adapter (nostr.ToNostrEvent) the
// operator uses and signing with the operator key. Mirrors
// relayclient_test.go's buildSignedPutReject. It panics on error (well-formed
// fixtures never fail) because it runs from the fake relay's own goroutine where
// t.Fatalf is unsafe.
func signOperatorEvent(operator identity.Signer, tags []string, antecedents []string, payload map[string]any) *identity.Event {
	pj, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("marshal payload: %v", err))
	}
	msg := &proto.Message{
		Sender:      operator.PubKeyHex(),
		Payload:     pj,
		Tags:        tags,
		Antecedents: antecedents,
		Timestamp:   time.Now().UnixNano(),
	}
	nev, err := nostr.ToNostrEvent(msg)
	if err != nil {
		panic(fmt.Sprintf("ToNostrEvent: %v", err))
	}
	ev := &identity.Event{
		PubKey:    nev.PubKey,
		CreatedAt: nev.CreatedAt,
		Kind:      nev.Kind,
		Tags:      nev.Tags,
		Content:   nev.Content,
	}
	if err := identity.SignEvent(operator, ev); err != nil {
		panic(fmt.Sprintf("SignEvent: %v", err))
	}
	return ev
}

func signedMatch(operator identity.Signer, buyID string) *identity.Event {
	return signOperatorEvent(operator, []string{exchange.TagMatch}, []string{buyID}, map[string]any{
		"results": []map[string]any{{
			"entry_id":          "entry-1",
			"put_msg_id":        "put-1",
			"seller_key":        "seller-abc",
			"description":       "a reusable flock contention test pattern for Go",
			"content_type":      "code",
			"price":             int64(900),
			"seller_reputation": 72,
		}},
		"guide": "ranked by correctness gate then efficiency",
	})
}

func signedBuyMiss(operator identity.Signer, buyID string) *identity.Event {
	return signOperatorEvent(operator, []string{exchange.TagBuyMiss, exchange.TagMatch}, []string{buyID}, map[string]any{
		"task_hash":          "abc123",
		"offered_price_rate": 70,
		"guide":              "No cached inference matched your task. A standing offer has been created.",
	})
}

func signedAssign(operator identity.Signer, buyID string) *identity.Event {
	return signOperatorEvent(operator, []string{exchange.TagAssign}, []string{buyID}, map[string]any{
		"assign_type": "brokered-match",
	})
}

// readItem is one scripted ReadMessage result: either data or a transport error
// (modeling a mid-await conn drop).
type readItem struct {
	data []byte
	err  error
}

// buyFakeConn is an in-process fake relay.WSConn tailored to the buy await. It
// captures the subscription id and buy id from the client's writes and scripts
// operator responses. Unlike relayclient_test.go's scriptedWSConn (put-focused),
// it can build a response LAZILY from the captured/observed buy id — required
// because the buy id is the client's own deterministic signed-event id, unknown
// to the test until the client publishes it.
type buyFakeConn struct {
	mu    sync.Mutex
	items chan readItem

	closeOnce sync.Once
	closed    chan struct{}

	operator identity.Signer

	// behavior knobs (set before use).
	okOnBuy      bool                                    // ACK the buy EVENT with OK accepted=true
	buildResp    func(buyID string) *identity.Event      // the operator response to deliver, built from the buy id
	respondAfter time.Duration                           // if buildResp set: deliver it this long after the buy OK (0 = immediately)
	respondOnReq bool                                     // deliver buildResp when a REQ arrives (buy id read from the #e filter) — models a reconnect replaying stored events
	dropAfterOK  bool                                     // after the buy OK, inject a transport drop instead of a response

	subID string
	buyID string
}

func newBuyFakeConn() *buyFakeConn {
	return &buyFakeConn{items: make(chan readItem, 32), closed: make(chan struct{})}
}

func (c *buyFakeConn) push(it readItem) {
	select {
	case c.items <- it:
	case <-c.closed:
	}
}

func (c *buyFakeConn) WriteMessage(_ int, data []byte) error {
	f, err := relay.ParseFrame(data)
	if err != nil {
		return nil
	}
	switch f.Type {
	case relay.LabelREQ:
		c.mu.Lock()
		c.subID = f.SubID
		c.mu.Unlock()
		if c.respondOnReq && c.buildResp != nil {
			var buyID string
			if len(f.Filters) > 0 {
				if e := f.Filters[0].Tags["e"]; len(e) > 0 {
					buyID = e[0]
				}
			}
			if buyID != "" {
				frame, _ := relay.EncodeSubEvent(f.SubID, c.buildResp(buyID))
				c.push(readItem{data: frame})
			}
		}
	case relay.LabelEVENT:
		if f.Event == nil {
			return nil
		}
		c.mu.Lock()
		c.buyID = f.Event.ID
		c.mu.Unlock()
		if c.okOnBuy {
			ok, _ := relay.EncodeOK(f.Event.ID, true, "")
			c.push(readItem{data: ok})
		}
		go c.afterBuy()
	}
	return nil
}

// afterBuy runs the scripted follow-up to a buy publish. The buy OK (if any) was
// already enqueued synchronously in WriteMessage before this goroutine starts,
// so the FIFO channel guarantees the client reads the OK before any drop/response
// this pushes — deterministic ordering without sleeps.
func (c *buyFakeConn) afterBuy() {
	if c.dropAfterOK {
		c.push(readItem{err: fmt.Errorf("fake relay: connection dropped mid-await")})
		return
	}
	if c.buildResp == nil {
		return
	}
	if c.respondOnReq {
		return // delivery happens on the (re)subscribe REQ instead
	}
	if c.respondAfter > 0 {
		select {
		case <-time.After(c.respondAfter):
		case <-c.closed:
			return
		}
	}
	c.mu.Lock()
	subID, buyID := c.subID, c.buyID
	c.mu.Unlock()
	frame, _ := relay.EncodeSubEvent(subID, c.buildResp(buyID))
	c.push(readItem{data: frame})
}

func (c *buyFakeConn) ReadMessage() (int, []byte, error) {
	select {
	case it := <-c.items:
		if it.err != nil {
			return 0, nil, it.err
		}
		return 1, it.data, nil
	case <-c.closed:
		return 0, nil, fmt.Errorf("fake relay: closed")
	}
}

func (c *buyFakeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// seqDialer hands out a fixed sequence of conns, one per Dial — modeling a
// reconnect where the client re-dials the (same) relay and lands on a fresh
// socket that must be re-subscribed.
type seqDialer struct {
	mu    sync.Mutex
	conns []relay.WSConn
	i     int
}

func (d *seqDialer) Dial(_ context.Context, _ string) (relay.WSConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.i >= len(d.conns) {
		return nil, fmt.Errorf("seqDialer: no more scripted conns (Dial #%d)", d.i+1)
	}
	c := d.conns[d.i]
	d.i++
	return c, nil
}

// --- tests -------------------------------------------------------------------

// TestBuy_Hit_MatchOneTickLate proves the subscribe-first ordering closes H1:
// the match EVENT is published one tick AFTER the buy OK, yet the client — having
// subscribed BEFORE publishing — receives it well within the timeout and surfaces
// the parsed match (entry id, price, seller) as the ed2-C seam.
func TestBuy_Hit_MatchOneTickLate(t *testing.T) {
	agent := newSigner(t)
	operator := newSigner(t)

	ws := newBuyFakeConn()
	ws.okOnBuy = true
	ws.buildResp = func(buyID string) *identity.Event { return signedMatch(operator, buyID) }
	ws.respondAfter = 40 * time.Millisecond // "one tick late"

	conn := NewConn("ws://fake", agent, WithDialer(fakeDialer{conn: ws}), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "flock contention test pattern for Go", Budget: 1000})
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if res.Outcome != BuyOutcomeMatch {
		t.Fatalf("outcome = %v, want match", res.Outcome)
	}
	m := res.Match()
	if m == nil {
		t.Fatalf("expected a surfaced match entry, got none")
	}
	if m.EntryID != "entry-1" || m.Price != 900 || m.SellerKey != "seller-abc" {
		t.Fatalf("surfaced match = %+v, want entry-1/900/seller-abc", m)
	}
	if res.MatchMsgID == "" {
		t.Fatalf("MatchMsgID (the ed2-C settle seam) must be set on a hit")
	}
}

// TestBuy_ConnDropMidAwait_ReSubscribeRecoversMatch proves H5: the connection
// drops AFTER the buy OK but BEFORE the match; the client must re-issue its REQ
// on the fresh socket (the relay never replays a REQ) and recover the match the
// relay stored. conn1 drops after OK; conn2 replays the match when the
// re-subscribe REQ arrives.
func TestBuy_ConnDropMidAwait_ReSubscribeRecoversMatch(t *testing.T) {
	agent := newSigner(t)
	operator := newSigner(t)

	conn1 := newBuyFakeConn()
	conn1.okOnBuy = true
	conn1.dropAfterOK = true

	conn2 := newBuyFakeConn()
	conn2.respondOnReq = true
	conn2.buildResp = func(buyID string) *identity.Event { return signedMatch(operator, buyID) }

	dialer := &seqDialer{conns: []relay.WSConn{conn1, conn2}}
	conn := NewConn("ws://fake", agent, WithDialer(dialer), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "cf-protocol README CF_NO_PINS", Budget: 1000})
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if res.Outcome != BuyOutcomeMatch {
		t.Fatalf("outcome = %v, want match (recovered after re-subscribe)", res.Outcome)
	}
	if res.Match() == nil || res.Match().EntryID != "entry-1" {
		t.Fatalf("expected recovered match entry-1, got %+v", res.Match())
	}
	dialer.mu.Lock()
	dials := dialer.i
	dialer.mu.Unlock()
	if dials < 2 {
		t.Fatalf("expected a reconnect (>=2 dials), got %d — the re-subscribe path was not exercised", dials)
	}
}

// TestBuy_Miss_PrintsDemandGuide proves failure-matrix (b): a kind-3403 WITH the
// exchange:buy-miss tag is a genuine miss, surfaced as the demand-signal guide,
// LOUD and not an error.
func TestBuy_Miss_PrintsDemandGuide(t *testing.T) {
	agent := newSigner(t)
	operator := newSigner(t)

	ws := newBuyFakeConn()
	ws.okOnBuy = true
	ws.buildResp = func(buyID string) *identity.Event { return signedBuyMiss(operator, buyID) }

	conn := NewConn("ws://fake", agent, WithDialer(fakeDialer{conn: ws}), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "something nobody has computed", Budget: 1000})
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if res.Outcome != BuyOutcomeMiss {
		t.Fatalf("outcome = %v, want buy-miss", res.Outcome)
	}
	if res.OfferedPriceRate != 70 {
		t.Fatalf("offered price rate = %d, want 70", res.OfferedPriceRate)
	}
	var buf bytes.Buffer
	WriteOutcome(&buf, res)
	out := buf.String()
	if !strings.Contains(out, "BUY-MISS") || !strings.Contains(strings.ToLower(out), "demand signal") {
		t.Fatalf("miss output missing the demand-signal guide:\n%s", out)
	}
	if !strings.Contains(out, "dontguess put") {
		t.Fatalf("miss output must tell the buyer to `dontguess put`:\n%s", out)
	}
}

// TestBuy_Timeout_PrintsAmbiguousEnumeratedCauses proves §5.4: a buy that gets an
// OK but no discriminating response times out as AMBIGUOUS, enumerating the
// actionable causes and NEVER claiming "no cache exists".
func TestBuy_Timeout_PrintsAmbiguousEnumeratedCauses(t *testing.T) {
	agent := newSigner(t)

	ws := newBuyFakeConn()
	ws.okOnBuy = true // OK only — the operator never answers.

	conn := NewConn("ws://fake", agent, WithDialer(fakeDialer{conn: ws}), WithBackoff(testBackoff()))
	defer conn.Close()

	budget := 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "ambiguous probe", Budget: 1000})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Buy (ambiguous is a terminal outcome, not an error): %v", err)
	}
	if res.Outcome != BuyOutcomeAmbiguous {
		t.Fatalf("outcome = %v, want ambiguous", res.Outcome)
	}
	if len(res.AmbiguousCauses) < 3 {
		t.Fatalf("expected >=3 enumerated ambiguous causes, got %d", len(res.AmbiguousCauses))
	}
	if elapsed > budget+2*time.Second {
		t.Fatalf("Buy took %s against a %s budget — the await bound leaked", elapsed, budget)
	}
	var buf bytes.Buffer
	WriteOutcome(&buf, res)
	out := buf.String()
	if !strings.Contains(out, "AMBIGUOUS") {
		t.Fatalf("ambiguous output missing the AMBIGUOUS header:\n%s", out)
	}
	if !strings.Contains(out, "does NOT mean no cache exists") {
		t.Fatalf("ambiguous output must not claim no cache exists:\n%s", out)
	}
	// The three wire-invisible/actionable causes must all be surfaced.
	for _, want := range []string{"under-funded", "mint", "allowlist"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ambiguous causes missing %q:\n%s", want, out)
		}
	}
}

// TestBuy_DeadRelay_FailsLoudInsideTimeout proves a dead/unreachable relay (dial
// always errors) exits LOUD via the bounded backoff, well inside the ctx budget —
// never a silent ambiguous, never a hang.
func TestBuy_DeadRelay_FailsLoudInsideTimeout(t *testing.T) {
	agent := newSigner(t)

	conn := NewConn("ws://fake", agent, WithDialer(errorDialer{}), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "dead relay probe", Budget: 1000})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected a loud transport error against a dead relay, got outcome=%v", res.Outcome)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Buy took %s against a dead relay with a 5s ctx — expected fast bounded-backoff failure", elapsed)
	}
}

// TestBuy_LeakedAssign_SurfacedLoud proves failure-matrix (c): an assign(3405)
// e-tagging the buy (BrokeredMatchMode leaked, out of scope) is discriminated and
// surfaced LOUD rather than silently timing out.
func TestBuy_LeakedAssign_SurfacedLoud(t *testing.T) {
	agent := newSigner(t)
	operator := newSigner(t)

	ws := newBuyFakeConn()
	ws.okOnBuy = true
	ws.buildResp = func(buyID string) *identity.Event { return signedAssign(operator, buyID) }

	conn := NewConn("ws://fake", agent, WithDialer(fakeDialer{conn: ws}), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "brokered probe", Budget: 1000})
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if res.Outcome != BuyOutcomeBrokered {
		t.Fatalf("outcome = %v, want brokered-assign-leaked", res.Outcome)
	}
	var buf bytes.Buffer
	WriteOutcome(&buf, res)
	if !strings.Contains(buf.String(), "brokered") {
		t.Fatalf("brokered output missing loud surface:\n%s", buf.String())
	}
}

// TestBuy_ForgedMatch_NotTrusted proves the security floor: a match event NOT
// signed by a valid key (or tampered) is a loud-skip, never surfaced as a hit —
// otherwise a hostile relay could spoof a match. Here a well-formed match is
// tampered post-sign (content changed), so VerifyEvent fails; the client must
// keep waiting and time out AMBIGUOUS rather than report a match.
func TestBuy_ForgedMatch_NotTrusted(t *testing.T) {
	agent := newSigner(t)
	operator := newSigner(t)

	ws := newBuyFakeConn()
	ws.okOnBuy = true
	ws.buildResp = func(buyID string) *identity.Event {
		ev := signedMatch(operator, buyID)
		ev.Content = ev.Content + " tampered" // breaks the id/signature binding
		return ev
	}

	conn := NewConn("ws://fake", agent, WithDialer(fakeDialer{conn: ws}), WithBackoff(testBackoff()))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	res, err := Buy(ctx, conn, agent, BuyRequest{Task: "forgery probe", Budget: 1000})
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	if res.Outcome != BuyOutcomeAmbiguous {
		t.Fatalf("outcome = %v, want ambiguous — a forged match must NOT be trusted as a hit", res.Outcome)
	}
}
