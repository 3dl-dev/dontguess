package main

// serve_relay_ed2c_allowlist_test.go — dontguess-980: proves the live gap
// pkg/exchange/trust.go's TrustChecker.Level() exposed — OperationBuy is
// TrustAnonymous (defaultOperationLevels, trust.go) so a minted-but-NOT-
// fleet-allowlisted buyer's `dontguess buy` MATCHES fine, but every buyer-side
// settle phase (buyer-accept, complete, ...) requires TrustAllowlisted
// (defaultSettlePhaseLevels, trust.go), so the buyer's settle(buyer-accept) is
// silently dropped pre-fold at the dispatch trust gate (engine_core.go
// dispatch: TrustChecker.Check fails -> logged + counted -> dispatch returns
// nil, no fold, no reject emitted). From the CLIENT's perspective this is
// indistinguishable from an operator/relay stall: the per-phase await times
// out -> SettleOutcomeAmbiguous.
//
// This test drives the REAL client (relayclient.Buy + relayclient.Settle)
// through a REAL engine with a REAL TrustChecker whose fleet allowlist
// contains the seller but deliberately OMITS the buyer, over the same
// ed2cRelayHub websocket bridge serve_relay_ed2c_test.go uses. It asserts:
//  1. The match succeeds (OperationBuy is anonymous-admitted).
//  2. Settle terminates SettleOutcomeAmbiguous (not a hang, not Settled) —
//     the buyer-accept never reaches the fold.
//  3. relayclient.WriteSettleOutcome's rendered AMBIGUOUS block mentions
//     buyer-allowlist status as a possible cause (the settle.go fix under
//     this item), so the client-side guidance actually tells the operator
//     what to do: `dontguess allowlist add <buyer-npub>`.
import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/relayclient"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// newEd2cFixtureSellerOnlyAllowlist mirrors newEd2cFixture but wires a real
// *exchange.TrustChecker whose fleet allowlist (KeySet) contains ONLY the
// seller — never the buyer. The buyer is minted (scrip funded) by the caller
// exactly as the other ed2c tests do; minting and allowlisting are
// independent axes (dontguess-980 is precisely that the doc failed to say
// both are required for a buyer).
func newEd2cFixtureSellerOnlyAllowlist(t *testing.T) *ed2cFixture {
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

	fleet := exchange.NewKeySet(seller.PubKeyHex())
	tc, err := exchange.NewTrustChecker(operator.PubKeyHex(), fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	st := newWireIDStack(t, ctx, ls, operator, dir+"/events.jsonl.pubcursor", tc)
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

// TestEd2C_RunBuy_MintedButNotAllowlistedBuyer_SettleIsRefused_NotAmbiguous is the
// dontguess-980 ground-source proof, RE-BASED on dontguess-c0a. It does NOT mock
// the trust gate, the engine, or the relay wire — it drives the exact path a
// minted-but-unallowlisted buyer hits in production.
//
// SUPERSEDED EXPECTATION, recorded so it is not reintroduced: this test used to
// require the outcome to be AMBIGUOUS, and asserted only that the timeout's
// printed guidance mentioned allowlisting. That enshrined the silent drop as the
// contract. dontguess-980 could not do better at the time — the engine dropped a
// blocked buyer-accept pre-fold and emitted nothing — so it improved the wording
// of the timeout instead of removing the timeout.
//
// The engine now emits a settle(buyer-accept-reject) with reason=not-allowlisted
// when the trust gate blocks a buyer-accept, exactly as dontguess-39d already did
// for a blocked put. So the correct expectation is a RECEIVED refusal, and a
// timeout here is now a regression. The ambiguous-outcome guidance still names
// allowlisting and is still asserted below: a genuine timeout can still happen for
// other reasons (notably an unallowlisted SELLER, whose reject goes to the seller),
// and that hint remains right for those.
func TestEd2C_RunBuy_MintedButNotAllowlistedBuyer_SettleIsRefused_NotAmbiguous(t *testing.T) {
	fx := newEd2cFixtureSellerOnlyAllowlist(t)
	buyer, _ := newBuyerAgent(t)
	// Minted (funded) — but never allowlisted. This is the exact gap: minting
	// alone is not sufficient for a team-tier buyer to complete a purchase.
	fx.st.mintBuyer(t, buyer)
	if got := fx.st.scrip.Balance(buyer.PubKeyHex()); got != wireIDBuyerMint {
		t.Fatalf("buyer balance before buy = %d, want minted %d", got, wireIDBuyerMint)
	}

	conn := newClientConn(t, fx.hub.wsURL(), buyer)
	defer conn.Close()

	// ONE shared ctx for the WHOLE buy->settle chain (design §3.5: "the whole
	// buy->settle chain runs in ONE invocation... bound lives entirely in the
	// client ctx" — mirrored by every RunE call site, which builds a single ctx
	// from --timeout and passes it to both Buy and Settle). This also matters
	// mechanically: NewConn's watchdogDialer (relayclient.go) installs its
	// force-close goroutine racing whatever ctx is live AT DIAL TIME (the
	// first Send/Recv on the connection, here inside Buy) and holds it for the
	// connection's whole lifetime — a Settle call reusing the same conn under a
	// DIFFERENT, shorter ctx would NOT actually bound the read; the dial-time
	// ctx would still govern when the socket is force-closed. Sizing this at 5s
	// keeps the genuine-timeout proof below tight instead of needlessly wide.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	buy, err := relayclientBuy(ctx, conn, buyer)
	if err != nil {
		t.Fatalf("Buy: %v", err)
	}
	// (1) The buy itself is unaffected: OperationBuy is TrustAnonymous
	// (defaultOperationLevels, trust.go) — an unallowlisted buyer still matches.
	assertClientMatch(t, buy)

	res, err := relayclientSettle(ctx, conn, buyer, buy, false)
	if err != nil {
		t.Fatalf("Settle returned a hard error, want a terminal AMBIGUOUS outcome: %v", err)
	}
	if res == nil {
		t.Fatalf("Settle returned nil result")
	}
	// (2) buyer-accept requires TrustAllowlisted (defaultSettlePhaseLevels,
	// trust.go). The dispatch trust gate blocks it pre-fold, and now emits a
	// settle(buyer-accept-reject) carrying reason=not-allowlisted so the client's
	// per-phase await on #e:[buyer-accept] RECEIVES a refusal instead of running
	// out the clock (dontguess-c0a).
	if res.Outcome == relayclient.SettleOutcomeAmbiguous {
		t.Fatalf("settle outcome = ambiguous-timeout — the blocked buyer-accept was dropped silently again; an unadmitted buyer cannot tell refusal from a slow operator (dontguess-c0a regression)")
	}
	if res.Outcome != relayclient.SettleOutcomeNotAdmitted {
		t.Fatalf("settle outcome = %s, want not-allowlisted-reject", res.Outcome)
	}
	// It must NOT be reported as underfunded: the buyer is fully minted, and
	// sending it to mint more is the wrong remedy.
	if res.Outcome == relayclient.SettleOutcomeUnderfunded {
		t.Fatalf("a fully minted, unadmitted buyer was told it is underfunded")
	}
	if res.RejectReason != exchange.BuyerAcceptRejectNotAllowlisted {
		t.Fatalf("reject reason = %q, want %q", res.RejectReason, exchange.BuyerAcceptRejectNotAllowlisted)
	}
	// No scrip should have moved — the hold handler in the engine never ran.
	if got := fx.st.scrip.Balance(buyer.PubKeyHex()); got != wireIDBuyerMint {
		t.Fatalf("buyer balance after ambiguous settle = %d, want unchanged %d (no fold occurred)", got, wireIDBuyerMint)
	}

	// (3) The printed block names the refusal for what it is and points at
	// admission — never at minting.
	var out bytes.Buffer
	relayclient.WriteSettleOutcome(&out, buy.BuyID, res)
	printed := out.String()
	if !strings.Contains(printed, "NOT ADMITTED") {
		t.Fatalf("printed settle outcome missing the NOT ADMITTED block:\n%s", printed)
	}
	if !strings.Contains(printed, "dontguess allowlist add") {
		t.Fatalf("printed guidance does not name the actionable operator command `dontguess allowlist add`:\n%s", printed)
	}
	if strings.Contains(printed, "dontguess mint") {
		t.Fatalf("printed guidance tells an unadmitted buyer to MINT SCRIP — the wrong remedy, and the specific wrong turn dontguess-c0a was chasing:\n%s", printed)
	}

	// (4) The AMBIGUOUS guidance still enumerates allowlisting (dontguess-980),
	// which remains correct for a genuine timeout — e.g. an unallowlisted SELLER,
	// whose put-reject goes to the seller and never reaches this buyer.
	var amb bytes.Buffer
	relayclient.WriteSettleOutcome(&amb, buy.BuyID, &relayclient.SettleResult{Outcome: relayclient.SettleOutcomeAmbiguous})
	ambPrinted := amb.String()
	if !strings.Contains(ambPrinted, "AMBIGUOUS") || !strings.Contains(ambPrinted, "allowlist") {
		t.Fatalf("the ambiguous-timeout guidance lost its allowlist hint (dontguess-980 regression):\n%s", ambPrinted)
	}
}
