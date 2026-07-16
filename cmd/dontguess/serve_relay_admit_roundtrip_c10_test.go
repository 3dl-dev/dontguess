package main

// serve_relay_admit_roundtrip_c10_test.go — dontguess-c10 GROUND-SOURCE
// (design §2/§3/§9 Gate B/D). The FULL admit round-trip end-to-end, on a RUNNING
// operator with NO restart: ONE operator-signed OpAllowlist IPC admit must be
// reflected in BOTH gates — the live exchange enforcement KeySet AND the relay
// projection (the operator-signed kind-30078 roster published to the relay and
// re-folded from it) — sub-second, with NO full-history re-subscribe, and a
// de-admit must mirror live on both sides.
//
// This is the composition of the two half-flows the c06 and 113 ground-source
// tests each proved in isolation, driven here as ONE real path with nothing stubbed
// but the websocket wire:
//
//   - a REAL operator 0700 unix socket (listenOperatorSocket + serveOperatorSocket)
//     backed by a REAL allowlistController whose publishRoster fans the roster out
//     over a REAL demuxPublisher (captured via WithLegPublisherSink) onto the SAME
//     in-process NIP-01 relay (fakeRelayConn, echo on) the rest of the serve_relay
//     suite uses — an OPEN dumb relay; the operator does 100% of verification;
//   - a REAL exchange.Engine whose TrustChecker enforces over ksExchange (the live
//     KeySet the controller mutates synchronously — Gate B / the "exchange KeySet");
//   - a REAL reader (attachRelayTransport: Intake + Outbox + rosterFolder) whose
//     rosterFolder folds the relay-echoed roster into a SEPARATE ksRelay — the
//     relay-projected view a peer/relay-aware consumer reconstructs purely from what
//     landed on the relay (the re-scoped "relay writePolicy" gate; ef1 optional).
//
// The two KeySets are deliberately distinct so the assertions cannot be satisfied by
// one write: ksExchange is proven by the synchronous mutation + SEAM enforcement of a
// real put; ksRelay is proven ONLY by a roster that round-tripped the relay and was
// re-folded by the reader. One admit lights up both.
//
// It asserts, for ONE signed admit and ONE signed de-admit, with no restart:
//
//	(1) the admit reflects in ksExchange IMMEDIATELY (synchronous, before the IPC OK);
//	(2) an operator-signed roster admitting the member is PUBLISHED to the relay;
//	(3) ksRelay reflects the member WITHIN 1s (round-trips the relay + re-folds);
//	(4) NO full-history flood — the live admit issues NO new REQ (no since=0 re-read);
//	(5) the exchange gate actually ENFORCES: the admitted member's put promotes to
//	    inventory while a non-admitted key's put is dropped_unlisted;
//	(6) the de-admit MIRRORS live on BOTH gates within 1s (ksExchange immediately,
//	    ksRelay via a new roster on the relay that omits the member) — again no flood,
//	    and the removed member's subsequent put is dropped_unlisted.

import (
	"context"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

func TestAdmitRoundTrip_BothGatesLive_NoRestart_c10(t *testing.T) {
	dir := t.TempDir()
	ls, err := dgstore.Open(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	// Real dgHome + config so the controller's Config.FleetAllowlist persist path is
	// the production one (restart durability), not a stub.
	dgHome := t.TempDir()
	if _, err := exchange.Init(exchange.InitOptions{DGHome: dgHome}); err != nil {
		t.Fatalf("exchange.Init: %v", err)
	}

	operator, _ := identity.Generate()
	member, _ := identity.Generate()   // admitted via the live IPC admit
	outsider, _ := identity.Generate() // never admitted — its put must be dropped

	// --- GATE B: the live exchange enforcement KeySet (starts EMPTY — the admit must
	// be what fills it). The TrustChecker enforces over THIS set at SEAM A/B.
	ksExchange := exchange.NewKeySet()
	tc, err := exchange.NewTrustChecker(operator.PubKeyHex(), ksExchange)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: operator.PubKeyHex(),
		TrustChecker:      tc,
		PollInterval:      5 * time.Millisecond,
		Logger:            func(string, ...any) {},
	})

	// --- RELAY-PROJECTION GATE: a SEPARATE KeySet fed ONLY by the rosterFolder from
	// what round-trips the relay. Distinct from ksExchange so an assertion on it can
	// only be satisfied by a roster that actually reached the relay and was re-folded.
	ksRelay := exchange.NewKeySet()
	rf, err := newRosterFolder(operator.PubKeyHex(), ksRelay, "", nil)
	if err != nil {
		t.Fatalf("newRosterFolder: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relayConn := newFakeRelayConn(true /* echo — the published roster comes back for the fold */)

	// Capture this leg's demuxPublisher so the controller republishes over the SAME
	// relay leg the reader subscribes to (production wires this via serve.go's
	// publishRoster closure; here we wire it directly to the captured leg publisher).
	var legPub *demuxPublisher
	stop, err := attachRelayTransport(ctx, ls, operator, operator.PubKeyHex(),
		dir+"/events.jsonl.pubcursor", relayConn, relayConn, 5*time.Millisecond, nil, nil, nil,
		WithRosterFolder(rf),
		WithLegPublisherSink(func(p *demuxPublisher) { legPub = p }))
	if err != nil {
		t.Fatalf("attachRelayTransport: %v", err)
	}
	if legPub == nil {
		t.Fatal("WithLegPublisherSink did not hand back the leg publisher")
	}

	engDone := make(chan struct{})
	go func() { defer close(engDone); _ = eng.Start(ctx) }()
	go func() {
		skipped := map[string]struct{}{}
		tk := time.NewTicker(10 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tk.C:
				eng.RunAutoAccept(1_000_000, now, skipped)
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-engDone; stop() })

	// The controller: live KeySet == ksExchange (Gate B), roster republished over the
	// real leg publisher (best-effort, bounded) — the production allowlistController.
	ctrl := &allowlistController{
		keys:           ksExchange,
		operatorSigner: operator,
		operatorKeyHex: operator.PubKeyHex(),
		dgHome:         dgHome,
		publishRoster: func(ev *identity.Event) {
			pctx, pcancel := context.WithTimeout(ctx, 3*time.Second)
			defer pcancel()
			if _, perr := legPub.PublishEvent(pctx, ev); perr != nil {
				t.Logf("roster republish over leg failed (non-fatal): %v", perr)
			}
		},
		nowUnix: func() int64 { return time.Now().Unix() },
	}

	// Real 0700 operator socket serving the real controller.
	sockPath := dir + "/ipc/operator.sock"
	ln, err := listenOperatorSocket(sockPath)
	if err != nil {
		t.Fatalf("listenOperatorSocket: %v", err)
	}
	srvDone := make(chan struct{})
	go func() { defer close(srvDone); serveOperatorSocket(ctx, ln, eng, ctrl) }()
	t.Cleanup(func() { cancel(); <-srvDone })

	// Wait for the reader's initial subscribe REQ, then snapshot the REQ count. The
	// live admit path must NOT issue another REQ — that snapshot is the anti-flood
	// baseline (a restart / re-subscribe would re-read history from since=0, the 61a
	// regression this whole path exists to avoid).
	waitFor(t, 4*time.Second, "reader issues its initial subscribe REQ", func() bool {
		return relayConn.reqCount() >= 1
	})
	reqBaseline := relayConn.reqCount()

	memberHex := member.PubKeyHex()

	// ==================== ONE SIGNED ADMIT ====================
	addAuth := buildAllowlistAuthEvent(allowlistActionAdd, memberHex, time.Now().Unix())
	if err := identity.SignEvent(operator, addAuth); err != nil {
		t.Fatalf("SignEvent(add auth): %v", err)
	}
	var addResp okResponse
	dialAndRequest(t, sockPath, map[string]any{
		"op":               OpAllowlist,
		"allowlist_action": allowlistActionAdd,
		"allowlist_target": memberHex,
		"allowlist_auth":   addAuth,
	}, &addResp)
	if !addResp.OK {
		t.Fatalf("operator-signed admit returned ok=false: %s", addResp.Error)
	}

	// (1) GATE B reflects IMMEDIATELY — the KeySet is mutated synchronously inside
	// apply() before the IPC OK is written, so no poll/restart is needed.
	if !ksExchange.Allowed(memberHex) {
		t.Fatal("admit did NOT reflect in the live exchange KeySet — Gate B hot-reload failed")
	}

	// (2) an operator-signed roster admitting the member was PUBLISHED to the relay.
	waitFor(t, 4*time.Second, "operator-signed roster admitting the member lands on the relay", func() bool {
		for _, ev := range relayConn.receivedByKind(nostr.KindFleetRoster) {
			if rosterAdmits(ev, memberHex) {
				return true
			}
		}
		return false
	})
	rosters := relayConn.receivedByKind(nostr.KindFleetRoster)
	last := rosters[len(rosters)-1]
	if err := identity.VerifyEvent(last); err != nil {
		t.Fatalf("published roster is not a valid signed event: %v", err)
	}
	if last.PubKey != operator.PubKeyHex() {
		t.Fatalf("published roster author = %s, want operator %s", last.PubKey, operator.PubKeyHex())
	}

	// (3) RELAY-PROJECTION GATE reflects the member WITHIN 1s — the roster round-trips
	// the relay (echo) and the rosterFolder re-folds it into ksRelay. This can ONLY
	// pass if the roster actually traversed the relay; ksExchange being set does not
	// touch ksRelay.
	admitStart := time.Now()
	waitFor(t, 1*time.Second, "ksRelay reflects the member folded from the relay-echoed roster (<1s)", func() bool {
		return ksRelay.Allowed(memberHex)
	})
	t.Logf("admit round-trip to relay-projection gate: %s", time.Since(admitStart))

	// (4) NO full-history flood — the live admit issued NO new REQ. A restart or a
	// re-subscribe would have bumped reqCount and re-read the whole log from since=0.
	if got := relayConn.reqCount(); got != reqBaseline {
		t.Fatalf("live admit issued %d new REQ(s) (reqCount %d -> %d) — a re-subscribe / full-history re-read, not a live incremental admit",
			got-reqBaseline, reqBaseline, got)
	}

	// (5) The exchange gate actually ENFORCES on the admit: a put from the admitted
	// member promotes to inventory (SEAM pass), a put from a never-admitted outsider
	// is dropped_unlisted and never promotes.
	putMember := signExchangeEvent(t, member,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil,
		localPutPayload("Go HTTP handler unit test generator (admitted member)", 8000))
	relayConn.inject(putMember)
	waitFor(t, 4*time.Second, "admitted member's put promotes to matchable inventory (SEAM pass)", func() bool {
		return len(eng.State().Inventory()) == 1
	})

	beforeUnlisted := eng.DegradationSnapshot().DroppedUnlisted
	putOutsider := signExchangeEvent(t, outsider,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:rust"}, nil,
		localPutPayload("Rust async task scheduler generator (never admitted)", 9000))
	relayConn.inject(putOutsider)
	waitFor(t, 4*time.Second, "never-admitted outsider's put is dropped_unlisted at the exchange gate", func() bool {
		return eng.DegradationSnapshot().DroppedUnlisted > beforeUnlisted
	})
	if got := len(eng.State().Inventory()); got != 1 {
		t.Fatalf("inventory = %d after outsider put, want 1 (outsider must never promote)", got)
	}

	// ==================== ONE SIGNED DE-ADMIT — MIRRORS LIVE ====================
	rmAuth := buildAllowlistAuthEvent(allowlistActionRemove, memberHex, time.Now().Unix())
	if err := identity.SignEvent(operator, rmAuth); err != nil {
		t.Fatalf("SignEvent(remove auth): %v", err)
	}
	var rmResp okResponse
	dialAndRequest(t, sockPath, map[string]any{
		"op":               OpAllowlist,
		"allowlist_action": allowlistActionRemove,
		"allowlist_target": memberHex,
		"allowlist_auth":   rmAuth,
	}, &rmResp)
	if !rmResp.OK {
		t.Fatalf("operator-signed de-admit returned ok=false: %s", rmResp.Error)
	}

	// (6a) GATE B de-admits IMMEDIATELY.
	if ksExchange.Allowed(memberHex) {
		t.Fatal("de-admit did NOT drop the member from the live exchange KeySet — Gate B mirror failed")
	}

	// (6b) RELAY-PROJECTION GATE mirrors the removal WITHIN 1s: a NEW operator-signed
	// roster that OMITS the member round-trips the relay and re-folds, dropping the
	// member from ksRelay (the parameterized-replaceable latest-wins fold).
	rmStart := time.Now()
	waitFor(t, 1*time.Second, "ksRelay de-admits the member via a new relay-round-tripped roster (<1s)", func() bool {
		return !ksRelay.Allowed(memberHex)
	})
	t.Logf("de-admit round-trip to relay-projection gate: %s", time.Since(rmStart))

	// The newest roster on the relay must omit the removed member.
	rostersAfterRm := relayConn.receivedByKind(nostr.KindFleetRoster)
	newest := rostersAfterRm[len(rostersAfterRm)-1]
	if rosterAdmits(newest, memberHex) {
		t.Fatal("post-removal roster on the relay still admits the removed member")
	}

	// (6c) still NO full-history flood on the de-admit path.
	if got := relayConn.reqCount(); got != reqBaseline {
		t.Fatalf("live de-admit issued %d new REQ(s) (reqCount %d -> %d) — a re-subscribe / full-history re-read",
			got-reqBaseline, reqBaseline, got)
	}

	// (6d) enforcement mirrors: the removed member's SUBSEQUENT put is dropped_unlisted.
	beforeUnlisted2 := eng.DegradationSnapshot().DroppedUnlisted
	putMember2 := signExchangeEvent(t, member,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:python"}, nil,
		localPutPayload("Python pytest fixture generator (member after removal)", 8100))
	relayConn.inject(putMember2)
	waitFor(t, 4*time.Second, "removed member's subsequent put is dropped_unlisted", func() bool {
		return eng.DegradationSnapshot().DroppedUnlisted > beforeUnlisted2
	})
	if got := len(eng.State().Inventory()); got != 1 {
		t.Fatalf("inventory = %d after removed-member put, want 1 (post-removal put must never promote)", got)
	}

	// The config on disk reflects the final membership (member removed) — restart
	// durability is not silently divergent from the live state.
	if configHas(t, dgHome, memberHex) {
		t.Fatal("Config.FleetAllowlist still carries the removed member — persist mirror failed")
	}
}
