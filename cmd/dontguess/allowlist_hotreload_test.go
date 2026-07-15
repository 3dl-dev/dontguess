package main

// allowlist_hotreload_test.go — dontguess-113 GROUND-SOURCE (design §3 + §9 Gate
// B/P6, ADV-16): the live fleet-allowlist hot-reload IPC op (OpAllowlist) must
// take effect sub-second on a RUNNING operator — live KeySet mutate + operator-
// signed roster republish + Config.FleetAllowlist persist — with NO restart, and
// it must require an operator-key signature (socket reachability is NOT admission).
//
// These tests drive the REAL operator socket server (serveOperatorSocket +
// handleOperatorConn wired with a real allowlistController) over a REAL net.Dial
// against a REAL 0700 unix socket. Nothing is stubbed but the relay publish sink
// (a recorder that captures the republished roster — there is no relay in the
// test); the KeySet mutation, the config persist, the BIP-340 signature verify,
// and the roster signing are all production code.
//
//	(a) a VALID operator-signed add reflects in the live KeySet immediately, records
//	    an operator-signed roster admitting the member, and persists the config;
//	(b) an UNSIGNED add and a FORGED-key add are BOTH rejected and change nothing —
//	    proving socket-reach != admit;
//	(c) a VALID operator-signed remove de-admits live + republishes + persists.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
)

// allowlistTestServer stands up a real operator socket backed by a real
// allowlistController and returns the socket path plus the live KeySet, the config
// dgHome, and a thread-safe accessor for the rosters the controller republished.
type allowlistTestServer struct {
	sockPath  string
	keys      *exchange.KeySet
	dgHome    string
	op        *identity.Secp256k1Identity
	mu        *sync.Mutex
	published *[]*identity.Event
}

func newAllowlistTestServer(t *testing.T) *allowlistTestServer {
	t.Helper()

	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate operator: %v", err)
	}

	// Real dgHome with a real config so persistFleetAllowlistChange can Load/Write it.
	dgHome := t.TempDir()
	if _, err := exchange.Init(exchange.InitOptions{DGHome: dgHome}); err != nil {
		t.Fatalf("exchange.Init: %v", err)
	}

	ks := exchange.NewKeySet() // start EMPTY — the admit must be what fills it
	var mu sync.Mutex
	var published []*identity.Event

	ctrl := &allowlistController{
		keys:           ks,
		operatorSigner: op,
		operatorKeyHex: op.PubKeyHex(),
		dgHome:         dgHome,
		publishRoster: func(ev *identity.Event) {
			mu.Lock()
			published = append(published, ev)
			mu.Unlock()
		},
		nowUnix: func() int64 { return time.Now().Unix() },
	}

	// A minimal engine — OpAllowlist never reads it, but serveOperatorSocket needs one.
	h := newOpTestHarness(t)
	eng := h.newEngine()

	// Real 0700 socket dir, mirroring production layout.
	sockPath := filepath.Join(t.TempDir(), "ipc", "test-operator.sock")
	ln, err := listenOperatorSocket(sockPath)
	if err != nil {
		t.Fatalf("listenOperatorSocket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveOperatorSocket(ctx, ln, eng, ctrl)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		os.Remove(sockPath)
	})

	return &allowlistTestServer{
		sockPath:  sockPath,
		keys:      ks,
		dgHome:    dgHome,
		op:        op,
		mu:        &mu,
		published: &published,
	}
}

// lastRoster returns the most recently republished roster, or nil.
func (s *allowlistTestServer) lastRoster() *identity.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(*s.published) == 0 {
		return nil
	}
	return (*s.published)[len(*s.published)-1]
}

func (s *allowlistTestServer) publishedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(*s.published)
}

// rosterAdmits reports whether ev carries a ["p", hexKey] member tag.
func rosterAdmits(ev *identity.Event, hexKey string) bool {
	if ev == nil {
		return false
	}
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == "p" && strings.EqualFold(tg[1], hexKey) {
			return true
		}
	}
	return false
}

// configHas reports whether the persisted Config.FleetAllowlist contains a key that
// normalizes to hexKey.
func configHas(t *testing.T, dgHome, hexKey string) bool {
	t.Helper()
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, e := range cfg.FleetAllowlist {
		if h, err := normalizeToHex(e); err == nil && h == hexKey {
			return true
		}
	}
	return false
}

func TestOperatorSocket_Allowlist_LiveAdmit_SignedIPC(t *testing.T) {
	member, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate member: %v", err)
	}
	memberHex := member.PubKeyHex()

	// --- (b1) UNSIGNED add is rejected even though it reaches the socket ---
	t.Run("unsigned_rejected", func(t *testing.T) {
		s := newAllowlistTestServer(t)
		var resp okResponse
		dialAndRequest(t, s.sockPath, map[string]any{
			"op":               OpAllowlist,
			"allowlist_action": allowlistActionAdd,
			"allowlist_target": memberHex,
			// allowlist_auth deliberately absent
		}, &resp)

		if resp.OK {
			t.Fatal("unsigned allowlist add returned ok=true — socket reachability must NOT authorize an admit")
		}
		if s.keys.Allowed(memberHex) {
			t.Fatal("unsigned add mutated the live KeySet — socket-reach must not equal admit")
		}
		if s.publishedCount() != 0 {
			t.Fatal("unsigned add republished a roster")
		}
		if configHas(t, s.dgHome, memberHex) {
			t.Fatal("unsigned add persisted the member to config")
		}
		t.Logf("unsigned add rejected: %s", resp.Error)
	})

	// --- (b2) add signed by a NON-operator key is rejected ---
	t.Run("forged_key_rejected", func(t *testing.T) {
		s := newAllowlistTestServer(t)
		attacker, err := identity.Generate()
		if err != nil {
			t.Fatalf("Generate attacker: %v", err)
		}
		ev := buildAllowlistAuthEvent(allowlistActionAdd, memberHex, time.Now().Unix())
		if err := identity.SignEvent(attacker, ev); err != nil {
			t.Fatalf("SignEvent attacker: %v", err)
		}

		var resp okResponse
		dialAndRequest(t, s.sockPath, map[string]any{
			"op":               OpAllowlist,
			"allowlist_action": allowlistActionAdd,
			"allowlist_target": memberHex,
			"allowlist_auth":   ev,
		}, &resp)

		if resp.OK {
			t.Fatal("allowlist add signed by a non-operator key returned ok=true — must be rejected")
		}
		if s.keys.Allowed(memberHex) {
			t.Fatal("forged-key add mutated the live KeySet (ADV-16 violated)")
		}
		if s.publishedCount() != 0 {
			t.Fatal("forged-key add republished a roster")
		}
		t.Logf("forged-key add rejected: %s", resp.Error)
	})

	// --- (b3) an operator signature bound to a DIFFERENT action cannot be replayed ---
	t.Run("rebound_action_rejected", func(t *testing.T) {
		s := newAllowlistTestServer(t)
		// Operator signs a "remove" auth, but the wire request asks to "add".
		ev := buildAllowlistAuthEvent(allowlistActionRemove, memberHex, time.Now().Unix())
		if err := identity.SignEvent(s.op, ev); err != nil {
			t.Fatalf("SignEvent operator: %v", err)
		}
		var resp okResponse
		dialAndRequest(t, s.sockPath, map[string]any{
			"op":               OpAllowlist,
			"allowlist_action": allowlistActionAdd, // != the signed action
			"allowlist_target": memberHex,
			"allowlist_auth":   ev,
		}, &resp)

		if resp.OK {
			t.Fatal("add with a signature bound to 'remove' returned ok=true — must be rejected")
		}
		if s.keys.Allowed(memberHex) {
			t.Fatal("rebound-action add mutated the live KeySet")
		}
		t.Logf("rebound-action add rejected: %s", resp.Error)
	})

	// --- (a) the legitimate operator-signed add reflects live + republishes + persists ---
	t.Run("operator_signed_add_live", func(t *testing.T) {
		s := newAllowlistTestServer(t)
		ev := buildAllowlistAuthEvent(allowlistActionAdd, memberHex, time.Now().Unix())
		if err := identity.SignEvent(s.op, ev); err != nil {
			t.Fatalf("SignEvent operator: %v", err)
		}
		var resp okResponse
		dialAndRequest(t, s.sockPath, map[string]any{
			"op":               OpAllowlist,
			"allowlist_action": allowlistActionAdd,
			"allowlist_target": memberHex,
			"allowlist_auth":   ev,
		}, &resp)

		if !resp.OK {
			t.Fatalf("legitimate operator add returned ok=false: %s", resp.Error)
		}
		// LIVE: the KeySet is mutated synchronously inside apply() BEFORE the OK is
		// written, so by the time dialAndRequest returns the admit is already live —
		// no restart, no poll.
		if !s.keys.Allowed(memberHex) {
			t.Fatal("operator add did NOT reflect in the live KeySet — hot-reload failed")
		}
		// ROSTER REPUBLISHED: an operator-signed kind-30078 roster admitting the member.
		roster := s.lastRoster()
		if roster == nil {
			t.Fatal("operator add did not republish a roster")
		}
		if !strings.EqualFold(roster.PubKey, s.op.PubKeyHex()) {
			t.Fatalf("republished roster author = %s, want operator %s", roster.PubKey, s.op.PubKeyHex())
		}
		if err := identity.VerifyEvent(roster); err != nil {
			t.Fatalf("republished roster is not a valid operator-signed event: %v", err)
		}
		if !rosterAdmits(roster, memberHex) {
			t.Fatal("republished roster does not admit the member")
		}
		// PERSISTED: the config on disk carries the member for restart durability.
		if !configHas(t, s.dgHome, memberHex) {
			t.Fatal("operator add did not persist the member to Config.FleetAllowlist")
		}

		// --- (c) live REMOVE de-admits + republishes without the member + persists ---
		rmEv := buildAllowlistAuthEvent(allowlistActionRemove, memberHex, time.Now().Unix())
		if err := identity.SignEvent(s.op, rmEv); err != nil {
			t.Fatalf("SignEvent operator remove: %v", err)
		}
		var rmResp okResponse
		dialAndRequest(t, s.sockPath, map[string]any{
			"op":               OpAllowlist,
			"allowlist_action": allowlistActionRemove,
			"allowlist_target": memberHex,
			"allowlist_auth":   rmEv,
		}, &rmResp)

		if !rmResp.OK {
			t.Fatalf("legitimate operator remove returned ok=false: %s", rmResp.Error)
		}
		if s.keys.Allowed(memberHex) {
			t.Fatal("operator remove did NOT de-admit the member from the live KeySet")
		}
		rmRoster := s.lastRoster()
		if rmRoster == nil || rmRoster == roster {
			t.Fatal("operator remove did not republish a new roster")
		}
		if err := identity.VerifyEvent(rmRoster); err != nil {
			t.Fatalf("remove roster is not a valid operator-signed event: %v", err)
		}
		if rosterAdmits(rmRoster, memberHex) {
			t.Fatal("remove roster still admits the removed member")
		}
		if configHas(t, s.dgHome, memberHex) {
			t.Fatal("operator remove did not drop the member from Config.FleetAllowlist")
		}
	})
}

// TestVerifyAllowlistAuth_Unit exercises verifyAllowlistAuth's rejection branches
// directly (the pure gate) so each reason is covered without a socket.
func TestVerifyAllowlistAuth_Unit(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	opHex := op.PubKeyHex()
	const target = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	sign := func(ev *identity.Event, signer *identity.Secp256k1Identity) *identity.Event {
		if err := identity.SignEvent(signer, ev); err != nil {
			t.Fatalf("SignEvent: %v", err)
		}
		return ev
	}

	t.Run("nil_auth", func(t *testing.T) {
		if err := verifyAllowlistAuth(nil, opHex, allowlistActionAdd, target); err == nil {
			t.Fatal("nil auth must be rejected")
		}
	})

	t.Run("empty_operator_key", func(t *testing.T) {
		ev := sign(buildAllowlistAuthEvent(allowlistActionAdd, target, 1), op)
		if err := verifyAllowlistAuth(ev, "", allowlistActionAdd, target); err == nil {
			t.Fatal("empty operator key must fail closed")
		}
	})

	t.Run("wrong_kind_mintauth_replay", func(t *testing.T) {
		// A real mint-auth event must not be replayable as an allowlist authorization.
		ev := buildMintAuthEvent(target, 1000, 1)
		ev = sign(ev, op)
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionAdd, target); err == nil {
			t.Fatal("a mint-auth event (wrong kind) must be rejected as an allowlist auth")
		}
	})

	t.Run("wrong_author", func(t *testing.T) {
		attacker, _ := identity.Generate()
		ev := sign(buildAllowlistAuthEvent(allowlistActionAdd, target, 1), attacker)
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionAdd, target); err == nil {
			t.Fatal("non-operator author must be rejected")
		}
	})

	t.Run("tampered_after_sign", func(t *testing.T) {
		ev := sign(buildAllowlistAuthEvent(allowlistActionAdd, target, 1), op)
		ev.Tags = [][]string{{allowlistAuthActionTag, allowlistActionRemove}, {allowlistAuthTargetTag, target}}
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionRemove, target); err == nil {
			t.Fatal("tampered-after-sign event must fail signature verification")
		}
	})

	t.Run("rebound_target", func(t *testing.T) {
		other := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		ev := sign(buildAllowlistAuthEvent(allowlistActionAdd, target, 1), op)
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionAdd, other); err == nil {
			t.Fatal("a signature bound to a different target must be rejected")
		}
	})

	t.Run("valid_add", func(t *testing.T) {
		ev := sign(buildAllowlistAuthEvent(allowlistActionAdd, target, 1), op)
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionAdd, target); err != nil {
			t.Fatalf("valid operator-signed add auth must pass, got %v", err)
		}
	})

	t.Run("valid_remove", func(t *testing.T) {
		ev := sign(buildAllowlistAuthEvent(allowlistActionRemove, target, 2), op)
		if err := verifyAllowlistAuth(ev, opHex, allowlistActionRemove, target); err != nil {
			t.Fatalf("valid operator-signed remove auth must pass, got %v", err)
		}
	})
}
