package exchange_test

// Unit tests for the trust primitive (dontguess-3311). This replaces the former
// campfire pkg/provenance gate. The primitive is NIP-42 allowlist membership +
// operator write authority + a behavioral reputation floor on sell-side ops.
//
// The former 4-level provenance ladder (anonymous/claimed/contactable/present)
// collapses to three tiers (anonymous/allowlisted/operator): an allowlist model
// cannot distinguish "claimed" from "contactable" — you are a vetted fleet
// member or you are not. These tests assert the SAME trust OUTCOMES the old
// suite protected — non-allowlisted senders are rejected for write ops,
// allowlisted senders cannot perform operator-only ops (match/mint/settle
// put-*), and the operator is accepted for everything — plus the net-new
// reputation floor.

import (
	"errors"
	"testing"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/campfire-net/dontguess/pkg/identity"
)

const (
	keyOperator    = "key-operator"
	keyAllowlisted = "key-allowlisted"
	keyAnon        = "key-anon"
)

// makeTrustChecker returns a checker with:
//
//	keyOperator    → TrustOperator    (the operator key)
//	keyAllowlisted → TrustAllowlisted (a fleet member on the KeySet)
//	keyAnon        → TrustAnonymous   (not admitted)
//
// No reputation floor is wired (reputation gating disabled).
func makeTrustChecker(t *testing.T) *exchange.TrustChecker {
	t.Helper()
	fleet := exchange.NewKeySet(keyAllowlisted)
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	return c
}

// TestRequiredLevel verifies the operation → trust level mapping.
func TestRequiredLevel(t *testing.T) {
	cases := []struct {
		name     string
		op       exchange.Operation
		phase    exchange.SettlePhase
		expected exchange.TrustLevel
		wantErr  bool
	}{
		// anonymous operations
		{"buy", exchange.OperationBuy, "", exchange.TrustAnonymous, false},
		{"inventory-read", exchange.OperationInventoryRead, "", exchange.TrustAnonymous, false},
		{"price-history-read", exchange.OperationPriceHistoryRead, "", exchange.TrustAnonymous, false},

		// allowlisted (fleet member) operations — put and assign both collapse here
		{"put", exchange.OperationPut, "", exchange.TrustAllowlisted, false},
		{"assign", exchange.OperationAssign, "", exchange.TrustAllowlisted, false},

		// operator operations
		{"mint", exchange.OperationMint, "", exchange.TrustOperator, false},
		{"burn", exchange.OperationBurn, "", exchange.TrustOperator, false},
		{"rate-publish", exchange.OperationRatePublish, "", exchange.TrustOperator, false},
		{"convention-promote", exchange.OperationConventionPromote, "", exchange.TrustOperator, false},
		{"convention-supersede", exchange.OperationConventionSupersede, "", exchange.TrustOperator, false},
		{"match", exchange.OperationMatch, "", exchange.TrustOperator, false},

		// settle buyer phases (allowlisted fleet member)
		{"settle buyer-accept", exchange.OperationSettle, exchange.SettlePhaseBuyerAccept, exchange.TrustAllowlisted, false},
		{"settle buyer-reject", exchange.OperationSettle, exchange.SettlePhaseBuyerReject, exchange.TrustAllowlisted, false},
		{"settle complete", exchange.OperationSettle, exchange.SettlePhaseComplete, exchange.TrustAllowlisted, false},
		{"settle dispute", exchange.OperationSettle, exchange.SettlePhaseDispute, exchange.TrustAllowlisted, false},

		// settle operator phases
		{"settle put-accept", exchange.OperationSettle, exchange.SettlePhasePutAccept, exchange.TrustOperator, false},
		{"settle put-reject", exchange.OperationSettle, exchange.SettlePhasePutReject, exchange.TrustOperator, false},
		{"settle deliver", exchange.OperationSettle, exchange.SettlePhaseDeliver, exchange.TrustOperator, false},

		// error cases
		{"settle without phase", exchange.OperationSettle, "", 0, true},
		{"unknown operation", "unknown-op", "", 0, true},
		{"settle unknown phase", exchange.OperationSettle, "made-up-phase", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := exchange.RequiredLevel(tc.op, tc.phase)
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got nil (level=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

// TestCheck_AnonymousRejectedForPut is the primary preserved outcome: a
// non-allowlisted sender's put is rejected with ErrInsufficientTrust.
func TestCheck_AnonymousRejectedForPut(t *testing.T) {
	c := makeTrustChecker(t)
	err := c.Check(keyAnon, exchange.OperationPut, "")
	if err == nil {
		t.Fatal("expected ErrInsufficientTrust for anonymous put, got nil")
	}
	if !errors.Is(err, exchange.ErrInsufficientTrust) {
		t.Errorf("expected ErrInsufficientTrust, got: %v", err)
	}
}

// TestCheck_AllowlistedSucceedsForPut: an allowlisted fleet member's put succeeds.
func TestCheck_AllowlistedSucceedsForPut(t *testing.T) {
	c := makeTrustChecker(t)
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); err != nil {
		t.Errorf("expected allowlisted sender to succeed for put, got: %v", err)
	}
}

// TestCheck_AnonymousAcceptedForBuy: non-allowlisted agents can still buy.
func TestCheck_AnonymousAcceptedForBuy(t *testing.T) {
	c := makeTrustChecker(t)
	if err := c.Check(keyAnon, exchange.OperationBuy, ""); err != nil {
		t.Errorf("expected anonymous sender to succeed for buy, got: %v", err)
	}
}

// TestCheck_TrustLevelMatrix runs sender tiers × operations. It preserves the
// core semantics of the former provenance matrix: anonymous cannot write,
// allowlisted cannot perform operator-only ops (this is the operator-forgery
// closure — an allowlisted npub must not be able to forge match/settle put-*/mint),
// and the operator is accepted for all.
func TestCheck_TrustLevelMatrix(t *testing.T) {
	c := makeTrustChecker(t)

	cases := []struct {
		name      string
		senderKey string
		op        exchange.Operation
		phase     exchange.SettlePhase
		wantErr   bool
	}{
		// anonymous: buy + reads only, blocked for everything else
		{"anon/buy ok", keyAnon, exchange.OperationBuy, "", false},
		{"anon/inventory-read ok", keyAnon, exchange.OperationInventoryRead, "", false},
		{"anon/put rejected", keyAnon, exchange.OperationPut, "", true},
		{"anon/assign rejected", keyAnon, exchange.OperationAssign, "", true},
		{"anon/mint rejected", keyAnon, exchange.OperationMint, "", true},
		{"anon/match rejected", keyAnon, exchange.OperationMatch, "", true},
		{"anon/settle buyer-accept rejected", keyAnon, exchange.OperationSettle, exchange.SettlePhaseBuyerAccept, true},

		// allowlisted: put, assign, buyer settle phases; blocked for operator-only ops
		{"allowlisted/buy ok", keyAllowlisted, exchange.OperationBuy, "", false},
		{"allowlisted/put ok", keyAllowlisted, exchange.OperationPut, "", false},
		{"allowlisted/assign ok", keyAllowlisted, exchange.OperationAssign, "", false},
		{"allowlisted/settle buyer-accept ok", keyAllowlisted, exchange.OperationSettle, exchange.SettlePhaseBuyerAccept, false},
		{"allowlisted/settle complete ok", keyAllowlisted, exchange.OperationSettle, exchange.SettlePhaseComplete, false},
		{"allowlisted/settle dispute ok", keyAllowlisted, exchange.OperationSettle, exchange.SettlePhaseDispute, false},
		{"allowlisted/mint rejected", keyAllowlisted, exchange.OperationMint, "", true},
		{"allowlisted/match rejected", keyAllowlisted, exchange.OperationMatch, "", true},
		{"allowlisted/settle put-accept rejected", keyAllowlisted, exchange.OperationSettle, exchange.SettlePhasePutAccept, true},

		// operator: allowed for all operations
		{"operator/put ok", keyOperator, exchange.OperationPut, "", false},
		{"operator/assign ok", keyOperator, exchange.OperationAssign, "", false},
		{"operator/mint ok", keyOperator, exchange.OperationMint, "", false},
		{"operator/burn ok", keyOperator, exchange.OperationBurn, "", false},
		{"operator/match ok", keyOperator, exchange.OperationMatch, "", false},
		{"operator/rate-publish ok", keyOperator, exchange.OperationRatePublish, "", false},
		{"operator/settle put-accept ok", keyOperator, exchange.OperationSettle, exchange.SettlePhasePutAccept, false},
		{"operator/settle deliver ok", keyOperator, exchange.OperationSettle, exchange.SettlePhaseDeliver, false},
		{"operator/convention-promote ok", keyOperator, exchange.OperationConventionPromote, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Check(tc.senderKey, tc.op, tc.phase)
			if tc.wantErr && err == nil {
				t.Errorf("expected rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected success, got: %v", err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, exchange.ErrInsufficientTrust) {
				t.Errorf("expected ErrInsufficientTrust, got different error: %v", err)
			}
		})
	}
}

// TestCheck_UnknownKeyDefaultsToAnonymous: a key that is neither the operator
// nor on the allowlist defaults to anonymous — buy ok, put rejected.
func TestCheck_UnknownKeyDefaultsToAnonymous(t *testing.T) {
	c := makeTrustChecker(t)
	unknownKey := "unknown-key-xyz"

	if err := c.Check(unknownKey, exchange.OperationBuy, ""); err != nil {
		t.Errorf("expected unknown key to default to anonymous for buy, got: %v", err)
	}

	err := c.Check(unknownKey, exchange.OperationPut, "")
	if err == nil {
		t.Fatalf("expected ErrInsufficientTrust for unknown key on put, got nil")
	}
	if !errors.Is(err, exchange.ErrInsufficientTrust) {
		t.Errorf("expected ErrInsufficientTrust, got: %v", err)
	}
}

// TestCheck_NilMembers: with a nil allowlist (individual tier, no team relay),
// only the operator is above anonymous; every other key is anonymous.
func TestCheck_NilMembers(t *testing.T) {
	c, err := exchange.NewTrustChecker(keyOperator, nil)
	if err != nil {
		t.Fatalf("NewTrustChecker(nil members): %v", err)
	}
	if got := c.Level(keyOperator); got != exchange.TrustOperator {
		t.Errorf("operator level = %v, want TrustOperator", got)
	}
	if got := c.Level("anybody"); got != exchange.TrustAnonymous {
		t.Errorf("non-operator level with nil members = %v, want TrustAnonymous", got)
	}
	// A non-operator put must be rejected (nobody is allowlisted).
	if err := c.Check("anybody", exchange.OperationPut, ""); !errors.Is(err, exchange.ErrInsufficientTrust) {
		t.Errorf("expected ErrInsufficientTrust for put with nil members, got: %v", err)
	}
}

// TestCheck_ReputationFloorRejectsLowRepPut is the net-new behavior: an
// allowlisted seller whose behavioral reputation is below the floor is rejected
// for put with ErrLowReputation — even though membership alone would admit them.
func TestCheck_ReputationFloorRejectsLowRepPut(t *testing.T) {
	fleet := exchange.NewKeySet(keyAllowlisted)
	rep := map[string]int{keyAllowlisted: 30}
	c, err := exchange.NewTrustChecker(keyOperator, fleet,
		exchange.WithReputationFloor(func(k string) int { return rep[k] }, 40))
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	// reputation 30 < floor 40 → put rejected with ErrLowReputation.
	err = c.Check(keyAllowlisted, exchange.OperationPut, "")
	if err == nil {
		t.Fatal("expected ErrLowReputation for low-rep put, got nil")
	}
	if !errors.Is(err, exchange.ErrLowReputation) {
		t.Errorf("expected ErrLowReputation, got: %v", err)
	}

	// Buy is NOT reputation-gated — a low-rep buyer can still buy.
	if err := c.Check(keyAllowlisted, exchange.OperationBuy, ""); err != nil {
		t.Errorf("expected buy to be exempt from reputation floor, got: %v", err)
	}

	// Raise reputation above the floor → put now succeeds.
	rep[keyAllowlisted] = 60
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); err != nil {
		t.Errorf("expected put to succeed once reputation ≥ floor, got: %v", err)
	}
}

// TestCheck_ReputationFloorExemptsOperator: the operator is never blocked by the
// reputation floor — operator-authored events are trust-anchored, not scored.
func TestCheck_ReputationFloorExemptsOperator(t *testing.T) {
	fleet := exchange.NewKeySet(keyAllowlisted)
	c, err := exchange.NewTrustChecker(keyOperator, fleet,
		exchange.WithReputationFloor(func(string) int { return -100 }, 40))
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	if err := c.Check(keyOperator, exchange.OperationPut, ""); err != nil {
		t.Errorf("operator must be exempt from reputation floor, got: %v", err)
	}
}

// TestCheck_SetReputationFloor exercises the post-construction setter used by the
// serve path (the reputation source — engine State — only exists after the
// TrustChecker is constructed and passed into NewEngine).
func TestCheck_SetReputationFloor(t *testing.T) {
	fleet := exchange.NewKeySet(keyAllowlisted)
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	// No floor wired yet → low-rep seller admitted for put.
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); err != nil {
		t.Fatalf("expected put to pass before floor wired, got: %v", err)
	}

	// Wire a floor of 40 with the seller scoring 10 → put now rejected.
	c.SetReputationFloor(func(string) int { return 10 }, 40)
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); !errors.Is(err, exchange.ErrLowReputation) {
		t.Errorf("expected ErrLowReputation after SetReputationFloor, got: %v", err)
	}

	// A nil source disables the floor again.
	c.SetReputationFloor(nil, 40)
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); err != nil {
		t.Errorf("expected put to pass after floor disabled, got: %v", err)
	}
}

// TestTrust_IdentityAllowlistAsMembership proves the reuse requirement: a real
// pkg/identity Allowlist (built from an npub) satisfies the Membership interface
// and drives the trust gate. This is the nostr fleet-npub path.
func TestTrust_IdentityAllowlistAsMembership(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	al, err := identity.NewAllowlist(id.Npub())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	// *identity.Allowlist must satisfy exchange.Membership.
	var _ exchange.Membership = al

	c, err := exchange.NewTrustChecker(keyOperator, al)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	// The allowlisted npub (matched by its hex pubkey) is a fleet member → put ok.
	if err := c.Check(id.PubKeyHex(), exchange.OperationPut, ""); err != nil {
		t.Errorf("expected allowlisted npub to pass put, got: %v", err)
	}
	// A different, non-admitted key is anonymous → put rejected.
	other, _ := identity.Generate()
	if err := c.Check(other.PubKeyHex(), exchange.OperationPut, ""); !errors.Is(err, exchange.ErrInsufficientTrust) {
		t.Errorf("expected non-admitted npub to be rejected for put, got: %v", err)
	}
}

// TestTrustLevelOverrides: config overrides change required levels; an unknown
// level name is a hard error.
func TestTrustLevelOverrides(t *testing.T) {
	fleet := exchange.NewKeySet(keyAllowlisted)

	// Override: require operator for put. Allowlisted seller now rejected.
	c, err := exchange.NewTrustChecker(keyOperator, fleet,
		exchange.WithTrustLevelOverrides(exchange.TrustLevels{"put": "operator"}))
	if err != nil {
		t.Fatalf("NewTrustChecker with override: %v", err)
	}
	if err := c.Check(keyAllowlisted, exchange.OperationPut, ""); !errors.Is(err, exchange.ErrInsufficientTrust) {
		t.Errorf("expected allowlisted put to be rejected after operator override, got: %v", err)
	}
	if err := c.Check(keyOperator, exchange.OperationPut, ""); err != nil {
		t.Errorf("expected operator put to pass after override, got: %v", err)
	}

	// Unknown level name → construction error.
	if _, err := exchange.NewTrustChecker(keyOperator, fleet,
		exchange.WithTrustLevelOverrides(exchange.TrustLevels{"put": "bogus-level"})); err == nil {
		t.Error("expected error for unknown trust level name, got nil")
	}
}
