package main

// child_grants_09a_test.go — delegated (parent-signed) admission, dontguess-09a.
//
// These tests pin the four properties the design commits to (§6):
//   1. a parent on the operator's allowlist CAN admit a child;
//   2. that child inherits full rights — put, buy AND deliver-on-credit — with no
//      standing threshold (fleet tier: every key is the operator's, §4);
//   3. a grant signed by a key NOT on the allowlist is refused;
//   4. a grant signed by a key that was itself admitted as a child is refused
//      (depth 1), and revoking a parent revokes its children durably.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
)

// writeTestConfig persists a minimal exchange config with the given membership.
func writeTestConfig(t *testing.T, dgHome, operatorHex string, allowlist []string, childGrants map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dgHome, 0o700); err != nil {
		t.Fatalf("mkdir dgHome: %v", err)
	}
	cfg := &exchange.Config{
		OperatorKeyHex: operatorHex,
		StorePath:      filepath.Join(dgHome, "events.jsonl"),
		FleetAllowlist: allowlist,
		ChildGrants:    childGrants,
	}
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func newTestSigner(t *testing.T) *identity.Secp256k1Identity {
	t.Helper()
	s, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	return s
}

// TestIssuerAuthorizer_ParentOnAllowlistMayAdmit is property (1): the whole point
// of the item. A key on the operator's own allowlist is authorized to issue grants.
func TestIssuerAuthorizer_ParentOnAllowlistMayAdmit(t *testing.T) {
	dg := t.TempDir()
	op := newTestSigner(t)
	parent := newTestSigner(t)
	writeTestConfig(t, dg, op.PubKeyHex(), []string{parent.PubKeyHex()}, nil)

	auth := newIssuerAuthorizer(dg, op.PubKeyHex())

	if got := auth(op.PubKeyHex()); got != nostr.IssuerOperator {
		t.Errorf("operator key role = %v, want IssuerOperator", got)
	}
	if got := auth(parent.PubKeyHex()); got != nostr.IssuerParent {
		t.Errorf("allowlisted parent role = %v, want IssuerParent -- an allowlisted key MUST be able to admit its children, this is the entire item", got)
	}
	// Case-insensitivity: an allowlist stored in mixed case must still match.
	if got := auth(strings.ToUpper(parent.PubKeyHex())); got != nostr.IssuerParent {
		t.Errorf("uppercase parent role = %v, want IssuerParent", got)
	}
}

// TestIssuerAuthorizer_RefusesStranger is property (3), and the security floor:
// a key that is not the operator and not on the allowlist admits nobody.
func TestIssuerAuthorizer_RefusesStranger(t *testing.T) {
	dg := t.TempDir()
	op := newTestSigner(t)
	parent := newTestSigner(t)
	stranger := newTestSigner(t)
	writeTestConfig(t, dg, op.PubKeyHex(), []string{parent.PubKeyHex()}, nil)

	auth := newIssuerAuthorizer(dg, op.PubKeyHex())
	if got := auth(stranger.PubKeyHex()); got != nostr.IssuerUnauthorized {
		t.Fatalf("non-allowlisted stranger role = %v, want IssuerUnauthorized -- a key off the allowlist must never admit anyone", got)
	}
	if got := auth(""); got != nostr.IssuerUnauthorized {
		t.Errorf("empty issuer role = %v, want IssuerUnauthorized", got)
	}
}

// TestIssuerAuthorizer_DepthOneChildMayNotAdmit is property (4): a key admitted AS
// a child cannot itself issue grants, even though it IS on the allowlist. Without
// this, admission chains arbitrarily deep and verification has to walk a chain.
func TestIssuerAuthorizer_DepthOneChildMayNotAdmit(t *testing.T) {
	dg := t.TempDir()
	op := newTestSigner(t)
	parent := newTestSigner(t)
	child := newTestSigner(t)

	// The child is genuinely on the allowlist (it was admitted) AND carries a
	// child edge. Membership alone must not be enough to make it an issuer.
	writeTestConfig(t, dg, op.PubKeyHex(),
		[]string{parent.PubKeyHex(), child.PubKeyHex()},
		map[string]string{child.PubKeyHex(): parent.PubKeyHex()})

	auth := newIssuerAuthorizer(dg, op.PubKeyHex())
	if got := auth(parent.PubKeyHex()); got != nostr.IssuerParent {
		t.Fatalf("parent role = %v, want IssuerParent", got)
	}
	if got := auth(child.PubKeyHex()); got != nostr.IssuerUnauthorized {
		t.Fatalf("child-admitted key role = %v, want IssuerUnauthorized -- depth 1: a child is on the allowlist but must NOT issue grandchildren", got)
	}
}

// TestIssuerAuthorizer_FailsClosedWithoutConfig proves the authorizer denies rather
// than defaults-open when it cannot read the operator's config.
func TestIssuerAuthorizer_FailsClosedWithoutConfig(t *testing.T) {
	dg := t.TempDir() // no config written
	op := newTestSigner(t)
	parent := newTestSigner(t)

	auth := newIssuerAuthorizer(dg, op.PubKeyHex())
	if got := auth(parent.PubKeyHex()); got != nostr.IssuerUnauthorized {
		t.Fatalf("role without config = %v, want IssuerUnauthorized (fail closed)", got)
	}
	// The operator key is pinned in-process and must still work without config.
	if got := auth(op.PubKeyHex()); got != nostr.IssuerOperator {
		t.Errorf("operator role without config = %v, want IssuerOperator", got)
	}
}

// TestChildGrants_RecordAndCascade covers the durable edge and what revocation
// must reach: childrenOf finds every child of a parent, forgetChildGrants drops
// them, and both survive a reload from disk (not just in-memory state).
func TestChildGrants_RecordAndCascade(t *testing.T) {
	dg := t.TempDir()
	op := newTestSigner(t)
	parent := newTestSigner(t)
	other := newTestSigner(t)
	kidA := newTestSigner(t)
	kidB := newTestSigner(t)
	kidC := newTestSigner(t) // belongs to `other`, must NOT cascade with parent

	writeTestConfig(t, dg, op.PubKeyHex(),
		[]string{parent.PubKeyHex(), other.PubKeyHex()}, nil)

	for _, k := range []*identity.Secp256k1Identity{kidA, kidB} {
		if err := recordChildGrant(dg, k.PubKeyHex(), parent.PubKeyHex()); err != nil {
			t.Fatalf("record child grant: %v", err)
		}
	}
	if err := recordChildGrant(dg, kidC.PubKeyHex(), other.PubKeyHex()); err != nil {
		t.Fatalf("record child grant for other: %v", err)
	}

	// Reload from disk — the edge must be durable, not process state.
	cfg, err := exchange.LoadConfig(dg)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	kids := childrenOf(cfg, parent.PubKeyHex())
	if len(kids) != 2 {
		t.Fatalf("childrenOf(parent) = %d children (%v), want 2 -- revocation cascade depends on this being complete", len(kids), kids)
	}
	if got := childrenOf(cfg, other.PubKeyHex()); len(got) != 1 {
		t.Fatalf("childrenOf(other) = %d, want 1 -- a cascade must not reach another parent's children", len(got))
	}

	// A child may not be its own parent, and empties are refused.
	if err := recordChildGrant(dg, parent.PubKeyHex(), parent.PubKeyHex()); err == nil {
		t.Error("recordChildGrant(self, self) succeeded, want error -- a self-edge would make a key its own parent")
	}
	if err := recordChildGrant(dg, "", parent.PubKeyHex()); err == nil {
		t.Error("recordChildGrant with empty child succeeded, want error")
	}

	// Cascade: forget the parent's children, leave the other parent's alone.
	if err := forgetChildGrants(dg, kids); err != nil {
		t.Fatalf("forget child grants: %v", err)
	}
	cfg2, err := exchange.LoadConfig(dg)
	if err != nil {
		t.Fatalf("reload after forget: %v", err)
	}
	if got := childrenOf(cfg2, parent.PubKeyHex()); len(got) != 0 {
		t.Errorf("after cascade, childrenOf(parent) = %v, want none", got)
	}
	if got := childrenOf(cfg2, other.PubKeyHex()); len(got) != 1 {
		t.Errorf("after cascade, childrenOf(other) = %v, want its 1 child untouched", got)
	}

	// And the formerly-child key may issue grants again once its edge is gone —
	// proving depth-1 keys off the edge map, not off some permanent mark.
	auth := newIssuerAuthorizer(dg, op.PubKeyHex())
	if got := auth(kidA.PubKeyHex()); got != nostr.IssuerUnauthorized {
		t.Errorf("kidA is not on the allowlist, role = %v, want IssuerUnauthorized", got)
	}
}
