package main

// child_grants.go — delegated (parent-signed) admission, dontguess-09a.
//
// A PARENT is a key already on the operator's own fleet allowlist. It may mint an
// invite signed with its OWN key, which a child redeems through the ordinary
// kind-3410 path. The operator still performs 100% of verification (ADV-2); this
// file supplies the policy the verifier asks about, and the durable parent -> child
// edge that makes revocation cascade.
//
// WHY THIS EXISTS: agents mint a per-project key via the .dg/ walk-up, and manual
// admission is O(agents) round-trips against a model that is O(project directories).
// Measured 2026-07-27: 47 distinct senders rejected `not-allowlisted`, zero overlap
// with the 48-member allowlist, and the failure is invisible to the agent that
// suffers it. See docs/design/hierarchical-agent-admission-09a.md §1.
//
// WHAT IS DELIBERATELY *NOT* HERE: per-parent child caps, credit non-inheritance,
// and standing thresholds. At fleet tier every key belongs to the operator, and
// Sybil defense is tier-gated to federation (operator ruling 2026-07-17,
// dontguess-5a3). A child inherits its parent's rights, deliver-on-credit included.
// The bounds return at federation — see design §5, and the one rule that carries
// forward: a grant is honoured ONLY for a parent on the LOCAL operator's allowlist.

import (
	"fmt"
	"strings"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
)

// newIssuerAuthorizer returns the policy nostr.VerifyRedeemWithIssuer consults.
//
// Evaluated against the operator's OWN persisted config every time, never against
// anything the redeem asserts about itself — which is what keeps a dumb or hostile
// relay unable to admit anyone.
//
// Order matters: the operator key wins outright, so an operator that somehow also
// appears on its own allowlist still issues as IssuerOperator (no child edge).
func newIssuerAuthorizer(dgHome, operatorKeyHex string) nostr.IssuerAuthorizer {
	opHex := strings.ToLower(strings.TrimSpace(operatorKeyHex))
	return func(issuerHexKey string) nostr.IssuerRole {
		issuer := strings.ToLower(strings.TrimSpace(issuerHexKey))
		if issuer == "" {
			return nostr.IssuerUnauthorized
		}
		if issuer == opHex {
			return nostr.IssuerOperator
		}
		cfg, err := exchange.LoadConfig(dgHome)
		if err != nil {
			// Fail closed: no config, no delegated admission.
			return nostr.IssuerUnauthorized
		}
		// DEPTH 1: a key that was itself admitted as a child may not issue grants.
		if _, isChild := normalizedChildGrants(cfg)[issuer]; isChild {
			return nostr.IssuerUnauthorized
		}
		for _, m := range cfg.FleetAllowlist {
			if h := normalizeMemberKey(m); h != "" && h == issuer {
				return nostr.IssuerParent
			}
		}
		return nostr.IssuerUnauthorized
	}
}

// normalizeMemberKey renders an allowlist entry (npub or hex) as lowercase hex.
// Returns "" for anything unparseable, so a malformed entry can never match.
func normalizeMemberKey(entry string) string {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return ""
	}
	if strings.HasPrefix(entry, "npub") {
		h, err := identity.DecodeNpubToHex(entry)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(h))
	}
	return entry
}

// normalizedChildGrants returns the child -> parent map with both sides lowercased,
// so lookups are case-insensitive regardless of how an edge was written.
func normalizedChildGrants(cfg *exchange.Config) map[string]string {
	out := make(map[string]string, len(cfg.ChildGrants))
	for child, parent := range cfg.ChildGrants {
		c := strings.ToLower(strings.TrimSpace(child))
		p := strings.ToLower(strings.TrimSpace(parent))
		if c == "" || p == "" {
			continue
		}
		out[c] = p
	}
	return out
}

// recordChildGrant durably persists the parent -> child edge.
//
// Called AFTER the child is promoted, so a crash between promotion and this write
// can only lose the edge (child admitted, revocation will not cascade to it — a
// visible, fixable state) rather than record an edge for a key that was never
// admitted (an invisible one).
func recordChildGrant(dgHome, childHex, parentHex string) error {
	child := strings.ToLower(strings.TrimSpace(childHex))
	parent := strings.ToLower(strings.TrimSpace(parentHex))
	if child == "" || parent == "" {
		return fmt.Errorf("child grant: empty child %q or parent %q", childHex, parentHex)
	}
	if child == parent {
		return fmt.Errorf("child grant: child and parent are the same key %s", child)
	}
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		return fmt.Errorf("child grant: load config: %w", err)
	}
	if cfg.ChildGrants == nil {
		cfg.ChildGrants = map[string]string{}
	}
	cfg.ChildGrants[child] = parent
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		return fmt.Errorf("child grant: persist: %w", err)
	}
	return nil
}

// childrenOf returns every key admitted under parentHex, for cascading revocation.
func childrenOf(cfg *exchange.Config, parentHex string) []string {
	parent := strings.ToLower(strings.TrimSpace(parentHex))
	if parent == "" {
		return nil
	}
	var kids []string
	for child, p := range normalizedChildGrants(cfg) {
		if p == parent {
			kids = append(kids, child)
		}
	}
	return kids
}

// forgetChildGrants drops edges for the given keys (used when a child is removed in
// its own right, and when a parent removal cascades). Missing keys are a no-op.
func forgetChildGrants(dgHome string, childHexes []string) error {
	if len(childHexes) == 0 {
		return nil
	}
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		return fmt.Errorf("child grant: load config: %w", err)
	}
	if len(cfg.ChildGrants) == 0 {
		return nil
	}
	for _, c := range childHexes {
		delete(cfg.ChildGrants, strings.ToLower(strings.TrimSpace(c)))
		delete(cfg.ChildGrants, strings.TrimSpace(c))
	}
	if len(cfg.ChildGrants) == 0 {
		cfg.ChildGrants = nil
	}
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		return fmt.Errorf("child grant: persist: %w", err)
	}
	return nil
}
