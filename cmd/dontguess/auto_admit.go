package main

// auto_admit.go — walk-up auto-admission for a freshly provisioned agent key
// (dontguess-09a §3, step 3 of the implementation order).
//
// THE FRICTION THIS REMOVES: `agent-init --fleet-member` provisions an identity and
// then tells you it is NOT admitted, because only the operator key could admit and
// a member cannot self-admit. That notice is the whole problem in one line —
// measured 2026-07-27, 47 distinct agent keys put real work and were dropped
// `not-allowlisted`, and the reject arrives out of band so the agent never sees it.
//
// WHAT CHANGES: if the .dg/ we provisioned into ALREADY holds an admitted identity
// (the project/user/machine key), that identity is a PARENT. It mints a grant signed
// with its own key and the new child redeems it immediately — one command, no
// operator round-trip. The operator still verifies everything (see child_grants.go);
// a parent that is not on the operator's allowlist simply gets its grant refused,
// which degrades to exactly today's behaviour rather than to a security hole.
//
// Default ON, per the operator direction. Disable per-tree with
// `"auto_admit": false` in .dg/config.json, or per-invocation with --no-auto-admit.

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/relayclient"
)

// autoAdmitTimeout bounds each per-relay publish of the child's redeem.
const autoAdmitTimeout = 15 * time.Second

// autoAdmitChildTTL is how long the self-issued grant stays redeemable. Short by
// design: it is minted and redeemed in the same breath, so a long window only
// widens the replay surface for a token that has already served its purpose.
const autoAdmitTTL = 5 * time.Minute

// parentSignerFor resolves the admitting parent identity in dgDir, or nil if the
// tree has none yet.
//
// The parent is the .dg/'s DEFAULT identity (config.agent_name) — the one already
// provisioned for this project/user/machine. A tree whose first identity is the one
// being created has no parent, which is the ordinary bootstrap case: that first key
// is admitted once by the operator, and everything below inherits from it.
func parentSignerFor(dgDir, childName string) (identity.Signer, string, error) {
	cfg, err := loadClientConfigAt(dgDir)
	if err != nil {
		return nil, "", err
	}
	parentName := cfg.AgentName
	if parentName == "" || parentName == childName {
		return nil, "", nil // no parent yet — this key IS the tree's first identity
	}
	signer, rerr := identity.Resolve(filepath.Join(dgDir, "agents", parentName))
	if rerr != nil {
		return nil, parentName, fmt.Errorf("resolve parent identity %q: %w", parentName, rerr)
	}
	return signer, parentName, nil
}

// autoAdmitChild mints a parent-signed grant for childName and publishes the child's
// redeem, so the new key is admitted without an operator round-trip.
//
// Returns (false, nil) when auto-admission simply does not apply — no parent, no
// relay — so the caller falls back to the manual-admission notice. Errors are
// returned for genuine failures the operator should see, but the CALLER treats them
// as non-fatal: a failed auto-admit must never fail `agent-init` itself, or a
// provisioning command starts depending on relay reachability.
func autoAdmitChild(ctx context.Context, dgDir, childName string, out io.Writer) (bool, error) {
	parentSigner, parentName, err := parentSignerFor(dgDir, childName)
	if err != nil {
		return false, err
	}
	if parentSigner == nil {
		return false, nil // bootstrap case: nothing to inherit from
	}

	cfg, _ := loadClientConfigAt(dgDir)
	relays := cfg.RelayURLs
	if len(relays) == 0 {
		// Individual tier or an unconfigured tree: there is no relay to carry the
		// redeem, and no operator to read it. Not an error.
		return false, nil
	}

	childSigner, rerr := identity.Resolve(filepath.Join(dgDir, "agents", childName))
	if rerr != nil {
		return false, fmt.Errorf("resolve child identity %q: %w", childName, rerr)
	}

	grantID, gerr := newInviteGrantID()
	if gerr != nil {
		return false, gerr
	}
	now := time.Now().Unix()
	// Signed with the PARENT key, not the operator's — that is the whole mechanism.
	// The operator's issuer gate decides whether this parent may admit; we do not.
	token, terr := nostr.BuildInviteToken(parentSigner, childName, grantID, relays, 0, now, now+int64(autoAdmitTTL.Seconds()))
	if terr != nil {
		return false, fmt.Errorf("mint parent grant: %w", terr)
	}
	in, perr := nostr.ParseInviteToken(token)
	if perr != nil {
		return false, fmt.Errorf("parse own grant: %w", perr)
	}
	redeem, berr := nostr.BuildRedeemEvent(childSigner, in, now)
	if berr != nil {
		return false, fmt.Errorf("build redeem: %w", berr)
	}

	published := false
	var lastErr error
	for _, url := range relays {
		pctx, cancel := context.WithTimeout(ctx, autoAdmitTimeout)
		conn := relayclient.NewConn(url, childSigner)
		accepted, msg, cerr := relayclient.PublishEvent(pctx, conn, redeem)
		_ = conn.Close()
		cancel()
		if cerr != nil {
			lastErr = cerr
			continue
		}
		if !accepted {
			lastErr = fmt.Errorf("relay %s rejected the redeem: %s", url, msg)
			continue
		}
		published = true
	}
	if !published {
		return false, fmt.Errorf("publish redeem: %w", lastErr)
	}

	fmt.Fprintf(out, "\n✓ auto-admission requested: %q is claiming admission under parent %q\n", childName, parentName)
	fmt.Fprintf(out, "  The operator admits it once it folds the redeem, IF %q is on the operator's allowlist.\n", parentName)
	fmt.Fprintf(out, "  If `put` still comes back REJECTED, the parent is not admitted — ask the operator for:\n")
	fmt.Fprintf(out, "    dontguess allowlist add %s\n", parentSigner.Npub())
	return true, nil
}
