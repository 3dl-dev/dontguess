package main

// allowlist_hotreload.go — dontguess-113 (design §3 + §9 Gate B/P6). The
// server-side half of live fleet-allowlist admission: an operator-signed
// OpAllowlist IPC request (mirroring OpMint) mutates the RUNNING operator's live
// state sub-second, with NO restart — so admitting/removing a fleet member never
// re-triggers the 61a Since=0 full-history re-read that a restart would.
//
// Three effects per the ruling (§3), in order:
//
//	1. Config.FleetAllowlist persist   — restart durability (the authoritative
//	   backing; done first so a persist failure aborts BEFORE any live mutation).
//	2. live KeySet.Add / Remove        — the same *KeySet the TrustChecker enforces
//	   (SEAM A/B) AND the rosterFolder folds into; reflected immediately.
//	3. roster republish                — an operator-signed kind-30078 roster with
//	   the new FULL membership, published to every attached relay leg so the
//	   (optional, out-of-repo) relay writePolicy and any peer folds converge. Its
//	   own echo re-folds via rosterFolder onto the SAME KeySet — idempotent.
//
// Authorization is NOT socket reachability: apply() runs verifyAllowlistAuth
// FIRST (an operator-key BIP-340 signature binding the exact action+target), so a
// local process merely reaching the 0700 socket cannot admit a fleet member any
// more than it can mint scrip (ADV-16).

import (
	"fmt"
	"strings"
	"sync"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
)

// allowlistController holds everything the OpAllowlist handler needs to hot-reload
// the live fleet allowlist on a running operator. It is constructed once per serve
// process (serve.go) and shared by the socket handler goroutines.
//
// On the individual/no-relay tier keys==nil and operatorSigner==nil: apply() still
// verifies the operator signature and persists Config.FleetAllowlist (so a later
// team-tier start picks it up), but performs no live KeySet mutation or roster
// republish — there is no admission gate to reload there.
type allowlistController struct {
	// keys is the live enforcement KeySet the TrustChecker reads AND the
	// rosterFolder folds into (serve.go builds one *KeySet shared by both). nil on
	// the individual/no-relay tier.
	keys *exchange.KeySet
	// operatorSigner signs the republished roster. It is the operator identity
	// (== the relay signer) on the team tier; nil on the individual tier.
	operatorSigner identity.Signer
	// operatorKeyHex is the persisted operator pubkey (State().OperatorKey) the
	// auth signature is verified against.
	operatorKeyHex string
	// dgHome is where Config.FleetAllowlist is persisted for restart durability.
	dgHome string
	// publishRoster fans an operator-signed roster event out to every attached
	// relay leg (best-effort — the live KeySet + config are the authoritative
	// local effects; a failed relay publish reconciles on the next fold). nil on
	// the individual tier and in unit tests that assert config-only behavior.
	publishRoster func(ev *identity.Event)

	// onRevoke / onReadmit apply the RETENTION side of a de-admit / re-admit to the
	// live engine (dontguess-23c): onRevoke records the durable revocation tombstone
	// and withholds the seller's accepted inventory from the index NOW; onReadmit
	// clears it and re-indexes the retained inventory. Wired to
	// Engine.DeAllowlistSeller / Engine.ReAllowlistSeller. nil on the individual
	// tier and in config-only unit tests.
	onRevoke  func(sellerHex string)
	onReadmit func(sellerHex string)

	// mu serializes apply() calls so the config write, the KeySet mutation, and the
	// roster snapshot form one atomic operator action — the republished roster
	// always reflects the membership just persisted. lastRoster keeps each
	// republished roster's created_at strictly increasing so the parameterized-
	// replaceable latest-wins fold never treats a rapid second admit as stale.
	mu         sync.Mutex
	lastRoster int64
	nowUnix    func() int64 // clock seam (defaults to time.Now().Unix())

	// logger reports non-fatal roster anomalies (e.g. quarantined allowlist
	// entries, dontguess-31b). nil in unit tests — use logf, never this directly.
	logger func(format string, args ...any)
}

// logf reports a non-fatal controller anomaly, tolerating a nil logger so the
// config-only unit tests can construct a controller without wiring one.
func (c *allowlistController) logf(format string, args ...any) {
	if c == nil || c.logger == nil {
		return
	}
	c.logger(format, args...)
}

// apply is the OpAllowlist handler entry point. action is add|remove; targetHex is
// the fleet member's lowercase hex pubkey; auth is the operator-key-signed
// authorization binding this exact action+target. It returns an error (surfaced to
// the CLI over the socket) on an invalid action, a failed authorization, or a
// config persist failure — and mutates nothing live in any of those cases.
func (c *allowlistController) apply(action, targetHex string, auth *identity.Event) error {
	action = strings.ToLower(strings.TrimSpace(action))
	targetHex = strings.ToLower(strings.TrimSpace(targetHex))
	if targetHex == "" {
		return fmt.Errorf("allowlist: empty target key")
	}
	if action != allowlistActionAdd && action != allowlistActionRemove {
		return fmt.Errorf("allowlist: unknown action %q (want add|remove)", action)
	}

	// AUTHORIZATION FIRST (ADV-16): socket reachability is necessary but not
	// sufficient — the request must prove possession of the operator key, bound to
	// this exact action+target. Verified BEFORE any state is touched.
	if err := verifyAllowlistAuth(auth, c.operatorKeyHex, action, targetHex); err != nil {
		return err
	}
	return c.applyAuthorized(action, targetHex)
}

// applyAuthorized performs the membership mutation AFTER authorization has been
// established, and is the shared body behind two callers with different ways of
// being authorized:
//
//	apply()             — an external caller over the operator socket, which must
//	                      prove possession of the operator key for this exact
//	                      action+target (ADV-16). That proof happens above.
//	Engine open admission — the operator's OWN engine, in-process (dontguess-f6d).
//	                      There is no signature to verify because there is no
//	                      caller to authenticate: this IS the operator.
//
// Splitting here keeps the signature check on exactly the path that needs it. It
// must never be called from a path that has not established authority.
func (c *allowlistController) applyAuthorized(action, targetHex string) error {
	action = strings.ToLower(strings.TrimSpace(action))
	targetHex = strings.ToLower(strings.TrimSpace(targetHex))
	if targetHex == "" {
		return fmt.Errorf("allowlist: empty target key")
	}
	if action != allowlistActionAdd && action != allowlistActionRemove {
		return fmt.Errorf("allowlist: unknown action %q (want add|remove)", action)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// (1) Persist config FIRST (restart durability, the authoritative backing). A
	// persist failure aborts before any live mutation, so on-disk state and the
	// live KeySet never diverge in the failure path. The returned slice is the
	// post-mutation config FleetAllowlist — the AUTHORITATIVE full membership this
	// admit/remove just committed under c.mu. The republished roster is built from
	// THIS, never from the concurrently-mutable live KeySet (dontguess-9ef): a
	// rosterFolder.fold() on another leg runs under rf.mu (not c.mu) and can
	// ReplaceAll the shared KeySet between our Add and a KeySet read, so reading the
	// live KeySet to build the roster could silently omit the just-admitted member
	// (or re-include a just-removed one) — a durable membership desync, since the
	// roster is authoritative-on-fold. The persisted config is immune: it is the
	// operator intent we hold c.mu across.
	// CASCADING REVOCATION (dontguess-09a): removing a parent removes every child it
	// admitted via a parent-signed grant, in this same operator-signed republish, so
	// revoking a parent actually revokes. Computed BEFORE the parent's own removal
	// so the edges are still present to read.
	var cascaded []string
	if action == allowlistActionRemove {
		if cfg, cerr := exchange.LoadConfig(c.dgHome); cerr == nil {
			cascaded = childrenOf(cfg, targetHex)
		}
	}

	cfgMembers, err := persistFleetAllowlistChange(c.dgHome, action, targetHex)
	if err != nil {
		return fmt.Errorf("allowlist: persist config: %w", err)
	}
	// Persist each cascaded child the same way, so the roster below is built from a
	// config that already excludes them. A child that fails to persist is surfaced
	// rather than silently left admitted under a revoked parent.
	for _, kid := range cascaded {
		m, kerr := persistFleetAllowlistChange(c.dgHome, allowlistActionRemove, kid)
		if kerr != nil {
			return fmt.Errorf("allowlist: cascade remove child %s of %s: %w", kid, targetHex, kerr)
		}
		cfgMembers = m
	}
	if len(cascaded) > 0 {
		if ferr := forgetChildGrants(c.dgHome, cascaded); ferr != nil {
			return fmt.Errorf("allowlist: cascade drop child edges of %s: %w", targetHex, ferr)
		}
	}
	// A key removed in its own right is no longer anybody's child either.
	if action == allowlistActionRemove {
		if ferr := forgetChildGrants(c.dgHome, []string{targetHex}); ferr != nil {
			return fmt.Errorf("allowlist: drop child edge for %s: %w", targetHex, ferr)
		}
	}

	// Individual/no-relay tier: no live admission gate to reload. The config
	// persist above is the whole effect.
	if c.keys == nil {
		return nil
	}

	// (2) Mutate the live KeySet — the SAME set the TrustChecker enforces, so the
	// change is reflected on the very next dispatch trust check (<1s, no restart).
	// This is for immediate local enforcement only; it is NOT the source the roster
	// is built from (see (3)). Even if a concurrent stale fold momentarily clobbers
	// this, our fresher republished roster's echo re-folds the correct config
	// membership back onto it.
	switch action {
	case allowlistActionAdd:
		c.keys.Add(targetHex)
		// Retention side: clear any revocation tombstone and re-index the seller's
		// retained inventory immediately (dontguess-23c).
		if c.onReadmit != nil {
			c.onReadmit(targetHex)
		}
	case allowlistActionRemove:
		c.keys.Remove(targetHex)
		// Retention side: record the durable revocation tombstone and withhold the
		// seller's accepted inventory from the index NOW (dontguess-23c).
		if c.onRevoke != nil {
			c.onRevoke(targetHex)
		}
		// Cascade to children in the LIVE set as well. The roster echo would
		// eventually correct this via ReplaceAll over the persisted config, but that
		// leaves a window in which a revoked parent's child still passes the trust
		// check — enforcement must be immediate, same as the parent's.
		for _, kid := range cascaded {
			c.keys.Remove(kid)
			if c.onRevoke != nil {
				c.onRevoke(kid)
			}
		}
	}

	// (3) Republish the roster (best-effort). Build it from the JUST-PERSISTED
	// CONFIG membership (cfgMembers, normalized to lowercase hex) — the authoritative
	// admit intent we hold c.mu across — NOT the live KeySet, which a concurrent
	// rosterFolder.fold() under a different mutex can ReplaceAll out from under us
	// (dontguess-9ef). Its echo re-folds this exact membership onto the shared KeySet
	// via rosterFolder — idempotent (ReplaceAll with the committed config set).
	if c.operatorSigner != nil && c.publishRoster != nil {
		rosterAllow, aerr := identity.NewAllowlist(cfgMembers...)
		if aerr != nil {
			// Every entry in the persisted config was validated on the way in, so this
			// is not expected; surface it rather than publishing a partial roster.
			return fmt.Errorf("allowlist: normalize config membership for republish: %w", aerr)
		}
		ev, err := c.buildRoster(rosterAllow.HexKeys())
		if err != nil {
			// The live KeySet + config are already updated (the authoritative local
			// effects); a roster-build failure is surfaced but does not roll them back.
			return fmt.Errorf("allowlist: build roster for republish: %w", err)
		}
		c.publishRoster(ev)
	}
	return nil
}

// rosterFromConfig builds a fresh operator-signed roster (created_at = now) over
// the CURRENT persisted Config.FleetAllowlist (dontguess-23c). Published on each
// leg attach at startup so the relay's latest roster always reflects the durable
// local config — a STALE roster left on the relay (e.g. from a prior process whose
// republish never landed) can never demote the live KeySet below config via the
// replaceable-event fold, because this fresher roster supersedes it. Returns the
// signed event and the member count. Safe for concurrent use (holds c.mu).
func (c *allowlistController) rosterFromConfig() (*identity.Event, int, error) {
	cfg, err := exchange.LoadConfig(c.dgHome)
	if err != nil {
		return nil, 0, err
	}
	// Partition, not hard-error (dontguess-31b): one unusable entry must not be
	// able to stop the operator republishing its roster. A hard error here meant
	// a poisoned config also silently froze the relay's view of fleet membership
	// at whatever stale roster was last published.
	allow, unusable := identity.NewAllowlistPartition(cfg.FleetAllowlist...)
	if len(unusable) > 0 {
		c.logf("roster: skipping %d unusable allowlist entr%s (not valid secp256k1 pubkeys)", len(unusable), plural(len(unusable), "y", "ies"))
	}
	members := allow.HexKeys()
	c.mu.Lock()
	defer c.mu.Unlock()
	ev, err := c.buildRoster(members)
	if err != nil {
		return nil, 0, err
	}
	return ev, len(members), nil
}

// buildRoster signs a kind-30078 fleet roster over the given FULL membership
// (lowercase hex). The caller passes the just-persisted config membership, NOT the
// live KeySet, so a concurrent rosterFolder.fold() (which mutates the shared KeySet
// under a different mutex) cannot corrupt the roster this admit republishes
// (dontguess-9ef). created_at strictly increases across calls so two admits within
// the same wall-clock second do not collide into a stale-drop at the replaceable
// fold. Caller holds c.mu.
func (c *allowlistController) buildRoster(members []string) (*identity.Event, error) {
	createdAt := c.nowUnix()
	if createdAt <= c.lastRoster {
		createdAt = c.lastRoster + 1
	}
	c.lastRoster = createdAt

	ev := &identity.Event{
		CreatedAt: createdAt,
		Kind:      nostr.KindFleetRoster,
		Tags:      nostr.FleetRosterTags(members),
		Content:   "",
	}
	if err := identity.SignEvent(c.operatorSigner, ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// plural picks the singular or plural suffix for n, so log lines read correctly
// without a second format string.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// pruneUnusableAllowlistEntries removes entries that can never be a nostr pubkey
// from the persisted Config.FleetAllowlist (dontguess-31b self-heal). Reports
// whether the config actually changed.
//
// This is what stops a single poisoned entry from being a permanent condition.
// Quarantining at load keeps the operator serving, but leaving the entry on disk
// means every boot re-quarantines it and every roster republish still has to
// route around it. Removal is monotonically safe — these entries authorize
// nobody — so it needs no operator confirmation.
func pruneUnusableAllowlistEntries(dgHome string, unusable []string) (bool, error) {
	if len(unusable) == 0 {
		return false, nil
	}
	drop := make(map[string]struct{}, len(unusable))
	for _, u := range unusable {
		drop[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
	}
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		return false, err
	}
	kept := make([]string, 0, len(cfg.FleetAllowlist))
	for _, e := range cfg.FleetAllowlist {
		if _, bad := drop[strings.ToLower(strings.TrimSpace(e))]; bad {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == len(cfg.FleetAllowlist) {
		return false, nil
	}
	cfg.FleetAllowlist = kept
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		return false, err
	}
	return true, nil
}

// persistFleetAllowlistChange applies an add|remove to the on-disk
// Config.FleetAllowlist and writes it back. Membership is compared by normalized
// hex (normalizeToHex) so an entry stored earlier as an npub and a hex target for
// the SAME key are recognised as one — a duplicate add is a no-op and a remove
// drops the entry regardless of the form it was stored in. This is the server-side
// analogue of runAllowlistAdd/runAllowlistRemove's config mutation; the CLI's
// offline path (operator not running) still writes the config directly. On success
// it returns the post-mutation FleetAllowlist — the authoritative full membership
// this change committed — so the caller can republish a roster from config intent
// rather than the concurrently-mutable live KeySet (dontguess-9ef).
func persistFleetAllowlistChange(dgHome, action, targetHex string) ([]string, error) {
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		return nil, err
	}
	if action != allowlistActionAdd && action != allowlistActionRemove {
		return nil, fmt.Errorf("allowlist: unknown action %q", action)
	}
	// dontguess-31b: never WRITE a key that the boot loader would refuse to READ.
	// This is the last chokepoint before durable state for every server-side
	// admission path (IPC `allowlist add`, invite redeem, open admission), so
	// validating here means no future admission caller can reintroduce the
	// boot-blocking poison by forgetting its own check. Removal is exempt —
	// see runAllowlistRemove.
	if action == allowlistActionAdd {
		if _, kerr := identity.NormalizeAllowlistEntry(targetHex); kerr != nil {
			return nil, fmt.Errorf("allowlist add: refusing to persist an unusable key: %w", kerr)
		}
	}
	// Mutate FleetAllowlist AND the RevokedSellers tombstone coherently
	// (dontguess-23c): remove records a tombstone, add clears it.
	mutateAllowlistConfig(cfg, action, targetHex)
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		return nil, err
	}
	return cfg.FleetAllowlist, nil
}

// firstAllowlistController returns the first non-nil controller from a variadic
// tail, or nil. It lets serveOperatorSocket/handleOperatorConn take the controller
// as an OPTIONAL trailing argument so the existing test call sites
// (serveOperatorSocket(ctx, ln, eng)) compile unchanged while the production serve
// path threads the controller through.
func firstAllowlistController(cs []*allowlistController) *allowlistController {
	if len(cs) > 0 {
		return cs[0]
	}
	return nil
}
