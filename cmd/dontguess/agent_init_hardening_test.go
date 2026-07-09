package main

// agent_init_hardening_test.go — Sybil enforcement hardening tests
// (item dontguess-ebf, follow-up to the ab9 security review).
//
// Three findings fixed here:
//  1. MEDIUM: the parent-key Sybil defense was OPT-IN — omitting --parent
//     silently fell through to minting a persistent npub, so a caller that
//     forgot to pass --parent for an ephemeral subagent got a throwaway
//     fleet-member identity instead of being rejected. Fixed: exactly one of
//     --parent / --fleet-member is now REQUIRED (fail-closed); neither given
//     is a hard error, both given is a hard error.
//  2. LOW: the "operator key never borrowed" guard compared the UNRESOLVED
//     (lexical) parent path against agentsRoot/dgHome. A symlink planted
//     under agents/ pointing outside it (e.g. at DG_HOME) would pass the
//     lexical check while the actual file read (inside BorrowParent -> Load
//     -> os.ReadFile, which follows symlinks) escaped to the operator's
//     identity. Fixed: symlinks are resolved (filepath.EvalSymlinks) before
//     the prefix check.
//  3. LOW: identity.Resolve was dead in production (only test-exercised).
//     Fixed: agent-init now calls identity.Resolve(agentHome) to obtain the
//     reported/exported identity, wiring it into the one production path
//     that provisions an identity home.
//
// Design: docs/design/nostr-first-rebuild-decision.md (key-management ruling).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/campfire-net/dontguess/pkg/identity"
)

// TestAgentInit_EphemeralWithoutParentRejected proves finding (1): omitting
// BOTH --parent and --fleet-member is a hard error, not a silent fallthrough
// to minting a persistent npub. This is the fail-closed enforcement point —
// an ephemeral subagent caller that forgets --parent must be rejected, never
// handed a throwaway fleet identity.
func TestAgentInit_EphemeralWithoutParentRejected(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	err := runAgentInitCore(dgHome, "orphan", "", false)
	if err == nil {
		t.Fatal("agent-init orphan (no --parent, no --fleet-member): expected rejection, got nil")
	}

	// Nothing must have been minted: no agent home, no nostr identity file.
	orphanHome := filepath.Join(dgHome, "agents", "orphan")
	if _, statErr := os.Stat(orphanHome); statErr == nil {
		if _, idErr := os.Stat(filepath.Join(orphanHome, identity.IdentityFile)); idErr == nil {
			t.Fatalf("orphan: a persistent npub was minted despite the fail-closed rejection (%s exists)", identity.IdentityFile)
		}
	}
}

// TestAgentInit_ParentAndFleetMemberMutuallyExclusive proves the two identity
// modes cannot both be asserted at once — a caller cannot claim to be a
// persistent fleet member while also borrowing a parent's npub.
func TestAgentInit_ParentAndFleetMemberMutuallyExclusive(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	if err := runAgentInitCore(dgHome, "fleet", "", true); err != nil {
		t.Fatalf("agent-init fleet: %v", err)
	}

	err := runAgentInitCore(dgHome, "confused", "fleet", true)
	if err == nil {
		t.Fatal("agent-init confused --parent fleet --fleet-member: expected rejection (mutually exclusive), got nil")
	}
}

// TestAgentInit_SymlinkParentEscapeBlocked proves finding (2): a symlink
// planted under agents/ that points OUTSIDE agents/ (e.g. straight at
// DG_HOME, the operator's own identity home) cannot be used as a --parent to
// borrow the operator's npub. The lexical prefix check alone would be fooled
// because the UNRESOLVED path "agents/evil" is still lexically under
// agentsRoot; only a resolved-symlink comparison catches the escape.
func TestAgentInit_SymlinkParentEscapeBlocked(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	// Plant the operator identity — the thing a symlink escape would expose.
	opID, _, err := identity.LoadOrCreate(dgHome)
	if err != nil {
		t.Fatalf("provision operator identity: %v", err)
	}

	// Provision one real fleet member so agentsRoot exists on disk.
	if err := runAgentInitCore(dgHome, "fleet", "", true); err != nil {
		t.Fatalf("agent-init fleet: %v", err)
	}
	agentsRoot := filepath.Join(dgHome, "agents")

	// Plant a symlink at agents/evil -> DG_HOME. Lexically,
	// filepath.Join(agentsRoot, "evil") == agentsRoot/evil, which passes an
	// unresolved HasPrefix(agentsRoot) check. Only resolving the symlink
	// reveals that its target (dgHome) escapes agentsRoot entirely.
	evilLink := filepath.Join(agentsRoot, "evil")
	if err := os.Symlink(dgHome, evilLink); err != nil {
		t.Fatalf("create symlink agents/evil -> DG_HOME: %v", err)
	}

	err = runAgentInitCore(dgHome, "sub", "evil", false)
	if err == nil {
		t.Fatal("agent-init sub --parent evil (symlink to DG_HOME): expected rejection, got nil (possible operator-key borrow via symlink)")
	}

	// No parent pointer may have been written for 'sub' — the escape must be
	// caught BEFORE BorrowParent runs, not after.
	subHome := filepath.Join(agentsRoot, "sub")
	if _, statErr := os.Stat(filepath.Join(subHome, identity.ParentFile)); statErr == nil {
		t.Fatal("subagent parent pointer was written despite the symlink-escape rejection")
	}

	// Defense in depth: even if something had been written, it must not
	// resolve to the operator's npub.
	if signer, resolveErr := identity.Resolve(subHome); resolveErr == nil {
		if signer.Npub() == opID.Npub() {
			t.Fatalf("subagent resolves to the OPERATOR npub %s via symlink escape", opID.Npub())
		}
	}
}
