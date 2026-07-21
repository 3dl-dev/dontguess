package main

// agent_init_sybil_test.go — Sybil / convergence-integrity tests for the
// parent-key concept (item dontguess-ab9).
//
// The key-management ruling requires ephemeral per-conversation subagents to
// sign with their PARENT fleet-member's npub, NOT a fresh throwaway (destroys
// reputation continuity and inflates convergence independence = a Sybil vector)
// and NEVER the operator key. These tests prove agent-init enforces that:
//   - a fresh fleet member (no --parent) gets a persistent, independent npub;
//   - an ephemeral subagent (--parent P) does NOT mint a new npub and signs
//     under its parent's npub;
//   - the operator key is never borrowed by a subagent.
//
// Design: docs/design/nostr-first-rebuild-decision.md (key-management ruling);
//         docs/design/convergence-sybil-defense.md.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// newAgentInitTestCmd builds a bare agent-init command (flags only) whose stderr
// is captured in buf, for exercising runAgentInit's user-facing output.
func newAgentInitTestCmd(buf *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("parent", "", "")
	c.Flags().Bool("fleet-member", false, "")
	c.Flags().String("relay", "", "")
	c.Flags().String("operator-npub", "", "")
	c.SetErr(buf)
	return c
}

// TestAgentInit_FleetMemberPrintsAdmissionNotice: a standalone
// agent-init --fleet-member tells the user the minted key is NOT admitted and
// how to fix it (dontguess-874) — a subagent, which borrows an already-admitted
// parent, does not.
func TestAgentInit_FleetMemberPrintsAdmissionNotice(t *testing.T) {
	t.Chdir(t.TempDir()) // hermetic: provision into a fresh ./.dg, not the repo's

	var fleetErr bytes.Buffer
	fleetCmd := newAgentInitTestCmd(&fleetErr)
	_ = fleetCmd.Flags().Set("fleet-member", "true")
	if err := runAgentInit(fleetCmd, []string{"m1"}); err != nil {
		t.Fatalf("agent-init m1 --fleet-member: %v", err)
	}

	m1, err := identity.Resolve(filepath.Join(".dg", "agents", "m1"))
	if err != nil {
		t.Fatalf("resolve m1: %v", err)
	}
	notice := fleetErr.String()
	if !strings.Contains(notice, "NOT admitted") {
		t.Errorf("fleet-member notice missing the not-admitted warning; got:\n%s", notice)
	}
	if !strings.Contains(notice, "allowlist add "+m1.Npub()) {
		t.Errorf("fleet-member notice missing the `allowlist add <npub>` remedy for %s; got:\n%s", m1.Npub(), notice)
	}
	if !strings.Contains(notice, "dontguess join") {
		t.Errorf("fleet-member notice missing the invite-redeem alternative; got:\n%s", notice)
	}

	// A subagent borrows m1's (eventually-admitted) key, so it gets NO notice.
	var subErr bytes.Buffer
	subCmd := newAgentInitTestCmd(&subErr)
	_ = subCmd.Flags().Set("parent", "m1")
	if err := runAgentInit(subCmd, []string{"sub1"}); err != nil {
		t.Fatalf("agent-init sub1 --parent m1: %v", err)
	}
	if strings.Contains(subErr.String(), "NOT admitted") {
		t.Errorf("subagent must not get the admission notice (it borrows an admitted parent); got:\n%s", subErr.String())
	}
}

// TestAgentInit_SubagentSignsUnderParent verifies the core Sybil defense:
//  1. a fleet member (no parent) gets its own persistent npub;
//  2. an ephemeral subagent under that member does NOT create an independent
//     npub — it has no nostr-identity.json of its own;
//  3. the subagent's resolved signing identity IS the parent's npub.
func TestAgentInit_SubagentSignsUnderParent(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	// Fleet member: gets a persistent npub of its own.
	if err := runAgentInitCore(dgHome, "fleet", "", true); err != nil {
		t.Fatalf("agent-init fleet: %v", err)
	}
	fleetHome := filepath.Join(dgHome, "agents", "fleet")
	fleetID, err := identity.Load(fleetHome)
	if err != nil {
		t.Fatalf("load fleet identity: %v", err)
	}

	// Ephemeral subagent under the fleet member.
	if err := runAgentInitCore(dgHome, "sub", "fleet", false); err != nil {
		t.Fatalf("agent-init sub --parent fleet: %v", err)
	}
	subHome := filepath.Join(dgHome, "agents", "sub")

	// Assert 1: the subagent minted NO independent key — no nostr-identity.json.
	if _, err := os.Stat(filepath.Join(subHome, identity.IdentityFile)); !os.IsNotExist(err) {
		t.Fatalf("subagent minted its own %s (err=%v) — expected NO independent npub", identity.IdentityFile, err)
	}

	// Assert 2: the subagent has a parent pointer.
	if _, err := os.Stat(filepath.Join(subHome, identity.ParentFile)); err != nil {
		t.Fatalf("subagent has no parent pointer %s: %v", identity.ParentFile, err)
	}

	// Assert 3: the subagent's RESOLVED signing identity is the parent's npub.
	subSigner, err := identity.Resolve(subHome)
	if err != nil {
		t.Fatalf("resolve subagent signing identity: %v", err)
	}
	if subSigner.Npub() != fleetID.Npub() {
		t.Fatalf("subagent signs under %s, expected parent's %s — not signing under parent",
			subSigner.Npub(), fleetID.Npub())
	}
	// And its pubkey hex — the value convergence is scored on — must match too.
	if subSigner.PubKeyHex() != fleetID.PubKeyHex() {
		t.Fatalf("subagent pubkey %s != parent pubkey %s — convergence independence inflated",
			subSigner.PubKeyHex(), fleetID.PubKeyHex())
	}

	// Assert 4: a SECOND subagent under the same parent also signs under the
	// parent — two ephemeral subagents do NOT produce two independent npubs.
	if err := runAgentInitCore(dgHome, "sub2", "fleet", false); err != nil {
		t.Fatalf("agent-init sub2 --parent fleet: %v", err)
	}
	sub2Signer, err := identity.Resolve(filepath.Join(dgHome, "agents", "sub2"))
	if err != nil {
		t.Fatalf("resolve sub2 signing identity: %v", err)
	}
	if sub2Signer.Npub() != fleetID.Npub() {
		t.Fatalf("sub2 signs under %s, expected parent's %s", sub2Signer.Npub(), fleetID.Npub())
	}
}

// TestAgentInit_FreshFleetMemberGetsPersistentNpub verifies a fresh fleet
// member (no parent) DOES get a persistent, independent npub, and two distinct
// fleet members are independent identities (convergence-relevant).
func TestAgentInit_FreshFleetMemberGetsPersistentNpub(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	if err := runAgentInitCore(dgHome, "m1", "", true); err != nil {
		t.Fatalf("agent-init m1: %v", err)
	}
	if err := runAgentInitCore(dgHome, "m2", "", true); err != nil {
		t.Fatalf("agent-init m2: %v", err)
	}
	m1, err := identity.Load(filepath.Join(dgHome, "agents", "m1"))
	if err != nil {
		t.Fatalf("load m1: %v", err)
	}
	m2, err := identity.Load(filepath.Join(dgHome, "agents", "m2"))
	if err != nil {
		t.Fatalf("load m2: %v", err)
	}
	// Fleet members are independent identities.
	if m1.Npub() == m2.Npub() {
		t.Fatalf("two fleet members share npub %s — not independent", m1.Npub())
	}
	// Persistent: re-init m1 loads the same npub (no re-mint).
	if err := runAgentInitCore(dgHome, "m1", "", true); err != nil {
		t.Fatalf("agent-init m1 (2nd run): %v", err)
	}
	m1b, err := identity.Load(filepath.Join(dgHome, "agents", "m1"))
	if err != nil {
		t.Fatalf("reload m1: %v", err)
	}
	if m1.Npub() != m1b.Npub() {
		t.Fatalf("fleet member m1 npub changed on re-init: %s -> %s (not persistent)", m1.Npub(), m1b.Npub())
	}
}

// TestAgentInit_OperatorKeyNeverBorrowed verifies a subagent can never borrow
// the OPERATOR's key. The operator home is DG_HOME (not under agents/), so any
// --parent value that would reach it must name '.' or '..', which validation
// rejects. We also plant an operator nostr identity and confirm it is never
// loaded/used as a parent.
func TestAgentInit_OperatorKeyNeverBorrowed(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	// Plant an operator secp256k1 identity at DG_HOME root (as the operator
	// would have after its own provisioning). If any --parent value could reach
	// it, a subagent would inherit operator signing authority.
	opID, _, err := identity.LoadOrCreate(dgHome)
	if err != nil {
		t.Fatalf("provision operator identity: %v", err)
	}
	opNpub := opID.Npub()

	// Every traversal-shaped parent value must be rejected — none may create an
	// agent home nor borrow the operator key.
	for _, parent := range []string{"..", ".", "../", "a/b", "a\\b", "foo/../..", "x..y"} {
		err := runAgentInitCore(dgHome, "evil", parent, false)
		if err == nil {
			t.Errorf("agent-init evil --parent %q: expected rejection, got nil (possible operator-key borrow)", parent)
		}
		// No 'evil' home may have been created by a rejected call.
		if _, statErr := os.Stat(filepath.Join(dgHome, "agents", "evil")); statErr == nil {
			t.Errorf("agent home created for rejected --parent %q", parent)
			os.RemoveAll(filepath.Join(dgHome, "agents", "evil"))
		}
	}

	// Even a well-formed parent name that does not correspond to an existing
	// fleet member must fail (BorrowParent.Load errors) — never silently mint,
	// never fall back to the operator key.
	if err := runAgentInitCore(dgHome, "sub", "does-not-exist", false); err == nil {
		t.Fatal("agent-init sub --parent does-not-exist: expected error (no such fleet member), got nil")
	}

	// A legitimately-provisioned subagent must sign under its FLEET parent, and
	// its npub must differ from the operator's — the operator key stays operator.
	if err := runAgentInitCore(dgHome, "fleet", "", true); err != nil {
		t.Fatalf("agent-init fleet: %v", err)
	}
	if err := runAgentInitCore(dgHome, "sub", "fleet", false); err != nil {
		t.Fatalf("agent-init sub --parent fleet: %v", err)
	}
	subSigner, err := identity.Resolve(filepath.Join(dgHome, "agents", "sub"))
	if err != nil {
		t.Fatalf("resolve sub: %v", err)
	}
	if subSigner.Npub() == opNpub {
		t.Fatalf("subagent signs under the OPERATOR npub %s — operator key was borrowed", opNpub)
	}
}

// TestAgentInit_SubagentCannotParentAnotherSubagent verifies no borrowing
// chains: a subagent (which has no persistent key of its own) cannot serve as a
// parent. This keeps the fleet-member / subagent distinction crisp so
// convergence stays scored at true fleet-member granularity.
func TestAgentInit_SubagentCannotParentAnotherSubagent(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	if err := runAgentInitCore(dgHome, "fleet", "", true); err != nil {
		t.Fatalf("agent-init fleet: %v", err)
	}
	if err := runAgentInitCore(dgHome, "sub", "fleet", false); err != nil {
		t.Fatalf("agent-init sub --parent fleet: %v", err)
	}
	// 'sub' is itself a subagent (no persistent key). Parenting under it must
	// fail — a subagent is not a fleet member with a borrowable npub.
	if err := runAgentInitCore(dgHome, "grandchild", "sub", false); err == nil {
		t.Fatal("agent-init grandchild --parent sub: expected error (parent is a subagent, no persistent key), got nil")
	}
}
