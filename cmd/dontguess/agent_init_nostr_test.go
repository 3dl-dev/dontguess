package main

// agent_init_nostr_test.go — ground-source tests for the FORCED secp256k1
// re-key: agent-init must issue a secp256k1/schnorr nostr identity alongside the
// (soon-to-be-removed) campfire Ed25519 identity.
//
// Item: dontguess-476. Design: docs/design/nostr-first-rebuild-decision.md
// (NFR key mgmt / key-management ruling).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/campfire-net/dontguess/pkg/identity"
)

// TestAgentInit_IssuesSecp256k1Identity verifies:
//  1. agent-init writes a nostr-identity.json holding a valid secp256k1 key;
//  2. two distinct agents get distinct npubs;
//  3. re-running the same agent yields the SAME npub (persistent, not minted).
func TestAgentInit_IssuesSecp256k1Identity(t *testing.T) {
	t.Parallel()

	dgHome := scratchExchange(t)

	if err := runAgentInitWith(t, dgHome, "alice"); err != nil {
		t.Fatalf("agent-init alice: %v", err)
	}
	aliceHome := filepath.Join(dgHome, "agents", "alice")

	// The nostr identity file must exist and load as a valid secp256k1 identity.
	aliceID, err := identity.Load(aliceHome)
	if err != nil {
		t.Fatalf("load alice nostr identity: %v", err)
	}
	if !strings.HasPrefix(aliceID.Npub(), "npub1") {
		t.Fatalf("alice npub malformed: %s", aliceID.Npub())
	}

	// Distinct agent -> distinct npub.
	if err := runAgentInitWith(t, dgHome, "bob"); err != nil {
		t.Fatalf("agent-init bob: %v", err)
	}
	bobID, err := identity.Load(filepath.Join(dgHome, "agents", "bob"))
	if err != nil {
		t.Fatalf("load bob nostr identity: %v", err)
	}
	if aliceID.Npub() == bobID.Npub() {
		t.Fatalf("alice and bob share an npub %s — identities not distinct", aliceID.Npub())
	}

	// Idempotency: re-run alice, npub must not change (no throwaway re-mint).
	if err := runAgentInitWith(t, dgHome, "alice"); err != nil {
		t.Fatalf("agent-init alice (2nd run): %v", err)
	}
	aliceID2, err := identity.Load(aliceHome)
	if err != nil {
		t.Fatalf("reload alice nostr identity: %v", err)
	}
	if aliceID.Npub() != aliceID2.Npub() {
		t.Fatalf("alice npub changed on re-init: %s -> %s (persistent-npub violated)", aliceID.Npub(), aliceID2.Npub())
	}
}
