package main

// allowlist_poison_recovery_31b_test.go — dontguess-31b recovery proofs.
//
// A poisoned Config.FleetAllowlist was SELF-SEALING on the live exchange:
//
//	boot   -> identity.NewAllowlist rejects the entry -> serve aborts, exchange down
//	repair -> `dontguess allowlist remove <entry>` validates the argument first,
//	          rejects it for being invalid, and refuses to remove it
//	even if it had gotten past that, dropHexEntry compared entries via
//	normalizeToHex and treated a normalization FAILURE as "not a match" — so the
//	one entry it could never delete was the malformed one.
//
// Three independent locks on the same door. The only exit was hand-editing JSON.
// These tests prove each is now open, and that boot self-heals so the operator
// does not depend on any of them being used.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
)

// poisonHex is the real off-curve sender key that bricked the live operator.
const poisonHex = "e53a88d79ef658a13d2befffb7312b7256563b5f94f0a240340f6580c68e3686"

// writePoisonedConfig persists an allowlist holding one good key and the exact
// poison entry, in the order the live config had them.
func writePoisonedConfig(t *testing.T, dgHome, goodHex string) {
	t.Helper()
	cfg, err := exchange.LoadConfig(dgHome)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.FleetAllowlist = []string{goodHex, poisonHex}
	if err := exchange.WriteConfig(exchange.ConfigPath(dgHome), cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
}

// TestDropHexEntry_CanDeleteAMalformedStoredEntry pins the innermost lock. The
// original `err == nil && h == target` guard silently KEPT any entry that failed
// to normalize, making the poisoned entry undeletable by construction.
func TestDropHexEntry_CanDeleteAMalformedStoredEntry(t *testing.T) {
	t.Parallel()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	good := id.PubKeyHex()

	got := dropHexEntry([]string{good, poisonHex}, poisonHex)
	if len(got) != 1 || got[0] != good {
		t.Fatalf("dropHexEntry = %v, want [%s] — a malformed entry that cannot be removed is a permanently poisoned config", got, good)
	}

	// Uppercase input must still match a lowercase stored entry: an operator
	// pasting the key out of a log message should not be defeated by case.
	got = dropHexEntry([]string{good, poisonHex}, strings.ToUpper(poisonHex))
	if len(got) != 1 || got[0] != good {
		t.Fatalf("dropHexEntry(upper) = %v, want [%s]", got, good)
	}

	// A valid key must still be removable by its npub form — the raw-string
	// fallback must not have displaced normal normalization.
	npub := id.Npub()
	got = dropHexEntry([]string{good, poisonHex}, mustNormalizeHex(t, npub))
	if len(got) != 1 || got[0] != poisonHex {
		t.Fatalf("dropHexEntry(by npub-normalized hex) = %v, want [%s]", got, poisonHex)
	}
}

// TestRunAllowlistRemove_ClearsAPoisonedEntry is the operator-facing recovery:
// the command that refused to repair the outage must now repair it.
func TestRunAllowlistRemove_ClearsAPoisonedEntry(t *testing.T) {
	t.Parallel()
	dgHome := bootstrapAllowlistHome(t)
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	good := id.PubKeyHex()
	writePoisonedConfig(t, dgHome, good)

	var out bytes.Buffer
	if err := runAllowlistRemove(dgHome, poisonHex, &out); err != nil {
		t.Fatalf("runAllowlistRemove refused to clear a poisoned entry: %v — the operator is then locked out of its own exchange with no CLI path back", err)
	}

	cfg := readAllowlistConfig(t, dgHome)
	for _, e := range cfg.FleetAllowlist {
		if strings.EqualFold(e, poisonHex) {
			t.Fatalf("poisoned entry survived removal: fleet_allowlist = %v", cfg.FleetAllowlist)
		}
	}
	if len(cfg.FleetAllowlist) != 1 || cfg.FleetAllowlist[0] != good {
		t.Fatalf("after removal fleet_allowlist = %v, want [%s] — removal must be surgical", cfg.FleetAllowlist, good)
	}
	// The config must now load through the STRICT boot-time constructor, which is
	// the actual definition of "the operator can start again".
	if _, aerr := identity.NewAllowlist(cfg.FleetAllowlist...); aerr != nil {
		t.Fatalf("config still fails the strict boot loader after removal: %v", aerr)
	}
}

// TestPruneUnusableAllowlistEntries_SelfHealsTheConfig pins the boot self-heal:
// the operator repairs its own durable state, so recovery does not depend on a
// human noticing and running a command.
func TestPruneUnusableAllowlistEntries_SelfHealsTheConfig(t *testing.T) {
	t.Parallel()
	dgHome := bootstrapAllowlistHome(t)
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	good := id.PubKeyHex()
	writePoisonedConfig(t, dgHome, good)

	// Exactly what serve does at boot: partition, then prune what it quarantined.
	allow, unusable := identity.NewAllowlistPartition(readAllowlistConfig(t, dgHome).FleetAllowlist...)
	if len(unusable) != 1 || allow.Len() != 1 {
		t.Fatalf("partition gave unusable=%v len=%d, want 1 and 1", unusable, allow.Len())
	}

	healed, err := pruneUnusableAllowlistEntries(dgHome, unusable)
	if err != nil {
		t.Fatalf("pruneUnusableAllowlistEntries: %v", err)
	}
	if !healed {
		t.Fatal("prune reported no change despite a poisoned entry being present")
	}

	cfg := readAllowlistConfig(t, dgHome)
	if len(cfg.FleetAllowlist) != 1 || cfg.FleetAllowlist[0] != good {
		t.Fatalf("after prune fleet_allowlist = %v, want [%s]", cfg.FleetAllowlist, good)
	}
	if _, aerr := identity.NewAllowlist(cfg.FleetAllowlist...); aerr != nil {
		t.Fatalf("pruned config still fails the strict boot loader: %v", aerr)
	}

	// Idempotent: a second boot must not rewrite a clean config.
	healed2, err := pruneUnusableAllowlistEntries(dgHome, unusable)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if healed2 {
		t.Fatal("prune rewrote an already-clean config — boot must not churn durable state every start")
	}
}

// TestPersistFleetAllowlistChange_RefusesToWriteAnUnusableKey pins the write-side
// fence shared by every server-side admission path (IPC add, invite redeem, open
// admission). Validating here means a future admission caller cannot reintroduce
// the poison by forgetting its own check.
func TestPersistFleetAllowlistChange_RefusesToWriteAnUnusableKey(t *testing.T) {
	t.Parallel()
	dgHome := bootstrapAllowlistHome(t)

	if _, err := persistFleetAllowlistChange(dgHome, allowlistActionAdd, poisonHex); err == nil {
		t.Fatal("persistFleetAllowlistChange persisted a key the boot loader will refuse — the exchange can brick itself again")
	}
	if got := readAllowlistConfig(t, dgHome).FleetAllowlist; len(got) != 0 {
		t.Fatalf("a refused add still mutated the config: %v — a rejected write must persist nothing", got)
	}

	// Removal stays exempt: the operator must always be able to take a key OUT,
	// including one that can no longer be validated.
	if _, err := persistFleetAllowlistChange(dgHome, allowlistActionRemove, poisonHex); err != nil {
		t.Fatalf("persistFleetAllowlistChange(remove) refused a malformed key: %v — removal must never be gated on validity", err)
	}
}

func mustNormalizeHex(t *testing.T, entry string) string {
	t.Helper()
	h, err := normalizeToHex(entry)
	if err != nil {
		t.Fatalf("normalizeToHex(%q): %v", entry, err)
	}
	return h
}
