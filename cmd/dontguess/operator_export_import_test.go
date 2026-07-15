package main

// operator_export_import_test.go — feature tests for dontguess-51c.
//
// 1Password is a live third-party account with no test tenancy — these tests
// MUST NOT create, read, or mutate real 1Password items. fakeOpRunner stands
// in for the `op` CLI (the opRunner seam in operator_export_import.go) and is
// an in-memory map, but every other line under test is the REAL production
// code path: buildOperatorItemTemplate's JSON shape, runOperatorExport /
// runOperatorImport's RunE logic (invoked directly, not re-implemented),
// importOperatorKey's conflict detection, and identity.LoadOrCreateRawKey's
// real atomic file write under DG_HOME (a real temp dir, real os.Link).
//
// Ground-source coverage (item's mandatory clauses):
//  1. TestOperatorExportImport_RoundTripByteIdentical — export on host A,
//     import on host B, assert privkey/pubkey/npub are byte-identical and the
//     on-disk key file matches.
//  2. TestOperatorImport_RefusesDistinctExistingIdentity — host B already has
//     its OWN distinct operator key; import must fail loud and must NOT
//     overwrite the existing file.
//  3. TestOperatorImport_IdempotentSameKey — importing the same key twice
//     succeeds both times and never leaves a torn/altered file.
//  4. TestOperatorExport_NeverWritesPlaintextScratchFile — export must not
//     create any new file under DG_HOME beyond the pre-existing operator key
//     file (the raw key must cross the process boundary only via the fake's
//     in-memory Create call, mirroring the real stdin pipe).
//  5. TestOperatorExport_RefusesDistinctExistingVaultItem — the 1Password
//     item under --title already holds a DIFFERENT pubkey (e.g. someone else's
//     export under the same title) — export must refuse, not clobber.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// fakeOpRunner is an in-memory double for the 1Password CLI. Keyed by
// "vault/title" -> field label -> value, exactly mirroring what the real `op`
// CLI would persist server-side.
type fakeOpRunner struct {
	items map[string]map[string]string
}

func newFakeOpRunner() *fakeOpRunner {
	return &fakeOpRunner{items: map[string]map[string]string{}}
}

func (f *fakeOpRunner) key(vault, title string) string { return vault + "/" + title }

func (f *fakeOpRunner) CreateItem(vault string, template []byte) error {
	var t opItemTemplate
	if err := json.Unmarshal(template, &t); err != nil {
		return fmt.Errorf("fake op: unmarshal template: %w", err)
	}
	fields := map[string]string{}
	for _, fl := range t.Fields {
		fields[fl.Label] = fl.Value
	}
	f.items[f.key(vault, t.Title)] = fields
	return nil
}

func (f *fakeOpRunner) ReadField(vault, title, field string) (string, error) {
	fields, ok := f.items[f.key(vault, title)]
	if !ok {
		// Genuinely no item at this vault/title — mirrors execOpRunner
		// wrapping errOpItemNotFound only when `op` positively confirms the
		// item itself does not exist.
		return "", fmt.Errorf("fake op: item %q not found in vault %q: %w", title, vault, errOpItemNotFound)
	}
	v, ok := fields[field]
	if !ok {
		// The item EXISTS but the field is missing/renamed — this must NOT
		// be treated as "item not found" (dontguess-3aa (2)): a caller that
		// conflates the two would fall through and mint a duplicate item.
		return "", fmt.Errorf("fake op: field %q not found on item %q", field, title)
	}
	return v, nil
}

// fakeOpRunnerErrReadField is a variant that simulates a transient/auth
// ReadField failure that is NOT item-not-found (e.g. a network blip or a
// permissions error) — used to prove export refuses rather than falls
// through to CreateItem on an ambiguous ReadField error.
type erroringOpRunner struct {
	create func(vault string, template []byte) error
	err    error
}

func (e *erroringOpRunner) CreateItem(vault string, template []byte) error {
	if e.create != nil {
		return e.create(vault, template)
	}
	return nil
}

func (e *erroringOpRunner) ReadField(vault, title, field string) (string, error) {
	return "", e.err
}

// withFakeOpRunner swaps opRunnerImpl for a fresh fake for the duration of fn
// and restores the real implementation afterward (belt-and-suspenders: no
// other test in the package should ever hit the real `op` binary, but this
// keeps the swap scoped and explicit).
func withFakeOpRunner(t *testing.T, fn func(f *fakeOpRunner)) {
	t.Helper()
	prev := opRunnerImpl
	fake := newFakeOpRunner()
	opRunnerImpl = fake
	t.Cleanup(func() { opRunnerImpl = prev })
	fn(fake)
}

// setExportImportFlags points the export/import command flag vars (shared
// package-level vars set by cobra normally) at vault/title, and restores them
// after the test.
func setExportImportFlags(t *testing.T, vault, title string) {
	t.Helper()
	prevEV, prevET, prevIV, prevIT := operatorExportVault, operatorExportTitle, operatorImportVault, operatorImportTitle
	operatorExportVault, operatorExportTitle = vault, title
	operatorImportVault, operatorImportTitle = vault, title
	t.Cleanup(func() {
		operatorExportVault, operatorExportTitle = prevEV, prevET
		operatorImportVault, operatorImportTitle = prevIV, prevIT
	})
}

func TestOperatorExportImport_RoundTripByteIdentical(t *testing.T) {
	withFakeOpRunner(t, func(_ *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		hostA := t.TempDir()
		hostB := t.TempDir()

		t.Setenv("DG_HOME", hostA)
		if err := operatorExportCmd.RunE(operatorExportCmd, nil); err != nil {
			t.Fatalf("export on host A: %v", err)
		}
		aKeyBytes, err := os.ReadFile(filepath.Join(hostA, "nostr-operator.key"))
		if err != nil {
			t.Fatalf("reading host A key: %v", err)
		}
		aID, err := identity.FromPrivHex(trimKey(string(aKeyBytes)))
		if err != nil {
			t.Fatalf("parsing host A key: %v", err)
		}

		t.Setenv("DG_HOME", hostB)
		if err := operatorImportCmd.RunE(operatorImportCmd, nil); err != nil {
			t.Fatalf("import on host B: %v", err)
		}
		bKeyBytes, err := os.ReadFile(filepath.Join(hostB, "nostr-operator.key"))
		if err != nil {
			t.Fatalf("reading host B key: %v", err)
		}
		bID, err := identity.FromPrivHex(trimKey(string(bKeyBytes)))
		if err != nil {
			t.Fatalf("parsing host B key: %v", err)
		}

		if aID.PrivHex() != bID.PrivHex() {
			t.Fatalf("private key mismatch after round-trip: A=%s B=%s", aID.PrivHex(), bID.PrivHex())
		}
		if aID.PubKeyHex() != bID.PubKeyHex() {
			t.Fatalf("pubkey mismatch after round-trip: A=%s B=%s", aID.PubKeyHex(), bID.PubKeyHex())
		}
		if aID.Npub() != bID.Npub() {
			t.Fatalf("npub mismatch after round-trip: A=%s B=%s", aID.Npub(), bID.Npub())
		}
	})
}

func TestOperatorImport_RefusesDistinctExistingIdentity(t *testing.T) {
	withFakeOpRunner(t, func(_ *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		hostA := t.TempDir()
		t.Setenv("DG_HOME", hostA)
		if err := operatorExportCmd.RunE(operatorExportCmd, nil); err != nil {
			t.Fatalf("export on host A: %v", err)
		}

		// Host B already has its OWN distinct operator identity (e.g. it ran
		// `up` and minted its own key before anyone tried to import).
		hostB := t.TempDir()
		bExisting, err := identity.Generate()
		if err != nil {
			t.Fatalf("generating host B's existing identity: %v", err)
		}
		bKeyPath := filepath.Join(hostB, "nostr-operator.key")
		if err := os.WriteFile(bKeyPath, []byte(bExisting.PrivHex()+"\n"), 0o600); err != nil {
			t.Fatalf("seeding host B existing key: %v", err)
		}

		t.Setenv("DG_HOME", hostB)
		err = operatorImportCmd.RunE(operatorImportCmd, nil)
		if err == nil {
			t.Fatalf("expected import to refuse over a distinct existing operator identity, got nil error")
		}

		// The existing file must be UNCHANGED — no fork, no silent overwrite.
		after, rerr := os.ReadFile(bKeyPath)
		if rerr != nil {
			t.Fatalf("reading host B key after refused import: %v", rerr)
		}
		if trimKey(string(after)) != bExisting.PrivHex() {
			t.Fatalf("host B's existing key was mutated by a refused import: got %s, want %s", trimKey(string(after)), bExisting.PrivHex())
		}
	})
}

func TestOperatorImport_IdempotentSameKey(t *testing.T) {
	withFakeOpRunner(t, func(_ *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		hostA := t.TempDir()
		t.Setenv("DG_HOME", hostA)
		if err := operatorExportCmd.RunE(operatorExportCmd, nil); err != nil {
			t.Fatalf("export on host A: %v", err)
		}

		hostB := t.TempDir()
		t.Setenv("DG_HOME", hostB)
		if err := operatorImportCmd.RunE(operatorImportCmd, nil); err != nil {
			t.Fatalf("first import on host B: %v", err)
		}
		// Second import of the SAME key must succeed (idempotent), not refuse.
		if err := operatorImportCmd.RunE(operatorImportCmd, nil); err != nil {
			t.Fatalf("second (idempotent) import on host B: %v", err)
		}
	})
}

// TestOperatorImport_ConcurrentMintRaceDetected is the (a) ground-source
// clause for dontguess-3aa: a real concurrent racer that wins the
// LoadOrCreateRawKey os.Link publish race with a DIFFERENT key than the one
// being imported must cause import to error loudly (not silently report the
// racer's npub as import success — the TOCTOU this item exists to close).
//
// N goroutines race importOperatorKey concurrently against the SAME fresh
// path, each with its OWN distinct generated key. Exactly one can win the
// underlying os.Link publish; every other goroutine's persisted-vs-imported
// verification MUST catch the mismatch and error — this exercises the REAL
// identity.LoadOrCreateRawKey atomic-publish primitive under the REAL race,
// not a simulated/mocked one.
func TestOperatorImport_ConcurrentMintRaceDetected(t *testing.T) {
	dgHome := t.TempDir()
	const n = 8

	keys := make([]string, n)
	for i := range keys {
		id, err := identity.Generate()
		if err != nil {
			t.Fatalf("generating racer key %d: %v", i, err)
		}
		keys[i] = id.PrivHex()
	}

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	results := make([]error, n)
	winners := make([]*identity.Secp256k1Identity, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait() // line every goroutine up at the same starting gate
			id, err := importOperatorKey(dgHome, keys[i])
			results[i] = err
			winners[i] = id
		}(i)
	}
	start.Done() // release all goroutines simultaneously
	wg.Wait()

	// Whichever key actually ended up on disk is the one true winner.
	onDiskRaw, err := os.ReadFile(filepath.Join(dgHome, "nostr-operator.key"))
	if err != nil {
		t.Fatalf("reading persisted key after race: %v", err)
	}
	onDiskHex := trimKey(string(onDiskRaw))

	successes := 0
	for i := 0; i < n; i++ {
		if results[i] == nil {
			successes++
			// A goroutine that reports success MUST have imported the key
			// that is actually on disk — never a racer's discarded key.
			if winners[i].PrivHex() != onDiskHex {
				t.Fatalf("goroutine %d reported success with npub %s but on-disk key is %s — silent identity fork (the TOCTOU this item fixes)", i, winners[i].Npub(), onDiskHex)
			}
			if keys[i] != onDiskHex {
				t.Fatalf("goroutine %d reported success for key %s but on-disk key is %s — should have errored on mismatch instead", i, keys[i], onDiskHex)
			}
		} else if keys[i] == onDiskHex {
			t.Fatalf("goroutine %d IS the on-disk winner but returned an error: %v", i, results[i])
		}
	}
	if successes == 0 {
		t.Fatalf("no goroutine reported success even though a key is on disk (%s) — the winner's own import must succeed", onDiskHex)
	}
}

// TestOperatorExport_RefusesOnAmbiguousReadFieldError is the (b)
// ground-source clause for dontguess-3aa: a ReadField failure that is NOT a
// positive "item does not exist" confirmation (auth error, network blip,
// missing/renamed field) must refuse export, never fall through to
// CreateItem — falling through would mint a SECOND item under the same
// vault/title (op item create never overwrites, allows duplicate titles).
func TestOperatorExport_RefusesOnAmbiguousReadFieldError(t *testing.T) {
	setExportImportFlags(t, "test-vault", "dontguess-operator")

	created := false
	runner := &erroringOpRunner{
		err: errors.New("op: 401 unauthorized (session expired)"),
		create: func(vault string, template []byte) error {
			created = true
			return nil
		},
	}
	prev := opRunnerImpl
	opRunnerImpl = runner
	t.Cleanup(func() { opRunnerImpl = prev })

	hostA := t.TempDir()
	t.Setenv("DG_HOME", hostA)

	err := operatorExportCmd.RunE(operatorExportCmd, nil)
	if err == nil {
		t.Fatalf("expected export to refuse on an ambiguous (non-not-found) ReadField error, got nil error")
	}
	if created {
		t.Fatalf("export called CreateItem despite an ambiguous ReadField error — this mints a duplicate 1Password item under the same vault/title")
	}
}

// TestOperatorImport_IdempotentMixedCaseHex is the (c) ground-source clause
// for dontguess-3aa: a hand-entered 1Password item may carry mixed/upper-case
// hex for the SAME private key as what's already on disk. Import must treat
// that as the identical identity (idempotent success), not a false refusal
// as a distinct identity.
func TestOperatorImport_IdempotentMixedCaseHex(t *testing.T) {
	withFakeOpRunner(t, func(_ *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		hostA := t.TempDir()
		t.Setenv("DG_HOME", hostA)
		if err := operatorExportCmd.RunE(operatorExportCmd, nil); err != nil {
			t.Fatalf("export on host A: %v", err)
		}

		hostB := t.TempDir()
		t.Setenv("DG_HOME", hostB)
		if err := operatorImportCmd.RunE(operatorImportCmd, nil); err != nil {
			t.Fatalf("first import on host B: %v", err)
		}

		// Mutate host B's on-disk key to mixed/upper-case hex — same bytes,
		// different textual representation, as if a human had hand-typed it
		// into 1Password with inconsistent casing.
		bKeyPath := filepath.Join(hostB, "nostr-operator.key")
		onDisk, err := os.ReadFile(bKeyPath)
		if err != nil {
			t.Fatalf("reading host B key: %v", err)
		}
		mixedCase := strings.ToUpper(trimKey(string(onDisk)))
		if err := os.WriteFile(bKeyPath, []byte(mixedCase+"\n"), 0o600); err != nil {
			t.Fatalf("seeding mixed-case host B key: %v", err)
		}

		// Re-importing the SAME key (still lower-case, from the vault) must
		// succeed as an idempotent no-op, not refuse as a distinct identity.
		if err := operatorImportCmd.RunE(operatorImportCmd, nil); err != nil {
			t.Fatalf("re-import against a mixed-case on-disk identical key was wrongly refused: %v", err)
		}

		// And the file must be UNCHANGED (still the mixed-case string) — a
		// no-op idempotent success, not a rewrite.
		after, err := os.ReadFile(bKeyPath)
		if err != nil {
			t.Fatalf("reading host B key after idempotent re-import: %v", err)
		}
		if trimKey(string(after)) != mixedCase {
			t.Fatalf("idempotent re-import rewrote the key file: got %s, want unchanged %s", trimKey(string(after)), mixedCase)
		}
	})
}

func TestOperatorExport_NeverWritesPlaintextScratchFile(t *testing.T) {
	withFakeOpRunner(t, func(_ *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		hostA := t.TempDir()
		t.Setenv("DG_HOME", hostA)

		// Pre-mint the operator key so export's "load" path doesn't itself
		// create the key file mid-test (isolate what export ADDS).
		if _, err := loadOrCreateNostrOperatorIdentity(hostA); err != nil {
			t.Fatalf("pre-minting host A key: %v", err)
		}
		before, err := os.ReadDir(hostA)
		if err != nil {
			t.Fatalf("listing DG_HOME before export: %v", err)
		}

		if err := operatorExportCmd.RunE(operatorExportCmd, nil); err != nil {
			t.Fatalf("export: %v", err)
		}

		after, err := os.ReadDir(hostA)
		if err != nil {
			t.Fatalf("listing DG_HOME after export: %v", err)
		}
		if len(after) != len(before) {
			names := make([]string, 0, len(after))
			for _, e := range after {
				names = append(names, e.Name())
			}
			t.Fatalf("export created new file(s) under DG_HOME (raw key must never spill to a new on-disk artifact): before=%d after=%d entries=%v", len(before), len(after), names)
		}
	})
}

func TestOperatorExport_RefusesDistinctExistingVaultItem(t *testing.T) {
	withFakeOpRunner(t, func(fake *fakeOpRunner) {
		setExportImportFlags(t, "test-vault", "dontguess-operator")

		// Someone else's export already occupies this vault+title.
		other, err := identity.Generate()
		if err != nil {
			t.Fatalf("generating other identity: %v", err)
		}
		fake.items[fake.key("test-vault", "dontguess-operator")] = map[string]string{
			operatorPrivKeyField: other.PrivHex(),
			operatorPubKeyField:  other.PubKeyHex(),
			operatorNpubField:    other.Npub(),
		}

		hostA := t.TempDir()
		t.Setenv("DG_HOME", hostA)
		err = operatorExportCmd.RunE(operatorExportCmd, nil)
		if err == nil {
			t.Fatalf("expected export to refuse clobbering a distinct existing vault item, got nil error")
		}

		// The vault item must be UNCHANGED.
		got := fake.items[fake.key("test-vault", "dontguess-operator")][operatorPubKeyField]
		if got != other.PubKeyHex() {
			t.Fatalf("vault item was mutated by a refused export: got pubkey %s, want %s", got, other.PubKeyHex())
		}
	})
}

// trimKey trims the trailing newline the key file writer appends (matches
// pkg/identity/keyfile.go's WriteString(candidate + "\n")).
func trimKey(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
