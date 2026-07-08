package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrCreate_Idempotent proves the first call creates a persistent
// identity and a second call loads the SAME key (the persistent-npub guarantee
// agent-init relies on).
func TestLoadOrCreate_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	id1, created1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if !created1 {
		t.Fatal("first LoadOrCreate should report created=true")
	}

	// File must exist with 0600 perms (private key material).
	info, err := os.Stat(filepath.Join(dir, IdentityFile))
	if err != nil {
		t.Fatalf("stat identity file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("identity file perms = %o, want 0600", info.Mode().Perm())
	}

	id2, created2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if created2 {
		t.Fatal("second LoadOrCreate should report created=false (loaded, not minted)")
	}
	if id1.Npub() != id2.Npub() {
		t.Fatalf("npub changed across LoadOrCreate calls: %s vs %s — identity was clobbered", id1.Npub(), id2.Npub())
	}
	if id1.PrivHex() != id2.PrivHex() {
		t.Fatal("private key changed across LoadOrCreate calls")
	}
}

// TestLoad_DetectsTamperedPubkey proves the load-time integrity check refuses a
// file whose recorded pubkey/npub was edited to disagree with the private key —
// signing with a key whose recorded identity is a lie must never happen.
func TestLoad_DetectsTamperedPubkey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	path := filepath.Join(dir, IdentityFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Corrupt the recorded npub while leaving the private key intact.
	other, _ := Generate()
	tampered := strings.Replace(string(raw), extractNpub(t, string(raw)), other.Npub(), 1)
	if tampered == string(raw) {
		t.Fatal("test setup: npub substitution did not change the file")
	}
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a file whose recorded npub disagrees with the private key")
	}
}

// extractNpub pulls the npub value out of the persisted JSON for the tamper test.
func extractNpub(t *testing.T, jsonStr string) string {
	t.Helper()
	const marker = `"npub": "`
	i := strings.Index(jsonStr, marker)
	if i < 0 {
		t.Fatal("no npub field in identity file")
	}
	rest := jsonStr[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("malformed npub field")
	}
	return rest[:j]
}
