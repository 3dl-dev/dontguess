package identity

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestLoadOrCreatePrivHexKey_ConcurrentCreate is the core ed5 race proof: many
// goroutines racing to first-create the SAME key path must all converge on ONE
// identical secp256k1 identity, and no loser may ever observe a torn/empty file
// (a partial read would FromPrivHex to a DIFFERENT valid key — the exact
// advertise!=sign split this fix exists to kill). Run with -race.
func TestLoadOrCreatePrivHexKey_ConcurrentCreate(t *testing.T) {
	t.Parallel()

	const goroutines = 32
	dir := t.TempDir()
	path := filepath.Join(dir, "nostr-operator.key")

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // release all goroutines at once to maximize the race window
			id, err := LoadOrCreatePrivHexKey(path)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = id.PubKeyHex()
		}(i)
	}
	close(start)
	wg.Wait()

	// No caller may fail: a loser reading a torn/empty file would surface a
	// FromPrivHex error here.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d errored (torn/empty read?): %v", i, err)
		}
	}

	// Every caller must return the exact same pubkey — one durable identity.
	want := results[0]
	if want == "" {
		t.Fatal("goroutine 0 returned empty pubkey")
	}
	for i, got := range results {
		if got != want {
			t.Fatalf("goroutine %d pubkey %q != goroutine 0 pubkey %q — advertise!=sign split", i, got, want)
		}
	}

	// The on-disk key must derive that same pubkey.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading persisted key: %v", err)
	}
	onDisk, err := FromPrivHex(trimKeyWS(string(data)))
	if err != nil {
		t.Fatalf("parsing persisted key: %v", err)
	}
	if onDisk.PubKeyHex() != want {
		t.Fatalf("on-disk pubkey %q != returned pubkey %q", onDisk.PubKeyHex(), want)
	}
}

// TestLoadOrCreateRawKey_ConcurrentCreate proves the same convergence for the
// opaque (non-secp256k1) local operator key path.
func TestLoadOrCreateRawKey_ConcurrentCreate(t *testing.T) {
	t.Parallel()

	const goroutines = 32
	dir := t.TempDir()
	path := filepath.Join(dir, "local-operator.key")

	gen := func() (string, error) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			key, err := LoadOrCreateRawKey(path, gen)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = key
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d errored: %v", i, err)
		}
	}
	want := results[0]
	if want == "" {
		t.Fatal("goroutine 0 returned empty key")
	}
	if len(want) != 32 {
		t.Fatalf("raw key len = %d, want 32 (16 bytes hex)", len(want))
	}
	for i, got := range results {
		if got != want {
			t.Fatalf("goroutine %d key %q != goroutine 0 key %q", i, got, want)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading persisted key: %v", err)
	}
	if trimKeyWS(string(data)) != want {
		t.Fatalf("on-disk key %q != returned key %q", trimKeyWS(string(data)), want)
	}
}

// TestLoadOrCreatePrivHexKey_Idempotent verifies a pre-existing key is reused
// verbatim, never re-minted or overwritten.
func TestLoadOrCreatePrivHexKey_Idempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nostr-operator.key")

	id1, err := LoadOrCreatePrivHexKey(path)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after first: %v", err)
	}

	id2, err := LoadOrCreatePrivHexKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second: %v", err)
	}

	if id1.PubKeyHex() != id2.PubKeyHex() {
		t.Errorf("pubkey changed on reload: %q -> %q", id1.PubKeyHex(), id2.PubKeyHex())
	}
	if string(first) != string(second) {
		t.Error("on-disk key bytes changed across loads — key was overwritten")
	}
}

// TestLoadOrCreatePrivHexKey_Perms0600 verifies the minted key is 0600.
func TestLoadOrCreatePrivHexKey_Perms0600(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nostr-operator.key")
	if _, err := LoadOrCreatePrivHexKey(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key perms = %o, want 0600", perm)
	}
}

// trimKeyWS strips surrounding whitespace from a key file read for test assertions.
func trimKeyWS(s string) string {
	for len(s) > 0 {
		switch s[len(s)-1] {
		case '\n', '\r', ' ', '\t':
			s = s[:len(s)-1]
		default:
			return s
		}
	}
	return s
}
