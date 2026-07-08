package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// IdentityFile is the on-disk name of a secp256k1 nostr identity within an
// identity home directory (operator home or a per-agent home under agents/).
const IdentityFile = "nostr-identity.json"

// KeyKind labels the identity scheme on disk so a future re-key is
// self-describing and a mismatched file is rejected loudly rather than
// misinterpreted.
const KeyKind = "secp256k1-schnorr"

// persisted is the JSON shape written to disk. PubKeyHex and Npub are
// derivable from PrivKeyHex; they are stored for human/debug convenience and
// re-verified against the private key on load so a hand-edited file cannot
// desync the recorded npub from the actual signing key.
type persisted struct {
	Kind       string `json:"kind"`
	PrivKeyHex string `json:"priv_key_hex"`
	PubKeyHex  string `json:"pub_key_hex"`
	Npub       string `json:"npub"`
}

// LoadOrCreate loads the secp256k1 identity from <dir>/nostr-identity.json,
// generating and persisting a fresh one if the file does not yet exist. The
// returned bool is true when a new identity was created.
//
// This is the single provisioning path agent-init uses. Idempotency is the
// whole point: a fleet member's npub is persistent, so a re-run loads the same
// key rather than minting a new one (the key-management ruling: never a fresh
// throwaway for a persistent member).
func LoadOrCreate(dir string) (*Secp256k1Identity, bool, error) {
	path := filepath.Join(dir, IdentityFile)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		id, loadErr := loadFrom(raw, path)
		return id, false, loadErr
	case os.IsNotExist(err):
		id, createErr := create(dir, path)
		return id, true, createErr
	default:
		return nil, false, fmt.Errorf("read identity file %s: %w", path, err)
	}
}

// Load reads an existing identity, erroring if the file is absent.
func Load(dir string) (*Secp256k1Identity, error) {
	path := filepath.Join(dir, IdentityFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file %s: %w", path, err)
	}
	return loadFrom(raw, path)
}

func loadFrom(raw []byte, path string) (*Secp256k1Identity, error) {
	var p persisted
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse identity file %s: %w", path, err)
	}
	if p.Kind != KeyKind {
		return nil, fmt.Errorf("identity file %s has kind %q, expected %q", path, p.Kind, KeyKind)
	}
	id, err := FromPrivHex(p.PrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("identity file %s: %w", path, err)
	}
	// Integrity check: the recorded pubkey/npub must match the derived key. A
	// mismatch means the file was tampered with or corrupted — refuse to sign
	// with a key whose recorded identity is a lie.
	if got := id.PubKeyHex(); got != p.PubKeyHex {
		return nil, fmt.Errorf("identity file %s: recorded pub_key_hex %q does not match private key (%q)", path, p.PubKeyHex, got)
	}
	if got := id.Npub(); got != p.Npub {
		return nil, fmt.Errorf("identity file %s: recorded npub %q does not match private key (%q)", path, p.Npub, got)
	}
	return id, nil
}

func create(dir, path string) (*Secp256k1Identity, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create identity dir %s: %w", dir, err)
	}
	id, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := Save(dir, id); err != nil {
		return nil, err
	}
	_ = path
	return id, nil
}

// Save writes the identity to <dir>/nostr-identity.json with 0600 permissions
// (it holds private key material). It writes atomically via a temp file rename
// so a crash mid-write cannot leave a half-written key file.
func Save(dir string, id *Secp256k1Identity) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir %s: %w", dir, err)
	}
	p := persisted{
		Kind:       KeyKind,
		PrivKeyHex: id.PrivHex(),
		PubKeyHex:  id.PubKeyHex(),
		Npub:       id.Npub(),
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	path := filepath.Join(dir, IdentityFile)
	tmp, err := os.CreateTemp(dir, IdentityFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp identity file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp identity file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp identity file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp identity file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename identity file into place: %w", err)
	}
	return nil
}
