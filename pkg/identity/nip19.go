package identity

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// npubHRP is the NIP-19 human-readable prefix for a public key.
const npubHRP = "npub"

// EncodeNpub encodes a 32-byte x-only public key as a NIP-19 "npub1…" bech32
// string. NIP-19 uses the original bech32 checksum (BIP-173), not bech32m.
func EncodeNpub(pubkey []byte) (string, error) {
	if len(pubkey) != 32 {
		return "", fmt.Errorf("npub encode: pubkey must be 32 bytes, got %d", len(pubkey))
	}
	// EncodeFromBase256 handles the 8-bit → 5-bit regrouping (with padding)
	// that bech32 requires, then appends the BIP-173 checksum.
	s, err := bech32.EncodeFromBase256(npubHRP, pubkey)
	if err != nil {
		return "", fmt.Errorf("npub bech32 encode: %w", err)
	}
	return s, nil
}

// EncodeNpubHex is EncodeNpub over a hex-encoded pubkey (the nostr on-wire
// form).
func EncodeNpubHex(pubkeyHex string) (string, error) {
	raw, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return "", fmt.Errorf("npub encode: decode pubkey hex: %w", err)
	}
	return EncodeNpub(raw)
}

// DecodeNpub decodes a NIP-19 "npub1…" string back to the 32-byte x-only public
// key. It rejects any other bech32 HRP (nsec, note, …) so a private key or a
// note id can never be mistaken for a public key in an allowlist.
func DecodeNpub(npub string) ([]byte, error) {
	hrp, data, err := bech32.DecodeToBase256(npub)
	if err != nil {
		return nil, fmt.Errorf("npub bech32 decode: %w", err)
	}
	if hrp != npubHRP {
		return nil, fmt.Errorf("npub decode: expected hrp %q, got %q", npubHRP, hrp)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("npub decode: expected 32-byte key, got %d bytes", len(data))
	}
	return data, nil
}

// DecodeNpubToHex decodes an npub to the lowercase-hex nostr pubkey form.
func DecodeNpubToHex(npub string) (string, error) {
	raw, err := DecodeNpub(npub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
