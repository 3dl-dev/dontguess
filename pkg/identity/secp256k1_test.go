package identity

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// TestGenerate_DistinctValidKeys proves keygen yields distinct, well-formed
// secp256k1 identities: 32-byte x-only pubkeys, valid npub encoding, and a
// private key that round-trips through hex.
func TestGenerate_DistinctValidKeys(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		id, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		pkHex := id.PubKeyHex()
		raw, err := hex.DecodeString(pkHex)
		if err != nil {
			t.Fatalf("pubkey not hex: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("pubkey is %d bytes, want 32 (x-only)", len(raw))
		}
		if _, err := schnorr.ParsePubKey(raw); err != nil {
			t.Fatalf("pubkey not a valid BIP-340 point: %v", err)
		}
		if seen[pkHex] {
			t.Fatalf("duplicate pubkey from Generate: %s", pkHex)
		}
		seen[pkHex] = true

		// npub must decode back to the same pubkey.
		npub := id.Npub()
		if !strings.HasPrefix(npub, "npub1") {
			t.Fatalf("npub %q missing npub1 prefix", npub)
		}
		backHex, err := DecodeNpubToHex(npub)
		if err != nil {
			t.Fatalf("DecodeNpubToHex: %v", err)
		}
		if backHex != pkHex {
			t.Fatalf("npub round-trip mismatch: %s vs %s", backHex, pkHex)
		}

		// Private key must round-trip and reproduce the same pubkey.
		reloaded, err := FromPrivHex(id.PrivHex())
		if err != nil {
			t.Fatalf("FromPrivHex: %v", err)
		}
		if reloaded.PubKeyHex() != pkHex {
			t.Fatalf("priv key round-trip changed pubkey: %s vs %s", reloaded.PubKeyHex(), pkHex)
		}
	}
}

// TestFromPrivHex_Rejects covers invalid private key material: bad hex, wrong
// length, the zero scalar, and a value ≥ the curve order (which btcec would
// otherwise silently reduce mod N, aliasing distinct on-disk keys).
func TestFromPrivHex_Rejects(t *testing.T) {
	t.Parallel()

	// secp256k1 group order N and N (== overflow to zero) both invalid.
	const curveOrderN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	cases := map[string]string{
		"bad hex":      "nothex!!",
		"too short":    "00112233",
		"too long":     strings.Repeat("ab", 33),
		"zero scalar":  strings.Repeat("00", 32),
		"equals order": curveOrderN,
		"above order":  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for name, in := range cases {
		if _, err := FromPrivHex(in); err == nil {
			t.Errorf("%s: expected error, got nil for %q", name, in)
		}
	}
}

// TestSignVerify_RoundTrip proves a signature over a hash verifies, and that
// tampering with the hash or using a different key fails verification.
func TestSignVerify_RoundTrip(t *testing.T) {
	t.Parallel()

	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var hash [32]byte
	copy(hash[:], []byte("dontguess-476 nip42 test message"))

	sig, err := id.SignHash(hash)
	if err != nil {
		t.Fatalf("SignHash: %v", err)
	}
	if len(sig) != schnorr.SignatureSize {
		t.Fatalf("sig is %d bytes, want %d", len(sig), schnorr.SignatureSize)
	}

	pub, err := schnorr.ParsePubKey(mustHex(t, id.PubKeyHex()))
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	if !parsed.Verify(hash[:], pub) {
		t.Fatal("valid signature failed to verify")
	}

	// Tamper the message: must not verify.
	var bad [32]byte
	copy(bad[:], hash[:])
	bad[0] ^= 0xff
	if parsed.Verify(bad[:], pub) {
		t.Fatal("signature verified over a tampered message")
	}

	// Different key: must not verify.
	other, _ := Generate()
	otherPub, _ := schnorr.ParsePubKey(mustHex(t, other.PubKeyHex()))
	if parsed.Verify(hash[:], otherPub) {
		t.Fatal("signature verified under the wrong public key")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}
