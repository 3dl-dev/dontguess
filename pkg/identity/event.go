package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Event is a NIP-01 nostr event. Only the fields dontguess needs are modelled;
// this is enough to build, id, sign, and verify a NIP-42 AUTH event.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// serializeForID produces the NIP-01 canonical serialization used to compute an
// event id: the UTF-8 JSON of the array
//
//	[0, pubkey, created_at, kind, tags, content]
//
// with no extra whitespace and with HTML escaping disabled (NIP-01 mandates
// escaping only \" \\ \n \r \t \b \f — Go's default json would additionally
// escape < > & to \u00XX, diverging from every other nostr implementation and
// producing a different id/signature).
func serializeForID(pubkey string, createdAt int64, kind int, tags [][]string, content string) ([]byte, error) {
	if tags == nil {
		tags = [][]string{}
	}
	arr := []interface{}{0, pubkey, createdAt, kind, tags, content}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(arr); err != nil {
		return nil, fmt.Errorf("serialize event for id: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; strip it so the sha256
	// input matches the canonical NIP-01 string exactly.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// computeID returns the NIP-01 event id: sha256 of the canonical serialization.
func computeID(pubkey string, createdAt int64, kind int, tags [][]string, content string) ([32]byte, error) {
	ser, err := serializeForID(pubkey, createdAt, kind, tags, content)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(ser), nil
}

// SignEvent fills in ev.PubKey, ev.ID, and ev.Sig using the signer. CreatedAt,
// Kind, Tags, and Content must already be set. It is the single choke point
// where an identity becomes a signed nostr event.
func SignEvent(signer Signer, ev *Event) error {
	ev.PubKey = signer.PubKeyHex()
	id, err := computeID(ev.PubKey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content)
	if err != nil {
		return err
	}
	sig, err := signer.SignHash(id)
	if err != nil {
		return fmt.Errorf("sign event id: %w", err)
	}
	ev.ID = hex.EncodeToString(id[:])
	ev.Sig = hex.EncodeToString(sig)
	return nil
}

// VerifyEvent checks that an event's id matches its content and that its
// signature is a valid BIP-340 Schnorr signature by ev.PubKey over that id.
// This is the portable client-side verification every dontguess reader runs;
// it is what makes a relay's NIP-42 pipe-auth insufficient on its own but also
// what lets any reader re-derive trust without trusting the relay.
func VerifyEvent(ev *Event) error {
	// 1. Recompute the id from the content — a mismatch means the id (and thus
	//    what was signed) was tampered with.
	wantID, err := computeID(ev.PubKey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content)
	if err != nil {
		return err
	}
	gotID, err := hex.DecodeString(ev.ID)
	if err != nil {
		return fmt.Errorf("verify: decode event id: %w", err)
	}
	if !bytes.Equal(gotID, wantID[:]) {
		return fmt.Errorf("verify: event id mismatch (content does not match claimed id)")
	}

	// 2. Verify the Schnorr signature over the id with the claimed pubkey.
	pkRaw, err := hex.DecodeString(ev.PubKey)
	if err != nil {
		return fmt.Errorf("verify: decode pubkey: %w", err)
	}
	if len(pkRaw) != 32 {
		return fmt.Errorf("verify: pubkey must be 32 bytes, got %d", len(pkRaw))
	}
	pub, err := schnorr.ParsePubKey(pkRaw)
	if err != nil {
		return fmt.Errorf("verify: parse pubkey: %w", err)
	}
	sigRaw, err := hex.DecodeString(ev.Sig)
	if err != nil {
		return fmt.Errorf("verify: decode sig: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigRaw)
	if err != nil {
		return fmt.Errorf("verify: parse sig: %w", err)
	}
	if !sig.Verify(wantID[:], pub) {
		return fmt.Errorf("verify: schnorr signature does not verify")
	}
	return nil
}

// parsePubKeyHex is a small shared helper (used by tests and callers) that
// validates a 32-byte hex nostr pubkey.
func parsePubKeyHex(pubkeyHex string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	return schnorr.ParsePubKey(raw)
}
