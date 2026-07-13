package relayclient

// deliver_v2_blob_fetch_test.go — dontguess-250: the BUYER's Blossom fetch of a
// §3.4 v2 confidential settle(deliver) whose ciphertext was OFFLOADED to a Blossom
// blob (oversize content) rather than inlined in the 3401 put. These exercise
// verifyDeliver/decryptDeliverV2 down the blob_pointer branch with REAL secp256k1
// identities, REAL NIP-44 wraps, REAL ChaCha20-Poly1305, and a REAL content-addressed
// MemoryBlobStore — no crypto mocks. The counterpart inline (put_event) path is
// covered by deliver_v2_decrypt_test.go (dontguess-5db).
//
// Proven here:
//
//	(a) a v2 blob_pointer deliver + a MemoryBlobStore pre-populated with the matching
//	    ciphertext ⇒ the buyer FETCHES the blob (UNAUTHENTICATED — §2: the blob is AEAD
//	    ciphertext, so the fetch yields only ciphertext, never the CEK), verifies
//	    sha256(ciphertext)==ciphertext_hash BEFORE decrypting, unwraps the CEK, and
//	    AEAD-decrypts to the ORIGINAL plaintext, byte-for-byte. conn is nil — the blob
//	    path must NOT touch the relay.
//	(b) a blob whose bytes do NOT match ciphertext_hash (corruption/tamper) ⇒ LOUD
//	    error, NO plaintext, and (because verifyDeliver errored) NO settle(complete).
//	(c) a missing blob (exchange.ErrBlobNotFound) ⇒ LOUD error, no settle(complete).
//	(d) a nil BlobStore + a blob_pointer deliver ⇒ LOUD error (not a silent pass):
//	    without a Blossom client the buyer cannot fetch the ciphertext, so it must
//	    refuse to settle(complete).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
)

// ciphertextBytes decodes the fixture put's inline enc.ciphertext back to the raw
// AEAD ciphertext bytes. For oversize content the operator would offload EXACTLY
// these bytes to a Blossom blob instead of inlining them; here we reuse the same
// ciphertext so the crypto is genuine, exercising only the blob-fetch source.
func (f *v2Fixture) ciphertextBytes(t *testing.T) []byte {
	t.Helper()
	var pp struct {
		Enc struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"enc"`
	}
	if err := json.Unmarshal([]byte(f.putEv.Content), &pp); err != nil {
		t.Fatalf("parse put content: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(pp.Enc.Ciphertext)
	if err != nil {
		t.Fatalf("decode fixture ciphertext: %v", err)
	}
	if len(ct) == 0 {
		t.Fatalf("fixture produced an empty ciphertext")
	}
	return ct
}

// blobDeliverEvent builds an operator-authored v2 settle(deliver) whose
// ciphertext_ref is a BLOSSOM blob_pointer (not an inline put_event) — the oversize
// path dontguess-250 implements. blobPointer/recipient/wrapped/ciphertextHash are
// parameterized so a test can tamper any of them. ev.PubKey is the operator key, so
// verifyDeliver unwraps the CEK from the deliver's AUTHOR (as on the inline path).
func (f *v2Fixture) blobDeliverEvent(blobPointer, recipient, wrapped, ciphertextHash string) *identity.Event {
	payload, _ := json.Marshal(map[string]any{
		"phase":           "deliver",
		"v":               2,
		"entry_id":        "entry-1",
		"content_alg":     "chacha20poly1305",
		"ciphertext_ref":  map[string]any{"blob_pointer": blobPointer},
		"ciphertext_hash": ciphertextHash,
		"key_wrap": map[string]any{
			"alg":       "nip44-v2-secp256k1",
			"recipient": recipient,
			"wrapped":   wrapped,
		},
	})
	return &identity.Event{
		ID:      "blob-deliver-wire-id",
		PubKey:  f.operator.PubKeyHex(),
		Content: string(payload),
	}
}

// (a) full v2 BLOB round-trip: fetch (unauthenticated) + hash-verify + unwrap +
// AEAD-decrypt to the ORIGINAL plaintext, byte-for-byte. conn is nil — the blob
// source must not touch the relay.
func TestVerifyDeliverV2_BlobFetch_RoundTrip_DecryptsToOriginalPlaintext(t *testing.T) {
	fx := newV2Fixture(t, []byte("package main\n\n// oversize content offloaded to Blossom; the exact bytes the buyer must recover\n"))
	ciphertext := fx.ciphertextBytes(t)

	// A REAL content-addressed store, pre-populated with the matching ciphertext.
	store := exchange.NewMemoryBlobStore()
	pointer, err := store.Put(ciphertext)
	if err != nil {
		t.Fatalf("pre-populate blob store: %v", err)
	}

	deliverEv := fx.blobDeliverEvent(pointer, fx.buyer.PubKeyHex(), fx.wrappedForBuyer, fx.ciphertextHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// conn == nil on purpose: a blob_pointer deliver resolves via the BlobStore and
	// must never REQ-fetch a put over the relay.
	got, gotHash, err := verifyDeliver(ctx, nil, fx.buyer, deliverEv, 0, store)
	if err != nil {
		t.Fatalf("verifyDeliver (v2 blob happy path): %v", err)
	}
	if string(got) != string(fx.plaintext) {
		t.Fatalf("decrypted plaintext mismatch:\n got %q\nwant %q", got, fx.plaintext)
	}
	if gotHash != fx.ciphertextHash {
		t.Fatalf("returned hash = %q, want the ciphertext_hash %q", gotHash, fx.ciphertextHash)
	}
}

// (b) a blob whose bytes do NOT match ciphertext_hash ⇒ LOUD error, no plaintext,
// and no settle(complete) (a verifyDeliver error aborts the chain before complete).
// We corrupt one byte of the ciphertext and store THAT; the content-addressed store
// hands back the corrupted bytes, whose sha256 diverges from the genuine
// ciphertext_hash the deliver still claims.
func TestVerifyDeliverV2_BlobFetch_HashMismatch_FailsLoud(t *testing.T) {
	fx := newV2Fixture(t, []byte("genuine cached inference result bytes"))
	genuine := fx.ciphertextBytes(t)

	corrupted := append([]byte(nil), genuine...)
	corrupted[0] ^= 0xFF // flip a bit: bytes no longer match the claimed ciphertext_hash

	store := exchange.NewMemoryBlobStore()
	badPointer, err := store.Put(corrupted)
	if err != nil {
		t.Fatalf("store corrupted blob: %v", err)
	}

	// Deliver still claims the GENUINE ciphertext_hash, but the blob at badPointer is
	// corrupted — the buyer must detect the mismatch BEFORE decrypting.
	deliverEv := fx.blobDeliverEvent(badPointer, fx.buyer.PubKeyHex(), fx.wrappedForBuyer, fx.ciphertextHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, _, err := verifyDeliver(ctx, nil, fx.buyer, deliverEv, 0, store)
	if err == nil {
		t.Fatalf("expected a LOUD ciphertext-hash mismatch error for a corrupted blob, got nil (plaintext=%q)", got)
	}
	if !strings.Contains(err.Error(), "CIPHERTEXT HASH MISMATCH") {
		t.Fatalf("error %q does not surface the ciphertext-hash mismatch", err)
	}
	if got != nil {
		t.Fatalf("no content must be returned on a corrupted-blob hash mismatch, got %q", got)
	}
}

// (c) a missing blob (exchange.ErrBlobNotFound) ⇒ LOUD error, no settle(complete).
func TestVerifyDeliverV2_BlobFetch_MissingBlob_FailsLoud(t *testing.T) {
	fx := newV2Fixture(t, []byte("bytes that were never uploaded to the blob store"))

	store := exchange.NewMemoryBlobStore() // deliberately EMPTY
	deliverEv := fx.blobDeliverEvent("memblob:0000000000000000000000000000000000000000000000000000000000000000",
		fx.buyer.PubKeyHex(), fx.wrappedForBuyer, fx.ciphertextHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, _, err := verifyDeliver(ctx, nil, fx.buyer, deliverEv, 0, store)
	if err == nil {
		t.Fatalf("expected a LOUD blob-not-found error, got nil (plaintext=%q)", got)
	}
	if !errors.Is(err, exchange.ErrBlobNotFound) {
		t.Fatalf("error %q does not wrap exchange.ErrBlobNotFound", err)
	}
	if got != nil {
		t.Fatalf("no content must be returned when the blob is missing, got %q", got)
	}
}

// (d) a nil BlobStore + a blob_pointer deliver ⇒ LOUD error, NOT a silent pass:
// without a Blossom client the buyer cannot fetch the ciphertext, so it must refuse
// to settle(complete). (Contrast: the inline put_event path never needs a BlobStore.)
func TestVerifyDeliverV2_BlobPointer_NoBlobStore_FailsLoud(t *testing.T) {
	fx := newV2Fixture(t, []byte("content the buyer has no way to fetch without a store"))
	deliverEv := fx.blobDeliverEvent("memblob:deadbeef", fx.buyer.PubKeyHex(), fx.wrappedForBuyer, fx.ciphertextHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// nil BlobStore: the blob_pointer deliver has nowhere to fetch from.
	got, _, err := verifyDeliver(ctx, nil, fx.buyer, deliverEv, 0, nil)
	if err == nil {
		t.Fatalf("expected a LOUD no-BlobStore error for a blob_pointer deliver, got nil (plaintext=%q)", got)
	}
	if !strings.Contains(err.Error(), "no buyer BlobStore is configured") {
		t.Fatalf("error %q does not surface the missing-BlobStore guard", err)
	}
	if got != nil {
		t.Fatalf("no content must be returned when no BlobStore is configured, got %q", got)
	}
}
