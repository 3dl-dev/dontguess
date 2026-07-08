package identity

import (
	"testing"
	"time"
)

// TestNpubKnownVector locks the bech32 encoding against a published NIP-19 test
// vector so a regression in the encoder is caught immediately (a wrong npub
// silently breaks every allowlist match).
func TestNpubKnownVector(t *testing.T) {
	t.Parallel()
	const (
		pubHex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
		want   = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
	)
	got, err := EncodeNpubHex(pubHex)
	if err != nil {
		t.Fatalf("EncodeNpubHex: %v", err)
	}
	if got != want {
		t.Fatalf("npub mismatch:\n got %s\nwant %s", got, want)
	}
	back, err := DecodeNpubToHex(want)
	if err != nil {
		t.Fatalf("DecodeNpubToHex: %v", err)
	}
	if back != pubHex {
		t.Fatalf("npub decode mismatch: got %s want %s", back, pubHex)
	}
}

// TestBuildAndVerifyAuthEvent proves an AUTH event built by a signer verifies
// against the same challenge/relay, and that VerifyEvent detects tampering.
func TestBuildAndVerifyAuthEvent(t *testing.T) {
	t.Parallel()

	signer, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const relay = "wss://relay.dontguess.ai"
	challenge := "challenge-abc-123"

	ev, err := BuildAuthEvent(signer, relay, challenge)
	if err != nil {
		t.Fatalf("BuildAuthEvent: %v", err)
	}
	if ev.Kind != KindAuth {
		t.Fatalf("kind = %d, want %d", ev.Kind, KindAuth)
	}
	if ev.PubKey != signer.PubKeyHex() {
		t.Fatalf("event pubkey mismatch")
	}

	// Signature + id must verify.
	if err := VerifyEvent(ev); err != nil {
		t.Fatalf("VerifyEvent on freshly built event: %v", err)
	}

	// Full auth verify against matching challenge/relay/time.
	pk, err := VerifyAuthEvent(ev, relay, challenge, time.Now())
	if err != nil {
		t.Fatalf("VerifyAuthEvent: %v", err)
	}
	if pk != signer.PubKeyHex() {
		t.Fatalf("VerifyAuthEvent returned pubkey %s, want %s", pk, signer.PubKeyHex())
	}

	// Tamper with content: id no longer matches -> VerifyEvent fails.
	bad := *ev
	bad.Content = "tampered"
	if err := VerifyEvent(&bad); err == nil {
		t.Fatal("VerifyEvent accepted an event whose content was altered")
	}

	// Tamper with the signature: must fail.
	badSig := *ev
	if badSig.Sig[0] == 'a' {
		badSig.Sig = "b" + badSig.Sig[1:]
	} else {
		badSig.Sig = "a" + badSig.Sig[1:]
	}
	if err := VerifyEvent(&badSig); err == nil {
		t.Fatal("VerifyEvent accepted an event with a tampered signature")
	}
}

// TestVerifyAuthEvent_Rejections covers the replay/binding/freshness guards:
// wrong challenge, wrong relay, wrong kind, and stale timestamp.
func TestVerifyAuthEvent_Rejections(t *testing.T) {
	t.Parallel()

	signer, _ := Generate()
	const relay = "wss://relay.dontguess.ai"
	const challenge = "the-one-true-challenge"

	ev, err := BuildAuthEvent(signer, relay, challenge)
	if err != nil {
		t.Fatalf("BuildAuthEvent: %v", err)
	}

	now := time.Unix(ev.CreatedAt, 0)

	if _, err := VerifyAuthEvent(ev, relay, "different-challenge", now); err == nil {
		t.Error("accepted an event signed for a different challenge (replay hole)")
	}
	if _, err := VerifyAuthEvent(ev, "wss://evil.example", challenge, now); err == nil {
		t.Error("accepted an event bound to a different relay")
	}

	stale := now.Add(authMaxClockSkew + time.Minute)
	if _, err := VerifyAuthEvent(ev, relay, challenge, stale); err == nil {
		t.Error("accepted a stale event outside the clock-skew window")
	}

	wrongKind := *ev
	wrongKind.Kind = 1
	if _, err := VerifyAuthEvent(&wrongKind, relay, challenge, now); err == nil {
		t.Error("accepted a non-22242 event as an AUTH event")
	}

	// Trailing-slash relay difference must still match (normalization).
	if _, err := VerifyAuthEvent(ev, relay+"/", challenge, now); err != nil {
		t.Errorf("rejected a relay URL differing only by trailing slash: %v", err)
	}
}
