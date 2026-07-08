package identity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// KindAuth is the nostr event kind for NIP-42 authentication (kind 22242).
const KindAuth = 22242

// authMaxClockSkew bounds how far an AUTH event's created_at may be from the
// relay's clock. NIP-42 events are ephemeral proofs of a live challenge; a wide
// window would let a captured event be replayed long after issuance. The
// challenge nonce is the primary replay defense, but a freshness bound is cheap
// defense-in-depth.
const authMaxClockSkew = 10 * time.Minute

// BuildAuthEvent constructs and signs a NIP-42 AUTH event (kind 22242) for the
// given relay URL and relay-issued challenge. Per NIP-42 the event carries two
// tags — ["relay", <url>] and ["challenge", <challenge>] — and empty content.
func BuildAuthEvent(signer Signer, relayURL, challenge string) (*Event, error) {
	if challenge == "" {
		return nil, fmt.Errorf("build auth event: empty challenge")
	}
	ev := &Event{
		CreatedAt: time.Now().Unix(),
		Kind:      KindAuth,
		Tags: [][]string{
			{"relay", relayURL},
			{"challenge", challenge},
		},
		Content: "",
	}
	if err := SignEvent(signer, ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// tagValue returns the value (index 1) of the first tag whose name (index 0)
// matches, or "" if absent.
func tagValue(tags [][]string, name string) string {
	for _, t := range tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}

// VerifyAuthEvent checks that ev is a valid NIP-42 AUTH response to the given
// challenge for the given relay URL, at the given wall-clock time. It verifies:
//
//  1. kind == 22242;
//  2. the challenge tag matches exactly (replay/nonce binding);
//  3. the relay tag matches (an event minted for relay A is not valid at B);
//  4. created_at is within authMaxClockSkew of now;
//  5. the event id recomputes and the Schnorr signature verifies (VerifyEvent).
//
// It returns the authenticated hex pubkey on success. Note this proves *who*
// holds the connection — the allowlist decision is a separate step so the two
// concerns (authenticity vs. authorization) stay independently testable.
func VerifyAuthEvent(ev *Event, relayURL, challenge string, now time.Time) (string, error) {
	if ev.Kind != KindAuth {
		return "", fmt.Errorf("auth verify: wrong kind %d, want %d", ev.Kind, KindAuth)
	}
	if got := tagValue(ev.Tags, "challenge"); got != challenge {
		return "", fmt.Errorf("auth verify: challenge mismatch")
	}
	if got := tagValue(ev.Tags, "relay"); !relayURLMatch(got, relayURL) {
		return "", fmt.Errorf("auth verify: relay tag %q does not match %q", got, relayURL)
	}
	created := time.Unix(ev.CreatedAt, 0)
	if d := now.Sub(created); d > authMaxClockSkew || d < -authMaxClockSkew {
		return "", fmt.Errorf("auth verify: created_at %s outside ±%s of now", created, authMaxClockSkew)
	}
	if err := VerifyEvent(ev); err != nil {
		return "", fmt.Errorf("auth verify: %w", err)
	}
	return ev.PubKey, nil
}

// relayURLMatch compares two relay URLs for NIP-42 purposes, tolerating a
// trailing-slash difference and case-insensitive scheme/host but nothing else.
func relayURLMatch(a, b string) bool {
	na := strings.TrimRight(strings.TrimSpace(a), "/")
	nb := strings.TrimRight(strings.TrimSpace(b), "/")
	return strings.EqualFold(na, nb)
}

// NewChallenge returns a fresh random challenge string (32 bytes hex) for a
// relay to issue. Randomness is the replay defense: each connection gets a
// unique nonce the client must sign.
func NewChallenge() (string, error) {
	b, err := randBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- Wire-message helpers (NIP-01/NIP-42 relay framing) --------------------
//
// A NIP-42 handshake is a sequence of JSON arrays on the websocket:
//
//	relay  → client:  ["AUTH", <challenge-string>]
//	client → relay:   ["AUTH", <signed-event-object>]
//	relay  → client:  ["OK", <event-id>, <bool>, <message>]
//
// These helpers marshal/parse those frames so both the client and relay halves
// of the handshake share one encoder and cannot drift.

// EncodeAuthChallenge builds the relay→client ["AUTH", challenge] frame.
func EncodeAuthChallenge(challenge string) ([]byte, error) {
	return json.Marshal([]interface{}{"AUTH", challenge})
}

// EncodeAuthResponse builds the client→relay ["AUTH", event] frame.
func EncodeAuthResponse(ev *Event) ([]byte, error) {
	return json.Marshal([]interface{}{"AUTH", ev})
}

// EncodeOK builds the relay→client ["OK", id, accepted, message] frame.
func EncodeOK(eventID string, accepted bool, message string) ([]byte, error) {
	return json.Marshal([]interface{}{"OK", eventID, accepted, message})
}

// ParseAuthChallenge parses a relay→client ["AUTH", challenge] frame.
func ParseAuthChallenge(raw []byte) (string, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", fmt.Errorf("parse AUTH challenge frame: %w", err)
	}
	if len(arr) < 2 {
		return "", fmt.Errorf("parse AUTH challenge frame: expected 2 elements, got %d", len(arr))
	}
	var label string
	if err := json.Unmarshal(arr[0], &label); err != nil || label != "AUTH" {
		return "", fmt.Errorf("parse AUTH challenge frame: first element is not \"AUTH\"")
	}
	var challenge string
	if err := json.Unmarshal(arr[1], &challenge); err != nil {
		return "", fmt.Errorf("parse AUTH challenge frame: challenge not a string: %w", err)
	}
	return challenge, nil
}

// ParseAuthResponse parses a client→relay ["AUTH", event] frame.
func ParseAuthResponse(raw []byte) (*Event, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("parse AUTH response frame: %w", err)
	}
	if len(arr) < 2 {
		return nil, fmt.Errorf("parse AUTH response frame: expected 2 elements, got %d", len(arr))
	}
	var label string
	if err := json.Unmarshal(arr[0], &label); err != nil || label != "AUTH" {
		return nil, fmt.Errorf("parse AUTH response frame: first element is not \"AUTH\"")
	}
	var ev Event
	if err := json.Unmarshal(arr[1], &ev); err != nil {
		return nil, fmt.Errorf("parse AUTH response frame: event object: %w", err)
	}
	return &ev, nil
}

// ParseOK parses a relay→client ["OK", id, accepted, message] frame.
func ParseOK(raw []byte) (eventID string, accepted bool, message string, err error) {
	var arr []json.RawMessage
	if e := json.Unmarshal(raw, &arr); e != nil {
		return "", false, "", fmt.Errorf("parse OK frame: %w", e)
	}
	if len(arr) < 3 {
		return "", false, "", fmt.Errorf("parse OK frame: expected ≥3 elements, got %d", len(arr))
	}
	var label string
	if e := json.Unmarshal(arr[0], &label); e != nil || label != "OK" {
		return "", false, "", fmt.Errorf("parse OK frame: first element is not \"OK\"")
	}
	_ = json.Unmarshal(arr[1], &eventID)
	_ = json.Unmarshal(arr[2], &accepted)
	if len(arr) >= 4 {
		_ = json.Unmarshal(arr[3], &message)
	}
	return eventID, accepted, message, nil
}
