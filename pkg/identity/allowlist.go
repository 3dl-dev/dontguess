package identity

import (
	"fmt"
	"strings"
)

// Allowlist is the set of fleet npubs permitted to authenticate at the NIP-42
// handshake. It is keyed internally by lowercase hex pubkey so that npub and
// hex forms compare equal.
//
// Per the design's enforcement model, NIP-42 secures the pipe, not the
// operation: an allowlisted npub is proven to hold the connection, but write
// authority for match/settle/mint/burn is enforced separately by client-side
// re-verification against the operator key. The allowlist's job is narrower and
// still essential — keep un-vetted npubs off the team relay entirely so
// convergence is scored only over known fleet identities.
type Allowlist struct {
	// hex pubkey -> the label it was admitted under (npub or hex), for
	// diagnostics only. Presence in the map is the authorization.
	members map[string]string
}

// NewAllowlist builds an allowlist from a mix of npub ("npub1…") and 64-char
// hex pubkey entries. Empty/whitespace entries are ignored; any malformed entry
// is a hard error (a silently-dropped allowlist entry is a security hole — it
// would fail-open by admitting nobody or, worse, admit an attacker whose entry
// was meant to be excluded elsewhere).
func NewAllowlist(entries ...string) (*Allowlist, error) {
	a := &Allowlist{members: make(map[string]string)}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if err := a.Add(e); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// Add admits a single entry (npub or hex) to the allowlist.
func (a *Allowlist) Add(entry string) error {
	entry = strings.TrimSpace(entry)
	var hexKey string
	switch {
	case strings.HasPrefix(entry, npubHRP+"1"):
		h, err := DecodeNpubToHex(entry)
		if err != nil {
			return fmt.Errorf("allowlist: invalid npub %q: %w", entry, err)
		}
		hexKey = h
	default:
		// Treat as hex; validate it is a well-formed 32-byte x-only pubkey.
		if _, err := parsePubKeyHex(entry); err != nil {
			return fmt.Errorf("allowlist: entry %q is neither a valid npub nor a valid hex pubkey: %w", entry, err)
		}
		hexKey = strings.ToLower(entry)
	}
	a.members[hexKey] = entry
	return nil
}

// Allowed reports whether the given hex pubkey (as it appears on a nostr event)
// is on the allowlist. Comparison is case-insensitive on the hex.
func (a *Allowlist) Allowed(pubkeyHex string) bool {
	_, ok := a.members[strings.ToLower(strings.TrimSpace(pubkeyHex))]
	return ok
}

// Len returns the number of admitted identities.
func (a *Allowlist) Len() int { return len(a.members) }
