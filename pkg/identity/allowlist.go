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

	// open, when true, makes Allowed report true for every pubkey. Only
	// OpenAllowlist sets this — it exists so "no allowlist enforcement" is an
	// explicit, named choice at the call site rather than an implicit
	// consequence of passing nil. See RelayAuthenticate.
	open bool
}

// OpenAllowlist returns an Allowlist that admits every pubkey. Pass this to
// RelayAuthenticate to explicitly disable allowlist enforcement (e.g. a
// single-operator/individual-tier relay with no fleet to restrict to). This
// is the only supported way to disable enforcement — RelayAuthenticate
// rejects a nil allowlist outright so an unconfigured allowlist fails closed
// instead of silently admitting anyone.
func OpenAllowlist() *Allowlist {
	return &Allowlist{open: true}
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
	hexKey, err := NormalizeAllowlistEntry(entry)
	if err != nil {
		return err
	}
	a.members[hexKey] = strings.TrimSpace(entry)
	return nil
}

// NormalizeAllowlistEntry validates one allowlist entry (npub or 64-char hex)
// and returns its canonical lowercase-hex pubkey form. It is the single place
// that decides whether a string can ever be a nostr pubkey, so every path that
// admits a key — operator `allowlist add`, invite redeem, and open admission —
// enforces exactly the same rule as the one that loads the allowlist at boot.
//
// dontguess-31b: open admission did NOT run this check, so it persisted a
// sender key that is not a point on the secp256k1 curve. The boot-time loader
// DID run it, so the operator then refused to start — a live exchange bricked
// by an entry that admission itself created. An admission path that is laxer
// than the load path can always poison durable state.
func NormalizeAllowlistEntry(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if strings.HasPrefix(entry, npubHRP+"1") {
		h, err := DecodeNpubToHex(entry)
		if err != nil {
			return "", fmt.Errorf("allowlist: invalid npub %q: %w", entry, err)
		}
		return h, nil
	}
	// Treat as hex; validate it is a well-formed 32-byte x-only pubkey.
	if _, err := parsePubKeyHex(entry); err != nil {
		return "", fmt.Errorf("allowlist: entry %q is neither a valid npub nor a valid hex pubkey: %w", entry, err)
	}
	return strings.ToLower(entry), nil
}

// NewAllowlistPartition builds an allowlist from the usable entries and returns
// the unusable ones instead of failing. It never errors.
//
// Use this wherever a malformed entry must not be able to take the exchange
// down — loading persisted config at boot, and rebuilding the roster to
// republish. Use NewAllowlist (hard error) for an explicit operator act like
// `dontguess allowlist add`, where the operator typed the entry and must be
// told it is wrong rather than have it silently swallowed.
//
// WHY DROPPING IS FAIL-CLOSED HERE, not the security hole NewAllowlist's doc
// warns about: Allowed() is only ever asked about pubkeys taken off signature-
// verified nostr events, which are by construction valid curve points. An entry
// that is NOT a valid pubkey therefore cannot match any caller — it admits
// nobody whether it is kept or dropped. Dropping it is strictly no more
// permissive than keeping it, while refusing to build the allowlist at all
// takes down every admission decision the operator needs to make. That
// asymmetry is the whole lesson of dontguess-31b: fail closed on the ENTRY,
// not on the SERVICE.
func NewAllowlistPartition(entries ...string) (*Allowlist, []string) {
	a := &Allowlist{members: make(map[string]string)}
	var unusable []string
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		hexKey, err := NormalizeAllowlistEntry(e)
		if err != nil {
			unusable = append(unusable, strings.TrimSpace(e))
			continue
		}
		a.members[hexKey] = strings.TrimSpace(e)
	}
	return a, unusable
}

// Allowed reports whether the given hex pubkey (as it appears on a nostr event)
// is on the allowlist. Comparison is case-insensitive on the hex. An
// OpenAllowlist reports true unconditionally.
func (a *Allowlist) Allowed(pubkeyHex string) bool {
	if a.open {
		return true
	}
	_, ok := a.members[strings.ToLower(strings.TrimSpace(pubkeyHex))]
	return ok
}

// Len returns the number of admitted identities.
func (a *Allowlist) Len() int { return len(a.members) }

// HexKeys returns the admitted pubkeys in lowercase hex form — the on-wire nostr
// event pubkey form a relay leg presents as the message Sender. The team-tier
// serve path materializes these into a mutable exchange.KeySet so a runtime
// de-allowlist (Remove) works and so npub-form allowlist entries compare equal to
// the hex Sender on incoming events. The returned slice is a fresh copy; order is
// unspecified. Returns nil for an OpenAllowlist (it admits everyone, so an
// explicit member set is meaningless).
func (a *Allowlist) HexKeys() []string {
	out := make([]string, 0, len(a.members))
	for hexKey := range a.members {
		out = append(out, hexKey)
	}
	return out
}
