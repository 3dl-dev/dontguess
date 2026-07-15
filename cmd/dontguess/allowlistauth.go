package main

// allowlistauth.go — dontguess-113 (design §3 + §9 Gate B/P6, ADV-16): the live
// fleet-allowlist hot-reload IPC op (OpAllowlist) must be authorized by an
// operator-key SIGNATURE, not merely by reaching the 0700 operator socket. The
// socket is SHARED with OpListHeld/OpAcceptPut/OpMint/OpPut/OpBuy, so ANY local
// process able to connect could otherwise admit an arbitrary npub into the live
// fleet KeySet (and republish a fleet roster under the operator key) without ever
// proving possession of the operator key. This mirrors verifyMintAuth exactly
// (mintauth.go / serve.go OpMint): the request must carry a BIP-340 Schnorr-signed
// nostr event, authored by the persisted operator key, that BINDS the exact
// admit/remove action and target key. Socket reachability is necessary but NOT
// sufficient; proof of the operator key is.
//
// The signed event never touches a relay — it is a local IPC auth token only. It
// is a real nostr Event so verification reuses identity.VerifyEvent (the same
// secp256k1 Schnorr verify the relay Intake uses), not a bespoke crypto path.

import (
	"fmt"
	"strings"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// allowlistAuthKind is the nostr event kind used for the OpAllowlist IPC auth
// token. It is a LOCAL-ONLY kind (never published to a relay); the value only has
// to be distinct enough to make an auth event self-describing and to prevent a
// signed event of another kind (a real put/settle, or a mint-auth event) from
// being replayed as an allowlist authorization. It sits outside the exchange kind
// range (3401–3411, 30401) and is distinct from mintAuthKind (27411).
const allowlistAuthKind = 27412

// Allowlist actions the auth event and the controller understand.
const (
	allowlistActionAdd    = "add"
	allowlistActionRemove = "remove"
)

// allowlistAuthActionTag / allowlistAuthTargetTag are the tag names that bind an
// auth event to a specific admit/remove. Both the signer (CLI) and the verifier
// (serve) use these so a captured signed event cannot be reused for a different
// action or a different key.
const (
	allowlistAuthActionTag = "allowlist-action"
	allowlistAuthTargetTag = "allowlist-target"
)

// buildAllowlistAuthEvent constructs the UNSIGNED auth event binding an `action`
// (add|remove) to the fleet member `targetHex`. Action and target are carried in
// tags so the verifier can confirm the signature covers exactly this operation
// (SignEvent folds the tags into the signed id). createdAt is the caller's clock
// (Unix seconds); it is not enforced for freshness (a same-uid attacker can read
// the key anyway — the gate proves key possession, not timing), but it makes each
// auth event unique.
func buildAllowlistAuthEvent(action, targetHex string, createdAt int64) *identity.Event {
	return &identity.Event{
		CreatedAt: createdAt,
		Kind:      allowlistAuthKind,
		Tags: [][]string{
			{allowlistAuthActionTag, strings.ToLower(strings.TrimSpace(action))},
			{allowlistAuthTargetTag, strings.ToLower(strings.TrimSpace(targetHex))},
		},
		Content: "",
	}
}

// verifyAllowlistAuth is the server-side gate. It rejects the OpAllowlist request
// unless `ev` is a nostr event that:
//
//	(1) is present (a nil auth = an unsigned request → rejected),
//	(2) is of kind allowlistAuthKind (a signed event of another kind — including a
//	    mint-auth event — cannot be replayed as an allowlist authorization),
//	(3) is authored by the persisted operator key (ev.PubKey == operatorKeyHex),
//	(4) carries a valid BIP-340 Schnorr signature over its id — the REAL crypto
//	    check (identity.VerifyEvent) that makes a forged/stolen pubkey field
//	    insufficient, and
//	(5) binds this exact operation (its action/target tags equal the request's
//	    action and target), so a signed event for one admit cannot be substituted
//	    onto a different action (add↔remove) or a different key.
//
// operatorKeyHex is the exchange's persisted operator public key
// (State().OperatorKey). An empty operator key (no persisted operator identity)
// fails closed.
func verifyAllowlistAuth(ev *identity.Event, operatorKeyHex, action, targetHex string) error {
	if ev == nil {
		return fmt.Errorf("allowlist: unsigned request rejected — an operator-key signature is required (socket reachability is not authorization)")
	}
	opKey := strings.ToLower(strings.TrimSpace(operatorKeyHex))
	if opKey == "" {
		return fmt.Errorf("allowlist: no persisted operator key to verify against")
	}
	if ev.Kind != allowlistAuthKind {
		return fmt.Errorf("allowlist: auth event has wrong kind %d (want %d)", ev.Kind, allowlistAuthKind)
	}
	// (3) Author must be the operator — reject a wrong-author event before spending
	// a signature verification on it.
	if !strings.EqualFold(strings.TrimSpace(ev.PubKey), opKey) {
		return fmt.Errorf("allowlist: auth not authored by operator key (pubkey %s != operator %s)",
			shortHex(ev.PubKey), shortHex(opKey))
	}
	// (4) The Schnorr signature (and id integrity) must verify against the claimed
	// pubkey. Only the operator's private key can produce it.
	if err := identity.VerifyEvent(ev); err != nil {
		return fmt.Errorf("allowlist: operator signature does not verify: %w", err)
	}
	// (5) The signature must cover THIS operation's action+target.
	gotAction, gotTarget, ok := allowlistAuthBinding(ev)
	if !ok {
		return fmt.Errorf("allowlist: auth event missing action/target binding tags")
	}
	if !strings.EqualFold(gotAction, strings.TrimSpace(action)) {
		return fmt.Errorf("allowlist: auth action does not match request (signed for a different action)")
	}
	if !strings.EqualFold(gotTarget, strings.ToLower(strings.TrimSpace(targetHex))) {
		return fmt.Errorf("allowlist: auth target does not match request (signed for a different key)")
	}
	return nil
}

// allowlistAuthBinding extracts the action/target binding tags from an auth event.
func allowlistAuthBinding(ev *identity.Event) (action, target string, ok bool) {
	var haveA, haveT bool
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case allowlistAuthActionTag:
			action, haveA = t[1], true
		case allowlistAuthTargetTag:
			target, haveT = t[1], true
		}
	}
	return action, target, haveA && haveT
}
