package exchange

import (
	"errors"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// engine_admission.go — OPEN ADMISSION at fleet tier (dontguess-f6d).
//
// THE PROBLEM, measured on the live exchange: 47 distinct agent keys did real
// work, published it, and were dropped `not-allowlisted`. Every one of those keys
// belongs to the operator. The allowlist was refusing the operator's own agents.
//
// dontguess-09a fixed HALF of this with walk-up auto-admission: a new agent in a
// tree that ALREADY holds an admitted identity gets admitted by that parent. But
// the first identity in any tree has no parent, so every new project, machine, or
// fresh checkout still stalls on a manual `dontguess allowlist add` — performed by
// the same operator whose keys these are.
//
// WHY THIS IS THE RIGHT SHAPE, not a weakening. At FLEET tier the allowlist is not
// defending a trust boundary; it is a federation-grade control applied where every
// key is already the operator's own. It costs real work and buys nothing. This is
// the same reasoning and the same tier gate as deliver-on-credit (engine_credit.go):
// serve the agent rather than turn it away, because at fleet tier the agent IS you.
// It is also why credit's vig, default and per-buyer caps were deliberately left
// unbuilt — those become real at FEDERATION, and so does this.
//
// WHAT IT DOES NOT DO — the scope fence, in the order it matters:
//
//	NEVER AT FEDERATION. Gated on !FederationGuardEnabled, the same flag credit
//	uses. Where a peer is not the operator's own agent, admission is a real trust
//	decision and stays manual (dontguess-5a3 territory).
//
//	NEVER GRANTS OPERATOR AUTHORITY. Admission only ever satisfies TrustAllowlisted.
//	An operation requiring TrustOperator — put-accept, put-reject, deliver, preview,
//	assign-post/accept/reject/expire, every settlement the operator authors — is
//	refused exactly as before. Auto-admitting there would let any key on the relay
//	forge settlements and mint scrip, which is a different universe from letting it
//	sell. This is the single most important line in this file.
//
//	NEVER OVERRIDES A REPUTATION FLOOR. ErrLowReputation is a behavioural judgment
//	about a key that HAS transacted; admission is about a key that never has.
//	Re-admitting a seller the exchange down-scored would launder that judgment away.
//
//	NEVER UN-REVOKES. A seller de-allowlisted FOR CAUSE carries a durable tombstone
//	(dontguess-23c). Open admission must not resurrect it — otherwise revocation
//	means nothing, since the next event re-admits. TrustChecker.AdmitMember leaves
//	the revoked set alone and admissionRefusedRevoked below refuses outright.
//
// THE TRADE, stated plainly rather than buried: with this on, any key that can
// reach the relay can sell into the exchange. At fleet tier the relays are the
// operator's own LAN hosts and that is the intended boundary. An operator who
// wants the old behaviour sets OpenAdmission=false.

// admissionOutcome describes what open admission did with a trust denial, for
// logging and for the tests that pin each branch.
type admissionOutcome int

const (
	admissionNotAttempted         admissionOutcome = iota // disabled, or the denial was not an admission problem
	admissionRefusedFederation                            // federation deployment: admission is a real trust decision
	admissionRefusedOperatorLevel                         // the op needs TrustOperator; never grantable on demand
	admissionRefusedReputation                            // ErrLowReputation: a behavioural judgment, not an admission gap
	admissionRefusedRevoked                               // de-allowlisted for cause; only the operator may clear it
	admissionRefusedMalformedKey                          // sender is not a valid pubkey; admitting it would poison durable state
	admissionGranted                                      // admitted; the caller should retry the check
)

func (o admissionOutcome) String() string {
	switch o {
	case admissionRefusedFederation:
		return "refused: federation deployment"
	case admissionRefusedOperatorLevel:
		return "refused: operation requires operator authority"
	case admissionRefusedReputation:
		return "refused: sender is below the reputation floor"
	case admissionRefusedRevoked:
		return "refused: sender was de-allowlisted for cause"
	case admissionRefusedMalformedKey:
		return "refused: sender is not a valid secp256k1 pubkey"
	case admissionGranted:
		return "granted"
	default:
		return "not attempted"
	}
}

// tryOpenAdmit decides whether a trust denial for senderKey should be resolved by
// admitting it, and if so admits it — live via TrustChecker.AdmitMember and
// durably via the AdmitMember hook, so the admission survives a restart instead of
// being re-granted on every event.
//
// Returns admissionGranted only when every fence above is satisfied. The caller
// re-runs its trust check afterwards rather than assuming success, so a failed or
// partial admission degrades to the ordinary rejection path.
func (e *Engine) tryOpenAdmit(senderKey string, op Operation, phase SettlePhase, denial error) admissionOutcome {
	if !e.opts.OpenAdmission || e.opts.TrustChecker == nil || senderKey == "" {
		return admissionNotAttempted
	}
	if e.opts.FederationGuardEnabled {
		return admissionRefusedFederation
	}
	// A reputation denial is not an admission gap — the sender is already a member.
	if errors.Is(denial, ErrLowReputation) {
		return admissionRefusedReputation
	}
	if !errors.Is(denial, ErrInsufficientTrust) {
		return admissionNotAttempted
	}
	// THE OPERATOR-AUTHORITY FENCE. Admission can only ever satisfy
	// TrustAllowlisted; an operator-level operation is refused unconditionally.
	required, rerr := e.opts.TrustChecker.RequiredLevel(op, phase)
	if rerr != nil || required != TrustAllowlisted {
		return admissionRefusedOperatorLevel
	}
	if e.opts.TrustChecker.IsRevoked(senderKey) {
		return admissionRefusedRevoked
	}
	// THE DURABLE-STATE FENCE (dontguess-31b). Admission WRITES the sender key
	// into Config.FleetAllowlist, which the next boot loads through
	// identity.NewAllowlist — a strictly stricter parser than anything on this
	// path used to be. A sender key that is not a valid secp256k1 point (45% of
	// this exchange's historical senders are dead campfire-era Ed25519 keys)
	// therefore admitted fine here and then refused to load at startup, taking
	// the whole operator down with it. Validate to the SAME standard the loader
	// uses, before touching live or durable state.
	//
	// Refusing costs the sender nothing it had before: a key that cannot be a
	// nostr pubkey cannot have signed the event that got here, so it can never
	// legitimately transact anyway. It falls through to the ordinary rejection.
	if _, kerr := identity.NormalizeAllowlistEntry(senderKey); kerr != nil {
		e.degradation.OpenAdmissionMalformedKey.Add(1)
		e.opts.log("engine: open admission: REFUSED %s — not a valid secp256k1 pubkey (%v); almost certainly a legacy pre-nostr identity. Not admitted, not persisted",
			shortKey(senderKey), kerr)
		return admissionRefusedMalformedKey
	}

	e.opts.TrustChecker.AdmitMember(senderKey)
	if e.opts.AdmitMember != nil {
		if err := e.opts.AdmitMember(senderKey); err != nil {
			// Live admission already happened, so this event proceeds; only the
			// durability failed. Loud, because the next restart will silently need
			// to re-admit and the operator should know the roster write is broken.
			e.opts.log("engine: open admission: WARN admitted %s live but FAILED to persist: %v — this admission will not survive a restart",
				shortKey(senderKey), err)
		}
	}
	e.degradation.OpenAdmissionGranted.Add(1)
	e.opts.log("engine: OPEN ADMISSION: admitted %s on demand for op=%s phase=%s (fleet tier — every key is the operator's; set OpenAdmission=false to require manual `dontguess allowlist add`)",
		shortKey(senderKey), op, phase)
	return admissionGranted
}
