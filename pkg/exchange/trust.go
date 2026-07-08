// Package exchange — trust gating for exchange operations.
//
// This replaces the former campfire pkg/provenance dependency. The trust model
// is deliberately narrow (NOT a web-of-trust — a self-minted root cartel is a
// trusted intermediary reintroduced one layer down; see
// docs/design/convergence-sybil-defense.md §"Family 2 — Attestation Graph"):
//
//	1. NIP-42 allowlist — the set of fleet npubs admitted to the team relay.
//	   Membership secures the pipe: an allowlisted key is a vetted fleet member.
//	2. Operator write authority — match/settle(put-*)/mint/burn are operator-only.
//	   The operator key is the single long-lived npub that signs those events.
//	3. Reputation floor — the EXISTING pkg/exchange behavioral reputation score
//	   (SellerStats.Reputation) gates sell-side operations: a seller who has
//	   burned trust (disputes, small-content refunds) is blocked from putting
//	   more inventory, independent of allowlist membership.
//
// Three trust tiers replace the former 4-level provenance ladder
// (anonymous/claimed/contactable/present). The claimed/contactable distinction
// does not survive an allowlist model — you are either a vetted fleet member or
// you are not:
//
//	anonymous   (0): not allowlisted — buy, inventory-read, price-history-read
//	allowlisted (1): a fleet member on the NIP-42 allowlist — put, assign,
//	                 settle(buyer-accept/reject/complete/dispute)
//	operator    (2): the operator key — match, mint, burn, rate-publish,
//	                 convention promote/supersede, settle(put-accept/reject/deliver)
//
// Operators can override these defaults in the exchange config file
// (trust_levels section) without rebuilding.
//
// References:
//   - docs/convention/core-operations.md §9 (Conformance Checker)
//   - docs/design/nostr-first-rebuild-decision.md §"Provenance/trust gate [TEAM]"
//   - docs/design/convergence-sybil-defense.md (web-of-trust rejected)
package exchange

import (
	"errors"
	"fmt"
	"strings"
)

// TrustLevel is the authority tier a sender holds for exchange operations.
// The integer values are stable (0=anonymous … 2=operator) so that the
// inventory downgrade machinery (AcceptedProvenanceLevel / MarkStaleProvenanceEntries)
// — which stores levels as plain ints — keeps working unchanged.
type TrustLevel int

const (
	// TrustAnonymous is any key not on the allowlist and not the operator.
	TrustAnonymous TrustLevel = 0
	// TrustAllowlisted is a fleet member admitted to the NIP-42 allowlist.
	TrustAllowlisted TrustLevel = 1
	// TrustOperator is the exchange operator key (write authority for
	// match/settle(put-*)/mint/burn).
	TrustOperator TrustLevel = 2
)

// String renders a TrustLevel as its config/name form.
func (l TrustLevel) String() string {
	switch l {
	case TrustAnonymous:
		return "anonymous"
	case TrustAllowlisted:
		return "allowlisted"
	case TrustOperator:
		return "operator"
	default:
		return fmt.Sprintf("TrustLevel(%d)", int(l))
	}
}

// Operation is an exchange operation type.
type Operation string

const (
	// Core operations (put, buy, match, settle).
	OperationPut    Operation = "put"
	OperationBuy    Operation = "buy"
	OperationMatch  Operation = "match"
	OperationSettle Operation = "settle"

	// Extended operations not in core convention v0.1, defined here for completeness.
	OperationAssign              Operation = "assign"
	OperationMint                Operation = "mint"
	OperationBurn                Operation = "burn"
	OperationRatePublish         Operation = "rate-publish"
	OperationConventionPromote   Operation = "convention-promote"
	OperationConventionSupersede Operation = "convention-supersede"

	// Read-only operations (inventory browse, price history).
	OperationInventoryRead    Operation = "inventory-read"
	OperationPriceHistoryRead Operation = "price-history-read"
)

// SettlePhase is a settlement phase within the settle operation.
// The trust requirement depends on both the operation and the settle phase.
type SettlePhase string

const (
	SettlePhaseBuyerAccept SettlePhase = "buyer-accept"
	SettlePhaseBuyerReject SettlePhase = "buyer-reject"
	SettlePhasePutAccept   SettlePhase = "put-accept"
	SettlePhasePutReject   SettlePhase = "put-reject"
	SettlePhaseDeliver     SettlePhase = "deliver"
	SettlePhaseComplete    SettlePhase = "complete"
	SettlePhaseDispute     SettlePhase = "dispute"
)

// defaultOperationLevels is the compiled-in default mapping.
//
// Collapse note vs the former 4-level provenance defaults: put (was claimed=1)
// and assign (was contactable=2) both require allowlisted membership now; all
// former "present" ops require the operator key.
var defaultOperationLevels = map[Operation]TrustLevel{
	OperationBuy:                 TrustAnonymous,
	OperationInventoryRead:       TrustAnonymous,
	OperationPriceHistoryRead:    TrustAnonymous,
	OperationPut:                 TrustAllowlisted,
	OperationAssign:              TrustAllowlisted,
	OperationMint:                TrustOperator,
	OperationBurn:                TrustOperator,
	OperationRatePublish:         TrustOperator,
	OperationConventionPromote:   TrustOperator,
	OperationConventionSupersede: TrustOperator,
	OperationMatch:               TrustOperator,
}

// defaultSettlePhaseLevels is the compiled-in default for settle phases.
// Buyer-side phases are fleet-member operations; put-accept/reject/deliver are
// operator-authored settlement events.
var defaultSettlePhaseLevels = map[SettlePhase]TrustLevel{
	SettlePhaseBuyerAccept: TrustAllowlisted,
	SettlePhaseBuyerReject: TrustAllowlisted,
	SettlePhaseComplete:    TrustAllowlisted,
	SettlePhaseDispute:     TrustAllowlisted,
	SettlePhasePutAccept:   TrustOperator,
	SettlePhasePutReject:   TrustOperator,
	SettlePhaseDeliver:     TrustOperator,
}

// TrustLevels configures the minimum trust level required for each exchange
// operation. Stored in the exchange config JSON as trust_levels.
//
// Keys are operation names (e.g. "put", "buy", "match") or "settle:<phase>"
// for settle phases (e.g. "settle:put-accept", "settle:buyer-reject").
// Values are level names: "anonymous", "allowlisted", "operator".
//
// Only overridden keys need to be present — missing keys use compiled defaults.
type TrustLevels map[string]string

// levelNames maps level name strings to TrustLevel values.
var levelNames = map[string]TrustLevel{
	"anonymous":   TrustAnonymous,
	"allowlisted": TrustAllowlisted,
	"operator":    TrustOperator,
}

// Membership reports whether a sender's hex pubkey is an admitted fleet member.
//
// *identity.Allowlist satisfies this (its Allowed method) for the nostr fleet-npub
// path. KeySet is the mutable, transport-agnostic implementation used by the
// campfire-backed serve path, where keys are ed25519 and do not parse as
// secp256k1 x-only npubs.
type Membership interface {
	Allowed(hexKey string) bool
}

// KeySet is a mutable set of admitted fleet-member hex pubkeys. It is the
// Membership used on the current campfire transport (operator + campfire members)
// and supports runtime de-allowlisting (Remove), which drives the inventory
// re-validation downgrade path.
type KeySet struct {
	members map[string]struct{}
}

// NewKeySet builds a KeySet from the given hex keys. Empty/whitespace entries
// are ignored. Comparison is case-insensitive (keys are lowercased).
func NewKeySet(keys ...string) *KeySet {
	ks := &KeySet{members: make(map[string]struct{}, len(keys))}
	for _, k := range keys {
		ks.Add(k)
	}
	return ks
}

// Add admits a hex key to the set.
func (k *KeySet) Add(hexKey string) {
	hexKey = strings.ToLower(strings.TrimSpace(hexKey))
	if hexKey == "" {
		return
	}
	k.members[hexKey] = struct{}{}
}

// Remove revokes a hex key from the set (runtime de-allowlisting).
func (k *KeySet) Remove(hexKey string) {
	delete(k.members, strings.ToLower(strings.TrimSpace(hexKey)))
}

// Allowed reports whether the hex key is admitted.
func (k *KeySet) Allowed(hexKey string) bool {
	_, ok := k.members[strings.ToLower(strings.TrimSpace(hexKey))]
	return ok
}

// Len returns the number of admitted keys.
func (k *KeySet) Len() int { return len(k.members) }

// ErrInsufficientTrust is returned when a sender's trust level does not meet the
// minimum required for the requested operation.
var ErrInsufficientTrust = errors.New("exchange: insufficient trust level for operation")

// ErrLowReputation is returned when a sender's behavioral reputation is below the
// configured floor for a reputation-gated (sell-side) operation.
var ErrLowReputation = errors.New("exchange: seller reputation below floor for operation")

// TrustChecker validates that a sender is authorized for an exchange operation,
// combining NIP-42 allowlist membership, operator write authority, and a
// behavioral reputation floor on sell-side operations.
type TrustChecker struct {
	operatorKey  string
	members      Membership
	opLevels     map[Operation]TrustLevel
	settleLevels map[SettlePhase]TrustLevel

	// reputation, when non-nil, gates sell-side operations (put): a sender whose
	// score is below minReputation is rejected with ErrLowReputation. nil disables
	// reputation gating entirely.
	reputation    func(key string) int
	minReputation int

	// pendingOverrides holds config overrides staged by WithTrustLevelOverrides
	// until NewTrustChecker validates and applies them. Cleared after construction.
	pendingOverrides TrustLevels
}

// TrustCheckerOption configures a TrustChecker.
type TrustCheckerOption func(*TrustChecker)

// WithTrustLevelOverrides applies operation→level overrides from exchange config.
// Returns an error via the checker constructor if any level name is unknown.
func WithTrustLevelOverrides(overrides TrustLevels) TrustCheckerOption {
	return func(c *TrustChecker) { c.pendingOverrides = overrides }
}

// WithReputationFloor wires a behavioral reputation source and a minimum score.
// Sellers whose reputation is below min are rejected for sell-side operations
// (put). A nil source or min<=math.MinInt is treated as "no reputation gate";
// pass a real source and a floor to enable it.
func WithReputationFloor(source func(key string) int, min int) TrustCheckerOption {
	return func(c *TrustChecker) {
		c.reputation = source
		c.minReputation = min
	}
}

// applyPending validates and applies staged config overrides during construction.
func (c *TrustChecker) applyPending() error {
	if c.pendingOverrides == nil {
		return nil
	}
	for key, levelName := range c.pendingOverrides {
		level, ok := levelNames[levelName]
		if !ok {
			return fmt.Errorf("exchange: unknown trust level %q for key %q", levelName, key)
		}
		if strings.HasPrefix(key, "settle:") {
			c.settleLevels[SettlePhase(strings.TrimPrefix(key, "settle:"))] = level
		} else {
			c.opLevels[Operation(key)] = level
		}
	}
	return nil
}

// reputationGatedOps are the operations subject to the reputation floor.
// Selling (put) is the sole sell-side entry point; buying and settling are not
// reputation-gated (a buyer's reputation should not block their purchase).
var reputationGatedOps = map[Operation]struct{}{
	OperationPut: {},
}

// NewTrustChecker creates a TrustChecker. operatorKey is the operator's pubkey
// (hex or npub form, matched exactly); it always resolves to TrustOperator.
// members is the fleet allowlist (may be nil, e.g. individual tier with no team
// relay — then only the operator is above anonymous). Options apply config
// overrides and the reputation floor.
func NewTrustChecker(operatorKey string, members Membership, opts ...TrustCheckerOption) (*TrustChecker, error) {
	c := &TrustChecker{
		operatorKey:  operatorKey,
		members:      members,
		opLevels:     make(map[Operation]TrustLevel, len(defaultOperationLevels)),
		settleLevels: make(map[SettlePhase]TrustLevel, len(defaultSettlePhaseLevels)),
	}
	for k, v := range defaultOperationLevels {
		c.opLevels[k] = v
	}
	for k, v := range defaultSettlePhaseLevels {
		c.settleLevels[k] = v
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := c.applyPending(); err != nil {
		return nil, err
	}
	c.pendingOverrides = nil
	return c, nil
}

// SetReputationFloor wires (or replaces) the behavioral reputation source and
// floor after construction. This exists because the reputation source (the
// engine State) is created inside NewEngine, after the TrustChecker it receives.
//
// Not safe for concurrent use with Check: call it once, before the engine's poll
// loop starts. A nil source disables reputation gating.
func (c *TrustChecker) SetReputationFloor(source func(key string) int, min int) {
	c.reputation = source
	c.minReputation = min
}

// Level returns the trust tier for a sender key: operator if it is the operator
// key, allowlisted if it is on the allowlist, anonymous otherwise.
func (c *TrustChecker) Level(key string) TrustLevel {
	if c.operatorKey != "" && key == c.operatorKey {
		return TrustOperator
	}
	if c.members != nil && c.members.Allowed(key) {
		return TrustAllowlisted
	}
	return TrustAnonymous
}

// Check returns nil if the sender is authorized for the operation, or a non-nil
// error (ErrInsufficientTrust or ErrLowReputation, wrapping details) if not.
func (c *TrustChecker) Check(senderKey string, op Operation, phase SettlePhase) error {
	required, err := c.RequiredLevel(op, phase)
	if err != nil {
		return err
	}

	actual := c.Level(senderKey)
	if actual < required {
		return fmt.Errorf("%w: operation=%q phase=%q requires %s, sender %q has %s",
			ErrInsufficientTrust, op, phase, required, shortSenderKey(senderKey), actual)
	}

	// Reputation floor on sell-side operations. Applied only when a reputation
	// source is configured. The operator is never blocked by the floor — the
	// operator's own settlement/mint events are trust-anchored, not reputation-scored.
	if c.reputation != nil && actual != TrustOperator {
		if _, gated := reputationGatedOps[op]; gated {
			if score := c.reputation(senderKey); score < c.minReputation {
				return fmt.Errorf("%w: operation=%q sender %q has reputation %d, floor is %d",
					ErrLowReputation, op, shortSenderKey(senderKey), score, c.minReputation)
			}
		}
	}
	return nil
}

// RequiredLevel returns the minimum trust level required for an operation (and
// settle phase). Returns an error if the operation or phase is unknown.
func (c *TrustChecker) RequiredLevel(op Operation, phase SettlePhase) (TrustLevel, error) {
	if op == OperationSettle {
		if phase == "" {
			return 0, fmt.Errorf("exchange: settle operation requires a non-empty phase")
		}
		level, ok := c.settleLevels[phase]
		if !ok {
			return 0, fmt.Errorf("exchange: unknown settle phase %q", phase)
		}
		return level, nil
	}

	level, ok := c.opLevels[op]
	if !ok {
		return 0, fmt.Errorf("exchange: unknown operation %q", op)
	}
	return level, nil
}

// RequiredLevel is a package-level convenience that uses the compiled defaults.
// Prefer the method on TrustChecker for production use.
func RequiredLevel(op Operation, phase SettlePhase) (TrustLevel, error) {
	if op == OperationSettle {
		if phase == "" {
			return 0, fmt.Errorf("exchange: settle operation requires a non-empty phase")
		}
		level, ok := defaultSettlePhaseLevels[phase]
		if !ok {
			return 0, fmt.Errorf("exchange: unknown settle phase %q", phase)
		}
		return level, nil
	}

	level, ok := defaultOperationLevels[op]
	if !ok {
		return 0, fmt.Errorf("exchange: unknown operation %q", op)
	}
	return level, nil
}

// shortSenderKey truncates a key for log/error readability without leaking the
// full key material into every rejection message.
func shortSenderKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "…"
}
