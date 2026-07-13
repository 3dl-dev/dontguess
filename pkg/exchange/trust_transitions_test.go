package exchange_test

// Tests for trust-level transitions (re-expressed from provenance_transitions_test.go,
// dontguess-hic/3311).
//
// The former tests exercised campfire provenance.Store transitions (attestation
// revocation, freshness expiry). The trust model has no attestation freshness —
// allowlist membership and operator authority do not decay on a clock. The
// meaningful runtime transitions are:
//
//  1. De-allowlisting (allowlisted → anonymous): removing a fleet member from the
//     allowlist drops their level immediately, and a put is then rejected. This
//     is the direct analog of the old "revocation drops level → Check(put) rejected".
//  2. Admission (anonymous → allowlisted): adding a key elevates it.
//  3. Reputation crossing the floor (a behavioral transition with no clock).
//
// The operator key is invariant — never de-allowlistable, always TrustOperator.

import (
	"errors"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// TestTrustTransition_DeAllowlistDropsLevel: removing a member from the allowlist
// immediately lowers their level from allowlisted to anonymous.
func TestTrustTransition_DeAllowlistDropsLevel(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet(keyAllowlisted)
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	if before := c.Level(keyAllowlisted); before != exchange.TrustAllowlisted {
		t.Fatalf("pre-remove level = %v, want TrustAllowlisted", before)
	}

	fleet.Remove(keyAllowlisted)

	if after := c.Level(keyAllowlisted); after != exchange.TrustAnonymous {
		t.Errorf("post-remove level = %v, want TrustAnonymous", after)
	}
}

// TestTrustTransition_DeAllowlistIsImmediate: the level transition takes effect on
// the very next Level() call, with no caching gap — Check re-evaluates membership
// synchronously on every operation.
func TestTrustTransition_DeAllowlistIsImmediate(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet(keyAllowlisted)
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	levelBefore := c.Level(keyAllowlisted)
	fleet.Remove(keyAllowlisted)
	levelAfter := c.Level(keyAllowlisted)

	if levelAfter >= levelBefore {
		t.Errorf("level did not drop after de-allowlist: before=%v after=%v", levelBefore, levelAfter)
	}
}

// TestTrustTransition_AdmissionElevatesLevel: adding a key to the allowlist
// elevates it from anonymous to allowlisted.
func TestTrustTransition_AdmissionElevatesLevel(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet() // empty
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	if before := c.Level("newcomer"); before != exchange.TrustAnonymous {
		t.Fatalf("pre-admit level = %v, want TrustAnonymous", before)
	}
	fleet.Add("newcomer")
	if after := c.Level("newcomer"); after != exchange.TrustAllowlisted {
		t.Errorf("post-admit level = %v, want TrustAllowlisted", after)
	}
}

// TestTrustTransition_OperatorInvariant: the operator key is always TrustOperator,
// regardless of allowlist membership — it cannot be de-allowlisted below operator.
func TestTrustTransition_OperatorInvariant(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet()
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	if got := c.Level(keyOperator); got != exchange.TrustOperator {
		t.Errorf("operator level with empty allowlist = %v, want TrustOperator", got)
	}
	// Even if the operator key were somehow removed from a KeySet, operator
	// authority comes from the operatorKey field, not membership.
	fleet.Add(keyOperator)
	fleet.Remove(keyOperator)
	if got := c.Level(keyOperator); got != exchange.TrustOperator {
		t.Errorf("operator level after KeySet churn = %v, want TrustOperator", got)
	}
}

// TestTrustTransition_CheckRejectsAfterDeAllowlist is the end-to-end integration:
// after de-allowlisting drops a seller below allowlisted, a put is rejected. This
// mirrors the old TestProvenanceTransition_CheckRejectsAfterRevocation.
func TestTrustTransition_CheckRejectsAfterDeAllowlist(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet("key-seller")
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	// Before de-allowlist: put is allowed (allowlisted ≥ required).
	if err := c.Check("key-seller", exchange.OperationPut, ""); err != nil {
		t.Errorf("Check(put) before de-allowlist: got error %v, want nil", err)
	}

	fleet.Remove("key-seller")

	// After de-allowlist: put is rejected (anonymous < allowlisted).
	checkErr := c.Check("key-seller", exchange.OperationPut, "")
	if checkErr == nil {
		t.Error("Check(put) after de-allowlist: got nil, want ErrInsufficientTrust")
		return
	}
	if !errors.Is(checkErr, exchange.ErrInsufficientTrust) {
		t.Errorf("Check(put) after de-allowlist: got %v, want ErrInsufficientTrust", checkErr)
	}
}

// TestTrustTransition_ReputationCrossesFloor: a behavioral transition. As a
// seller's reputation crosses the floor, the put Check outcome flips — with no
// change to allowlist membership.
func TestTrustTransition_ReputationCrossesFloor(t *testing.T) {
	t.Parallel()
	fleet := exchange.NewKeySet("key-seller")
	score := 50 // starts above floor
	c, err := exchange.NewTrustChecker(keyOperator, fleet,
		exchange.WithReputationFloor(func(string) int { return score }, 40))
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	// Above floor → put allowed.
	if err := c.Check("key-seller", exchange.OperationPut, ""); err != nil {
		t.Errorf("Check(put) at reputation 50 (floor 40): got %v, want nil", err)
	}

	// Reputation drops below floor (e.g. accumulated disputes) → put rejected.
	score = 20
	err = c.Check("key-seller", exchange.OperationPut, "")
	if !errors.Is(err, exchange.ErrLowReputation) {
		t.Errorf("Check(put) at reputation 20 (floor 40): got %v, want ErrLowReputation", err)
	}

	// Reputation recovers → put allowed again. Low reputation is not permanent.
	score = 45
	if err := c.Check("key-seller", exchange.OperationPut, ""); err != nil {
		t.Errorf("Check(put) at recovered reputation 45 (floor 40): got %v, want nil", err)
	}
}
