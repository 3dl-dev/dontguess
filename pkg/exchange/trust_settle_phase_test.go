package exchange

// dontguess-471 fix #1 (trust phases): preview-request and small-content-dispute
// were OMITTED from defaultSettlePhaseLevels. RequiredLevel therefore returned an
// "unknown settle phase" error, and the dispatch trust gate silently DROPPED
// every such buyer message — breaking preview-before-purchase and the automated
// small-content refund. Both are now fleet-member (allowlisted) phases.

import (
	"testing"
)

func TestTrustGate_BuyerPhases_AllowlistedPasses_AnonymousRejected(t *testing.T) {
	const member = "member-key"
	const operator = "operator-key"

	ks := NewKeySet(member)
	tc, err := NewTrustChecker(operator, ks)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	for _, phase := range []SettlePhase{SettlePhasePreviewRequest, SettlePhaseSmallContentDispute} {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			// The phase must now be a KNOWN, allowlisted-tier phase (pre-fix this
			// errored as an unknown phase → silent drop at the dispatch gate).
			lvl, rlErr := tc.RequiredLevel(OperationSettle, phase)
			if rlErr != nil {
				t.Fatalf("RequiredLevel(%s) errored (phase still missing from trust map?): %v", phase, rlErr)
			}
			if lvl != TrustAllowlisted {
				t.Errorf("RequiredLevel(%s) = %v, want allowlisted", phase, lvl)
			}

			// A fleet member passes the gate.
			if err := tc.Check(member, OperationSettle, phase); err != nil {
				t.Errorf("allowlisted member Check(%s) = %v, want nil (must pass the gate)", phase, err)
			}
			// The operator (higher tier) also passes.
			if err := tc.Check(operator, OperationSettle, phase); err != nil {
				t.Errorf("operator Check(%s) = %v, want nil", phase, err)
			}
			// A non-allowlisted stranger is rejected (still gated, not wide open).
			if err := tc.Check("stranger-key", OperationSettle, phase); err == nil {
				t.Errorf("anonymous Check(%s) = nil, want rejection", phase)
			}
		})
	}
}
