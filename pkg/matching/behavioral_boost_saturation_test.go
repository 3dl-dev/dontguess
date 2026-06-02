package matching

// TestComputeBehavioralBoost_ConsumeSaturationBoundary verifies the saturation
// boundary of the consume-signal contribution in computeBehavioralBoost.
//
// From the function definition:
//
//	consumeNorm = log1p(ConsumeCount) / log1p(10.0)
//	if consumeNorm > 1.0 { consumeNorm = 1.0 }
//	consumeContrib = consumeNorm * (MaxBehavioralBoost / 2.0)
//
// The saturation point is ConsumeCount=10 (log1p(10)/log1p(10) = 1.0).
// ConsumeCount=11 and ConsumeCount=10000 must produce the SAME consume
// contribution as ConsumeCount=10: exactly MaxBehavioralBoost/2.
//
// This test exercises computeBehavioralBoost directly (the real function,
// no mocks) with ConsumeCount 10, 11, and 10000 and zero DistinctBuyerCount
// so the convergence contribution is 0 and the total equals the consume
// contribution alone.

import (
	"math"
	"testing"
)

// TestComputeBehavioralBoost_ConsumeSaturationAt10(t) verifies:
//  1. ConsumeCount=10 produces exactly MaxBehavioralBoost/2 (consume half-weight cap).
//  2. ConsumeCount=11 produces the same value as ConsumeCount=10 (saturated).
//  3. ConsumeCount=10000 produces the same value as ConsumeCount=10 (saturated).
//  4. All three are equal to each other.
func TestComputeBehavioralBoost_ConsumeSaturationAt10(t *testing.T) {
	t.Parallel()

	// ConsumeCount=10 is the exact saturation point:
	//   log1p(10) / log1p(10) = 1.0 → consumeContrib = MaxBehavioralBoost / 2
	boost10 := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10})
	boost11 := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 11})
	boost10000 := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10000})

	halfMax := MaxBehavioralBoost / 2.0
	const eps = 1e-10

	// Assert ConsumeCount=10 equals exactly MaxBehavioralBoost/2.
	if math.Abs(boost10-halfMax) > eps {
		t.Errorf("ConsumeCount=10 boost = %.15f, want MaxBehavioralBoost/2 = %.15f (should be exact saturation point)",
			boost10, halfMax)
	}

	// Assert ConsumeCount=11 == ConsumeCount=10 (saturated, no increase beyond 10).
	if math.Abs(boost11-boost10) > eps {
		t.Errorf("ConsumeCount=11 boost = %.15f, want same as ConsumeCount=10 boost = %.15f (must be saturated)",
			boost11, boost10)
	}

	// Assert ConsumeCount=10000 == ConsumeCount=10 (saturated at any very large count).
	if math.Abs(boost10000-boost10) > eps {
		t.Errorf("ConsumeCount=10000 boost = %.15f, want same as ConsumeCount=10 boost = %.15f (must be saturated)",
			boost10000, boost10)
	}

	// All three equal each other (transitivity check).
	if math.Abs(boost11-boost10000) > eps {
		t.Errorf("ConsumeCount=11 (%f) != ConsumeCount=10000 (%f): both must saturate at the same value",
			boost11, boost10000)
	}

	// And all three equal exactly MaxBehavioralBoost/2.
	for _, tc := range []struct {
		name  string
		boost float64
	}{
		{"ConsumeCount=10", boost10},
		{"ConsumeCount=11", boost11},
		{"ConsumeCount=10000", boost10000},
	} {
		if math.Abs(tc.boost-halfMax) > eps {
			t.Errorf("%s boost = %.15f, want exactly MaxBehavioralBoost/2 = %.15f (consume half-weight cap)",
				tc.name, tc.boost, halfMax)
		}
	}

	t.Logf("PASS: consume saturation: boost10=%.10f boost11=%.10f boost10000=%.10f halfMax=%.10f",
		boost10, boost11, boost10000, halfMax)
}

// TestComputeBehavioralBoost_ConsumeSaturationIsHalfWeight verifies that the
// saturated consume contribution (ConsumeCount >= 10) equals exactly half the
// total MaxBehavioralBoost ceiling, leaving the other half for convergence.
//
// Design invariant: consume and convergence each contribute up to MaxBehavioralBoost/2.
// This test pins the half-weight design so a refactor cannot accidentally change
// the split ratio.
func TestComputeBehavioralBoost_ConsumeSaturationIsHalfWeight(t *testing.T) {
	t.Parallel()

	halfMax := MaxBehavioralBoost / 2.0

	// Saturated consume alone (no convergence buyers).
	saturatedConsumeOnly := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10})

	if saturatedConsumeOnly != halfMax {
		t.Errorf("saturated consume-only boost = %f, want exactly MaxBehavioralBoost/2 = %f",
			saturatedConsumeOnly, halfMax)
	}

	// Saturated convergence alone (no consumes).
	// 3 distinct buyers = full convergence threshold = MaxBehavioralBoost/2.
	saturatedConvergenceOnly := computeBehavioralBoost(BehavioralSignals{DistinctBuyerCount: 3})
	if saturatedConvergenceOnly != halfMax {
		t.Errorf("saturated convergence-only boost = %f, want exactly MaxBehavioralBoost/2 = %f",
			saturatedConvergenceOnly, halfMax)
	}

	// Both saturated: total = MaxBehavioralBoost (capped).
	bothSaturated := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10, DistinctBuyerCount: 3})
	if bothSaturated != MaxBehavioralBoost {
		t.Errorf("both-saturated boost = %f, want exactly MaxBehavioralBoost = %f",
			bothSaturated, MaxBehavioralBoost)
	}

	t.Logf("PASS: half-weight split: consumeHalf=%f convergenceHalf=%f both=%f maxBoost=%f",
		saturatedConsumeOnly, saturatedConvergenceOnly, bothSaturated, MaxBehavioralBoost)
}
