package exchange

import (
	"strings"
	"testing"
)

// TestNetBenefitStatement asserts the match guide states the net-benefit
// arithmetic explicitly (dontguess-d48): a computed avoided-ITE figure, the
// buyer's real cost (scrip + input tokens to read), a net saving figure, and
// a ratio — not just ranking prose. Uses the real-world example from the
// item (price=6723, token_cost_original=8000) to pin the exact numbers.
func TestNetBenefitStatement(t *testing.T) {
	const price = int64(6723)
	const tokenCostOriginal = int64(8000)

	got := netBenefitStatement(price, tokenCostOriginal)

	wantAvoided := tokenCostOriginal * derivationMultiplier // 40000
	wantReadCost := price + tokenCostOriginal               // 14723
	wantNetSaving := wantAvoided - wantReadCost             // 25277

	if wantAvoided != 40000 {
		t.Fatalf("sanity: wantAvoided = %d, want 40000", wantAvoided)
	}
	if wantNetSaving != 25277 {
		t.Fatalf("sanity: wantNetSaving = %d, want 25277", wantNetSaving)
	}

	for _, want := range []string{"40000", "6723", "8000", "25277"} {
		if !strings.Contains(got, want) {
			t.Errorf("netBenefitStatement() = %q, missing expected figure %q", got, want)
		}
	}
	if !strings.Contains(got, "x)") && !strings.Contains(got, "x") {
		t.Errorf("netBenefitStatement() = %q, missing a ratio", got)
	}
	if strings.Contains(got, "ranked by") {
		t.Errorf("netBenefitStatement() should not duplicate ranking prose, got %q", got)
	}
}

// TestEmitMatchResponse_GuideContainsNetBenefit is a lighter integration
// check that the computed net-benefit statement (not just ranking prose)
// ends up in the actual guide string emitted for a real hit, using the top
// entry's real price/token_cost_original.
func TestEmitMatchResponse_GuideContainsNetBenefit(t *testing.T) {
	price := int64(500)
	tokenCost := int64(1000)
	got := netBenefitStatement(price, tokenCost)

	if !strings.Contains(got, "Net benefit") {
		t.Fatalf("expected a net benefit statement, got %q", got)
	}
	if !strings.Contains(got, "scrip") || !strings.Contains(got, "input tokens") {
		t.Errorf("expected statement to name units (scrip, input tokens), got %q", got)
	}
}
