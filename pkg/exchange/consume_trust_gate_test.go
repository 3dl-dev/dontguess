package exchange_test

// Test for the exchange:consume dispatch trust-gate mapping (dontguess-9ed item g).
//
// Before this item tagToTrustOp returned "" for TagConsume, so a forged
// non-operator consume signal bypassed the dispatch trust gate entirely — it
// was never gated and never counted, letting any sender feed the per-entry
// behavioral booster (entryConsumeCount). tagToTrustOp now routes TagConsume
// through the operator-only OperationConsume, so a forged consume is rejected +
// counted as a not-operator denial, while an operator-sent consume passes.

import (
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// TestConsume_ForgedNonOperator_CountsNotOperator: an allowlisted (non-operator)
// sender's consume signal is trust-rejected at dispatch and increments exactly
// TrustDenialNotOperator.
func TestConsume_ForgedNonOperator_CountsNotOperator(t *testing.T) {
	t.Parallel()
	h, eng := newEngineWithTrust(t, dispatchTrustChecker(t))

	before := eng.DegradationSnapshot()

	rec := injectMsg(t, h, exchange.TagConsume, keyAllowlisted)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Errorf("dispatch returned error, want nil (silent-to-poll-loop reject): %v", err)
	}

	after := eng.DegradationSnapshot()
	if got := after.TrustDenialNotOperator - before.TrustDenialNotOperator; got != 1 {
		t.Errorf("TrustDenialNotOperator delta = %d, want 1 (forged consume must be gated as not-operator)", got)
	}
	if after.TrustDenialNotAllowlisted != before.TrustDenialNotAllowlisted {
		t.Errorf("TrustDenialNotAllowlisted changed, want unchanged (allowlisted sender must not bucket as not-allowlisted)")
	}
}

// TestConsume_Operator_Passes: an operator-sent consume clears the trust gate —
// no degradation counter moves.
func TestConsume_Operator_Passes(t *testing.T) {
	t.Parallel()
	h, eng := newEngineWithTrust(t, dispatchTrustChecker(t))

	before := eng.DegradationSnapshot()

	rec := injectMsg(t, h, exchange.TagConsume, keyOperator)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Errorf("dispatch returned error for operator consume, want nil: %v", err)
	}

	after := eng.DegradationSnapshot()
	if after != before {
		t.Errorf("degradation counters changed on an operator-sent consume: before=%+v after=%+v", before, after)
	}
}
