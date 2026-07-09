package exchange

// Tests for the State-fold security-drop counters (dontguess-9ed / dontguess-1a2).
//
// Three security-relevant fold guards inside State.Apply previously dropped a
// message with a bare `return` — no counter, no alarm:
//
//   1. applySettlePutAccept / applySettlePutReject / applySettleDeliver reject a
//      non-operator sender for an operator-authored settlement → FoldDenialNotOperator.
//   2. applySettleBuyerAccept rejects a settle(buyer-accept) whose sender is not
//      the buyer bound to the match → FoldDenialBuyerIdentity.
//
// These are internal (package exchange) tests so they can seed the unexported
// matchToBuyer map directly and read the wired DegradationMetrics via the
// exported DegradationSnapshot — no full buy→match→deliver cycle needed.

import (
	"testing"
	"time"
)

// foldTestEngine builds a minimal engine with a known operator key and the
// fold-denial callback wired (NewEngine wires it). No store/clients needed —
// the fold guards run purely inside State.Apply.
func foldTestEngine(t *testing.T, operatorKey string) *Engine {
	t.Helper()
	return NewEngine(EngineOptions{
		OperatorPublicKey: operatorKey,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})
}

func settleMsg(id, phase, sender string, antecedents []string) *Message {
	return &Message{
		ID:          id,
		Sender:      sender,
		Tags:        []string{TagSettle, TagPhasePrefix + phase},
		Antecedents: antecedents,
		Payload:     []byte(`{}`),
		Timestamp:   time.Now().UnixNano(),
	}
}

// TestFoldDenial_NonOperatorSettlement_Counts asserts each operator-only
// settlement fold guard increments FoldDenialNotOperator (and nothing else) when
// a non-operator forges the settlement.
func TestFoldDenial_NonOperatorSettlement_Counts(t *testing.T) {
	const op = "operator-key"
	for _, phase := range []string{SettlePhaseStrPutAccept, SettlePhaseStrPutReject, SettlePhaseStrDeliver} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			eng := foldTestEngine(t, op)
			before := eng.DegradationSnapshot()

			// Sender is NOT the operator → the guard must reject and count.
			eng.State().Apply(settleMsg("forged-"+phase, phase, "attacker-key", []string{"ante-1"}))

			after := eng.DegradationSnapshot()
			if got := after.FoldDenialNotOperator - before.FoldDenialNotOperator; got != 1 {
				t.Errorf("FoldDenialNotOperator delta = %d, want 1", got)
			}
			if after.FoldDenialBuyerIdentity != before.FoldDenialBuyerIdentity {
				t.Errorf("FoldDenialBuyerIdentity changed, want unchanged (reason must not cross-bucket)")
			}
			if after.TrustDenialNotOperator != before.TrustDenialNotOperator {
				t.Errorf("dispatch TrustDenialNotOperator changed — the STATE fold guard must not touch the dispatch bucket")
			}
		})
	}
}

// TestFoldDenial_OperatorSettlement_NoCount asserts a legitimately operator-sent
// settlement passes the guard without incrementing any fold counter.
func TestFoldDenial_OperatorSettlement_NoCount(t *testing.T) {
	const op = "operator-key"
	eng := foldTestEngine(t, op)
	before := eng.DegradationSnapshot()

	// Operator sender clears the guard. (No pendingPuts seeded, so the handler
	// returns after the guard for an unrelated reason — but the guard itself,
	// the only thing under test, does not fire.)
	eng.State().Apply(settleMsg("legit-put-accept", SettlePhaseStrPutAccept, op, []string{"ante-1"}))

	after := eng.DegradationSnapshot()
	if after != before {
		t.Errorf("degradation counters changed on an operator-sent settlement: before=%+v after=%+v", before, after)
	}
}

// TestFoldDenial_BuyerIdentityForgery_Counts asserts a settle(buyer-accept) whose
// sender is not the bound buyer increments FoldDenialBuyerIdentity.
func TestFoldDenial_BuyerIdentityForgery_Counts(t *testing.T) {
	const op = "operator-key"
	eng := foldTestEngine(t, op)
	st := eng.State()

	// Seed a match bound to buyerA. (Direct map write is safe — single-threaded test.)
	st.matchToBuyer["match-1"] = "buyerA"

	before := eng.DegradationSnapshot()

	// buyerB forges a buyer-accept against buyerA's match.
	st.Apply(settleMsg("forged-accept", SettlePhaseStrBuyerAccept, "buyerB", []string{"match-1"}))

	after := eng.DegradationSnapshot()
	if got := after.FoldDenialBuyerIdentity - before.FoldDenialBuyerIdentity; got != 1 {
		t.Errorf("FoldDenialBuyerIdentity delta = %d, want 1", got)
	}
	if after.FoldDenialNotOperator != before.FoldDenialNotOperator {
		t.Errorf("FoldDenialNotOperator changed, want unchanged (reason must not cross-bucket)")
	}
	// The forged accept must not bind the order.
	if _, bound := st.acceptedOrders["match-1"]; bound {
		t.Errorf("forged buyer-accept must not create an accepted order")
	}
}

// TestFoldDenial_UnknownMatch_NoCount asserts a buyer-accept against an UNKNOWN
// match (benign stale antecedent) is dropped WITHOUT counting — only a bound
// match with the wrong sender is a security-relevant identity forgery.
func TestFoldDenial_UnknownMatch_NoCount(t *testing.T) {
	const op = "operator-key"
	eng := foldTestEngine(t, op)
	before := eng.DegradationSnapshot()

	eng.State().Apply(settleMsg("stale-accept", SettlePhaseStrBuyerAccept, "buyerB", []string{"unknown-match"}))

	after := eng.DegradationSnapshot()
	if after != before {
		t.Errorf("degradation counters changed on an unknown-match buyer-accept: before=%+v after=%+v", before, after)
	}
}

// TestFoldDenial_Replay_DoesNotCount asserts a forged settlement sitting on the
// log does NOT re-inflate the counters on Replay — the log is replayed on every
// restart, so only real-time Apply counts.
func TestFoldDenial_Replay_DoesNotCount(t *testing.T) {
	const op = "operator-key"
	eng := foldTestEngine(t, op)
	before := eng.DegradationSnapshot()

	forged := settleMsg("forged-on-log", SettlePhaseStrPutAccept, "attacker-key", []string{"ante-1"})
	eng.State().Replay([]Message{*forged})

	after := eng.DegradationSnapshot()
	if after != before {
		t.Errorf("Replay of a forged settlement incremented counters: before=%+v after=%+v", before, after)
	}
}
