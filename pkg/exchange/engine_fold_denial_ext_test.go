package exchange

// Extended fold-denial counting tests (dontguess-471 fix #3). recordFoldDenial
// (count + alarm, suppressed on Replay) was added ONLY to applySettleBuyerAccept
// and the operator-only settlement guards. This item extends it to EVERY
// fold-level identity/operator guard that silent-drops:
//   - applySettleBuyerReject / applySettleComplete / applySettleSmallContentDispute
//     / applySettlePreviewRequest  → buyer-identity
//   - applyAssignClaim ExclusiveSender                → assign-exclusive-sender
//   - applyAssignComplete ClaimantKey                 → assign-claimant
//   - applyConsume operator guard                     → not-operator
//
// These are internal (package exchange) tests: they seed the unexported State
// maps directly and read the wired DegradationMetrics via DegradationSnapshot.
// They reuse foldTestEngine + settleMsg from fold_denial_metrics_test.go.

import (
	"encoding/json"
	"testing"
	"time"
)

func assignClaimMsg(id, sender, assignID string) *Message {
	return &Message{
		ID:          id,
		Sender:      sender,
		Tags:        []string{TagAssignClaim},
		Antecedents: []string{assignID},
		Payload:     []byte(`{}`),
		Timestamp:   time.Now().UnixNano(),
	}
}

func assignCompleteMsg(id, sender, claimID string) *Message {
	return &Message{
		ID:          id,
		Sender:      sender,
		Tags:        []string{TagAssignComplete},
		Antecedents: []string{claimID},
		Payload:     []byte(`{}`),
		Timestamp:   time.Now().UnixNano(),
	}
}

func consumeSignalMsg(id, sender, entryID string) *Message {
	payload, _ := json.Marshal(map[string]string{"entry_id": entryID})
	return &Message{
		ID:        id,
		Sender:    sender,
		Tags:      []string{TagConsume},
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
	}
}

// TestFoldDenial_BuyerSideForgeries_Count asserts that a buyer-identity forgery
// on each buyer-authored settlement fold guard (reject / complete /
// small-content-dispute / preview-request) increments FoldDenialBuyerIdentity
// (and nothing else).
func TestFoldDenial_BuyerSideForgeries_Count(t *testing.T) {
	const buyerA = "buyerA"
	const attacker = "buyerB"

	cases := []struct {
		name  string
		build func(st *State) *Message
	}{
		{
			name: "buyer-reject",
			build: func(st *State) *Message {
				st.matchToBuyer["m-rej"] = buyerA
				return settleMsg("forge-rej", SettlePhaseStrBuyerReject, attacker, []string{"m-rej"})
			},
		},
		{
			name: "complete",
			build: func(st *State) *Message {
				st.deliverToMatch["d-cmp"] = "m-cmp"
				st.matchToEntry["m-cmp"] = "e-cmp"
				st.matchToBuyer["m-cmp"] = buyerA
				return settleMsg("forge-cmp", SettlePhaseStrComplete, attacker, []string{"d-cmp"})
			},
		},
		{
			name: "small-content-dispute",
			build: func(st *State) *Message {
				st.deliverToMatch["d-scd"] = "m-scd"
				st.matchToBuyer["m-scd"] = buyerA
				return settleMsg("forge-scd", SettlePhaseStrSmallContentDispute, attacker, []string{"d-scd"})
			},
		},
		{
			name: "preview-request",
			build: func(st *State) *Message {
				st.matchToBuyer["m-pvr"] = buyerA
				return settleMsg("forge-pvr", SettlePhaseStrPreviewRequest, attacker, []string{"m-pvr"})
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eng := foldTestEngine(t, "operator-key")
			st := eng.State()
			msg := tc.build(st)

			before := eng.DegradationSnapshot()
			st.Apply(msg)
			after := eng.DegradationSnapshot()

			if got := after.FoldDenialBuyerIdentity - before.FoldDenialBuyerIdentity; got != 1 {
				t.Errorf("FoldDenialBuyerIdentity delta = %d, want 1", got)
			}
			if after.FoldDenialNotOperator != before.FoldDenialNotOperator {
				t.Errorf("FoldDenialNotOperator changed — reason must not cross-bucket")
			}
			if after.FoldDenialAssignExclusive != before.FoldDenialAssignExclusive ||
				after.FoldDenialAssignClaimant != before.FoldDenialAssignClaimant {
				t.Errorf("assign counters changed on a buyer-side forgery — cross-bucket")
			}
		})
	}
}

// TestFoldDenial_AssignExclusive_Counts asserts a claim by a non-designated
// sender on an exclusive assign increments FoldDenialAssignExclusive.
func TestFoldDenial_AssignExclusive_Counts(t *testing.T) {
	eng := foldTestEngine(t, "operator-key")
	st := eng.State()
	st.assignByID["a-excl"] = &AssignRecord{
		Status:          AssignOpen,
		ExclusiveSender: "agentA",
	}

	before := eng.DegradationSnapshot()
	st.Apply(assignClaimMsg("claim-forge", "agentB", "a-excl"))
	after := eng.DegradationSnapshot()

	if got := after.FoldDenialAssignExclusive - before.FoldDenialAssignExclusive; got != 1 {
		t.Errorf("FoldDenialAssignExclusive delta = %d, want 1", got)
	}
	if after.FoldDenialBuyerIdentity != before.FoldDenialBuyerIdentity {
		t.Errorf("FoldDenialBuyerIdentity changed — cross-bucket")
	}
}

// TestFoldDenial_AssignClaimant_Counts asserts a completion by a non-claimant
// increments FoldDenialAssignClaimant.
func TestFoldDenial_AssignClaimant_Counts(t *testing.T) {
	eng := foldTestEngine(t, "operator-key")
	st := eng.State()
	st.assignByID["a-clm"] = &AssignRecord{
		Status:      AssignClaimed,
		ClaimantKey: "agentA",
	}
	st.claimMsgToAssign["c-clm"] = "a-clm"

	before := eng.DegradationSnapshot()
	st.Apply(assignCompleteMsg("complete-forge", "agentB", "c-clm"))
	after := eng.DegradationSnapshot()

	if got := after.FoldDenialAssignClaimant - before.FoldDenialAssignClaimant; got != 1 {
		t.Errorf("FoldDenialAssignClaimant delta = %d, want 1", got)
	}
	if after.FoldDenialBuyerIdentity != before.FoldDenialBuyerIdentity {
		t.Errorf("FoldDenialBuyerIdentity changed — cross-bucket")
	}
}

// TestFoldDenial_ConsumeNonOperator_Counts asserts a non-operator consume signal
// increments FoldDenialNotOperator.
func TestFoldDenial_ConsumeNonOperator_Counts(t *testing.T) {
	eng := foldTestEngine(t, "operator-key")

	before := eng.DegradationSnapshot()
	eng.State().Apply(consumeSignalMsg("consume-forge", "attacker", "entry-x"))
	after := eng.DegradationSnapshot()

	if got := after.FoldDenialNotOperator - before.FoldDenialNotOperator; got != 1 {
		t.Errorf("FoldDenialNotOperator delta = %d, want 1", got)
	}
	if after.FoldDenialBuyerIdentity != before.FoldDenialBuyerIdentity {
		t.Errorf("FoldDenialBuyerIdentity changed — cross-bucket")
	}
}

// TestFoldDenial_ConsumeOperator_NoCount asserts a legitimate operator consume
// passes the guard without counting.
func TestFoldDenial_ConsumeOperator_NoCount(t *testing.T) {
	eng := foldTestEngine(t, "operator-key")

	before := eng.DegradationSnapshot()
	eng.State().Apply(consumeSignalMsg("consume-ok", "operator-key", "entry-y"))
	after := eng.DegradationSnapshot()

	if after != before {
		t.Errorf("operator consume changed counters: before=%+v after=%+v", before, after)
	}
}

// TestFoldDenial_ExtendedGuards_Replay_DoesNotCount asserts the extended guards
// do NOT re-inflate counters on Replay (the log is re-applied on every restart).
// The consume operator-guard fires independent of prior state, so it exercises
// the replay-suppression path without needing a seeded match/assign binding
// (Replay resets all derived maps before folding).
func TestFoldDenial_ExtendedGuards_Replay_DoesNotCount(t *testing.T) {
	eng := foldTestEngine(t, "operator-key")

	before := eng.DegradationSnapshot()
	eng.State().Replay([]Message{
		*consumeSignalMsg("csm-rep", "attacker", "entry-z"),
	})
	after := eng.DegradationSnapshot()

	if after != before {
		t.Errorf("Replay of a forged consume inflated counters: before=%+v after=%+v", before, after)
	}
}
