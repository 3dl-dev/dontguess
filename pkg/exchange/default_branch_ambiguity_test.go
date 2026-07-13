package exchange

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// TestDefaultBranchRespectsOpAmbiguity is the dontguess-5be regression: the
// residual half of the parser-differential that c22/e15/13c closed only for the
// switch-dispatched path. applyLocked's default branch (state_core.go) formerly
// RAW-SCANNED msg.Tags for scrip.TagScripBuyHold / TagConsume independent of
// exchangeOp's ambiguity result, so an ambiguous message — one where exchangeOp
// correctly returned "" to block the switch-dispatched handler (e.g. a smuggled
// assign-auction-close) — STILL fired the default-branch handler's side effect
// (index write / consume-count increment). The fix dispatches on the RESOLVED
// op: if exchangeOp returned "" the default branch fires nothing, consistent
// with the switch path; a legit lone scrip-buy-hold / consume still folds.
//
// See docs/design/relay-transport.md §2.4a D2.
func TestDefaultBranchRespectsOpAmbiguity(t *testing.T) {
	const operator = "operator-pubkey"
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC).UnixNano()

	// (1) Ambiguous [scrip-buy-hold, assign-auction-close]: exchangeOp sees two
	// distinct canonical ops and returns "" -> the default branch must NOT fire
	// applyScripBuyHold. Verify via GetBuyHoldReservation: no reservation is
	// indexed off the smuggled buy-hold tag.
	t.Run("ambiguous_scrip_buy_hold_does_not_index", func(t *testing.T) {
		st := NewState()
		st.OperatorKey = operator
		holdPayload, _ := json.Marshal(scrip.BuyHoldPayload{
			Buyer:         "buyer-1",
			Amount:        150,
			Price:         140,
			Fee:           10,
			ReservationID: "reservation-smuggled",
			BuyMsg:        "buy-msg-smuggled",
		})
		st.Apply(&Message{
			ID:        "ambiguous-buy-hold",
			Sender:    operator,
			Tags:      []string{scrip.TagScripBuyHold, TagAssignAuctionClose},
			Payload:   holdPayload,
			Timestamp: base,
		})
		if got := st.GetBuyHoldReservation("buy-msg-smuggled"); got != "" {
			t.Fatalf("ambiguous scrip-buy-hold fired applyScripBuyHold via default branch: GetBuyHoldReservation(buy-msg-smuggled) = %q, want %q (inert)", got, "")
		}
	})

	// (2) Ambiguous [consume, assign-auction-close]: exchangeOp returns "" -> the
	// default branch must NOT fire applyConsume. Verify via the behavioral-signal
	// consume count: no consume is recorded for the smuggled entry.
	t.Run("ambiguous_consume_does_not_count", func(t *testing.T) {
		st := NewState()
		st.OperatorKey = operator
		consumePayload, _ := json.Marshal(map[string]any{"entry_id": "entry-smuggled"})
		st.Apply(&Message{
			ID:        "ambiguous-consume",
			Sender:    operator,
			Tags:      []string{TagConsume, TagAssignAuctionClose},
			Payload:   consumePayload,
			Timestamp: base,
		})
		if sig := st.AllEntryBehavioralSignals()["entry-smuggled"]; sig.ConsumeCount != 0 {
			t.Fatalf("ambiguous consume fired applyConsume via default branch: ConsumeCount = %d, want 0 (inert)", sig.ConsumeCount)
		}
	})

	// (3) Legit lone scrip-buy-hold still folds: exchangeOp resolves the single
	// canonical op and the default branch indexes the reservation as before.
	t.Run("legit_scrip_buy_hold_still_folds", func(t *testing.T) {
		st := NewState()
		st.OperatorKey = operator
		holdPayload, _ := json.Marshal(scrip.BuyHoldPayload{
			Buyer:         "buyer-1",
			Amount:        150,
			Price:         140,
			Fee:           10,
			ReservationID: "reservation-legit",
			BuyMsg:        "buy-msg-legit",
		})
		st.Apply(&Message{
			ID:        "legit-buy-hold",
			Sender:    operator,
			Tags:      []string{scrip.TagScripBuyHold},
			Payload:   holdPayload,
			Timestamp: base,
		})
		if got := st.GetBuyHoldReservation("buy-msg-legit"); got != "reservation-legit" {
			t.Fatalf("legit lone scrip-buy-hold did not fold/index: GetBuyHoldReservation(buy-msg-legit) = %q, want %q", got, "reservation-legit")
		}
	})

	// (4) Legit lone consume still folds: the single canonical op resolves and
	// the default branch increments the per-entry consume count as before.
	t.Run("legit_consume_still_folds", func(t *testing.T) {
		st := NewState()
		st.OperatorKey = operator
		consumePayload, _ := json.Marshal(map[string]any{"entry_id": "entry-legit"})
		st.Apply(&Message{
			ID:        "legit-consume",
			Sender:    operator,
			Tags:      []string{TagConsume},
			Payload:   consumePayload,
			Timestamp: base,
		})
		if sig := st.AllEntryBehavioralSignals()["entry-legit"]; sig.ConsumeCount != 1 {
			t.Fatalf("legit lone consume did not fold/index: ConsumeCount = %d, want 1", sig.ConsumeCount)
		}
	})
}
