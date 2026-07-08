package exchange

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/campfire-net/dontguess/pkg/scrip"
)

// TestExchangeOp_CanonicalSourceOnly locks the canonical-source op-determination
// contract (docs/design/relay-transport.md §2.4a D2, reworked):
//
//   - a message naming exactly one op constant resolves to that op;
//   - secondary markers that are NOT op constants (buy-miss, consume, synthetic,
//     phase/domain/verdict tags) are ignored and never select the op;
//   - a message naming two or more DISTINCT op constants is ambiguous and
//     resolves to "" (unroutable) — the smuggled-op defense.
//
// The last group is the security-critical case: after a nostr round-trip a
// smuggled ["x","exchange:assign-auction-close"] lands as a sibling string
// alongside the legitimate discriminator, so exchangeOp sees two op constants
// and must fail loud regardless of their order.
func TestExchangeOp_CanonicalSourceOnly(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want string
	}{
		// Single canonical op — the ordinary path.
		{"put", []string{TagPut}, TagPut},
		{"buy", []string{TagBuy}, TagBuy},
		{"match", []string{TagMatch}, TagMatch},
		{"settle", []string{TagSettle, TagPhasePrefix + "put-accept"}, TagSettle},
		{"assign", []string{TagAssign}, TagAssign},
		{"assign_claim", []string{TagAssignClaim}, TagAssignClaim},
		{"assign_auction_close", []string{TagAssignAuctionClose}, TagAssignAuctionClose},

		// Secondary markers are not ops. A buy-miss standing offer is a match
		// message with a buy-miss marker; it must fold as match.
		{"buy_miss_marker_after", []string{TagMatch, TagBuyMiss}, TagMatch},
		{"buy_miss_marker_before", []string{TagBuyMiss, TagMatch}, TagMatch},
		{"buy_miss_marker_synthetic", []string{TagBuyMiss, TagMatch, TagSynthetic}, TagMatch},
		{"consume_is_not_an_op", []string{TagConsume}, ""},
		{"empty", nil, ""},
		{"no_op_tags", []string{TagPhasePrefix + "deliver", "exchange:domain:go"}, ""},

		// Smuggled second op — ambiguous canonical source, fail loud in BOTH
		// wire orders (proves this is not first-match-wins). The smuggled tag is
		// inert: it can never quietly become the executed op.
		{"smuggle_close_after_claim", []string{TagAssignClaim, TagAssignAuctionClose}, ""},
		{"smuggle_close_before_claim", []string{TagAssignAuctionClose, TagAssignClaim}, ""},
		{"smuggle_settle_onto_put", []string{TagPut, TagSettle}, ""},
		{"smuggle_settle_before_put", []string{TagSettle, TagPut}, ""},

		// A duplicated identical op is not ambiguous — same canonical op.
		{"duplicate_same_op", []string{TagMatch, TagBuyMiss, TagMatch}, TagMatch},

		// Scrip ops (dontguess-e15, wave-7 review of dontguess-c22): a lone
		// scrip op tag folds cleanly to itself, and — the security-critical
		// case — a scrip op sharing a message with ANY other distinct
		// canonical op (smuggled or not) is ambiguous and must fail loud.
		// Before this fix scrip ops were excluded from isExchangeOpTag, so a
		// scrip-mint carrying a smuggled assign-auction-close resolved as a
		// single, unambiguous op (assign-auction-close) — the bug this test
		// locks shut.
		{"scrip_mint_alone", []string{scrip.TagScripMint}, scrip.TagScripMint},
		{"scrip_buy_hold_alone", []string{scrip.TagScripBuyHold}, scrip.TagScripBuyHold},
		{"smuggle_close_onto_scrip_mint", []string{scrip.TagScripMint, TagAssignAuctionClose}, ""},
		{"smuggle_close_before_scrip_mint", []string{TagAssignAuctionClose, scrip.TagScripMint}, ""},
		{"smuggle_scrip_mint_onto_put", []string{TagPut, scrip.TagScripMint}, ""},
		{"duplicate_same_scrip_op", []string{scrip.TagScripMint, scrip.TagScripMint}, scrip.TagScripMint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exchangeOp(tc.tags); got != tc.want {
				t.Fatalf("exchangeOp(%v) = %q, want %q", tc.tags, got, tc.want)
			}
		})
	}
}

// TestExchangeOp_SmuggledAuctionCloseIsInertAtFold proves DONE(1) at the FOLD
// level: a message carrying a smuggled exchange:assign-auction-close alongside a
// benign discriminator does NOT finalize a live Vickrey auction, while an
// otherwise-identical canonical auction-close DOES. The operator key is set and
// the operator is the sender for BOTH closes, so the per-handler authorship
// guard is satisfied in both cases — the ONLY thing that differs is the extra
// smuggled op constant, isolating the op-determination guard as the cause.
func TestExchangeOp_SmuggledAuctionCloseIsInertAtFold(t *testing.T) {
	const operator = "operator-pubkey"
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC).UnixNano()

	newAuctionState := func() (*State, string) {
		st := NewState()
		st.OperatorKey = operator
		assignID := "assign-auction-1"
		assignPayload, _ := json.Marshal(map[string]any{
			"entry_id":               "entry-1",
			"task_type":              "compression",
			"reward":                 int64(1000),
			"auction_window_seconds": 10,
		})
		st.Apply(&Message{
			ID:        assignID,
			Sender:    operator,
			Tags:      []string{TagAssign},
			Payload:   assignPayload,
			Timestamp: base,
		})
		// Two worker bids, both timestamped inside the auction window.
		for i, bid := range []struct {
			worker string
			amount int64
		}{{"worker-a", 800}, {"worker-b", 600}} {
			bidPayload, _ := json.Marshal(map[string]any{"bid": bid.amount})
			st.Apply(&Message{
				ID:          "bid-" + bid.worker,
				Sender:      bid.worker,
				Tags:        []string{TagAssignClaim},
				Antecedents: []string{assignID},
				Payload:     bidPayload,
				Timestamp:   base + int64(i+1)*int64(time.Second),
			})
		}
		if rec := st.AssignByIDForTest()[assignID]; rec == nil || rec.Status != AssignOpen || len(rec.AuctionBids) != 2 {
			t.Fatalf("setup: want AssignOpen with 2 bids, got %+v", rec)
		}
		return st, assignID
	}

	closeTS := base + 20*int64(time.Second) // after the 10s auction window

	// (1) Smuggled close: canonical discriminator is a benign assign-claim, with
	// the auction-close op riding as a sibling string (the post-round-trip shape
	// of an ["x","exchange:assign-auction-close"] smuggle). exchangeOp must see
	// two ops and fail loud -> no handler runs -> auction stays OPEN.
	stSmuggle, assignID := newAuctionState()
	stSmuggle.Apply(&Message{
		ID:          "close-smuggled",
		Sender:      operator,
		Tags:        []string{TagAssignClaim, TagAssignAuctionClose},
		Antecedents: []string{assignID},
		Timestamp:   closeTS,
	})
	if rec := stSmuggle.AssignByIDForTest()[assignID]; rec.Status != AssignOpen {
		t.Fatalf("smuggled auction-close changed the executed op: status = %v, want AssignOpen (inert)", rec.Status)
	}

	// (2) Canonical close: the same setup + the same operator sender, but ONLY
	// the auction-close op. It must finalize the auction (winner = lowest bid).
	stCanonical, assignID2 := newAuctionState()
	stCanonical.Apply(&Message{
		ID:          "close-canonical",
		Sender:      operator,
		Tags:        []string{TagAssignAuctionClose},
		Antecedents: []string{assignID2},
		Timestamp:   closeTS,
	})
	rec := stCanonical.AssignByIDForTest()[assignID2]
	if rec.Status != AssignClaimed {
		t.Fatalf("canonical auction-close did not finalize: status = %v, want AssignClaimed", rec.Status)
	}
	if rec.ClaimantKey != "worker-b" {
		t.Fatalf("canonical auction-close winner = %q, want worker-b (lowest bid)", rec.ClaimantKey)
	}
}

// TestExchangeOp_ScripCarrierSmuggledAuctionCloseIsInert is the dontguess-e15
// regression: the wave-7 security review of dontguess-c22 found that
// isExchangeOpTag omitted scrip ops (dontguess:scrip-*) from the canonical op
// set, so a Kind=3411 scrip event carrying a smuggled
// ["x","exchange:assign-auction-close"] tag contributed ZERO isExchangeOpTag
// members from its own scrip op, leaving assign-auction-close as the only
// canonical op found — a clean, unambiguous (and wrong) resolution. The
// multi-op fail-loud in exchangeOp never triggered, so the smuggled
// auction-close op finalized a live Vickrey auction it should never have
// touched. This test proves DONE at the fold level with a scrip-mint carrier
// (mirrors TestExchangeOp_SmuggledAuctionCloseIsInertAtFold's assign-carrier
// case) and additionally proves a legitimate lone scrip-buy-hold event still
// folds and indexes normally, unaffected by counting scrip ops as canonical.
func TestExchangeOp_ScripCarrierSmuggledAuctionCloseIsInert(t *testing.T) {
	const operator = "operator-pubkey"
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC).UnixNano()

	newAuctionState := func() (*State, string) {
		st := NewState()
		st.OperatorKey = operator
		assignID := "assign-auction-scrip-1"
		assignPayload, _ := json.Marshal(map[string]any{
			"entry_id":               "entry-1",
			"task_type":              "compression",
			"reward":                 int64(1000),
			"auction_window_seconds": 10,
		})
		st.Apply(&Message{
			ID:        assignID,
			Sender:    operator,
			Tags:      []string{TagAssign},
			Payload:   assignPayload,
			Timestamp: base,
		})
		for i, bid := range []struct {
			worker string
			amount int64
		}{{"worker-a", 800}, {"worker-b", 600}} {
			bidPayload, _ := json.Marshal(map[string]any{"bid": bid.amount})
			st.Apply(&Message{
				ID:          "bid-" + bid.worker,
				Sender:      bid.worker,
				Tags:        []string{TagAssignClaim},
				Antecedents: []string{assignID},
				Payload:     bidPayload,
				Timestamp:   base + int64(i+1)*int64(time.Second),
			})
		}
		if rec := st.AssignByIDForTest()[assignID]; rec == nil || rec.Status != AssignOpen || len(rec.AuctionBids) != 2 {
			t.Fatalf("setup: want AssignOpen with 2 bids, got %+v", rec)
		}
		return st, assignID
	}

	closeTS := base + 20*int64(time.Second) // after the 10s auction window

	// (1) Scrip-carrier smuggle: a Kind=3411 scrip-mint event (its own op,
	// dontguess:scrip-mint, is now a canonical op) with the auction-close op
	// riding as a sibling string — the folded shape of a scrip-kind event
	// carrying a smuggled ["x","exchange:assign-auction-close"] tag.
	// exchangeOp must see two distinct canonical ops (scrip-mint AND
	// assign-auction-close) and fail loud -> neither the assign-auction-close
	// handler nor any scrip handler runs -> auction stays OPEN.
	stSmuggle, assignID := newAuctionState()
	mintPayload, _ := json.Marshal(map[string]any{"agent": operator, "amount": int64(1000)})
	stSmuggle.Apply(&Message{
		ID:          "close-smuggled-via-scrip",
		Sender:      operator,
		Tags:        []string{scrip.TagScripMint, TagAssignAuctionClose},
		Antecedents: []string{assignID},
		Payload:     mintPayload,
		Timestamp:   closeTS,
	})
	if rec := stSmuggle.AssignByIDForTest()[assignID]; rec.Status != AssignOpen {
		t.Fatalf("scrip-carrier-smuggled auction-close changed the executed op: status = %v, want AssignOpen (inert)", rec.Status)
	}

	// (2) Legit scrip event, only its own canonical op: proves counting scrip
	// ops as canonical does not disturb ordinary scrip-buy-hold folding. The
	// event indexes into matchToBuyHold exactly as before this fix.
	stLegit := NewState()
	stLegit.OperatorKey = operator
	holdPayload, _ := json.Marshal(scrip.BuyHoldPayload{
		Buyer:         "buyer-1",
		Amount:        150,
		Price:         140,
		Fee:           10,
		ReservationID: "reservation-1",
		BuyMsg:        "buy-msg-1",
	})
	stLegit.Apply(&Message{
		ID:        "buy-hold-1",
		Sender:    operator,
		Tags:      []string{scrip.TagScripBuyHold},
		Payload:   holdPayload,
		Timestamp: base,
	})
	if got := stLegit.GetBuyHoldReservation("buy-msg-1"); got != "reservation-1" {
		t.Fatalf("legit scrip-buy-hold did not fold/index: GetBuyHoldReservation(buy-msg-1) = %q, want %q", got, "reservation-1")
	}
}
