package exchange

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// TestNetBenefitStatement is a pure unit test of netBenefitStatement's
// arithmetic (dontguess-d48): a computed avoided-ITE figure, the buyer's real
// cost (scrip + input tokens to read), a net saving figure, and a ratio VALUE
// — not just ranking prose. Uses the real-world example from the item
// (price=6723, token_cost_original=8000) to pin the exact numbers.
//
// contentSize=28712 bytes (arbitrary, chosen so contentSize/approxBytesPerToken
// is a round 7178) is the buyer's read-cost input (dontguess-af3 defect 2):
// tokenCostOriginal must NOT be used for that figure anymore.
func TestNetBenefitStatement(t *testing.T) {
	const price = int64(6723)
	const tokenCostOriginal = int64(8000)
	const contentSize = int64(28712)

	got := netBenefitStatement(price, tokenCostOriginal, contentSize)

	wantAvoided := tokenCostOriginal * derivationMultiplier // 40000
	wantReadTokens := contentSize / approxBytesPerToken     // 7178
	wantReadCost := price + wantReadTokens                  // 13901
	wantNetSaving := wantAvoided - wantReadCost             // 26099
	wantRatio := float64(wantAvoided) / float64(wantReadCost)

	if wantAvoided != 40000 {
		t.Fatalf("sanity: wantAvoided = %d, want 40000", wantAvoided)
	}
	if wantReadTokens != 7178 {
		t.Fatalf("sanity: wantReadTokens = %d, want 7178", wantReadTokens)
	}
	if wantNetSaving != 26099 {
		t.Fatalf("sanity: wantNetSaving = %d, want 26099", wantNetSaving)
	}

	for _, want := range []string{"40000", "6723", "8000", "7178", "26099"} {
		if !strings.Contains(got, want) {
			t.Errorf("netBenefitStatement() = %q, missing expected figure %q", got, want)
		}
	}
	// Assert the RATIO VALUE, not the literal letter "x" (which is present
	// unconditionally in the format string's "output tokens burned x %dx"
	// segment regardless of whether the (%.1fx) ratio survives at all).
	wantRatioStr := fmt.Sprintf("(%.1fx)", wantRatio)
	if !strings.Contains(got, wantRatioStr) {
		t.Errorf("netBenefitStatement() = %q, missing ratio %q", got, wantRatioStr)
	}
	if strings.Contains(got, "ranked by") {
		t.Errorf("netBenefitStatement() should not duplicate ranking prose, got %q", got)
	}
	// dontguess-af3 defect 2 regression: the buyer-facing "input tokens to
	// read" figure must be derived from contentSize, NEVER equal to
	// tokenCostOriginal (a live 1:1 OUTPUT->INPUT collapse — tokenCostOriginal
	// is OUTPUT tokens the seller burned producing the artifact, not what the
	// buyer reads). This fixture deliberately picks contentSize so
	// wantReadTokens (7178) != tokenCostOriginal (8000): a reintroduced
	// `price + tokenCostOriginal` regression would emit "8000" as the read
	// cost instead of "7178", failing the exact-fragment check below.
	wantCostFrag := fmt.Sprintf("this costs %d scrip + ~%d input tokens to read", price, wantReadTokens)
	if !strings.Contains(got, wantCostFrag) {
		t.Errorf("netBenefitStatement() = %q, missing read-cost fragment %q (buyer read cost must come from contentSize, not tokenCostOriginal)", got, wantCostFrag)
	}
	regressionFrag := fmt.Sprintf("this costs %d scrip + ~%d input tokens to read", price, tokenCostOriginal)
	if strings.Contains(got, regressionFrag) {
		t.Errorf("netBenefitStatement() = %q, contains the FORBIDDEN 1:1 collapse fragment %q (tokenCostOriginal used as buyer read cost)", got, regressionFrag)
	}
}

// netBenefitTestEntry builds a minimal InventoryEntry for wiring tests.
func netBenefitTestEntry(entryID, seller string, tokenCost int64) *InventoryEntry {
	plaintext := []byte("net-benefit wiring fixture content for " + entryID)
	return &InventoryEntry{
		EntryID:      entryID,
		PutMsgID:     entryID,
		SellerKey:    seller,
		Description:  "net benefit wiring fixture entry",
		ContentType:  "exchange:content-type:code",
		Domains:      []string{"go"},
		TokenCost:    tokenCost,
		ContentSize:  int64(len(plaintext)),
		PutTimestamp: time.Now().UnixNano(),
		Content:      plaintext,
		ContentHash:  sha256Ref(plaintext),
	}
}

// parsedNetBenefitMatch mirrors the fields of MatchResult this test needs.
type parsedNetBenefitMatch struct {
	EntryID           string `json:"entry_id"`
	Price             int64  `json:"price"`
	TokenCostOriginal int64  `json:"token_cost_original"`
	ContentSize       int64  `json:"content_size"`
}

// emitAndReadGuide drives emitMatchResponse (the real wiring, per the
// climb_fence_grandfather_egress_9d1_test.go harness pattern) and reads the
// emitted match payload back out of the local store.
func emitAndReadGuide(t *testing.T, eng *Engine, ls *dgstore.Store, operatorKey, task string, semanticMatches []rankedCandidate, candidates []*InventoryEntry, synthetic bool) (string, []parsedNetBenefitMatch) {
	t.Helper()

	buyMsg := &Message{
		ID:        newReservationID(),
		Sender:    "buyer-key",
		Tags:      []string{TagBuy},
		Payload:   []byte(`{"task":"` + task + `","budget":1000000,"max_results":5}`),
		Timestamp: time.Now().UnixNano(),
	}

	// emitMatchResponse writes and sends the exchange:match message (which is
	// what this helper reads back) BEFORE its unrelated, pre-existing warm-
	// compression-offer tail (`semanticMatches[0].entry`, engine_buy.go ~L425)
	// unconditionally indexes semanticMatches[0]. That tail is unreachable in
	// production (handleBuy only calls emitMatchResponse when
	// len(semanticMatches) > 0) and is out of scope for dontguess-d48 (it owns
	// the guide/net-benefit text, not the warm-compression dispatch). Recover
	// here so a genuinely-empty semanticMatches slice can still exercise and
	// assert the guide's zero-match polarity without failing on that
	// unrelated tail.
	func() {
		defer func() {
			if r := recover(); r != nil && len(semanticMatches) > 0 {
				panic(r)
			}
		}()
		if err := eng.emitMatchResponse(buyMsg, task, semanticMatches, candidates, synthetic); err != nil {
			t.Fatalf("emitMatchResponse: %v", err)
		}
	}()

	recs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("ls.ReadAll: %v", err)
	}
	var matchPayload []byte
	for i := len(recs) - 1; i >= 0; i-- {
		m := &recs[i]
		if m.Sender != operatorKey {
			continue
		}
		if tagPresent(m.Tags, TagMatch) && !tagPresent(m.Tags, TagBuyMiss) {
			// Only messages that are a response to THIS buy (antecedent match).
			found := false
			for _, a := range m.Antecedents {
				if a == buyMsg.ID {
					found = true
					break
				}
			}
			if found {
				matchPayload = m.Payload
				break
			}
		}
	}
	if matchPayload == nil {
		t.Fatal("no operator exchange:match message emitted for this buy")
	}

	var parsed struct {
		Guide   string                  `json:"guide"`
		Results []parsedNetBenefitMatch `json:"results"`
	}
	if err := json.Unmarshal(matchPayload, &parsed); err != nil {
		t.Fatalf("unmarshal match payload: %v", err)
	}
	return parsed.Guide, parsed.Results
}

// TestEmitMatchResponse_GuideIncludesTopMatchNetBenefit is the real
// integration check (challenges 1/3/4): it drives emitMatchResponse with TWO
// entries carrying DIFFERENT token costs, reads the guide back out of the
// local store, and asserts the net-benefit figures embedded in the guide are
// bound to the TOP match's own price/token_cost_original — not the second
// match's, and not just present-somewhere-in-the-string.
func TestEmitMatchResponse_GuideIncludesTopMatchNetBenefit(t *testing.T) {
	eng, ls, operatorKey := egressTestEngine(t)

	top := netBenefitTestEntry("top-entry", newReservationID(), 8000)
	other := netBenefitTestEntry("other-entry", newReservationID(), 3000)
	injectInventory(eng, top)
	injectInventory(eng, other)

	// top ranked first (higher confidence) -- it must be matchResults[0].
	semanticMatches := []rankedCandidate{
		{entry: top, confidence: 0.95, similarity: 0.95, hasSemanticScore: true},
		{entry: other, confidence: 0.5, similarity: 0.5, hasSemanticScore: true},
	}
	candidates := []*InventoryEntry{top, other}

	guide, results := emitAndReadGuide(t, eng, ls, operatorKey, "net benefit wiring fixture entry", semanticMatches, candidates, false)

	if len(results) < 2 {
		t.Fatalf("expected 2 match results, got %d", len(results))
	}
	if results[0].EntryID != top.EntryID {
		t.Fatalf("expected top-ranked result to be %q, got %q -- statement would describe the wrong entry", top.EntryID, results[0].EntryID)
	}

	topPrice := results[0].Price
	topTokenCost := results[0].TokenCostOriginal
	topContentSize := results[0].ContentSize
	if topTokenCost != top.TokenCost {
		t.Fatalf("results[0].TokenCostOriginal = %d, want %d", topTokenCost, top.TokenCost)
	}
	if topContentSize != top.ContentSize {
		t.Fatalf("results[0].ContentSize = %d, want %d", topContentSize, top.ContentSize)
	}

	avoidedITE := topTokenCost * derivationMultiplier
	topReadTokens := topContentSize / approxBytesPerToken
	readCost := topPrice + topReadTokens
	netSaving := avoidedITE - readCost
	ratio := float64(avoidedITE) / float64(readCost)

	// dontguess-af3 defect 2 regression: the fixture's TokenCost (8000) must
	// differ from its content-size-derived read tokens, so a reintroduced
	// `price + tokenCostOriginal` collapse (using TokenCost as the buyer's
	// read cost) is DISTINGUISHABLE from the correct contentSize-derived
	// figure below, not accidentally identical.
	if topReadTokens == topTokenCost {
		t.Fatalf("test fixture error: topReadTokens (%d) == topTokenCost (%d) -- fixture cannot distinguish the two units, strengthen it (bigger TokenCost or ContentSize)", topReadTokens, topTokenCost)
	}

	// Bind each figure to its role via the exact surrounding format, not a
	// bare substring -- so a swap of avoidedITE<->netSaving, or a read from
	// the wrong match, cannot pass by accident.
	wantAvoidedFrag := fmt.Sprintf("avoid ~%d ITE of derivation (%d output tokens burned x %dx)", avoidedITE, topTokenCost, derivationMultiplier)
	wantCostFrag := fmt.Sprintf("this costs %d scrip + ~%d input tokens to read", topPrice, topReadTokens)
	wantSavingFrag := fmt.Sprintf("net saving ~%d ITE (%.1fx)", netSaving, ratio)

	if !strings.Contains(guide, wantAvoidedFrag) {
		t.Errorf("guide = %q, missing top-match avoided-ITE fragment %q", guide, wantAvoidedFrag)
	}
	if !strings.Contains(guide, wantCostFrag) {
		t.Errorf("guide = %q, missing top-match cost fragment %q", guide, wantCostFrag)
	}
	if !strings.Contains(guide, wantSavingFrag) {
		t.Errorf("guide = %q, missing top-match saving fragment %q", guide, wantSavingFrag)
	}

	// dontguess-af3 defect 2: the buyer-facing string itself must not carry a
	// 1:1 OUTPUT->INPUT collapse. This drives the REAL emitMatchResponse wiring
	// (not just netBenefitStatement in isolation, per TestNetBenefitStatement
	// above) and asserts the collapse fragment is ABSENT from the actual
	// emitted guide -- catching a regression anywhere between MatchResult
	// construction and the guide string, not just in netBenefitStatement's
	// own arithmetic.
	regressionFrag := fmt.Sprintf("this costs %d scrip + ~%d input tokens to read", topPrice, topTokenCost)
	if strings.Contains(guide, regressionFrag) {
		t.Errorf("guide = %q, contains the FORBIDDEN 1:1 collapse fragment %q (TokenCostOriginal used as buyer read cost instead of ContentSize)", guide, regressionFrag)
	}

	// Regression guard against reading matchResults[len-1] (the "other"
	// entry) instead of the top match: other's avoided-ITE figure must be
	// absent, since it differs numerically from top's.
	otherAvoidedITE := other.TokenCost * derivationMultiplier
	if otherAvoidedITE != avoidedITE {
		otherFrag := fmt.Sprintf("%d output tokens burned", otherAvoidedITE)
		if strings.Contains(guide, otherFrag) {
			t.Errorf("guide = %q, contains the SECOND match's figures (%d) -- statement is bound to the wrong entry", guide, otherAvoidedITE)
		}
	}
}

// TestEmitMatchResponse_ZeroMatchesOmitsNetBenefit covers the untested
// zero-match polarity of `if len(matchResults) > 0` in emitMatchResponse: the
// emitted guide must OMIT the net-benefit statement entirely (there is no top
// match to describe).
//
// This test does NOT assert a no-panic guarantee. emitAndReadGuide deliberately
// recovers when semanticMatches is empty, because emitMatchResponse's
// pre-existing warm-compression tail unconditionally indexes semanticMatches[0].
// That tail is unreachable in production — handleBuy (engine_buy.go:77) returns
// via handleBuyMiss on zero matches, and its line-82 call is the only call site
// — and hardening it is out of scope for dontguess-d48, which owns the guide
// text. The recover fires strictly AFTER the match record is written, so the
// OMIT assertion below is load-bearing, not vacuous: verified by mutation —
// emitting any "Net benefit" text on the zero-match path fails this test.
func TestEmitMatchResponse_ZeroMatchesOmitsNetBenefit(t *testing.T) {
	eng, ls, operatorKey := egressTestEngine(t)

	guide, results := emitAndReadGuide(t, eng, ls, operatorKey, "task with no inventory matches at all", nil, nil, false)

	if len(results) != 0 {
		t.Fatalf("expected 0 match results, got %d", len(results))
	}
	if strings.Contains(guide, "Net benefit") {
		t.Errorf("guide = %q, should OMIT the net-benefit statement when there are zero matches", guide)
	}
}
