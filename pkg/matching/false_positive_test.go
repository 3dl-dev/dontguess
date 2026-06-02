package matching

// Tests for dontguess-046: false-positive demotion and expiry-candidate flagging.
//
// Covers (4 required proofs):
//   1. An entry with sustained high deliver-without-consume ranks BELOW an
//      equivalent entry without that pattern, through real Rank()/Search().
//   2. A single miss (DeliverCount < FalsePositiveWindowMin) does NOT demote
//      or flag for expiry — the window/sustain requirement is enforced.
//   3. Past the threshold, the entry appears in IsFalsePositiveExpiry (operator
//      facing expiry-candidate report predicate).
//   4. Demotion does not resurrect a below-floor junk entry — floor gates first.
//
// Testing philosophy: all tests exercise the REAL Rank() / computeFalsePositiveDemotion /
// IsFalsePositiveExpiry paths. No mocking of the path under test. Signals are
// seeded via BehavioralSignals fields (same as 860 consume/buyer seeding pattern).
//
// §3.1 (foundation doc): convergence/consume are ~0 in live data today (single
// identity). Tests seed deliver/consume counts directly into BehavioralSignals —
// the same pattern as TestRank_BehavioralBoostRaisesConvergedEntryAboveEquivalent.

import (
	"testing"
	"time"
)

// --- Unit tests for computeFalsePositiveDemotion ---

// TestComputeFalsePositiveDemotion_ZeroDelivers verifies no demotion when
// DeliverCount is zero (the zero-safe invariant).
func TestComputeFalsePositiveDemotion_ZeroDelivers(t *testing.T) {
	t.Parallel()
	d := computeFalsePositiveDemotion(BehavioralSignals{})
	if d != 0 {
		t.Errorf("zero delivers: want 0.0, got %f", d)
	}
}

// TestComputeFalsePositiveDemotion_BelowWindowNoEffect verifies that
// DeliverCount below FalsePositiveWindowMin does NOT demote, even with
// zero consumes (single-miss guard — proof #2).
func TestComputeFalsePositiveDemotion_BelowWindowNoEffect(t *testing.T) {
	t.Parallel()

	// FalsePositiveWindowMin = 3; deliver counts 1 and 2 must NOT demote.
	for _, dc := range []int{1, 2} {
		d := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: dc, ConsumeCount: 0})
		if d != 0 {
			t.Errorf("DeliverCount=%d (< window): want 0.0 demotion, got %f", dc, d)
		}
	}
}

// TestComputeFalsePositiveDemotion_LowRatioNoEffect verifies that a high
// DeliverCount with a proportionally high ConsumeCount does NOT demote.
// A well-consumed entry should not be penalised even if deliver count is large.
func TestComputeFalsePositiveDemotion_LowRatioNoEffect(t *testing.T) {
	t.Parallel()

	// DeliverCount=10, ConsumeCount=8 → ratio=1.25 (below ratioLow=2.0)
	d := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 10, ConsumeCount: 8})
	if d != 0 {
		t.Errorf("low ratio (1.25): want 0.0 demotion, got %f", d)
	}

	// DeliverCount=4, ConsumeCount=3 → ratio=1.33 (below ratioLow=2.0)
	d2 := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 4, ConsumeCount: 3})
	if d2 != 0 {
		t.Errorf("low ratio (1.33): want 0.0 demotion, got %f", d2)
	}
}

// TestComputeFalsePositiveDemotion_SustainedHighRatioDemotes verifies that
// a sustained high deliver-without-consume ratio produces a negative demotion.
func TestComputeFalsePositiveDemotion_SustainedHighRatioDemotes(t *testing.T) {
	t.Parallel()

	// DeliverCount=10, ConsumeCount=0 → ratio=10 (well above threshold=5)
	d := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 10, ConsumeCount: 0})
	if d >= 0 {
		t.Errorf("high ratio: want negative demotion, got %f", d)
	}
	// Must be bounded at MaxBehavioralDemotion floor.
	if d < MaxBehavioralDemotion {
		t.Errorf("demotion %f below MaxBehavioralDemotion floor %f", d, MaxBehavioralDemotion)
	}
}

// TestComputeFalsePositiveDemotion_Monotonic verifies that demotion increases
// (becomes more negative) as ratio increases, up to the cap.
func TestComputeFalsePositiveDemotion_Monotonic(t *testing.T) {
	t.Parallel()

	// ratio=2.5 (just above ratioLow), ratio=4.0, ratio=10.0
	d25 := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 5, ConsumeCount: 2}) // ratio=2.5
	d40 := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 8, ConsumeCount: 2}) // ratio=4.0
	d10 := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 10, ConsumeCount: 1}) // ratio=10

	// All should be <= 0.
	if d25 > 0 || d40 > 0 || d10 > 0 {
		t.Errorf("all demotions should be <= 0: d25=%f d40=%f d10=%f", d25, d40, d10)
	}

	// Demotion should grow (more negative) with higher ratio.
	if d40 >= d25 {
		t.Errorf("demotion at ratio=4.0 (%f) should be more negative than ratio=2.5 (%f)", d40, d25)
	}

	// At ratio >= threshold, should hit the cap.
	if d10 != MaxBehavioralDemotion {
		t.Errorf("demotion at ratio=10 should be MaxBehavioralDemotion=%f, got %f",
			MaxBehavioralDemotion, d10)
	}
}

// TestComputeFalsePositiveDemotion_BoundedAtMax verifies the demotion is
// bounded at MaxBehavioralDemotion for extreme signal counts.
func TestComputeFalsePositiveDemotion_BoundedAtMax(t *testing.T) {
	t.Parallel()

	d := computeFalsePositiveDemotion(BehavioralSignals{DeliverCount: 999999, ConsumeCount: 0})
	if d < MaxBehavioralDemotion {
		t.Errorf("extreme demotion %f is below MaxBehavioralDemotion floor %f", d, MaxBehavioralDemotion)
	}
	if d != MaxBehavioralDemotion {
		t.Errorf("extreme count: want MaxBehavioralDemotion=%f, got %f", MaxBehavioralDemotion, d)
	}
}

// --- Unit tests for IsFalsePositiveExpiry ---

// TestIsFalsePositiveExpiry_BelowWindow verifies entries below FalsePositiveWindowMin
// are NOT flagged (single-miss guard — proof #2).
func TestIsFalsePositiveExpiry_BelowWindow(t *testing.T) {
	t.Parallel()

	for _, dc := range []int{0, 1, 2} {
		if IsFalsePositiveExpiry(BehavioralSignals{DeliverCount: dc, ConsumeCount: 0}) {
			t.Errorf("DeliverCount=%d (< window): should NOT be expiry candidate", dc)
		}
	}
}

// TestIsFalsePositiveExpiry_AtThreshold verifies that an entry at exactly the
// threshold is flagged (proof #3).
func TestIsFalsePositiveExpiry_AtThreshold(t *testing.T) {
	t.Parallel()

	// DeliverCount=FalsePositiveWindowMin=3, ConsumeCount=0 → ratio=3.0 (< threshold=5.0)
	// NOT yet an expiry candidate — ratio is below threshold.
	if IsFalsePositiveExpiry(BehavioralSignals{DeliverCount: 3, ConsumeCount: 0}) {
		t.Error("DeliverCount=3, ConsumeCount=0: ratio=3.0 below threshold — should NOT be flagged")
	}

	// DeliverCount=15, ConsumeCount=2 → ratio=7.5 >= threshold=5.0 AND > window=3
	// Should be flagged.
	if !IsFalsePositiveExpiry(BehavioralSignals{DeliverCount: 15, ConsumeCount: 2}) {
		t.Error("DeliverCount=15, ConsumeCount=2: ratio=7.5 >= threshold — should be flagged")
	}
}

// TestIsFalsePositiveExpiry_ExactThreshold verifies the boundary at exactly
// FalsePositiveRatioThreshold (proof #3).
func TestIsFalsePositiveExpiry_ExactThreshold(t *testing.T) {
	t.Parallel()

	// DeliverCount=5, ConsumeCount=0 → ratio=5.0 (exactly threshold) AND >= window=3
	// Should be flagged (ratio >= threshold is the condition).
	if !IsFalsePositiveExpiry(BehavioralSignals{DeliverCount: 5, ConsumeCount: 0}) {
		t.Error("DeliverCount=5, ConsumeCount=0: ratio=5.0 exactly at threshold — should be flagged")
	}
}

// TestIsFalsePositiveExpiry_WellConsumedNotFlagged verifies that a well-consumed
// entry (low ratio) is NOT flagged even with a high deliver count.
func TestIsFalsePositiveExpiry_WellConsumedNotFlagged(t *testing.T) {
	t.Parallel()

	// DeliverCount=20, ConsumeCount=10 → ratio=2.0 (below threshold)
	if IsFalsePositiveExpiry(BehavioralSignals{DeliverCount: 20, ConsumeCount: 10}) {
		t.Error("DeliverCount=20, ConsumeCount=10: ratio=2.0 below threshold — should NOT be flagged")
	}
}

// --- Integration tests through real Rank() / Index.Search() ---

// TestRank_FalsePositiveDemotionBelowEquivalent is proof #1:
// An entry with sustained high deliver-without-consume ranks BELOW an
// equivalent entry without that pattern, through real Rank().
//
// Both entries have identical descriptions, seller, reputation, freshness,
// and domain. The only difference is BehavioralSignals. Both start above
// the similarity floor (same description, same task).
func TestRank_FalsePositiveDemotionBelowEquivalent(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	desc := "Go HTTP handler unit test generator JSON validation"
	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// "demoted" entry: sustained high deliver-without-consume (10 delivers, 0 consumes → ratio=10)
	demoted := RankInput{
		EntryID:          "demoted",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			DeliverCount: 10,
			ConsumeCount: 0, // never consumed after delivery
		},
	}

	// "plain" entry: identical in every way except zero signals.
	plain := RankInput{
		EntryID:          "plain",
		SellerKey:        "seller-b", // different seller so novelty is equal
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals:          BehavioralSignals{}, // zero signals
	}

	results := Rank("Go HTTP unit test generator JSON validation", []RankInput{demoted, plain}, e, RankOptions{})
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var demotedResult, plainResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "demoted":
			demotedResult = &results[i]
		case "plain":
			plainResult = &results[i]
		}
	}
	if demotedResult == nil {
		t.Fatal("demoted entry not found in results")
	}
	if plainResult == nil {
		t.Fatal("plain entry not found in results")
	}

	// Proof #1: demoted entry must have a negative FalsePositiveDemotion.
	if demotedResult.FalsePositiveDemotion >= 0 {
		t.Errorf("demoted FalsePositiveDemotion = %f, want < 0", demotedResult.FalsePositiveDemotion)
	}
	// Plain entry must have zero demotion.
	if plainResult.FalsePositiveDemotion != 0 {
		t.Errorf("plain FalsePositiveDemotion = %f, want 0", plainResult.FalsePositiveDemotion)
	}
	// Proof #1: demoted entry must rank BELOW the plain entry.
	if demotedResult.CompositeScore >= plainResult.CompositeScore {
		t.Errorf("demoted entry CompositeScore (%f) should be < plain CompositeScore (%f) — demotion not applied",
			demotedResult.CompositeScore, plainResult.CompositeScore)
	}
	if results[0].EntryID != "plain" {
		t.Errorf("plain entry should rank first, got %q (scores: plain=%.4f demoted=%.4f)",
			results[0].EntryID, plainResult.CompositeScore, demotedResult.CompositeScore)
	}
}

// TestRank_SingleMissDoesNotDemote is proof #2:
// A single deliver-without-consume (DeliverCount < FalsePositiveWindowMin)
// does NOT produce a demotion, ensuring we require a SUSTAINED pattern.
func TestRank_SingleMissDoesNotDemote(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	desc := "Go HTTP handler unit test generator JSON validation"
	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// Entry with a single deliver-without-consume (below the window).
	singleMiss := RankInput{
		EntryID:          "single-miss",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			DeliverCount: 1, // single miss — below FalsePositiveWindowMin=3
			ConsumeCount: 0,
		},
	}

	// Also test DeliverCount=2 (still below window).
	twoMiss := singleMiss
	twoMiss.EntryID = "two-miss"
	twoMiss.SellerKey = "seller-b"
	twoMiss.Signals = BehavioralSignals{DeliverCount: 2, ConsumeCount: 0}

	// Plain entry with no signals.
	plain := singleMiss
	plain.EntryID = "plain"
	plain.SellerKey = "seller-c"
	plain.Signals = BehavioralSignals{}

	results := Rank("Go HTTP unit test generator JSON validation",
		[]RankInput{singleMiss, twoMiss, plain}, e, RankOptions{})

	for _, r := range results {
		switch r.EntryID {
		case "single-miss", "two-miss":
			// Proof #2: no demotion for single/double miss below window.
			if r.FalsePositiveDemotion != 0 {
				t.Errorf("%s (DeliverCount below window): FalsePositiveDemotion = %f, want 0",
					r.EntryID, r.FalsePositiveDemotion)
			}
		}
	}
}

// TestRank_DemotionDoesNotResurrectBelowFloor is proof #4:
// A below-floor entry (sim < MinSimilarity) with zero signals is NOT resurrected
// when a high-deliver-count entry is demoted. The floor gates everything.
//
// The test verifies that: (a) the junk entry remains excluded, and (b) the demoted
// entry (above floor) still appears and is demoted — but the junk entry stays out.
func TestRank_DemotionDoesNotResurrectBelowFloor(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// A junk entry with completely unrelated vocabulary.
	// With TF-IDF, cosine similarity is 0 against the "Go HTTP" task.
	// This entry has zero signals — it is purely below-floor junk.
	junk := RankInput{
		EntryID:          "junk-below-floor",
		SellerKey:        "seller-junk",
		Description:      "financial accounting ledger quarterly report spreadsheet excel",
		ContentType:      "data",
		Domains:          []string{"finance"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 90,
		PutTimestamp:     ts,
		Signals:          BehavioralSignals{},
	}

	// A legitimate above-floor entry with a sustained false-positive signal.
	// It will be demoted but should still appear (above-floor, just ranked lower).
	demoted := RankInput{
		EntryID:          "demoted-above-floor",
		SellerKey:        "seller-b",
		Description:      "Go HTTP handler unit test generator JSON validation",
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			DeliverCount: 10,
			ConsumeCount: 0,
		},
	}

	// Index corpus so IDF is computed from both descriptions.
	e.IndexCorpus([]string{junk.Description, demoted.Description})

	task := "Go HTTP unit test generator JSON validation"
	results := Rank(task, []RankInput{junk, demoted}, e, RankOptions{})

	// Proof #4: junk entry must NOT appear in results regardless of demotion.
	for _, r := range results {
		if r.EntryID == "junk-below-floor" {
			t.Errorf("junk-below-floor appeared in results (sim=%f) — floor gate violated by demotion path",
				r.Similarity)
		}
	}

	// The demoted above-floor entry should still appear (it's above the floor — just demoted).
	found := false
	for _, r := range results {
		if r.EntryID == "demoted-above-floor" {
			found = true
			// Verify demotion was applied.
			if r.FalsePositiveDemotion >= 0 {
				t.Errorf("demoted-above-floor FalsePositiveDemotion = %f, want < 0", r.FalsePositiveDemotion)
			}
			break
		}
	}
	if !found && len(results) > 0 {
		t.Errorf("demoted-above-floor not found in results; results: %v", summarizeResults(results))
	}
}

// TestIndex_FalsePositiveDemotion_ThroughSearch verifies proof #1 through the
// full Index.Search → Rank chain (the path used by the exchange engine).
// Signals are injected via SetBehavioralSignals, same as the 860 integration test.
func TestIndex_FalsePositiveDemotion_ThroughSearch(t *testing.T) {
	t.Parallel()

	e := NewTFIDFEmbedder()
	idx := NewIndex(e, RankOptions{})

	ts := time.Now().Add(-1 * time.Hour).UnixNano()
	desc := "Go HTTP handler unit test generator JSON validation"

	demotedInput := RankInput{
		EntryID:          "idx-demoted",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
	}
	plainInput := RankInput{
		EntryID:          "idx-plain",
		SellerKey:        "seller-b",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
	}

	idx.Rebuild([]RankInput{demotedInput, plainInput})

	// Inject behavioral signals for the "demoted" entry only.
	signals := map[string]BehavioralSignals{
		"idx-demoted": {
			DeliverCount: 10,
			ConsumeCount: 0,
		},
	}
	idx.SetBehavioralSignals(signals)

	results := idx.Search("Go HTTP unit test generator JSON validation", 10)
	if len(results) < 2 {
		t.Fatalf("expected >=2 results from index search, got %d", len(results))
	}

	var demotedResult, plainResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "idx-demoted":
			demotedResult = &results[i]
		case "idx-plain":
			plainResult = &results[i]
		}
	}
	if demotedResult == nil {
		t.Fatal("idx-demoted entry not found in results")
	}
	if plainResult == nil {
		t.Fatal("idx-plain entry not found in results")
	}

	// Demoted entry must have negative FalsePositiveDemotion.
	if demotedResult.FalsePositiveDemotion >= 0 {
		t.Errorf("idx-demoted FalsePositiveDemotion = %f, want < 0 (signals not applied)",
			demotedResult.FalsePositiveDemotion)
	}
	// Plain entry must have zero demotion.
	if plainResult.FalsePositiveDemotion != 0 {
		t.Errorf("idx-plain FalsePositiveDemotion = %f, want 0 (no signals set)",
			plainResult.FalsePositiveDemotion)
	}
	// Demoted entry must rank below plain entry (proof #1 through Search()).
	if demotedResult.CompositeScore >= plainResult.CompositeScore {
		t.Errorf("idx-demoted CompositeScore (%f) should be < idx-plain (%f) via Search()",
			demotedResult.CompositeScore, plainResult.CompositeScore)
	}
	if results[0].EntryID != "idx-plain" {
		t.Errorf("expected idx-plain to rank first via signals, got %q (scores: plain=%.4f demoted=%.4f)",
			results[0].EntryID, plainResult.CompositeScore, demotedResult.CompositeScore)
	}
}

// TestRank_DemotionComposesWithPositiveBoost verifies that demotion and positive
// boost compose correctly: an entry with both positive consume signals AND a
// sustained false-positive pattern has both adjustments applied, and still ranks
// based on the net composite score.
func TestRank_DemotionComposesWithPositiveBoost(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	desc := "Go HTTP handler unit test generator JSON validation"
	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// Entry with both positive boost (3 distinct buyers) AND negative demotion (high deliver ratio).
	// Net effect depends on the magnitude: boost ≤ MaxBehavioralBoost=0.10,
	// demotion ≤ |MaxBehavioralDemotion|=0.10.
	mixed := RankInput{
		EntryID:          "mixed",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			ConsumeCount:       5, // positive boost
			DistinctBuyerCount: 3, // convergence boost
			DeliverCount:       25, // high deliver, almost no consume → strong demotion
		},
	}

	// Entry with only positive boost (no false-positive pattern).
	boosted := RankInput{
		EntryID:          "boosted-only",
		SellerKey:        "seller-b",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			ConsumeCount:       5,
			DistinctBuyerCount: 3,
			DeliverCount:       0, // no false-positive pattern
		},
	}

	results := Rank("Go HTTP unit test generator JSON validation", []RankInput{mixed, boosted}, e, RankOptions{})
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var mixedResult, boostedResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "mixed":
			mixedResult = &results[i]
		case "boosted-only":
			boostedResult = &results[i]
		}
	}
	if mixedResult == nil {
		t.Fatal("mixed entry not found")
	}
	if boostedResult == nil {
		t.Fatal("boosted-only entry not found")
	}

	// Both should have positive BehavioralBoost (from consume+convergence signals).
	if mixedResult.BehavioralBoost <= 0 {
		t.Errorf("mixed BehavioralBoost = %f, want > 0", mixedResult.BehavioralBoost)
	}
	if boostedResult.BehavioralBoost <= 0 {
		t.Errorf("boosted-only BehavioralBoost = %f, want > 0", boostedResult.BehavioralBoost)
	}

	// Mixed entry must have a negative demotion.
	if mixedResult.FalsePositiveDemotion >= 0 {
		t.Errorf("mixed FalsePositiveDemotion = %f, want < 0", mixedResult.FalsePositiveDemotion)
	}
	// Boosted-only must have zero demotion (no delivers).
	if boostedResult.FalsePositiveDemotion != 0 {
		t.Errorf("boosted-only FalsePositiveDemotion = %f, want 0", boostedResult.FalsePositiveDemotion)
	}

	// With both boost AND demotion applied to "mixed", its net composite should be
	// below the "boosted-only" entry (same positive boost but demotion applied).
	if mixedResult.CompositeScore >= boostedResult.CompositeScore {
		t.Errorf("mixed CompositeScore (%f) should be < boosted-only (%f) due to demotion",
			mixedResult.CompositeScore, boostedResult.CompositeScore)
	}
}
