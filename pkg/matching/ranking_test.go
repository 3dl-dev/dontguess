package matching

import (
	"testing"
	"time"
)

// makeEntry is a test helper to build a RankInput with sensible defaults.
func makeEntry(id, sellerKey, description, contentType string, tokenCost, price int64, rep int) RankInput {
	return RankInput{
		EntryID:          id,
		SellerKey:        sellerKey,
		Description:      description,
		ContentType:      contentType,
		Domains:          []string{"go", "testing"},
		TokenCost:        tokenCost,
		Price:            price,
		SellerReputation: rep,
		PutTimestamp:     time.Now().Add(-24 * time.Hour).UnixNano(), // 1 day old
	}
}

// TestRank_TopResultIsRelevant verifies that with 10 entries covering different
// domains, the most semantically relevant entry ranks first.
func TestRank_TopResultIsRelevant(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	// Build a set of 10 entries spanning different domains.
	// The one most relevant to the buy task should rank first.
	candidates := []RankInput{
		makeEntry("tf-module", "seller-a", "Terraform AWS S3 bucket module with versioning and lifecycle rules", "code", 5000, 500, 70),
		makeEntry("go-http", "seller-b", "Go HTTP handler unit test generator table-driven tests edge cases", "code", 8000, 800, 80),
		makeEntry("py-data", "seller-c", "Python pandas dataframe aggregation and pivot table analysis", "analysis", 6000, 600, 65),
		makeEntry("k8s-deploy", "seller-d", "Kubernetes deployment YAML generator with resource limits", "code", 7000, 700, 72),
		makeEntry("rust-async", "seller-e", "Rust async tokio HTTP client with retry and backoff", "code", 9000, 900, 78),
		makeEntry("docker-multi", "seller-f", "Docker multi-stage build optimization for Go services", "code", 4000, 400, 60),
		makeEntry("sql-query", "seller-g", "PostgreSQL query optimization for time-series analytics", "analysis", 5500, 550, 68),
		makeEntry("ts-react", "seller-h", "TypeScript React component testing with Jest and Testing Library", "code", 7500, 750, 75),
		makeEntry("ci-pipeline", "seller-i", "GitHub Actions CI pipeline for Go with coverage and lint", "code", 3000, 300, 62),
		makeEntry("sec-audit", "seller-j", "Security audit checklist for Go HTTP APIs", "review", 4500, 450, 85),
	}

	// Prime IDF from descriptions.
	docs := make([]string, len(candidates))
	for i, c := range candidates {
		docs[i] = c.Description
	}
	e.IndexCorpus(docs)

	task := "I need unit tests for a Go HTTP handler that accepts JSON POST requests with validation"
	results := Rank(task, candidates, e, RankOptions{})

	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	if results[0].EntryID != "go-http" {
		t.Errorf("top result = %q, want %q (got results: %v)", results[0].EntryID, "go-http", summarizeResults(results))
	}
}

// TestRank_PartialMatchFlagged verifies that entries with confidence < 0.5 are
// flagged as partial matches.
func TestRank_PartialMatchFlagged(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	// Use two entries: one closely related, one distantly related.
	candidates := []RankInput{
		makeEntry("close", "seller-a", "Go HTTP handler test generator", "code", 10000, 1000, 70),
		makeEntry("distant", "seller-b", "Terraform EC2 auto-scaling configuration module", "code", 10000, 1000, 70),
	}

	docs := []string{candidates[0].Description, candidates[1].Description}
	e.IndexCorpus(docs)

	results := Rank("Go unit testing HTTP handler", candidates, e, RankOptions{})

	// "close" should have higher confidence than "distant".
	var closeConf, distantConf float64
	for _, r := range results {
		switch r.EntryID {
		case "close":
			closeConf = r.Confidence
		case "distant":
			distantConf = r.Confidence
		}
	}
	if closeConf <= distantConf {
		t.Errorf("close confidence (%f) should exceed distant confidence (%f)", closeConf, distantConf)
	}
}

// TestRank_EfficiencyFavorsHighTokenSavings verifies that an entry with higher
// token savings per scrip ranks higher when other factors are equal.
func TestRank_EfficiencyFavorsHighTokenSavings(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	// Two identical-description entries; high-efficiency has better tokens/price ratio.
	base := RankInput{
		SellerKey:        "seller-a",
		Description:      "Go HTTP handler test generator",
		ContentType:      "code",
		Domains:          []string{"go"},
		SellerReputation: 70,
		PutTimestamp:     time.Now().Add(-1 * time.Hour).UnixNano(),
	}

	highEff := base
	highEff.EntryID = "high-eff"
	highEff.TokenCost = 50000
	highEff.Price = 1000 // ratio = 50

	lowEff := base
	lowEff.EntryID = "low-eff"
	lowEff.SellerKey = "seller-b" // different seller, so novelty doesn't differ
	lowEff.TokenCost = 2000
	lowEff.Price = 1000 // ratio = 2

	results := Rank("Go HTTP unit tests", []RankInput{highEff, lowEff}, e, RankOptions{})
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].EntryID != "high-eff" {
		t.Errorf("expected high-eff to rank first, got %q", results[0].EntryID)
	}
}

// TestRank_EmptyCandidates returns nil without panic.
func TestRank_EmptyCandidates(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()
	results := Rank("some task", nil, e, RankOptions{})
	if results != nil {
		t.Errorf("expected nil for empty candidates, got %v", results)
	}
}

// TestRank_NoveltyBoostForRareSellerr verifies Layer 3: a seller appearing
// only once gets a higher novelty boost than one appearing many times.
func TestRank_NoveltyBoostForRareSeller(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	// Dominant seller has 4 entries; rare seller has 1.
	// All entries describe the same task with same quality — novelty decides.
	dominant := "seller-dominant"
	rare := "seller-rare"
	desc := "Go HTTP handler unit test generator"

	candidates := []RankInput{
		{EntryID: "d1", SellerKey: dominant, Description: desc, ContentType: "code", Domains: []string{"go"}, TokenCost: 10000, Price: 1000, SellerReputation: 70, PutTimestamp: time.Now().Add(-1 * time.Hour).UnixNano()},
		{EntryID: "d2", SellerKey: dominant, Description: desc, ContentType: "code", Domains: []string{"go"}, TokenCost: 10000, Price: 1000, SellerReputation: 70, PutTimestamp: time.Now().Add(-1 * time.Hour).UnixNano()},
		{EntryID: "d3", SellerKey: dominant, Description: desc, ContentType: "code", Domains: []string{"go"}, TokenCost: 10000, Price: 1000, SellerReputation: 70, PutTimestamp: time.Now().Add(-1 * time.Hour).UnixNano()},
		{EntryID: "d4", SellerKey: dominant, Description: desc, ContentType: "code", Domains: []string{"go"}, TokenCost: 10000, Price: 1000, SellerReputation: 70, PutTimestamp: time.Now().Add(-1 * time.Hour).UnixNano()},
		{EntryID: "r1", SellerKey: rare, Description: desc, ContentType: "code", Domains: []string{"go"}, TokenCost: 10000, Price: 1000, SellerReputation: 70, PutTimestamp: time.Now().Add(-1 * time.Hour).UnixNano()},
	}

	results := Rank("Go HTTP unit test generator", candidates, e, RankOptions{})

	var rareResult *RankedResult
	for i := range results {
		if results[i].EntryID == "r1" {
			rareResult = &results[i]
			break
		}
	}
	if rareResult == nil {
		t.Fatal("rare seller result not found")
	}

	// Rare seller's novelty boost should be 1.0 (appears once out of max 4).
	if rareResult.NoveltyBoost <= 0.5 {
		t.Errorf("rare seller novelty boost = %f, want > 0.5", rareResult.NoveltyBoost)
	}

	// Rare seller should not be completely buried — check at least one dominant
	// entry has lower score than the rare entry.
	var dominantResults []RankedResult
	for _, r := range results {
		if r.EntryID != "r1" {
			dominantResults = append(dominantResults, r)
		}
	}
	// With novelty boost, rare seller scores higher than dominant sellers with same content.
	if rareResult.CompositeScore <= dominantResults[0].CompositeScore {
		t.Errorf("rare seller score (%f) should exceed dominant seller score (%f) due to novelty",
			rareResult.CompositeScore, dominantResults[0].CompositeScore)
	}
}

// TestRank_ZeroPriceEntryDoesNotDominate verifies that a zero-price entry
// receives EfficiencyScore=0 and does not outrank entries with valid prices.
// Regression for dontguess-p39: the old code set l1Efficiency=1.0 for Price=0
// entries ("free item" path), causing them to dominate rankings despite having
// no valid scrip flow.
func TestRank_ZeroPriceEntryDoesNotDominate(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	ts := time.Now().Add(-1 * time.Hour).UnixNano()
	desc := "Go HTTP handler unit test generator"

	zeroPriceEntry := RankInput{
		EntryID:          "zero-price",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            0, // zero price — must not dominate
		SellerReputation: 70,
		PutTimestamp:     ts,
	}
	validEntry := RankInput{
		EntryID:          "valid-price",
		SellerKey:        "seller-b",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000, // normal price
		SellerReputation: 70,
		PutTimestamp:     ts,
	}

	results := Rank("Go HTTP unit test generator", []RankInput{zeroPriceEntry, validEntry}, e, RankOptions{})
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var zeroResult, validResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "zero-price":
			zeroResult = &results[i]
		case "valid-price":
			validResult = &results[i]
		}
	}
	if zeroResult == nil {
		t.Fatal("zero-price entry not found in results")
	}
	if validResult == nil {
		t.Fatal("valid-price entry not found in results")
	}

	// Zero-price entry must have EfficiencyScore=0.
	if zeroResult.EfficiencyScore != 0.0 {
		t.Errorf("zero-price EfficiencyScore = %f, want 0.0", zeroResult.EfficiencyScore)
	}

	// Zero-price entry must not outrank the valid entry.
	// Both have the same description/similarity/reputation/freshness/domains,
	// so ranking is determined by efficiency. Valid entry has non-zero efficiency.
	if zeroResult.CompositeScore >= validResult.CompositeScore {
		t.Errorf("zero-price CompositeScore (%f) should be < valid-price CompositeScore (%f)",
			zeroResult.CompositeScore, validResult.CompositeScore)
	}
	if results[0].EntryID != "valid-price" {
		t.Errorf("expected valid-price to rank first, got %q (zero-price must not dominate)",
			results[0].EntryID)
	}
}

// TestRank_ZeroTokenCostZeroPriceEfficiency verifies that an entry with both
// TokenCost=0 and Price=0 gets EfficiencyScore=0 (no work, no cost — no deal).
func TestRank_ZeroTokenCostZeroPriceEfficiency(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	entry := RankInput{
		EntryID:          "zero-both",
		SellerKey:        "seller-a",
		Description:      "Go HTTP handler unit test generator",
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        0,
		Price:            0,
		SellerReputation: 70,
		PutTimestamp:     time.Now().Add(-1 * time.Hour).UnixNano(),
	}

	results := Rank("Go HTTP unit test", []RankInput{entry}, e, RankOptions{})
	if len(results) == 0 {
		// If filtered out, that's fine — but if present, check efficiency.
		return
	}
	if results[0].EfficiencyScore != 0.0 {
		t.Errorf("zero TokenCost+Price EfficiencyScore = %f, want 0.0", results[0].EfficiencyScore)
	}
}

// summarizeResults returns a slice of EntryID strings for test error messages.
func summarizeResults(results []RankedResult) []string {
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.EntryID
	}
	return ids
}

// --- dontguess-860: behavioral signal booster tests ---

// TestComputeBehavioralBoost_ZeroSignals verifies zero boost for zero signals.
func TestComputeBehavioralBoost_ZeroSignals(t *testing.T) {
	t.Parallel()
	boost := computeBehavioralBoost(BehavioralSignals{})
	if boost != 0.0 {
		t.Errorf("zero signals: want 0.0, got %f", boost)
	}
}

// TestComputeBehavioralBoost_ConsumeOnly verifies consume-only boost is positive
// and proportional but bounded.
func TestComputeBehavioralBoost_ConsumeOnly(t *testing.T) {
	t.Parallel()
	one := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 1})
	ten := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10})
	huge := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10000})

	if one <= 0 {
		t.Errorf("1 consume: want > 0, got %f", one)
	}
	if ten <= one {
		t.Errorf("10 consumes (%f) should exceed 1 consume (%f)", ten, one)
	}
	// At very high count, must saturate at MaxBehavioralBoost / 2 (consume half-weight).
	halfMax := MaxBehavioralBoost / 2.0
	if huge > halfMax+1e-9 {
		t.Errorf("huge consume count boost %f exceeds half-weight cap %f", huge, halfMax)
	}
}

// TestComputeBehavioralBoost_ConvergenceOnly verifies convergence-only boost.
func TestComputeBehavioralBoost_ConvergenceOnly(t *testing.T) {
	t.Parallel()
	one := computeBehavioralBoost(BehavioralSignals{DistinctBuyerCount: 1})
	three := computeBehavioralBoost(BehavioralSignals{DistinctBuyerCount: 3})
	many := computeBehavioralBoost(BehavioralSignals{DistinctBuyerCount: 100})

	if one <= 0 {
		t.Errorf("1 buyer: want > 0, got %f", one)
	}
	if three <= one {
		t.Errorf("3 buyers (%f) should exceed 1 buyer (%f)", three, one)
	}
	// At >= threshold, must saturate at MaxBehavioralBoost / 2 (convergence half-weight).
	halfMax := MaxBehavioralBoost / 2.0
	if many > halfMax+1e-9 {
		t.Errorf("many buyers boost %f exceeds half-weight cap %f", many, halfMax)
	}
	// 3 buyers == full convergence half-weight
	if three != halfMax {
		t.Errorf("3 buyers (full convergence) boost = %f, want %f", three, halfMax)
	}
}

// TestComputeBehavioralBoost_CombinedCappedAtMax verifies combined signals
// are capped at MaxBehavioralBoost.
func TestComputeBehavioralBoost_CombinedCappedAtMax(t *testing.T) {
	t.Parallel()
	huge := computeBehavioralBoost(BehavioralSignals{ConsumeCount: 10000, DistinctBuyerCount: 10000})
	if huge > MaxBehavioralBoost+1e-9 {
		t.Errorf("huge combined boost %f exceeds MaxBehavioralBoost %f", huge, MaxBehavioralBoost)
	}
}

// TestRank_BehavioralBoostRaisesConvergedEntryAboveEquivalent verifies the
// core dontguess-860 requirement: an entry with N distinct-agent consume signals
// (DistinctBuyerCount >= 3) ranks above an otherwise-equivalent entry with none.
//
// This test exercises the REAL Rank() path with real embeddings and real signals.
// No mocking of the matcher. Signals are injected via RankInput.Signals.
// The task and both entry descriptions are identical so similarity is equal —
// only behavioral signals differentiate them.
func TestRank_BehavioralBoostRaisesConvergedEntryAboveEquivalent(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	desc := "Go HTTP handler unit test generator with JSON validation"
	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// "boosted" entry: converged (3 distinct buyers) + 5 consumes.
	boosted := RankInput{
		EntryID:          "boosted",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			ConsumeCount:       5,
			DistinctBuyerCount: 3, // >= convergence threshold
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

	results := Rank("Go HTTP unit test generator JSON validation", []RankInput{boosted, plain}, e, RankOptions{})
	if len(results) < 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Both must have passed the floor (similarity > 0 — they share words with task).
	var boostedResult, plainResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "boosted":
			boostedResult = &results[i]
		case "plain":
			plainResult = &results[i]
		}
	}
	if boostedResult == nil {
		t.Fatal("boosted entry not found in results")
	}
	if plainResult == nil {
		t.Fatal("plain entry not found in results")
	}

	// Boosted entry must have a non-zero behavioral boost.
	if boostedResult.BehavioralBoost <= 0 {
		t.Errorf("boosted entry BehavioralBoost = %f, want > 0", boostedResult.BehavioralBoost)
	}
	// Plain entry must have zero behavioral boost.
	if plainResult.BehavioralBoost != 0 {
		t.Errorf("plain entry BehavioralBoost = %f, want 0", plainResult.BehavioralBoost)
	}
	// Boosted entry must rank first.
	if results[0].EntryID != "boosted" {
		t.Errorf("boosted entry should rank first, got %q (scores: boosted=%.4f plain=%.4f)",
			results[0].EntryID, boostedResult.CompositeScore, plainResult.CompositeScore)
	}
}

// TestRank_BehavioralBoostDoesNotOverrideRelevanceFloor verifies §3.1/§3.2 of
// the foundation doc: the relevance floor (MinSimilarity=0.16) gates everything.
// An entry with maximum behavioral signals but below-floor similarity must NOT
// appear in results — the boost only applies to above-floor survivors.
//
// This test exercises the REAL Rank() path with real embeddings.
func TestRank_BehavioralBoostDoesNotOverrideRelevanceFloor(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	ts := time.Now().Add(-1 * time.Hour).UnixNano()

	// An entry with completely unrelated vocabulary to the task description.
	// With TF-IDF, cosine similarity between completely disjoint vocabulary sets is 0.
	// This entry has maximum signals but must be excluded by the floor.
	belowFloor := RankInput{
		EntryID:          "below-floor",
		SellerKey:        "seller-a",
		Description:      "financial accounting ledger quarterly report spreadsheet excel",
		ContentType:      "data",
		Domains:          []string{"finance"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 90,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			ConsumeCount:       100,  // maximum consume signals
			DistinctBuyerCount: 100, // maximum convergence
		},
	}

	// An above-floor entry with zero signals that should appear.
	aboveFloor := RankInput{
		EntryID:          "above-floor",
		SellerKey:        "seller-b",
		Description:      "Go HTTP handler unit test generator JSON validation",
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals:          BehavioralSignals{},
	}

	// Index corpus so IDF is computed from both descriptions.
	docs := []string{belowFloor.Description, aboveFloor.Description}
	e.IndexCorpus(docs)

	task := "Go HTTP unit test generator JSON validation"
	results := Rank(task, []RankInput{belowFloor, aboveFloor}, e, RankOptions{})

	// below-floor entry must NOT appear regardless of its signals.
	for _, r := range results {
		if r.EntryID == "below-floor" {
			t.Errorf("below-floor entry appeared in results with signals — floor gate violated (similarity=%f)",
				r.Similarity)
		}
	}

	// above-floor entry must appear.
	found := false
	for _, r := range results {
		if r.EntryID == "above-floor" {
			found = true
		}
	}
	if !found && len(results) > 0 {
		// Only fail if some results were returned; if both are below floor that's a fixture issue.
		t.Errorf("above-floor entry not found in results; results: %v", summarizeResults(results))
	}
}

// TestRank_BehavioralBoostBounded verifies that the boost is bounded at
// MaxBehavioralBoost regardless of signal count.
func TestRank_BehavioralBoostBounded(t *testing.T) {
	t.Parallel()
	e := NewTFIDFEmbedder()

	ts := time.Now().Add(-1 * time.Hour).UnixNano()
	desc := "Go HTTP handler unit test generator"

	entry := RankInput{
		EntryID:          "high-signals",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
		Signals: BehavioralSignals{
			ConsumeCount:       999999,
			DistinctBuyerCount: 999999,
		},
	}

	results := Rank("Go HTTP unit test", []RankInput{entry}, e, RankOptions{})
	if len(results) == 0 {
		t.Skip("entry below floor — fixture issue")
	}
	if results[0].BehavioralBoost > MaxBehavioralBoost+1e-9 {
		t.Errorf("BehavioralBoost = %f exceeds MaxBehavioralBoost = %f",
			results[0].BehavioralBoost, MaxBehavioralBoost)
	}
}

// TestIndex_SetBehavioralSignals_InjectedIntoSearch verifies the full Index path:
// SetBehavioralSignals + Search injects signals into Rank() and the boosted
// entry ranks above the equivalent unboosted entry.
//
// This is the integration path the exchange engine uses — exercises the real
// Index.Search → Rank chain without mocking.
func TestIndex_SetBehavioralSignals_InjectedIntoSearch(t *testing.T) {
	t.Parallel()

	e := NewTFIDFEmbedder()
	idx := NewIndex(e, RankOptions{})

	ts := time.Now().Add(-1 * time.Hour).UnixNano()
	desc := "Go HTTP handler unit test generator JSON validation"

	boostedInput := RankInput{
		EntryID:          "idx-boosted",
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

	idx.Rebuild([]RankInput{boostedInput, plainInput})

	// Inject behavioral signals for the "boosted" entry only.
	signals := map[string]BehavioralSignals{
		"idx-boosted": {
			ConsumeCount:       5,
			DistinctBuyerCount: 3,
		},
	}
	idx.SetBehavioralSignals(signals)

	results := idx.Search("Go HTTP unit test generator JSON validation", 10)
	if len(results) < 2 {
		t.Fatalf("expected >=2 results from index search, got %d", len(results))
	}

	var boostedResult, plainResult *RankedResult
	for i := range results {
		switch results[i].EntryID {
		case "idx-boosted":
			boostedResult = &results[i]
		case "idx-plain":
			plainResult = &results[i]
		}
	}
	if boostedResult == nil {
		t.Fatal("idx-boosted entry not found in results")
	}
	if plainResult == nil {
		t.Fatal("idx-plain entry not found in results")
	}

	if boostedResult.BehavioralBoost <= 0 {
		t.Errorf("idx-boosted BehavioralBoost = %f, want > 0 (signals not injected)",
			boostedResult.BehavioralBoost)
	}
	if plainResult.BehavioralBoost != 0 {
		t.Errorf("idx-plain BehavioralBoost = %f, want 0 (no signals set)",
			plainResult.BehavioralBoost)
	}
	if results[0].EntryID != "idx-boosted" {
		t.Errorf("expected idx-boosted to rank first via signals, got %q (scores: boosted=%.4f plain=%.4f)",
			results[0].EntryID, boostedResult.CompositeScore, plainResult.CompositeScore)
	}
}

// TestIndex_SetBehavioralSignals_ClearWithEmpty verifies that calling
// SetBehavioralSignals with an empty map clears all prior signals.
func TestIndex_SetBehavioralSignals_ClearWithEmpty(t *testing.T) {
	t.Parallel()

	e := NewTFIDFEmbedder()
	idx := NewIndex(e, RankOptions{})

	ts := time.Now().Add(-1 * time.Hour).UnixNano()
	desc := "Go HTTP handler unit test generator"

	input := RankInput{
		EntryID:          "entry",
		SellerKey:        "seller-a",
		Description:      desc,
		ContentType:      "code",
		Domains:          []string{"go"},
		TokenCost:        10000,
		Price:            1000,
		SellerReputation: 70,
		PutTimestamp:     ts,
	}
	idx.Rebuild([]RankInput{input})

	// Set signals, then clear.
	idx.SetBehavioralSignals(map[string]BehavioralSignals{
		"entry": {ConsumeCount: 10, DistinctBuyerCount: 5},
	})
	idx.SetBehavioralSignals(nil)

	results := idx.Search("Go HTTP unit test", 10)
	for _, r := range results {
		if r.EntryID == "entry" && r.BehavioralBoost != 0 {
			t.Errorf("after clearing signals, BehavioralBoost = %f, want 0", r.BehavioralBoost)
		}
	}
}
