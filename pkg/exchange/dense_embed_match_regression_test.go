package exchange_test

// Ground-source regression test for dontguess-553: every buy result returned
// confidence=0.500 with is_partial_match=false regardless of semantic relevance,
// because entries routed to the reputation-fallback path (computeConfidence =
// rep/100 = 50/100 = 0.5) instead of the semantic path.
//
// This test drives a real put+buy through the engine wired with the REAL dense
// embedder (cmd/embed/main.py, all-MiniLM-L6-v2). No mocks, no TF-IDF stand-in.
// It asserts that an exact-text entry ranks #1 with high similarity and an
// unrelated entry scores far below the floor — mirroring the standalone embedder
// (cos(q,exact)=0.979, cos(q,unrelated)=0.02-0.26).
//
// The all-0.5 symptom cannot recur as long as: (a) the match index is populated
// after replay (rebuildMatchIndex), so accepted entries route through the
// semantic path; and (b) the semantic path reports the raw cosine Similarity.
// This test fails loudly if either regresses (an entry served at the flat 0.5
// fallback confidence with similarity 0).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/campfire-net/campfire/cf-protocol/store"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/campfire-net/dontguess/pkg/matching"
)

// denseEmbedScriptPath returns the absolute path to cmd/embed/main.py, located
// relative to this test file so the test is independent of the working dir.
func denseEmbedScriptPath(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("DONTGUESS_EMBED_SCRIPT"); env != "" {
		return env
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed: cannot locate test file")
	}
	// thisFile = <repo>/pkg/exchange/dense_embed_match_regression_test.go
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(repoRoot, "cmd", "embed", "main.py")
}

// requireFunctionalDenseEmbedder builds a DenseEmbedder and verifies it actually
// discriminates between an exact match and an unrelated string. If the embedder
// is not functional (missing python3 / onnxruntime / model), the test FAILS —
// per the ground-source rule, a dense-embedder regression test must run the real
// embedder, not skip. CI installs the dependency (see .github/workflows/ci.yml).
func requireFunctionalDenseEmbedder(t *testing.T, scriptPath string) *matching.DenseEmbedder {
	t.Helper()
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("embed script not found at %s: %v\n"+
			"The dense-embedder regression test requires cmd/embed/main.py and its "+
			"python deps (numpy, onnxruntime, tokenizers). Install them; do not skip.", scriptPath, err)
	}
	emb := matching.NewDenseEmbedder(scriptPath)
	q := emb.Embed("purple elephant quantum telegram distinctive marker")
	exact := emb.Embed("purple elephant quantum telegram distinctive marker entry")
	unrelated := emb.Embed("go http server middleware routing handlers")
	if len(q) != 384 || len(exact) != 384 || len(unrelated) != 384 {
		t.Fatalf("dense embedder not functional: got vector dims q=%d exact=%d unrelated=%d (want 384).\n"+
			"python3/onnxruntime/tokenizers + the all-MiniLM-L6-v2 model must be available. Do not skip — install the deps.",
			len(q), len(exact), len(unrelated))
	}
	simExact := emb.Similarity(q, exact)
	simUnrelated := emb.Similarity(q, unrelated)
	if simExact < 0.80 {
		t.Fatalf("dense embedder sanity: cos(q,exact)=%.3f, want >=0.80 — embedder is degraded", simExact)
	}
	if simUnrelated > 0.30 {
		t.Fatalf("dense embedder sanity: cos(q,unrelated)=%.3f, want <0.30 — embedder is degraded", simUnrelated)
	}
	return emb
}

// TestDenseEmbed_ExactMatchRanksFirst is the primary done-condition regression
// test for dontguess-553. A put+buy through the real engine with the real dense
// embedder must rank the exact-text entry #1 with similarity >= 0.80, and the
// unrelated entry must score below 0.30 (and thus typically below the relevance
// floor, excluded from results). Before the fix, both came back at the flat 0.5
// fallback confidence with similarity 0.
func TestDenseEmbed_ExactMatchRanksFirst(t *testing.T) {
	t.Parallel()
	scriptPath := denseEmbedScriptPath(t)
	emb := requireFunctionalDenseEmbedder(t, scriptPath)

	h := newTestHarness(t)
	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.Embedder = emb
	})

	// The exact-match entry the buy will target.
	exactDesc := "purple elephant quantum telegram distinctive marker entry"
	exactPut := h.sendMessage(h.seller,
		putPayload(exactDesc, "sha256:aabbccdd00000000000000000000000000000000000000000000000000000553", "code", 5000, 8000),
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)

	// An unrelated entry that must NOT outrank (or even reach) the exact match.
	unrelatedDesc := "go http server middleware routing handlers and request logging"
	unrelatedPut := h.sendMessage(h.seller,
		putPayload(unrelatedDesc, "sha256:aabbccdd00000000000000000000000000000000000000000000000000000554", "code", 5000, 8000),
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		nil,
	)

	msgs, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("listing messages: %v", err)
	}
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	if err := eng.AutoAcceptPut(exactPut.ID, 3500, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut (exact): %v", err)
	}
	if err := eng.AutoAcceptPut(unrelatedPut.ID, 3500, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut (unrelated): %v", err)
	}

	if got := eng.State().Inventory(); len(got) != 2 {
		t.Fatalf("expected 2 inventory entries, got %d", len(got))
	}
	// Both accepted entries must be in the match index (HasEmbedding=true) so they
	// route through the semantic path, not the reputation fallback. This is the
	// invariant whose violation produced the all-0.5 symptom.
	if got := eng.MatchIndexLen(); got != 2 {
		t.Fatalf("match index has %d entries, want 2 — accepted entries missing from index "+
			"would route to the 0.5 fallback path (the dontguess-553 regression)", got)
	}

	// Buy with the exact text (minus the trailing "entry" word).
	buyTask := "purple elephant quantum telegram distinctive marker"
	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	preMatchCount := len(preMsgs)

	buyMsg := h.sendMessage(h.buyer,
		buyPayload(buyTask, 50000),
		[]string{exchange.TagBuy},
		nil,
	)
	buyRec, err := h.st.GetMessage(buyMsg.ID)
	if err != nil {
		t.Fatalf("getting buy message: %v", err)
	}
	eng.State().Apply(exchange.FromStoreRecord(buyRec))
	if err := eng.DispatchForTest(exchange.FromStoreRecord(buyRec)); err != nil {
		t.Fatalf("DispatchForTest: %v", err)
	}

	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))

	postMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	if len(postMsgs) <= preMatchCount {
		t.Fatal("engine emitted no match-tagged message for the exact-match buy")
	}
	emitted := postMsgs[len(postMsgs)-1]
	if hasTag(emitted.Tags, exchange.TagBuyMiss) {
		t.Fatalf("exact-match buy served as MISS; want a real semantic match. Tags: %v", emitted.Tags)
	}

	var mp struct {
		Results []struct {
			EntryID        string  `json:"entry_id"`
			Description    string  `json:"description"`
			Confidence     float64 `json:"confidence"`
			Similarity     float64 `json:"similarity"`
			IsPartialMatch bool    `json:"is_partial_match"`
		} `json:"results"`
	}
	if err := json.Unmarshal(emitted.Payload, &mp); err != nil {
		t.Fatalf("parsing match payload: %v", err)
	}
	if len(mp.Results) == 0 {
		t.Fatal("match payload has no results — exact-match entry should rank #1")
	}

	top := mp.Results[0]
	if top.EntryID != exactPut.ID {
		t.Errorf("top result EntryID=%s (desc=%q), want exact-match entry %s (%q)",
			top.EntryID[:8], top.Description, exactPut.ID[:8], exactDesc)
	}

	// PRIMARY ASSERTION: the exact-match entry ranks #1 with high similarity.
	// Before the fix this was 0.5 confidence / 0 similarity (fallback path).
	if top.Similarity < 0.80 {
		t.Errorf("top result similarity=%.3f, want >=0.80 (standalone embedder gives 0.979). "+
			"A low/zero similarity means the entry routed through the reputation fallback path "+
			"instead of semantic ranking — the dontguess-553 defect.", top.Similarity)
	}
	// Confidence (L2 composite) must be meaningfully above the flat 0.5 fallback.
	if top.Confidence <= 0.5 {
		t.Errorf("top result confidence=%.3f, want >0.5 — flat 0.5 is the fallback signature", top.Confidence)
	}
	if top.IsPartialMatch {
		t.Errorf("exact match flagged is_partial_match=true; want false for a 0.97-similarity hit")
	}

	// The unrelated entry must NOT appear as a high-similarity result. With
	// cos(q,unrelated) ~0.02-0.26 it is below the relevance floor and should be
	// excluded; if it slips in, it must carry a similarity < 0.30.
	for _, r := range mp.Results {
		if r.EntryID == unrelatedPut.ID {
			if r.Similarity >= 0.30 {
				t.Errorf("unrelated entry similarity=%.3f, want <0.30 — semantic ranking is not discriminating", r.Similarity)
			}
		}
	}

	// Antecedent integrity: the match fulfills the buy.
	if len(emitted.Antecedents) == 0 || emitted.Antecedents[0] != buyMsg.ID {
		t.Errorf("match antecedent=%v, want [%s]", emitted.Antecedents, buyMsg.ID)
	}
}
