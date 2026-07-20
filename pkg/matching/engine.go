package matching

import (
	"sync"
)

// Index is the matching engine's in-memory search index.
// It holds pre-computed embeddings for inventory entries and supports
// ranked search against buy task descriptions.
//
// Thread safety: Index is safe for concurrent reads. Mutations (Add, Remove,
// Rebuild, SetBehavioralSignals) must not be called concurrently with reads
// or each other. The exchange engine calls Rebuild after state replay and
// Add/Remove/SetBehavioralSignals incrementally as entries change.
type Index struct {
	mu       sync.RWMutex
	embedder Embedder
	opts     RankOptions
	entries  []indexedEntry
	// signals holds the most-recently-set behavioral signals per entry.
	// Keyed by EntryID. Updated by SetBehavioralSignals.
	// Injected into RankInput.Signals in Search before calling Rank.
	signals map[string]BehavioralSignals
}

// indexedEntry stores a single inventory entry and its precomputed embedding.
type indexedEntry struct {
	input     RankInput
	embedding []float64
}

// NewIndex returns an empty matching index using the given embedder.
// Use Rebuild to populate from a full inventory snapshot, or Add to
// insert entries incrementally.
func NewIndex(embedder Embedder, opts RankOptions) *Index {
	if embedder == nil {
		embedder = NewTFIDFEmbedder()
	}
	return &Index{
		embedder: embedder,
		opts:     opts,
		signals:  make(map[string]BehavioralSignals),
	}
}

// Rebuild replaces the index contents with the given entries.
// It re-computes IDF weights from the corpus of descriptions before
// embedding each entry, improving relevance when the inventory is large.
//
// Rebuild acquires a write lock for the duration of indexing.
// This is typically called once at engine startup after state replay.
func (idx *Index) Rebuild(entries []RankInput) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Re-prime IDF weights from the new corpus if the embedder supports it.
	if ci, ok := idx.embedder.(CorpusIndexer); ok {
		docs := make([]string, len(entries))
		for i, e := range entries {
			docs[i] = e.Description
		}
		ci.IndexCorpus(docs)
	}

	idx.entries = make([]indexedEntry, 0, len(entries))
	for _, e := range entries {
		emb := idx.embedder.Embed(e.Description)
		idx.entries = append(idx.entries, indexedEntry{input: e, embedding: emb})
	}
}

// Add inserts a new entry into the index. If an entry with the same EntryID
// already exists, it is replaced.
// Add acquires a write lock.
func (idx *Index) Add(entry RankInput) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	emb := idx.embedder.Embed(entry.Description)
	for i, e := range idx.entries {
		if e.input.EntryID == entry.EntryID {
			idx.entries[i] = indexedEntry{input: entry, embedding: emb}
			return
		}
	}
	idx.entries = append(idx.entries, indexedEntry{input: entry, embedding: emb})
}

// Remove removes an entry by EntryID. No-op if the entry does not exist.
// Remove acquires a write lock.
func (idx *Index) Remove(entryID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	for i, e := range idx.entries {
		if e.input.EntryID == entryID {
			idx.entries[i] = idx.entries[len(idx.entries)-1]
			idx.entries = idx.entries[:len(idx.entries)-1]
			return
		}
	}
}

// Len returns the number of indexed entries.
func (idx *Index) Len() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

// HasEmbedding reports whether an entry with the given ID exists in the index
// (i.e. has a precomputed embedding). Entries that are indexed but scored below
// the MinSimilarity floor in Search are still present here — HasEmbedding returns
// true for them. This allows callers to distinguish genuine index-gap entries
// (not yet embedded, HasEmbedding=false) from below-floor embedded entries
// (HasEmbedding=true) that the floor intentionally excluded.
func (idx *Index) HasEmbedding(entryID string) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	for _, e := range idx.entries {
		if e.input.EntryID == entryID {
			return true
		}
	}
	return false
}

// SetBehavioralSignals replaces the behavioral signals map used by Search.
// The exchange engine calls this after every state update that changes
// consume counts or distinct buyer counts (e.g., after settle:complete
// emits a TagConsume message and updates EntryBuyerMap).
//
// signals maps entryID → BehavioralSignals. Entries absent from the map
// receive zero signals (no boost). The map is copied, so the caller may
// reuse or mutate the original after this call.
//
// SetBehavioralSignals acquires a write lock.
func (idx *Index) SetBehavioralSignals(signals map[string]BehavioralSignals) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if len(signals) == 0 {
		idx.signals = make(map[string]BehavioralSignals)
		return
	}
	cp := make(map[string]BehavioralSignals, len(signals))
	for k, v := range signals {
		cp[k] = v
	}
	idx.signals = cp
}

// Search returns ranked results for a buy task, capped at maxResults.
//
// The task description is preprocessed by NormalizeQuery before embedding to
// align buyer vocabulary with inventory description vocabulary (dontguess-af7).
// This improves TF-IDF hit rate for informally phrased buyer tasks without
// changing the inventory index or the 4-layer ranking algorithm.
//
// All indexed entries are evaluated against the 4-layer value stack. Results
// with composite score below the minimum similarity threshold are excluded.
//
// Behavioral signals (consume count, distinct buyer count) stored via
// SetBehavioralSignals are injected into each candidate's RankInput.Signals
// before calling Rank, enabling the post-floor behavioral booster.
//
// Partial matches (confidence < 0.5) are included with IsPartialMatch=true.
// The caller (engine.go) decides whether to include them in the match payload.
//
// If maxResults <= 0, all qualifying results are returned.
func (idx *Index) Search(task string, maxResults int) []RankedResult {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if len(idx.entries) == 0 {
		return nil
	}

	// Normalize the buyer query to align with inventory vocabulary before embedding.
	// NormalizeQuery appends generic technical synonyms for informal buyer terms,
	// improving TF-IDF term overlap without injecting corpus-specific content.
	normalized := NormalizeQuery(task)

	// Build candidate list from indexed entries, injecting behavioral signals AND
	// the entry's precomputed embedding (dontguess-3cc): Rank/applyFloorGate use
	// it directly instead of re-embedding every Description on every query, which
	// is what made buy→match latency scale with inventory size (~40s for 54
	// entries on the pure-Go MiniLM).
	candidates := make([]RankInput, len(idx.entries))
	for i, e := range idx.entries {
		candidates[i] = e.input
		candidates[i].Embedding = e.embedding
		if sig, ok := idx.signals[e.input.EntryID]; ok {
			candidates[i].Signals = sig
		}
	}

	results := Rank(normalized, candidates, idx.embedder, idx.opts)

	if maxResults > 0 && len(results) > maxResults {
		results = results[:maxResults]
	}
	return results
}
