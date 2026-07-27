package exchange

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// This file implements the dontguess-b2b migration: an auditable, reversible
// mechanism for retroactively reinterpreting the 166 pre-ruling inventory
// entries under the dontguess-96e two-unit pricing definition (token_cost :=
// output tokens; delivery price amortized across resaleAmortizationN resales,
// dontguess-af3).
//
// OPERATOR RULING dontguess-96e decision 2 chose retroactive reinterpretation
// OVER the recommended grandfather option — silently repricing history. The
// mandatory mitigation for that override is this file: an auditable repricing
// EVENT per entry (old_price, new_price, basis, ruling ref) rather than any
// in-place mutation. InventoryEntry carries no price field to mutate — the
// buyer-facing price has always been computed on demand by computePrice — so
// there is nothing to overwrite in the first place; the event log IS the
// migration's only artifact, and it is what State.RollbackReprice reads back
// to recover the pre-ruling prices exactly.
//
// SCOPE FENCE (per dontguess-b2b): this file does NOT modify computePrice
// (dontguess-af3 owns it), the credit path (dontguess-29b), or elasticity
// (dontguess-742). legacyComputePrice below is a SEPARATE, additive
// reconstruction of the pre-af3 one-off-commission formula — computePrice
// minus the resaleAmortizationDivisor division step — built by reusing the
// same named signal-factor helpers computePrice itself calls, so the two
// formulas can never drift apart on the parts they share.

// RepriceRulingRef96e is the rd item ID of the operator ruling authorizing
// this migration.
const RepriceRulingRef96e = "dontguess-96e"

// RepriceBasisTwoUnit describes why every one of the 166 entries is being
// reinterpreted: both the 80 legacy-plaintext-shape entries and the 86 v=2
// envelope entries (dontguess-5b8) were put under the SAME undefined
// token_cost semantic, so both are repriced uniformly — this migration draws
// no distinction between the two envelope shapes.
const RepriceBasisTwoUnit = "two-unit reinterpretation (dontguess-96e decision 1-3): token_cost := output tokens; delivery price now amortizes the acquisition-scale base across resaleAmortizationN resales (dontguess-af3) instead of quoting it as a one-off commission. Applies uniformly to legacy-plaintext and v2-envelope entries alike — both were put under the same previously-undefined semantic."

// legacyComputePrice reconstructs the PRE-dontguess-af3 asking price for
// entry: the exact same acquisition-scale base and six signal multipliers
// computePrice (engine_pricing.go) still uses today, MINUS the
// resaleAmortizationDivisor division step that af3 added. This is not a
// duplicate of computePrice's logic in spirit — it is the historical formula
// computePrice replaced, reconstructed here (additively, without touching
// computePrice) purely so this migration has a well-defined "old_price" to
// record. See git history of engine_pricing.go (dontguess-af3 commit) for the
// literal diff this mirrors.
//
// Reuses e.computeDemandFactor / computeAgeFactor / e.computeRepFactor /
// computeSizeFactor / e.computeFastFactor / e.computeDensityFactor /
// computeTierFactor — the same signal-factor helpers computePrice calls — so
// the "old" and "new" formulas can never silently disagree on what those six
// signals mean, only on whether the amortization division is applied.
func (e *Engine) legacyComputePrice(entry *InventoryEntry) int64 {
	var base float64
	if entry.PutPrice > 0 {
		if entry.PutPrice > math.MaxInt64/operatorMarginOverflowGuard {
			return math.MaxInt64
		}
		base = float64(entry.PutPrice) * operatorMargin
	} else {
		if entry.TokenCost <= 0 {
			return computePriceMinPrice
		}
		if entry.TokenCost > math.MaxInt64/sellerShareOverflowGuard {
			return math.MaxInt64
		}
		base = float64(entry.TokenCost) * sellerShareFactor
		if base < float64(computePriceMinPrice) {
			base = float64(computePriceMinPrice)
		}
	}

	demandFactor := e.computeDemandFactor(entry.EntryID)
	ageFactor := computeAgeFactor(entry.PutTimestamp)
	repFactor := e.computeRepFactor(entry.SellerKey)
	sizeFactor := computeSizeFactor(entry.ContentSize)
	fastFactor := e.computeFastFactor(entry.EntryID)
	densityFactor := e.computeDensityFactor(entry)
	tierFactor := computeTierFactor(entry.CompressionTier)

	price := base * demandFactor * ageFactor * repFactor * sizeFactor * fastFactor * densityFactor * tierFactor

	rounded := math.Round(price)
	if rounded < float64(computePriceMinPrice) {
		return computePriceMinPrice
	}
	if rounded >= float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(rounded)
}

// EmitReprice sends and applies an operator-signed exchange:reprice event
// (TagReprice) recording entryID's old and new price under basis/rulingRef.
// It mutates nothing on the entry itself — InventoryEntry has no price field
// — the event is the entire artifact. Modeled on emitPutReject
// (engine_pricing.go): it takes no opMu, since it only touches LocalStore and
// State (each independently self-locked), and this migration runs
// administratively, never interleaved with the live buy/put dispatch path
// this codebase's opMu protects.
func (e *Engine) EmitReprice(entryID string, oldPrice, newPrice int64, basis, rulingRef string) (*RepriceRecord, error) {
	payload, err := json.Marshal(map[string]any{
		"entry_id":   entryID,
		"old_price":  oldPrice,
		"new_price":  newPrice,
		"basis":      basis,
		"ruling_ref": rulingRef,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding reprice payload: %w", err)
	}

	tags := []string{TagReprice}
	antecedents := []string{entryID}

	msg, err := e.sendOperatorMessage(payload, tags, antecedents)
	if err != nil {
		return nil, fmt.Errorf("engine: emitting reprice for entry %s: %w", shortKey(entryID), err)
	}

	var ts int64
	if msg != nil {
		ts = msg.Timestamp
		e.state.Apply(msg)
	}

	return &RepriceRecord{
		EntryID:   entryID,
		OldPrice:  oldPrice,
		NewPrice:  newPrice,
		Basis:     basis,
		RulingRef: rulingRef,
		Timestamp: ts,
	}, nil
}

// RepriceSkipReasonAlreadyRepriced is the RepriceSkip.Reason recorded when an
// entry already carries a reprice event for the ruling being run — the
// migration's idempotency guard (state.HasReprice). This is an EXPECTED,
// benign skip on a re-run; it is still reported (not silently dropped) so a
// caller diffing two runs' skip lists can tell "already done" apart from any
// future skip reason that would represent an actual gap.
const RepriceSkipReasonAlreadyRepriced = "already-repriced-for-ruling"

// RepriceSkip records one inventory entry RepriceInventoryForRuling visited
// but did NOT emit a new reprice event for, and why. This exists because a
// prior version of this migration walked State.Inventory() (which silently
// filters IsExpired() entries — see AllInventoryEntries) with no accounting
// at all: an expired entry was dropped from the walk with no error and no
// count, so the migration could report full success while an unknown slice
// of the declared corpus was never repriced. Every entry the migration is
// responsible for now surfaces either a RepriceRecord (repriced) or a
// RepriceSkip (why it wasn't) — nothing disappears silently.
type RepriceSkip struct {
	EntryID string
	Reason  string
}

// RepriceInventoryForRuling implements the dontguess-b2b migration end to
// end: it walks EVERY accepted inventory entry — including expired ones, via
// AllInventoryEntries, not the live-only Inventory() — and emits one
// auditable exchange:reprice event per entry that does not already carry one
// for rulingRef.
//
// EXPIRED ENTRIES ARE REPRICED, NOT OMITTED: an entry's declared token_cost
// still needs auditable reinterpretation, and residual math on any
// already-sold copy still needs to be reconstructible, regardless of whether
// the entry has since expired off the live buy/match surface. Using
// State.Inventory() here (as an earlier version of this function did) would
// silently drop expired entries from the walk with no error and no count —
// exactly the finding this comment documents. AllInventoryEntries applies no
// expiry filter, so every entry the corpus contains is visited.
//
// DEDUP BY EVENT ID (KNOWN DATA HAZARD a, dontguess-8f5): the inventory is a
// map keyed by EntryID, so a relay double-appended put message already
// collapses to a single entry before this function ever iterates it — the
// naive ~6% inflation dontguess-8f5 measured against raw events.jsonl lines
// cannot reach this loop.
//
// BOTH ENVELOPE SHAPES REINTERPRETED (KNOWN DATA HAZARD b, dontguess-5b8):
// this function applies NO branch on entry.LegacyPlaintext or
// entry.WrappedCEKOperator — the 80 legacy-plaintext entries and the 86 v2
// envelope entries were put under the SAME undefined token_cost semantic, so
// every entry is repriced uniformly regardless of shape.
//
// IDEMPOTENT: an entry that already has a reprice event for rulingRef
// (state.HasReprice) is skipped (recorded as RepriceSkipReasonAlreadyRepriced,
// not silently dropped), so re-running this after a partial failure (or
// simply re-running it) does not emit duplicate audit events.
//
// Entries are processed in EntryID order for deterministic output. Returns
// the emitted records, a skip report for every entry visited but not
// repriced, and an error if a write failed partway through (in which case
// both slices reflect progress up to the failure).
func (e *Engine) RepriceInventoryForRuling(rulingRef, basis string) ([]RepriceRecord, []RepriceSkip, error) {
	candidates, skipped := e.candidateEntriesForReprice(rulingRef)

	out := make([]RepriceRecord, 0, len(candidates))
	for _, entry := range candidates {
		oldPrice := e.legacyComputePrice(entry)
		newPrice := e.computePrice(entry)
		rec, err := e.EmitReprice(entry.EntryID, oldPrice, newPrice, basis, rulingRef)
		if err != nil {
			return out, skipped, err
		}
		out = append(out, *rec)
	}
	return out, skipped, nil
}

// RepricePreview is what RepriceInventoryForRuling WOULD emit for one entry —
// the old/new price pair — WITHOUT ever calling EmitReprice: no message is
// signed, appended, or folded, and State is left completely untouched.
type RepricePreview struct {
	EntryID  string
	OldPrice int64
	NewPrice int64
}

// PreviewRepriceInventoryForRuling is the read-only "dry run" counterpart to
// RepriceInventoryForRuling — required so an operator (via `dontguess
// reprice-migration --dry-run`) can see exactly what a real run WOULD change
// before committing to writing 166 audit events. It walks the identical
// candidate set (same AllInventoryEntries + HasReprice idempotency skip,
// same EntryID ordering, same legacyComputePrice/computePrice formulas
// RepriceInventoryForRuling uses) but never calls EmitReprice, so it has zero
// side effects: no message is signed or appended, no repriceEvents entry is
// created, State.Reprices/HasReprice are unaffected by having run this.
func (e *Engine) PreviewRepriceInventoryForRuling(rulingRef string) ([]RepricePreview, []RepriceSkip) {
	candidates, skipped := e.candidateEntriesForReprice(rulingRef)

	out := make([]RepricePreview, 0, len(candidates))
	for _, entry := range candidates {
		out = append(out, RepricePreview{
			EntryID:  entry.EntryID,
			OldPrice: e.legacyComputePrice(entry),
			NewPrice: e.computePrice(entry),
		})
	}
	return out, skipped
}

// candidateEntriesForReprice is the shared walk RepriceInventoryForRuling and
// PreviewRepriceInventoryForRuling both use: every accepted inventory entry
// (including expired ones — AllInventoryEntries, not the live-only
// Inventory()), in deterministic EntryID order, split into "needs a reprice
// event for rulingRef" (returned) and "already has one" (reported as a
// RepriceSkip, RepriceSkipReasonAlreadyRepriced — never silently dropped).
// Keeping this walk in exactly one place is what guarantees the dry-run
// preview and the real run can never silently diverge on WHICH entries they
// consider.
func (e *Engine) candidateEntriesForReprice(rulingRef string) ([]*InventoryEntry, []RepriceSkip) {
	entries := e.state.AllInventoryEntries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].EntryID < entries[j].EntryID })

	candidates := make([]*InventoryEntry, 0, len(entries))
	var skipped []RepriceSkip
	for _, entry := range entries {
		if e.state.HasReprice(entry.EntryID, rulingRef) {
			skipped = append(skipped, RepriceSkip{EntryID: entry.EntryID, Reason: RepriceSkipReasonAlreadyRepriced})
			continue
		}
		candidates = append(candidates, entry)
	}
	return candidates, skipped
}

// applyReprice folds an exchange:reprice message into s.repriceEvents.
// Operator-only (mirrors every other operator-authored settlement fold —
// applySettlePutAccept, applyConsume, etc.): a non-operator sender is
// rejected and counted/alarmed via recordFoldDenial, never silently dropped.
// Per-message-ID dedup guard (repriceCounted, dontguess-f86 pattern) so a
// concurrent live Apply racing a Replay of the same message cannot
// double-append the same event.
func (s *State) applyReprice(msg *Message) {
	if s.OperatorKey != "" && msg.Sender != s.OperatorKey {
		s.recordFoldDenial(foldDenialNotOperator, msg)
		return
	}
	if _, dup := s.repriceCounted[msg.ID]; dup {
		return
	}

	var p struct {
		EntryID   string `json:"entry_id"`
		OldPrice  int64  `json:"old_price"`
		NewPrice  int64  `json:"new_price"`
		Basis     string `json:"basis"`
		RulingRef string `json:"ruling_ref"`
	}
	if err := json.Unmarshal(msg.Payload, &p); err != nil || p.EntryID == "" {
		return
	}

	s.repriceCounted[msg.ID] = struct{}{}
	s.repriceEvents[p.EntryID] = append(s.repriceEvents[p.EntryID], RepriceRecord{
		EntryID:   p.EntryID,
		OldPrice:  p.OldPrice,
		NewPrice:  p.NewPrice,
		Basis:     p.Basis,
		RulingRef: p.RulingRef,
		Timestamp: msg.Timestamp,
	})
}

// HasReprice reports whether entryID already has a recorded reprice event for
// rulingRef — the idempotency check RepriceInventoryForRuling uses so re-runs
// do not emit duplicate audit events.
func (s *State) HasReprice(entryID, rulingRef string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.repriceEvents[entryID] {
		if r.RulingRef == rulingRef {
			return true
		}
	}
	return false
}

// Reprices returns a copy of entryID's repricing event history, in log
// (append) order. Empty if entryID was never repriced.
func (s *State) Reprices(entryID string) []RepriceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := s.repriceEvents[entryID]
	if len(recs) == 0 {
		return nil
	}
	out := make([]RepriceRecord, len(recs))
	copy(out, recs)
	return out
}

// AllReprices returns a deep copy of every entry's repricing event history.
func (s *State) AllReprices() map[string][]RepriceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]RepriceRecord, len(s.repriceEvents))
	for id, recs := range s.repriceEvents {
		cp := make([]RepriceRecord, len(recs))
		copy(cp, recs)
		out[id] = cp
	}
	return out
}

// RollbackReprice reconstructs the pre-ruling price, SCOPED TO rulingRef, for
// every entry that has a reprice event under that ruling — USING ONLY the
// reprice event log (s.repriceEvents, itself derived purely by
// folding/replaying TagReprice messages — nothing else in State feeds it).
// This is the "roll the repricing back from the event log alone" mechanism
// dontguess-b2b requires.
//
// Scoping by rulingRef (rather than always returning the entry's globally
// OLDEST reprice record, regardless of which ruling produced it) is what
// makes a LATER, independent re-interpretation under a DIFFERENT ruling
// separately recoverable: an entry can accumulate reprice events from more
// than one ruling over its lifetime (e.g. a pre-96e experimental reprice,
// then the real dontguess-96e migration reprice), and rolling back a specific
// ruling must return exactly what THAT ruling changed — the entry's price
// immediately before that ruling first repriced it — never whatever the
// entry's very first reprice event ever recorded happened to be. Passing the
// wrong (or no) ruling_ref would silently recover the wrong price under a
// later re-interpretation.
//
// For an entry repriced more than once under the SAME rulingRef (unusual —
// RepriceInventoryForRuling's HasReprice idempotency guard prevents this on
// the normal migration path, but a manual EmitReprice call could), this
// returns the OLDEST such record's OldPrice: the state immediately before
// that ruling first took effect for the entry.
func (s *State) RollbackReprice(rulingRef string) map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.repriceEvents))
	for entryID, recs := range s.repriceEvents {
		for _, r := range recs {
			if r.RulingRef != rulingRef {
				continue
			}
			if _, has := out[entryID]; has {
				continue
			}
			out[entryID] = r.OldPrice
		}
	}
	return out
}
