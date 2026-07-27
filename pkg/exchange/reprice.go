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

// RepriceInventoryForRuling implements the dontguess-b2b migration end to
// end: it walks every LIVE inventory entry and emits one auditable
// exchange:reprice event per entry that does not already carry one for
// rulingRef.
//
// DEDUP BY EVENT ID (KNOWN DATA HAZARD a, dontguess-8f5): State.Inventory()
// is a map keyed by EntryID, so a relay double-appended put message already
// collapses to a single entry before this function ever iterates it — the
// naive ~6% inflation dontguess-8f5 measured against raw events.jsonl lines
// cannot reach this loop.
//
// BOTH ENVELOPE SHAPES REINTERPRETED (KNOWN DATA HAZARD b, dontguess-5b8):
// this function applies NO branch on entry.LegacyPlaintext or
// entry.WrappedCEKOperator — the 80 legacy-plaintext entries and the 86 v2
// envelope entries were put under the SAME undefined token_cost semantic, so
// every live entry is repriced uniformly regardless of shape.
//
// IDEMPOTENT: an entry that already has a reprice event for rulingRef
// (state.HasReprice) is skipped, so re-running this after a partial failure
// (or simply re-running it) does not emit duplicate audit events.
//
// Entries are processed in EntryID order for deterministic output.
func (e *Engine) RepriceInventoryForRuling(rulingRef, basis string) ([]RepriceRecord, error) {
	entries := e.state.Inventory()
	sort.Slice(entries, func(i, j int) bool { return entries[i].EntryID < entries[j].EntryID })

	out := make([]RepriceRecord, 0, len(entries))
	for _, entry := range entries {
		if e.state.HasReprice(entry.EntryID, rulingRef) {
			continue
		}
		oldPrice := e.legacyComputePrice(entry)
		newPrice := e.computePrice(entry)
		rec, err := e.EmitReprice(entry.EntryID, oldPrice, newPrice, basis, rulingRef)
		if err != nil {
			return out, err
		}
		out = append(out, *rec)
	}
	return out, nil
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

// RollbackReprice reconstructs the pre-ruling price for every repriced entry
// USING ONLY the reprice event log (s.repriceEvents, itself derived purely by
// folding/replaying TagReprice messages — nothing else in State feeds it).
// This is the "roll the repricing back from the event log alone" mechanism
// dontguess-b2b requires: for each entry it returns the OLDEST recorded
// OldPrice — the first reprice event ever folded for that entry, in log
// order — not the most recent, so a later re-reinterpretation under a
// different ruling does not shadow the true original pre-ruling price.
func (s *State) RollbackReprice() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.repriceEvents))
	for entryID, recs := range s.repriceEvents {
		if len(recs) == 0 {
			continue
		}
		out[entryID] = recs[0].OldPrice
	}
	return out
}
