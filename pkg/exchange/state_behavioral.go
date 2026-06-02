package exchange

import (
	"time"

	"github.com/campfire-net/dontguess/pkg/matching"
)

// AllEntryBehavioralSignals returns a snapshot map of per-entry behavioral signals
// for all inventory entries that have at least one signal (consume, buyer, or deliver).
// Used by the exchange engine to update the matching index's behavioral signals
// after state changes (settle:complete, consume emission, settle:deliver).
//
// The returned map is safe to use without holding the State lock — it is a copy.
// Entries with zero signals on all fields are omitted.
func (s *State) AllEntryBehavioralSignals() map[string]matching.BehavioralSignals {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]matching.BehavioralSignals)

	// Collect consume counts.
	for entryID, count := range s.entryConsumeCount {
		if count > 0 {
			sig := out[entryID]
			sig.ConsumeCount = count
			out[entryID] = sig
		}
	}

	// Collect distinct buyer counts from per-seller EntryBuyerMap.
	for _, stats := range s.sellers {
		for entryID, buyers := range stats.EntryBuyerMap {
			if len(buyers) == 0 {
				continue
			}
			sig := out[entryID]
			sig.DistinctBuyerCount += len(buyers)
			out[entryID] = sig
		}
	}

	// Collect deliver counts (dontguess-046): feeds the false-positive demotion signal.
	for entryID, count := range s.entryDeliverCount {
		if count > 0 {
			sig := out[entryID]
			sig.DeliverCount = count
			out[entryID] = sig
		}
	}

	// Remove entries that ended up with zero signals after aggregation.
	for entryID, sig := range out {
		if sig.ConsumeCount == 0 && sig.DistinctBuyerCount == 0 && sig.DeliverCount == 0 {
			delete(out, entryID)
		}
	}

	return out
}

// ExpiryCandidateReport describes a single inventory entry flagged as a
// false-positive expiry candidate by the operator-facing report.
type ExpiryCandidateReport struct {
	// EntryID is the inventory entry's ID.
	EntryID string
	// DeliverCount is the number of times the entry was delivered.
	DeliverCount int
	// ConsumeCount is the number of times the entry was consumed.
	ConsumeCount int
	// Ratio is DeliverCount / max(ConsumeCount, 1). High ratio = strong false-positive signal.
	Ratio float64
}

// ExpiryCandidates returns an operator-facing report of inventory entries that
// are flagged as false-positive expiry candidates based on a sustained high
// deliver-without-consume ratio.
//
// An entry is a candidate when:
//   - DeliverCount >= matching.FalsePositiveWindowMin (sustained pattern, not a
//     single miss), AND
//   - ratio = DeliverCount / max(ConsumeCount, 1) >= matching.FalsePositiveRatioThreshold
//
// This is a READ-ONLY report. The exchange does NOT autonomously expire or delete
// entries based on this signal — the operator decides what action to take.
// Operators may use this list to manually expire entries, re-price them, or
// request re-validation via an assign task.
//
// Thread-safe.
func (s *State) ExpiryCandidates() []ExpiryCandidateReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build a combined deliver+consume view.
	type counts struct {
		deliver int
		consume int
	}
	combined := make(map[string]counts)
	for entryID, dc := range s.entryDeliverCount {
		if dc > 0 {
			c := combined[entryID]
			c.deliver = dc
			combined[entryID] = c
		}
	}
	for entryID, cc := range s.entryConsumeCount {
		if cc > 0 {
			c := combined[entryID]
			c.consume = cc
			combined[entryID] = c
		}
	}

	var candidates []ExpiryCandidateReport
	for entryID, c := range combined {
		sig := matching.BehavioralSignals{
			DeliverCount: c.deliver,
			ConsumeCount: c.consume,
		}
		if matching.IsFalsePositiveExpiry(sig) {
			consumeDenom := c.consume
			if consumeDenom < 1 {
				consumeDenom = 1
			}
			candidates = append(candidates, ExpiryCandidateReport{
				EntryID:      entryID,
				DeliverCount: c.deliver,
				ConsumeCount: c.consume,
				Ratio:        float64(c.deliver) / float64(consumeDenom),
			})
		}
	}

	return candidates
}

// UpdateCoOccurrence records that entryA and entryB co-occurred in the same
// buyer session (both were settled by the same buyer within a session window).
// The co-occurrence is bidirectional: both A→B and B→A are updated.
// Increments by 1 per call; the bounded map evicts the lowest-count peer when
// at capacity (K=20). Self-pairs (entryA == entryB) are silently ignored.
// Thread-safe.
func (s *State) UpdateCoOccurrence(entryA, entryB string) {
	if entryA == "" || entryB == "" || entryA == entryB {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A → B
	if s.coOccurrence[entryA] == nil {
		s.coOccurrence[entryA] = newCoOccurrenceMap()
	}
	s.coOccurrence[entryA].increment(entryB)
	// B → A
	if s.coOccurrence[entryB] == nil {
		s.coOccurrence[entryB] = newCoOccurrenceMap()
	}
	s.coOccurrence[entryB].increment(entryA)
}

// PredictNext returns the top-K entry IDs most likely to be needed after entryID,
// based on co-occurrence patterns from prior settled buyer sessions. Returns at
// most CoOccurrenceK results (or fewer if less data is available). Returns nil if
// no co-occurrence data exists for entryID.
// Thread-safe.
func (s *State) PredictNext(entryID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.coOccurrence[entryID]
	if !ok {
		return nil
	}
	return m.topK(CoOccurrenceK)
}

// OpenPredictionAssignsForEntry returns the count of open (unclaimed or actively
// claimed) brokered-match assigns whose entry_id matches entryID and whose
// DeadlineAt is in the future (or zero). Used to enforce the MaxPredictionFanout
// limit when pre-staging standing assigns.
// Caller must hold s.mu (at least read lock).
func (s *State) openPredictionAssignsForEntry(entryID string) int {
	now := time.Now().UTC()
	count := 0
	for _, rec := range s.assignsByEntry[entryID] {
		if rec.TaskType != "brokered-match" {
			continue
		}
		if rec.Status == AssignAccepted || rec.Status == AssignRejected || rec.Status == AssignPaid {
			continue
		}
		// Expired standing assigns don't count toward the fanout limit.
		if !rec.DeadlineAt.IsZero() && now.After(rec.DeadlineAt) {
			continue
		}
		count++
	}
	return count
}

// OpenPredictionAssignsForEntry is the exported thread-safe version for the engine.
// Thread-safe.
func (s *State) OpenPredictionAssignsForEntry(entryID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.openPredictionAssignsForEntry(entryID)
}

// StalePredictionAssigns returns the assign IDs of AssignOpen brokered-match
// assigns whose DeadlineAt is non-zero and has passed. These are safe to cancel
// (they will not be claimed by any worker after their deadline).
// Caller must hold s.mu (read lock is sufficient).
func (s *State) StalePredictionAssigns() []string {
	now := time.Now().UTC()
	var stale []string
	for id, rec := range s.assignByID {
		if rec.TaskType != "brokered-match" {
			continue
		}
		if rec.Status != AssignOpen {
			continue
		}
		if rec.DeadlineAt.IsZero() {
			continue
		}
		if now.After(rec.DeadlineAt) {
			stale = append(stale, id)
		}
	}
	return stale
}
