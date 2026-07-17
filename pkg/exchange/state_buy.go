package exchange

import (
	"encoding/json"
	"time"
)

// applyBuy processes an exchange:buy message.
func (s *State) applyBuy(msg *Message) {
	var payload struct {
		Task                     string   `json:"task"`
		Budget                   int64    `json:"budget"`
		MinReputation            int      `json:"min_reputation"`
		FreshnessHours           int      `json:"freshness_hours"`
		ContentType              string   `json:"content_type"`
		Domains                  []string `json:"domains"`
		MaxResults               int      `json:"max_results"`
		CompressionTier          string   `json:"compression_tier"`
		GuaranteeDeadlineSeconds int      `json:"guarantee_deadline_seconds"`
		InsuredAmount            int64    `json:"insured_amount"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return
	}
	// Validate TAINTED fields. Drop silently — see applyPut comment.
	if len(payload.Task) > MaxTaskBytes {
		return
	}
	maxResults := payload.MaxResults
	if maxResults <= 0 {
		maxResults = 3
	}
	if maxResults > MaxBuyMaxResults {
		return
	}
	order := &ActiveOrder{
		OrderID:         msg.ID,
		BuyerKey:        msg.Sender,
		Task:            payload.Task,
		Budget:          payload.Budget,
		MinReputation:   payload.MinReputation,
		FreshnessHours:  payload.FreshnessHours,
		ContentType:     stripTagPrefix(payload.ContentType, "exchange:content-type:"),
		Domains:         stripDomainPrefixes(payload.Domains),
		MaxResults:      maxResults,
		CompressionTier: payload.CompressionTier,
		CreatedAt:       msg.Timestamp,
		InsuredAmount:   payload.InsuredAmount,
	}
	// Set guarantee deadline: receive time + deadline seconds from payload.
	if payload.GuaranteeDeadlineSeconds > 0 {
		receivedAt := time.Now().UTC()
		if msg.Timestamp > 0 {
			receivedAt = time.Unix(0, msg.Timestamp).UTC()
		}
		order.GuaranteeDeadline = receivedAt.Add(
			time.Duration(payload.GuaranteeDeadlineSeconds) * time.Second,
		)
	}
	s.activeOrders[msg.ID] = order
}

// applyMatch processes an exchange:match message.
// The match fulfills a buy future. We mark the order matched and record match→buyer.
func (s *State) applyMatch(msg *Message) {
	if s.OperatorKey != "" && msg.Sender != s.OperatorKey {
		return
	}
	// Demand-only registration (67e0 ruling): a D1-dropped unfunded miss is
	// emitted as [TagBuyMiss, TagMatch, TagDemandOnly] so `dontguess demand` sees
	// it, but it MUST NOT fold into matching/ranking/pricing (the D1 anti-Sybil
	// invariant). Route it to the dedup/cap bookkeeper and return BEFORE touching
	// any match-state map (matchedOrders / matchToBuyer / matchToEntry /
	// matchToResults). The operator-sender guard above still applies, so a forged
	// demand-only from a non-operator is dropped.
	if tagsContain(msg.Tags, TagDemandOnly) {
		s.applyDemandOnly(msg)
		return
	}
	if len(msg.Antecedents) == 0 {
		return
	}
	buyMsgID := msg.Antecedents[0]
	s.matchedOrders[buyMsgID] = struct{}{}
	// Track match → buy correlation for guarantee deadline lookup at settle time.
	s.matchToBuyMsgID[msg.ID] = buyMsgID

	// Find the buyer key from the order; also snapshot guarantee terms.
	if order, ok := s.activeOrders[buyMsgID]; ok {
		s.matchToBuyer[msg.ID] = order.BuyerKey
		if !order.GuaranteeDeadline.IsZero() {
			s.matchGuarantee[msg.ID] = [2]int64{
				order.GuaranteeDeadline.UnixNano(),
				order.InsuredAmount,
			}
		}
	}

	// Extract all result entry_ids.
	// matchToResults tracks the full set for buyer-accept validation.
	// matchToEntry is pre-populated with the first result as the default selection.
	var payload struct {
		Results []struct {
			EntryID string `json:"entry_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err == nil && len(payload.Results) > 0 {
		s.matchToEntry[msg.ID] = payload.Results[0].EntryID
		entryIDs := make([]string, 0, len(payload.Results))
		for _, r := range payload.Results {
			if r.EntryID != "" {
				entryIDs = append(entryIDs, r.EntryID)
			}
		}
		s.matchToResults[msg.ID] = entryIDs
	}
}

// applyDemandOnly folds a DEMAND-ONLY buy-miss message (67e0 ruling). It records
// ONLY the dedup + per-sender-cap bookkeeping needed by registerDemandOnly and
// never mutates any matching/ranking/pricing state — that is the whole point of
// the demand-only path (preserve the D1 anti-Sybil invariant). Caller holds s.mu
// (invoked from applyMatch, itself under applyLocked). buyer_key and task_hash
// are carried in the operator-authored payload because msg.Sender is the operator.
//
// Idempotent per message ID via demandOnlyCounted: the emitted message is folded
// once directly (e.state.Apply after emit) and again by the poll-loop snapshot
// fold, so the per-sender time list must be appended EXACTLY once — otherwise the
// window cap would trip at half the intended volume.
func (s *State) applyDemandOnly(msg *Message) {
	if _, seen := s.demandOnlyCounted[msg.ID]; seen {
		return
	}
	var p struct {
		TaskHash string `json:"task_hash"`
		BuyerKey string `json:"buyer_key"`
	}
	if err := json.Unmarshal(msg.Payload, &p); err != nil || p.TaskHash == "" {
		return
	}
	s.demandOnlyCounted[msg.ID] = struct{}{}
	s.demandOnlyTaskHashes[p.TaskHash] = struct{}{}
	if p.BuyerKey != "" {
		s.demandOnlySenderTimes[p.BuyerKey] = append(s.demandOnlySenderTimes[p.BuyerKey], msg.Timestamp)
	}
}

// tagsContain reports whether tags includes want.
func tagsContain(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
