package exchange

import (
	"encoding/json"

	"github.com/campfire-net/dontguess/pkg/scrip"
)

// NewState creates an empty exchange state.
func NewState() *State {
	return &State{
		inventory:          make(map[string]*InventoryEntry),
		pendingPuts:        make(map[string]*InventoryEntry),
		activeOrders:       make(map[string]*ActiveOrder),
		priceHistory:       nil,
		sellers:            make(map[string]*SellerStats),
		matchedOrders:      make(map[string]struct{}),
		putToEntry:         make(map[string]string),
		matchToBuyer:       make(map[string]string),
		matchToEntry:       make(map[string]string),
		matchToResults:     make(map[string][]string),
		acceptedOrders:     make(map[string]string),
		buyerAcceptToMatch: make(map[string]string),
		deliveredOrders:    make(map[string]struct{}),
		deliverToMatch:     make(map[string]string),
		completedEntries:      make(map[string]string),
		completedSettlements:  make(map[string]struct{}),
		previewsByEntry:       make(map[string]map[string]string),
		previewCountByMatch:   make(map[string]int),
		previewRequestToMatch: make(map[string]string),
		previewToMatch:        make(map[string]string),
		smallContentDisputes:  make(map[string]int),
		entryPreviewCount:     make(map[string]int),
		entryConversionCount:  make(map[string]int),
		entryConsumeCount:     make(map[string]int),
		entryDeliverCount:     make(map[string]int),
		priceAdjustments:     make(map[string]PriceAdjustment),
		matchToBuyHold:       make(map[string]string),
		assignsByEntry:       make(map[string][]*AssignRecord),
		assignByID:           make(map[string]*AssignRecord),
		claimedAssigns:       make(map[string]string),
		pendingAssignResults: make(map[string]*AssignRecord),
		claimMsgToAssign:     make(map[string]string),
		completeMsgToAssign:  make(map[string]string),
		buyMissOffers:        make(map[string]*BuyMissOffer),
		matchToBuyMsgID:      make(map[string]string),
		matchGuarantee:       make(map[string][2]int64),
		brokerAssigns:        make(map[string]string),
		brokerMatchIDs:       make(map[string]struct{}),
		debtorScores:         make(map[string]float64),
		coOccurrence:         make(map[string]*coOccurrenceMap),
		senderHopDepth:       make(map[string][]int),
		federationProfiles:   make(map[string]*FederationNodeProfile),
		heldForReview:        make(map[string]struct{}),
		contentHashIndex:     make(map[string]struct{}),
	}
}

// Replay builds state from scratch by processing all messages in log order.
// It resets the state before processing. Thread-safe.
func (s *State) Replay(msgs []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset.
	s.inventory = make(map[string]*InventoryEntry)
	s.pendingPuts = make(map[string]*InventoryEntry)
	s.activeOrders = make(map[string]*ActiveOrder)
	s.priceHistory = nil
	s.sellers = make(map[string]*SellerStats)
	s.matchedOrders = make(map[string]struct{})
	s.putToEntry = make(map[string]string)
	s.matchToBuyer = make(map[string]string)
	s.matchToEntry = make(map[string]string)
	s.matchToResults = make(map[string][]string)
	s.acceptedOrders = make(map[string]string)
	s.buyerAcceptToMatch = make(map[string]string)
	s.deliveredOrders = make(map[string]struct{})
	s.deliverToMatch = make(map[string]string)
	s.completedEntries = make(map[string]string)
	s.completedSettlements = make(map[string]struct{})
	s.previewsByEntry = make(map[string]map[string]string)
	s.previewCountByMatch = make(map[string]int)
	s.previewRequestToMatch = make(map[string]string)
	s.previewToMatch = make(map[string]string)
	s.smallContentDisputes = make(map[string]int)
	s.entryPreviewCount = make(map[string]int)
	s.entryConversionCount = make(map[string]int)
	s.entryConsumeCount = make(map[string]int)
	s.entryDeliverCount = make(map[string]int)
	s.matchToBuyHold = make(map[string]string)
	s.assignsByEntry = make(map[string][]*AssignRecord)
	s.assignByID = make(map[string]*AssignRecord)
	s.claimedAssigns = make(map[string]string)
	s.pendingAssignResults = make(map[string]*AssignRecord)
	s.claimMsgToAssign = make(map[string]string)
	s.completeMsgToAssign = make(map[string]string)
	s.buyMissOffers = make(map[string]*BuyMissOffer)
	s.matchToBuyMsgID = make(map[string]string)
	s.matchGuarantee = make(map[string][2]int64)
	s.brokerAssigns = make(map[string]string)
	s.coOccurrence = make(map[string]*coOccurrenceMap)
	// Note: priceAdjustments and brokerMatchIDs are intentionally NOT reset on
	// Replay. They are externally written (by the fast pricing loop and engine
	// respectively), not derived from the campfire log.
	s.brokeredAcceptedOrders = 0
	s.brokeredCompletions = 0
	// senderHopDepth is re-derived from the campfire log on Replay.
	// Reset it so the replay loop rebuilds it cleanly from messages.
	s.senderHopDepth = make(map[string][]int)
	// contentHashIndex is rebuilt from the campfire log on Replay.
	// The replay loop re-runs applyPut for every exchange:put message, which
	// repopulates the index from the canonical log.
	s.contentHashIndex = make(map[string]struct{})
	// federationProfiles is NOT reset on Replay. The trust_score values written
	// by the slow loop (via SetFederationTrustScore) are externally managed and
	// must survive engine restarts. The HopDepth and FirstSeenAt fields will be
	// updated as messages replay (via trackSenderHopDepth). New senders will get
	// profiles created during replay; existing profiles keep their trust_scores.

	for i := range msgs {
		s.applyLocked(&msgs[i])
	}
}

// Apply processes a single new message, updating state.
// Thread-safe.
func (s *State) Apply(msg *Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyLocked(msg)
}

// applyLocked applies a message to state. Caller must hold s.mu.
func (s *State) applyLocked(msg *Message) {
	// Track provenance hop depth for every message from a known sender.
	// Hop depth is approximated from the Antecedents chain length.
	// This populates senderHopDepth for the slow loop's trust_score computation.
	if msg.Sender != "" {
		s.trackSenderHopDepth(msg)
	}

	op := exchangeOp(msg.Tags)
	switch op {
	case TagPut:
		s.applyPut(msg)
	case TagBuy:
		s.applyBuy(msg)
	case TagMatch:
		s.applyMatch(msg)
	case TagSettle:
		s.applySettle(msg)
	case TagAssign:
		s.applyAssign(msg)
	case TagAssignClaim:
		s.applyAssignClaim(msg)
	case TagAssignComplete:
		s.applyAssignComplete(msg)
	case TagAssignAccept:
		s.applyAssignAccept(msg)
	case TagAssignReject:
		s.applyAssignReject(msg)
	case TagAssignExpire:
		s.applyAssignExpire(msg)
	case TagAssignAuctionClose:
		s.applyAssignAuctionClose(msg)
	default:
		// Handle non-exchange-op messages that carry known tags.
		for _, tag := range msg.Tags {
			switch tag {
			case scrip.TagScripBuyHold:
				s.applyScripBuyHold(msg)
				return
			case TagConsume:
				s.applyConsume(msg)
				return
			}
		}
	}
}

// applyScripBuyHold indexes a scrip-buy-hold message into matchToBuyHold.
// Enables O(1) lookup in GetBuyHoldReservation, replacing the O(n) log scan
// in findExistingBuyerAcceptHold.
func (s *State) applyScripBuyHold(msg *Message) {
	var p scrip.BuyHoldPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return
	}
	if p.BuyMsg == "" || p.ReservationID == "" {
		return
	}
	s.matchToBuyHold[p.BuyMsg] = p.ReservationID
}

// GetBuyHoldReservation returns the reservation ID for a prior scrip-buy-hold
// message matching the given match message ID, or "" if none exists.
// O(1) — replaces the O(n) log scan in findExistingBuyerAcceptHold.
func (s *State) GetBuyHoldReservation(matchMsgID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchToBuyHold[matchMsgID]
}

// applyConsume processes an exchange:consume message, incrementing the
// per-entry consume counter. The entry_id is read from the payload and must
// be non-empty to count. Called from applyLocked.
//
// Operator-sender guard: consume messages must originate from the operator.
// Any non-operator sender is silently rejected to prevent arbitrary campfire
// members from inflating entryConsumeCount and gaming the behavioral booster.
func (s *State) applyConsume(msg *Message) {
	if s.OperatorKey != "" && msg.Sender != s.OperatorKey {
		return
	}
	var p struct {
		EntryID string `json:"entry_id"`
	}
	if err := json.Unmarshal(msg.Payload, &p); err != nil || p.EntryID == "" {
		return
	}
	s.entryConsumeCount[p.EntryID]++
}
