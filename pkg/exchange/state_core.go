package exchange

import (
	"encoding/json"

	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// NewState creates an empty exchange state.
func NewState() *State {
	return &State{
		inventory:              make(map[string]*InventoryEntry),
		pendingPuts:            make(map[string]*InventoryEntry),
		activeOrders:           make(map[string]*ActiveOrder),
		priceHistory:           nil,
		sellers:                make(map[string]*SellerStats),
		matchedOrders:          make(map[string]struct{}),
		putToEntry:             make(map[string]string),
		matchToBuyer:           make(map[string]string),
		matchToEntry:           make(map[string]string),
		matchToResults:         make(map[string][]string),
		acceptedOrders:         make(map[string]string),
		buyerAcceptToMatch:     make(map[string]string),
		deliveredOrders:        make(map[string]struct{}),
		deliverToMatch:         make(map[string]string),
		deliverTimeByMatch:     make(map[string]int64),
		completedEntries:       make(map[string]string),
		completedSettlements:   make(map[string]struct{}),
		previewsByEntry:        make(map[string]map[string]string),
		previewCountByMatch:    make(map[string]int),
		previewRequestToMatch:  make(map[string]string),
		previewToMatch:         make(map[string]string),
		smallContentDisputes:   make(map[string]int),
		entryPreviewCount:      make(map[string]int),
		entryConversionCount:   make(map[string]int),
		entryConsumeCount:      make(map[string]int),
		entryDeliverCount:      make(map[string]int),
		buyerDeliverCount:      make(map[string]int),
		buyerConsumeCount:      make(map[string]int),
		entryDeliverBuyerCount: make(map[string]map[string]int),
		entryConsumeBuyerCount: make(map[string]map[string]int),
		priceAdjustments:       make(map[string]PriceAdjustment),
		wireToStore:            make(map[string]string),
		matchToBuyHold:         make(map[string]string),
		matchToBuyHoldAmount:   make(map[string]int64),
		settledMatches:         make(map[string]struct{}),
		assignsByEntry:         make(map[string][]*AssignRecord),
		assignByID:             make(map[string]*AssignRecord),
		claimedAssigns:         make(map[string]string),
		pendingAssignResults:   make(map[string]*AssignRecord),
		claimMsgToAssign:       make(map[string]string),
		completeMsgToAssign:    make(map[string]string),
		buyMissOffers:          make(map[string]*BuyMissOffer),
		demandOnlyTaskHashes:   make(map[string]int64),
		demandOnlySenderTimes:  make(map[string][]int64),
		demandOnlyCounted:      make(map[string]struct{}),
		matchToBuyMsgID:        make(map[string]string),
		matchGuarantee:         make(map[string][2]int64),
		brokerAssigns:          make(map[string]string),
		brokerMatchIDs:         make(map[string]struct{}),
		debtorScores:           make(map[string]float64),
		coOccurrence:           make(map[string]*coOccurrenceMap),
		senderHopDepth:         make(map[string][]int),
		federationProfiles:     make(map[string]*FederationNodeProfile),
		heldForReview:          make(map[string]struct{}),
		contentHashIndex:       make(map[string]struct{}),
		foldDenialCounted:      make(map[string]struct{}),
		hopDepthCounted:        make(map[string]struct{}),
		consumeCounted:         make(map[string]struct{}),
		disputeCounted:         make(map[string]struct{}),
	}
}

// replayFoldWindow is the number of log messages folded per Replay window
// (dontguess-0ba). Replay prefetches only ONE window's offloaded-put ciphertexts
// off the lock at a time, folds them, then discards them before prefetching the
// next window — so resident blob memory is bounded to at most this many
// ciphertexts (≤ replayFoldWindow × MaxContentBytes) regardless of how many
// offloaded puts the log contains. The old code prefetched EVERY offloaded blob
// in the whole log into one map before folding, which is O(log) resident and
// OOMs / stalls a Replay of a large offloaded-put log. A window is a message
// count, not a byte budget: each individual blob is already separately capped
// (fetch drop > MaxContentBytes, dontguess-00d), so a fixed count bounds the
// aggregate. Larger = fewer lock reacquisitions; smaller = tighter memory bound.
const replayFoldWindow = 128

// Replay builds state from scratch by processing all messages in log order.
// It resets the state before processing. Thread-safe.
//
// Memory-bounded windowed fold (dontguess-0ba): Replay no longer prefetches the
// WHOLE log's offloaded ciphertexts into one map, nor holds s.mu across the
// entire fold. It processes the log in replayFoldWindow-sized windows; for each
// window it prefetches only that window's ciphertexts OFF the lock (preserving
// the dontguess-a5e discipline that no BlobStore.Fetch ever runs under s.mu),
// then folds the window under s.mu and releases. Resident blob memory is thus
// O(window), not O(log). The reset + operator-put-accept pre-scan run under the
// FIRST window's lock (beginReplayLocked) so the reset and the first fold are
// atomic; the replay scope (replaying / replayPutAccepts / replayMsgIDs) stays
// installed across the inter-window lock gaps and is torn down by endReplayLocked
// after the last window. Because that scope is live during the gaps, every
// replay-only fold behavior gates on replayMsgIDs (isReplayMsg) rather than the
// bare s.replaying flag, so a concurrent live Apply interleaving in a gap is
// never mistaken for replay (see replayMsgIDs doc + isReplayMsg).
func (s *State) Replay(msgs []Message) {
	// Build the replay msg-ID set up front (pure, off-lock). This is the scope
	// every replay-only behavior keys on so a live Apply in a between-window gap
	// is treated as live, not replay (dontguess-0ba).
	replaySet := make(map[string]struct{}, len(msgs))
	for i := range msgs {
		replaySet[msgs[i].ID] = struct{}{}
	}

	first := true
	for start := 0; start < len(msgs); start += replayFoldWindow {
		end := start + replayFoldWindow
		if end > len(msgs) {
			end = len(msgs)
		}
		batch := msgs[start:end]

		// Prefetch ONLY this window's offloaded ciphertexts, off the lock. The
		// returned map holds at most this window's blobs and is discarded when the
		// window's fold returns — bounding resident blob memory to O(window).
		prefetchTargets := make([]*Message, len(batch))
		for i := range batch {
			prefetchTargets[i] = &batch[i]
		}
		blobs := s.prefetchPutBlobs(prefetchTargets)

		s.mu.Lock()
		if first {
			// Reset + install replay scope + pre-scan put-accepts atomically with
			// the first window's fold, so no reader/Apply observes a reset-but-not-
			// yet-refolded state gap before folding begins.
			s.beginReplayLocked(msgs, replaySet)
			first = false
		}
		for i := range batch {
			s.applyLocked(&batch[i], blobs)
		}
		s.mu.Unlock()
	}

	// Empty log: no window ran, but Replay must still reset state (the pre-0ba
	// contract that Replay(nil) wipes state) and leave the replay scope cleared.
	if first {
		s.mu.Lock()
		s.beginReplayLocked(msgs, replaySet)
		s.endReplayLocked()
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.endReplayLocked()
	s.mu.Unlock()
}

// beginReplayLocked installs the replay scope, pre-scans the log for operator
// put-accepts, and resets all log-derived state. Caller holds s.mu. Split out of
// Replay so the reset runs under the first window's lock (dontguess-0ba).
func (s *State) beginReplayLocked(msgs []Message, replaySet map[string]struct{}) {
	// Suppress fold-guard denial counting for messages BELONGING TO the replay:
	// the full log is re-applied on every engine restart / state rebuild, so a
	// forged message already on the log must not re-increment the live alarm
	// counters each time (dontguess-9ed). Only real-time Apply counts. Scoped by
	// replayMsgIDs (not the bare flag) so a live Apply in a between-window gap
	// still counts (dontguess-0ba).
	s.replaying = true
	s.replayMsgIDs = replaySet

	// Pre-scan the log for operator put-accepts (dontguess-00d FIX 1). The §6
	// legacy-plaintext grandfather block in applyPut only fires for a put that
	// was PREVIOUSLY ACCEPTED — a genuine pre-cutover plaintext put has an
	// operator put-accept in the log; a post-cutover plaintext put was
	// fail-closed dropped live and has none. applyPut runs during the fold loop,
	// but a put-accept always folds AFTER its put (it e-tags the put as its
	// antecedent), so applyPut cannot learn "was accepted?" from live fold order.
	// This pre-scan resolves it: collect the put IDs that any operator put-accept
	// references so applyPut can gate grandfathering on membership. The
	// operator-sender guard mirrors applySettlePutAccept exactly (an empty
	// OperatorKey accepts any sender; a set key requires a match) so a forged
	// non-operator put-accept cannot bait a post-cutover plaintext put into
	// inventory. Cleared by endReplayLocked — meaningful only for this replay.
	s.replayPutAccepts = make(map[string]struct{}, len(msgs))
	for i := range msgs {
		m := &msgs[i]
		if exchangeOp(m.Tags) != TagSettle {
			continue
		}
		if settlePhaseFromTags(m.Tags) != SettlePhaseStrPutAccept {
			continue
		}
		// resolveAlias canonicalizes a pre-P3 legacy operator sender to the stable
		// nostr operator key (design §6, ADV-17) so a solo-era put-accept still
		// grandfathers its plaintext put; identity for every non-aliased sender, so
		// the forged-non-operator rejection below is unchanged where no alias exists.
		if s.OperatorKey != "" && s.resolveAlias(m.Sender) != s.OperatorKey {
			continue
		}
		if len(m.Antecedents) == 0 {
			continue
		}
		s.replayPutAccepts[m.Antecedents[0]] = struct{}{}
	}

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
	s.deliverTimeByMatch = make(map[string]int64)
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
	s.buyerDeliverCount = make(map[string]int)
	s.buyerConsumeCount = make(map[string]int)
	s.entryDeliverBuyerCount = make(map[string]map[string]int)
	s.entryConsumeBuyerCount = make(map[string]map[string]int)
	s.matchToBuyHold = make(map[string]string)
	s.matchToBuyHoldAmount = make(map[string]int64)
	s.settledMatches = make(map[string]struct{})
	s.assignsByEntry = make(map[string][]*AssignRecord)
	s.assignByID = make(map[string]*AssignRecord)
	s.claimedAssigns = make(map[string]string)
	s.pendingAssignResults = make(map[string]*AssignRecord)
	s.claimMsgToAssign = make(map[string]string)
	s.completeMsgToAssign = make(map[string]string)
	s.buyMissOffers = make(map[string]*BuyMissOffer)
	// Demand-only D1 bookkeeping (67e0) is derived from the log: reset so Replay
	// rebuilds the dedup set + per-sender window from the demand-only messages.
	s.demandOnlyTaskHashes = make(map[string]int64)
	s.demandOnlySenderTimes = make(map[string][]int64)
	s.demandOnlyCounted = make(map[string]struct{})
	s.matchToBuyMsgID = make(map[string]string)
	s.matchGuarantee = make(map[string][2]int64)
	s.brokerAssigns = make(map[string]string)
	s.coOccurrence = make(map[string]*coOccurrenceMap)
	// Note: priceAdjustments and brokerMatchIDs are intentionally NOT reset on
	// Replay. They are externally written (by the fast pricing loop and engine
	// respectively), not derived from the campfire log.
	// wireToStore is likewise NOT reset on Replay (dontguess-55c GAP 1): the
	// wire→store alias is a deterministic function of the operator log + the
	// operator signer, but State has no signer to re-derive it — the Outbox
	// (live) and seedEmittedFromStore (restart) repopulate it. Wiping it here
	// would strand every in-flight wire-id-tagged settle until the next publish.
	s.brokeredAcceptedOrders = 0
	s.brokeredCompletions = 0
	// senderHopDepth is re-derived from the campfire log on Replay.
	// Reset it so the replay loop rebuilds it cleanly from messages.
	s.senderHopDepth = make(map[string][]int)
	// contentHashIndex is rebuilt from the campfire log on Replay.
	// The replay loop re-runs applyPut for every exchange:put message, which
	// repopulates the index from the canonical log.
	s.contentHashIndex = make(map[string]struct{})
	// Fold-accumulator dedup guards (dontguess-f86) are reset so a full rebuild
	// starts fresh and repopulates them in log order as the windowed fold runs.
	s.foldDenialCounted = make(map[string]struct{})
	s.hopDepthCounted = make(map[string]struct{})
	s.consumeCounted = make(map[string]struct{})
	s.disputeCounted = make(map[string]struct{})
	// federationProfiles is NOT reset on Replay. The trust_score values written
	// by the slow loop (via SetFederationTrustScore) are externally managed and
	// must survive engine restarts. The HopDepth and FirstSeenAt fields will be
	// updated as messages replay (via trackSenderHopDepth). New senders will get
	// profiles created during replay; existing profiles keep their trust_scores.
}

// endReplayLocked tears down the replay scope installed by beginReplayLocked.
// Caller holds s.mu. Called once after the final Replay window (dontguess-0ba).
func (s *State) endReplayLocked() {
	s.replaying = false
	s.replayPutAccepts = nil
	s.replayMsgIDs = nil
}

// isReplayMsg reports whether id belongs to the log currently being replayed.
// Caller holds s.mu. Replay-only fold behaviors (the §6 legacy-plaintext
// grandfather admission and recordFoldDenial suppression) gate on THIS, not the
// bare s.replaying flag: because Replay folds in memory-bounded windows and
// releases s.mu between them (dontguess-0ba), a concurrent live Apply can
// interleave while s.replaying is still true. Such a live message is not part of
// the replay log — its ID is absent here — so it is treated as live, preserving
// the fail-closed drop of a live plaintext downgrade and the alarm on a live
// fold-guard denial that a bare-flag check would wrongly suppress.
func (s *State) isReplayMsg(id string) bool {
	if s.replayMsgIDs == nil {
		return false
	}
	_, ok := s.replayMsgIDs[id]
	return ok
}

// Apply processes a single new message, updating state.
// Thread-safe.
func (s *State) Apply(msg *Message) {
	// Fetch any offloaded-put ciphertext BEFORE taking s.mu (dontguess-a5e): a
	// slow/hung Blossom HTTP fetch must never stall State reads/writes under the
	// write lock during live-fold. The pre-fetched blobs are threaded into the
	// fold; decryptV2Put reads them instead of calling BlobStore.Fetch under s.mu.
	blobs := s.prefetchPutBlobs([]*Message{msg})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyLocked(msg, blobs)
}

// applyLocked applies a message to state. Caller must hold s.mu. blobs carries
// any offloaded-put ciphertext pre-fetched off the lock (dontguess-a5e); it is
// nil when no blob store is configured or the message references no blob.
func (s *State) applyLocked(msg *Message, blobs map[string][]byte) {
	// P3 operator-identity migration (design §6, ADV-17): a pre-P3 solo home signed
	// its operator records under an opaque local operator key that serve registers
	// as a wire-alias of the stable nostr operator key (RegisterWireAlias). Canonicalize
	// the sender through that alias BEFORE any operator-sender gate or attribution so
	// historical solo operator records fold under State.OperatorKey instead of being
	// dropped by the sender-must-be-operator guards. resolveAlias is the identity for
	// every non-aliased sender — participant keys, the operator's own nostr key, and
	// every sender on a fresh home / the in-process suite where no operator-key alias
	// is registered — so this is byte-for-byte unchanged wherever the migration did
	// not run. (Namespaces never collide: an operator wire-alias key is a pubkey; the
	// message-id aliases in the same map are content-hash event ids.)
	if canon := s.resolveAlias(msg.Sender); canon != msg.Sender {
		c := *msg
		c.Sender = canon
		msg = &c
	}

	// Track provenance hop depth for every message from a known sender.
	// Hop depth is approximated from the Antecedents chain length.
	// This populates senderHopDepth for the slow loop's trust_score computation.
	if msg.Sender != "" {
		s.trackSenderHopDepth(msg)
	}

	op := exchangeOp(msg.Tags)
	switch op {
	case TagPut:
		s.applyPut(msg, blobs)
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
		// Canonical ops with no switch case above (scrip ops, consume) dispatch
		// here. CRITICAL (dontguess-5be, docs/design/relay-transport.md §2.4a D2):
		// dispatch on the RESOLVED op, never on a raw msg.Tags scan. exchangeOp
		// already enforced the single-canonical-op invariant — if it returned ""
		// the message is ambiguous/smuggled (two+ distinct canonical ops) or
		// carries no canonical op at all, and MUST be dropped, consistent with
		// the switch path. A raw msg.Tags scan would instead fire a handler off a
		// smuggled tag (e.g. [scrip-buy-hold, assign-auction-close] resolving to
		// "" yet still triggering applyScripBuyHold) — the residual half of the
		// parser-differential that c22/e15/13c closed only for the switch path.
		switch op {
		case scrip.TagScripBuyHold:
			s.applyScripBuyHold(msg)
		case scrip.TagScripSettle:
			s.applyScripSettle(msg)
		case TagConsume:
			s.applyConsume(msg)
		}
	}
}

// recordFoldDenial counts + alarms a security-relevant fold-guard rejection
// (operator-only settlement guard, or the buyer-identity gate) via the callback
// wired by NewEngine. It is a no-op for a message BELONGING TO the replay log (so
// a re-applied log does not re-inflate the counters) and when no callback is
// wired (State built directly in tests). Caller must hold s.mu — the callback
// only touches atomic counters and the logger, so holding s.mu across it
// introduces no lock-ordering hazard.
//
// Replay suppression is scoped to isReplayMsg, NOT the bare s.replaying flag
// (dontguess-0ba): Replay now folds in memory-bounded windows and releases s.mu
// between them, so a concurrent live Apply can run while s.replaying is still
// true. A live message is not in the replay log, so isReplayMsg is false and its
// denial IS counted+alarmed — a live forged non-operator settle/consume in a
// between-window gap must not have its alarm swallowed just because a Replay is
// in flight. Replay-log messages still suppress exactly as before.
//
// Per-message-ID dedup guard (dontguess-f86): foldDenialCounted ensures a given
// message's denial is counted at most once even if the SAME message is folded
// twice — e.g. once inside a concurrent rebuildAndDispatchGapLocal's full
// state.Replay and again by a poll-loop foldAndDispatchLocalSnapshot's stale,
// unlocked in-flight Apply loop (see State.foldDenialCounted doc). Previously
// this guard was ONLY s.replaying, which suppresses counting for the entire
// duration of a Replay call but does nothing once Replay returns — so a
// message re-applied via a standalone Apply after Replay finished still
// double-counted its denial reason.
func (s *State) recordFoldDenial(reason foldDenialReason, msg *Message) {
	if s.onFoldDenial == nil {
		return
	}
	if s.replaying && s.isReplayMsg(msg.ID) {
		return
	}
	if _, seen := s.foldDenialCounted[msg.ID]; seen {
		return
	}
	s.foldDenialCounted[msg.ID] = struct{}{}
	s.onFoldDenial(reason, msg)
}

// applyScripBuyHold indexes a scrip-buy-hold message into matchToBuyHold (and
// records the ORIGINAL held amount in matchToBuyHoldAmount). Enables O(1) lookup
// in GetBuyHoldReservation / GetBuyHoldAmount, replacing the O(n) log scan in
// findExistingBuyerAcceptHold.
func (s *State) applyScripBuyHold(msg *Message) {
	var p scrip.BuyHoldPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return
	}
	if p.BuyMsg == "" || p.ReservationID == "" {
		return
	}
	s.matchToBuyHold[p.BuyMsg] = p.ReservationID
	// Record the original held amount so restoreExistingHold can restore the
	// EXACT scrip that was decremented at buyer-accept time, rather than
	// recomputing from a possibly-drifted current price (dontguess-471 MED).
	s.matchToBuyHoldAmount[p.BuyMsg] = p.Amount
}

// GetBuyHoldReservation returns the reservation ID for a prior scrip-buy-hold
// message matching the given match message ID, or "" if none exists.
// O(1) — replaces the O(n) log scan in findExistingBuyerAcceptHold.
func (s *State) GetBuyHoldReservation(matchMsgID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchToBuyHold[matchMsgID]
}

// GetBuyHoldAmount returns the ORIGINAL held amount (price + fee) recorded in the
// scrip-buy-hold event for the given match, and whether one exists. Used by
// restoreExistingHold to re-hydrate a reservation with the exact amount held at
// buyer-accept time instead of recomputing from the current dynamic price
// (dontguess-471). Returns (0, false) when no buy-hold has been recorded.
func (s *State) GetBuyHoldAmount(matchMsgID string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	amt, ok := s.matchToBuyHoldAmount[matchMsgID]
	return amt, ok
}

// applyScripSettle folds a durable scrip-settle message (dontguess-400 FIX-M1,
// design §1.4/§4). It marks the settled match in the durable settledMatches set
// and RETIRES the match's buy-hold index (matchToBuyHold + matchToBuyHoldAmount)
// so a replayed/re-sent buyer-accept for an already-settled match can neither
// re-hydrate the consumed reservation (restoreExistingHold) nor re-settle
// (performScripSettlement). The match key is SettlePayload.MatchMsg — the match
// msg ID the settlement is for.
//
// Operator-sender guard: scrip-settle is operator-authored egress. A non-operator
// sender is rejected (mirrors applyConsume / the scrip-ledger operator gate) so a
// participant cannot forge a settle marker to grief a live match's settlement.
func (s *State) applyScripSettle(msg *Message) {
	if s.OperatorKey != "" && msg.Sender != s.OperatorKey {
		s.recordFoldDenial(foldDenialNotOperator, msg)
		return
	}
	var p scrip.SettlePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil || p.MatchMsg == "" {
		return
	}
	s.markMatchSettledLocked(p.MatchMsg)
}

// markMatchSettledLocked records matchMsgID as settled and retires its buy-hold
// index. Caller must hold s.mu. Shared by the durable fold path (applyScripSettle)
// and the live-mark path (MarkMatchSettled).
func (s *State) markMatchSettledLocked(matchMsgID string) {
	if matchMsgID == "" {
		return
	}
	s.settledMatches[matchMsgID] = struct{}{}
	delete(s.matchToBuyHold, matchMsgID)
	delete(s.matchToBuyHoldAmount, matchMsgID)
}

// MarkMatchSettled marks a match settled from the live settlement path
// (performScripSettlement), so the settled-match guard holds WITHIN the current
// session — before the durable scrip-settle folds on the next poll. The same set
// is rebuilt independently on Replay by applyScripSettle. Idempotent.
func (s *State) MarkMatchSettled(matchMsgID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markMatchSettledLocked(matchMsgID)
}

// IsMatchSettled reports whether a scrip settlement has already been durably
// emitted (or live-marked) for the given match msg ID. Used by the engine to
// gate restoreExistingHold, handleSettleBuyerAcceptScrip and
// performScripSettlement against a double-settle mint (dontguess-400 FIX-M1).
func (s *State) IsMatchSettled(matchMsgID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.settledMatches[matchMsgID]
	return ok
}

// applyConsume processes an exchange:consume message, incrementing the
// per-entry consume counter. The entry_id is read from the payload and must
// be non-empty to count. Called from applyLocked.
//
// Operator-sender guard: consume messages must originate from the operator.
// A non-operator sender is rejected to prevent arbitrary campfire members from
// inflating entryConsumeCount and gaming the behavioral booster — counted +
// alarmed as an operator-forgery drop rather than dropped silently
// (dontguess-471 LOCKED-5).
func (s *State) applyConsume(msg *Message) {
	if s.OperatorKey != "" && msg.Sender != s.OperatorKey {
		s.recordFoldDenial(foldDenialNotOperator, msg)
		return
	}
	// Per-message-ID dedup guard (dontguess-f86, consumeCounted): entryConsumeCount++
	// is a raw counter increment with no natural per-message-ID map to dedup
	// against. Without this guard a concurrent rebuildAndDispatchGapLocal
	// state.Replay racing foldAndDispatchLocalSnapshot's unlocked incremental
	// Apply loop double-counts the consume signal (see State.foldDenialCounted
	// doc for the exact interleave), skewing the M5 consume signal
	// (dontguess-860) the pricing/behavioral-signal layer reads.
	if _, dup := s.consumeCounted[msg.ID]; dup {
		return
	}
	var p struct {
		EntryID string `json:"entry_id"`
	}
	if err := json.Unmarshal(msg.Payload, &p); err != nil || p.EntryID == "" {
		return
	}
	s.consumeCounted[msg.ID] = struct{}{}
	s.entryConsumeCount[p.EntryID]++
}
