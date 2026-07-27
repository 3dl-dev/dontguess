package exchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// computePriceMinPrice is the floor price returned when an entry has no valid
// base price (TokenCost <= 0 or PutPrice <= 0 with no token cost).
// A floor of 1 prevents zero-price entries from bypassing budget filters and
// from receiving l1Efficiency=1.0 (free-item dominance) in the ranker.
const computePriceMinPrice int64 = 1

// Named constants used in computePrice and rankResults.
const (
	// Base price coefficients.
	operatorMargin    = 1.20 // operator takes 20% on top of PutPrice
	sellerShareFactor = 0.70 // seller receives 70% of TokenCost as proxy price

	// Overflow guards: largest PutPrice/TokenCost that won't overflow int64 when
	// multiplied by the corresponding margin (MaxInt64 / guard ≈ safe threshold).
	operatorMarginOverflowGuard = 120 // PutPrice * 1.20 → guard at MaxInt64/120
	sellerShareOverflowGuard    = 70  // TokenCost * 0.70 → guard at MaxInt64/70

	// Demand multiplier coefficients.
	demandCountCap   = 10   // maximum distinct buyers counted toward demand
	demandStepFactor = 0.10 // +10% per distinct completed buyer

	// Age decay (computePrice): decays linearly from 1.0 to ageDecayFloor over computePriceAgeDays.
	ageDecayFloor       = 0.5              // floor of age decay
	computePriceAgeDays = 60 * 24 * 3600.0 // age window in seconds (60 days)

	// Age decay (rankResults): recency score decays from 1.0 to 0.0 over rankResultsRecencyDays.
	rankResultsRecencyDays = 30 * 24 * 3600.0 // recency window in seconds (30 days)

	// Reputation multiplier: rep=0 -> 0.8x, rep=50 -> 1.0x, rep=100 -> 1.2x.
	repFactorBase  = 0.8 // base reputation multiplier (rep=0 -> 0.8x)
	repFactorRange = 0.4 // reputation multiplier range (rep=100 -> 1.2x = base + range)

	// Content size multiplier: +0.3% per KB, capped at +30%.
	sizeBonusPerKB = 0.003 // +0.3% per KB
	sizeBonusCap   = 0.30  // cap at +30% for sizes >= 100KB

	// Reputation weight in rankResults scoring (recency = 1.0 - scoreRepWeight).
	scoreRepWeight = 0.6

	// Compression tier price multipliers (dontguess-cb5).
	// Hot entries have high cache hit rate and low staleness — price premium reflects
	// their higher value to buyers (fewer tokens wasted on stale or unmatched results).
	tierMultiplierHot  = 1.5 // "hot"  — frequently hit, highly current
	tierMultiplierWarm = 1.2 // "warm" — moderately active
	tierMultiplierCold = 1.0 // "cold" or unset — no premium

	// --- Two-unit pricing model (dontguess-af3, operator ruling dontguess-96e) ---
	//
	// The exchange ACQUIRES in OUTPUT tokens and DELIVERS in INPUT tokens — two
	// units, deliberately, not one unit collapsed with a multiplier. TokenCost
	// (and the PutPrice derived from it at accept time) IS DEFINED AS OUTPUT
	// TOKENS — what the seller actually burned producing the artifact. See
	// CLAUDE.md §Scrip and state_put.go's plausibility check for the same
	// definition. There is no separate wire field for input tokens (ruling
	// decision 3): a buyer's real read cost is proxied by entry.ContentSize
	// (already stored, already feeding sizeFactor above) — never by TokenCost.
	//
	// outputToInputMultiplier documents WHY the acquisition side is expensive
	// relative to the delivery side (output tokens cost ~5x input tokens across
	// every model tier this exchange has seen — Fable 10/50, Opus 5/25, Sonnet
	// 3/15, Haiku 1/5 — output is consistently ~5x input). It is not multiplied
	// into computePrice's arithmetic directly (there is no code path that
	// converts one unit into the other 1:1 or otherwise here); it exists as the
	// single named source other pricing-adjacent code (e.g. engine_buy.go's
	// netBenefitStatement) can reference instead of re-deriving the ratio.
	outputToInputMultiplier = 5

	// resaleAmortizationN is the flat assumed resale count (ruling decision 4:
	// no cold-start reuse estimator — the fast/medium loops adjust later from
	// observed demand). The exchange cannot recover a seller's full OUTPUT-token
	// acquisition cost from a single buyer's INPUT-token read — that was the
	// defect this item fixes (a live match once quoted 84% of token_cost to one
	// reader). Instead every entry's asking price is amortized as if it will be
	// resold resaleAmortizationN times; break-even is re-derived (not trusted)
	// in the pricing_two_unit_af3_test.go net-positive-at-N4 test.
	//
	// resaleAmortizationN is calibrated against the STANDARD residual rate
	// (standardResidualFraction, 10%) — see resaleAmortizationDivisor below,
	// which is what computePrice actually divides by. A flat N applied
	// unmodified to a class with a DIFFERENT residual rate (high-reuse, 20%)
	// under-recovers: that was defect 1 of the veracity review on
	// dontguess-af3 (a live token_cost=8000 high-reuse entry lost 272 scrip
	// net across the assumed 4 resales instead of profiting).
	resaleAmortizationN = 4.0

	// standardResidualFraction is the residual payout fraction for standard
	// (non-high-reuse) entries: price / ResidualRate = 10%. resaleAmortizationN
	// was calibrated against this rate — it is the baseline resaleAmortizationDivisor
	// scales other residual classes against.
	standardResidualFraction = 1.0 / float64(ResidualRate)
)

// residualDenominatorFor returns the residual divisor (10 standard, 5
// high-reuse) for entry's reuse class. Single source of truth shared by
// settlement (performScripSettlement, engine_settle.go) and pricing
// (resaleAmortizationDivisor below) so the two paths can never disagree about
// which residual rate applies to a given entry — a prerequisite for pricing
// to amortize correctly against the residual settlement will actually pay.
func residualDenominatorFor(entry *InventoryEntry) int64 {
	if entry != nil && IsHighReuseArtifact(entry) {
		return HighReuseResidualDenominator
	}
	return int64(ResidualRate)
}

// residualFractionFor returns the fraction of the DELIVERY price paid out as
// seller residual for entry's reuse class (0.10 standard, 0.20 high-reuse),
// derived from residualDenominatorFor so it can never drift from the real
// settlement rate.
func residualFractionFor(entry *InventoryEntry) float64 {
	return 1.0 / float64(residualDenominatorFor(entry))
}

// resaleAmortizationDivisor returns the residual-aware amortization divisor
// computePrice actually divides the acquisition-scale base by (dontguess-af3
// defect 1 fix, veracity-reproduced 2026-07-27).
//
// The flat resaleAmortizationN=4 divisor recovers, net of residual, exactly
// base*(1-frac) across N sales. That was calibrated so standard entries
// (frac=10%) net a small profit over PutPrice at N=4 (reproduced: token_cost
// 8000 standard nets +448 scrip over PutPrice=5600 at 4 sales — the
// already-working case). High-reuse entries pay DOUBLE residual (frac=20%)
// but were divided by the SAME flat 4, so they net a LOSS at N=4 (reproduced:
// token_cost 8000 high-reuse nets -272 scrip at 4 sales, breaking even only
// at ~4.17 sales) — the assumed resale count silently didn't cover the real
// payout for that class.
//
// Fix: scale the divisor by the entry's residual burden relative to the
// standard baseline, so every reuse class recovers the SAME margin over
// PutPrice at exactly N=resaleAmortizationN sales:
//
//	D(entry) = N * (1 - residualFraction(entry)) / (1 - standardResidualFraction)
//
// For standard entries this reduces to exactly N (unchanged — the
// already-validated case is untouched, so no regression on the existing
// pinned standard-case tests). For high-reuse (frac=0.20): D = 4*0.8/0.9 ≈
// 3.556 — a SMALLER divisor than the flat 4, i.e. a HIGHER buyer price,
// because the exchange must collect more upfront per sale to fund the bigger
// residual payout it owes the seller. (A LARGER divisor — e.g. N/(1-frac) —
// would make the price and therefore post-residual revenue SMALLER for
// high-reuse: the wrong direction. Verified by the net-positive-at-N4 test
// for both classes in pricing_two_unit_af3_test.go, and by mutation:
// reverting to the flat resaleAmortizationN for all classes makes the
// high-reuse subtest net-negative at N=4 again.)
func resaleAmortizationDivisor(entry *InventoryEntry) float64 {
	frac := residualFractionFor(entry)
	return resaleAmortizationN * (1.0 - frac) / (1.0 - standardResidualFraction)
}

// computePrice returns the exchange's DELIVERY (buyer-facing) asking price for
// an entry — the scrip a buyer pays for one copy, not what the exchange paid
// to acquire the entry.
//
// Two-unit model (dontguess-af3, operator ruling dontguess-96e): ACQUISITION
// (exchange <- seller) is denominated in OUTPUT tokens — entry.TokenCost IS
// DEFINED AS OUTPUT TOKENS (see CLAUDE.md §Scrip, state_put.go plausibility
// check). DELIVERY (exchange -> buyer) is denominated in INPUT tokens, which
// are ~5x cheaper (outputToInputMultiplier) — a buyer's real read cost is
// proxied by entry.ContentSize, never by TokenCost.
//
// Acquisition-scale base: PutPrice * 1.2 (20% operator margin) when a
// put-accept exists, otherwise TokenCost * 0.7 (seller's 70% share as a proxy
// pending acceptance) — this is what the exchange paid or will pay the
// seller, unchanged from before this fix.
//
// That acquisition-scale figure is then AMORTIZED across resaleAmortizationN
// (flat 4, ruling decision 4) assumed resales before it becomes the buyer's
// per-copy asking price: the exchange runs a deficit on any single sale and
// recovers it only across resales of the same entry (the publisher model
// already documented in CLAUDE.md, never implemented in pricing until now).
// This is the fix for the one-off-commission defect: a live match once quoted
// price=6723 against token_cost_original=8000 (84%) — a reader was charged
// near-full production cost. Post-fix, the equivalent buyer price is a
// fraction of that (see TestComputePrice_BuyerPriceMaterialyBelowTokenCost).
//
// Six inventory signals adjust the acquisition-scale base BEFORE amortization:
//   - Demand count: +10% per distinct completed buyer, capped at +100%.
//   - Age decay: decays from 1.0 to 0.5 linearly over 60 days (PutTimestamp=0 = no decay).
//   - Reputation: rep=0 -> 0.8x, rep=50 -> 1.0x, rep=100 -> 1.2x.
//   - Content size: +0.3% per KB, capped at +30% (>=100KB).
//   - Compression tier: hot=1.5x, warm=1.2x, cold or unset=1.0x (dontguess-cb5).
//   - Density markup (compressed derivatives only): base * (original_size / compressed_size)
//     * DensityMarkupFactor (default 1.2). Higher density = higher per-token price.
//     Total cost is still lower than raw because fewer tokens are delivered.
//     Falls back to base pricing when the original entry is not found.
//
// Invariants:
//   - Returns at least computePriceMinPrice (never 0 or negative).
//   - Guards against int64 overflow for large TokenCost and PutPrice values.
//   - No code path converts the OUTPUT-token acquisition figure into the
//     INPUT-token delivery figure at 1:1 — it is always divided by
//     resaleAmortizationN.
func (e *Engine) computePrice(entry *InventoryEntry) int64 {
	// Step 1: acquisition-scale base (OUTPUT-token denominated — what the
	// exchange paid or will pay the seller; see dontguess-96e decision 1/3).
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

	// Compound all multipliers (still acquisition-scale, OUTPUT-token terms).
	price := base * demandFactor * ageFactor * repFactor * sizeFactor * fastFactor * densityFactor * tierFactor

	// Step 2: DELIVERY amortization (dontguess-af3/96e). Convert the
	// acquisition-scale figure into a per-copy DELIVERY price by dividing
	// across a residual-aware divisor (resaleAmortizationDivisor) built from
	// resaleAmortizationN assumed resales. This is the two-unit spread: the
	// exchange recovers what it paid the seller in OUTPUT tokens across N
	// copies sold, rather than charging one buyer the full amount as a
	// one-off commission (the defect this fixes). The divisor is scaled by
	// entry's residual class (standard vs. high-reuse) so BOTH classes are
	// net-positive at the assumed N — a flat divisor under-recovers the
	// higher (20%) high-reuse residual rate (defect 1 of the veracity review).
	price /= resaleAmortizationDivisor(entry)

	// Clamp and round (nearest-integer, not truncate, for stable results).
	rounded := math.Round(price)
	if rounded < float64(computePriceMinPrice) {
		return computePriceMinPrice
	}
	if rounded >= float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(rounded)
}

// computeDemandFactor returns the demand multiplier (+10% per buyer, capped at +100%).
func (e *Engine) computeDemandFactor(entryID string) float64 {
	demandCount := e.state.EntryDemandCount(entryID)
	if demandCount > demandCountCap {
		demandCount = demandCountCap
	}
	return 1.0 + float64(demandCount)*demandStepFactor
}

// computeAgeFactor returns the age decay factor (PutTimestamp=0 means no decay).
func computeAgeFactor(putTimestamp int64) float64 {
	if putTimestamp <= 0 {
		return 1.0
	}
	ageSec := float64(time.Now().UnixNano()-putTimestamp) / 1e9
	decay := ageSec / computePriceAgeDays
	if decay > 1.0 {
		decay = 1.0
	}
	return 1.0 - ageDecayFloor*decay
}

// computeRepFactor returns the reputation multiplier (rep=0->0.8x, rep=50->1.0x, rep=100->1.2x).
func (e *Engine) computeRepFactor(sellerKey string) float64 {
	rep := e.state.SellerReputation(sellerKey)
	return repFactorBase + float64(rep)/100.0*repFactorRange
}

// computeSizeFactor returns the content size multiplier (+0.3% per KB, capped at +30%).
func computeSizeFactor(contentSize int64) float64 {
	if contentSize <= 0 {
		return 1.0
	}
	sizeKB := float64(contentSize) / 1024.0
	sizeBonus := sizeKB * sizeBonusPerKB
	if sizeBonus > sizeBonusCap {
		sizeBonus = sizeBonusCap
	}
	return 1.0 + sizeBonus
}

// computeFastFactor returns the dynamic price adjustment multiplier from the fast pricing loop.
func (e *Engine) computeFastFactor(entryID string) float64 {
	fastAdj := e.state.GetPriceAdjustment(entryID)
	if fastAdj.Multiplier <= 0 {
		return 1.0
	}
	return fastAdj.Multiplier
}

// computeDensityFactor returns the density markup for compressed derivatives.
// Formula: (original_size / compressed_size) * density_markup_factor.
// Falls back to 1.0 when the entry is not a derivative or the original is not found.
func (e *Engine) computeDensityFactor(entry *InventoryEntry) float64 {
	if entry.CompressedFrom == "" || entry.ContentSize <= 0 {
		return 1.0
	}
	orig := e.state.GetInventoryEntry(entry.CompressedFrom)
	if orig == nil || orig.ContentSize <= 0 {
		return 1.0
	}
	ratio := float64(orig.ContentSize) / float64(entry.ContentSize)
	return ratio * e.opts.densityMarkupFactor()
}

// computeTierFactor returns the compression tier multiplier.
func computeTierFactor(tier string) float64 {
	switch tier {
	case "hot":
		return tierMultiplierHot
	case "warm":
		return tierMultiplierWarm
	default:
		return tierMultiplierCold
	}
}

// computeConfidence returns a composite confidence score [0,1].
// For v0.1 uses seller reputation as proxy.
func (e *Engine) computeConfidence(entry *InventoryEntry, _ string) float64 {
	rep := e.state.SellerReputation(entry.SellerKey)
	return float64(rep) / 100.0
}

// AutoAcceptPut sends a settle(put-accept) for a pending put message, accepting
// it into inventory at the given price and expiry. This implements automatic
// acceptance for the engine; a real deployment would add validation first.
//
// The put message must exist in the store. This method does not require the put
// to already be in the engine's in-memory state — it will replay the store to
// pick up new messages first.
//
// This is the public API entrypoint. It acquires opMu and delegates to
// autoAcceptPutLocked. RunAutoAccept (which holds opMu) calls autoAcceptPutLocked
// directly to avoid a self-deadlock.
func (e *Engine) AutoAcceptPut(putMsgID string, price int64, expiresAt time.Time) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	return e.autoAcceptPutLocked(putMsgID, price, expiresAt)
}

// autoAcceptPutLocked is the internal implementation of AutoAcceptPut.
// Callers must hold e.opMu before calling. RunAutoAccept calls this directly.
func (e *Engine) autoAcceptPutLocked(putMsgID string, price int64, expiresAt time.Time) error {
	// Refresh state before checking. In local mode this also dispatches any
	// buy appended since the last poll, so a concurrently-arriving buy is
	// matched rather than folded into State and silently dropped (dontguess-b84).
	if err := e.refreshBeforeOperatorOp(); err != nil {
		return fmt.Errorf("refresh before put-accept: %w", err)
	}

	pendingEntry, pending := e.state.GetPendingPut(putMsgID)
	var putSellerKey string
	if pending {
		putSellerKey = pendingEntry.SellerKey
	}
	_ = putSellerKey // used below after e.state.Apply(rec)
	if !pending {
		return fmt.Errorf("put %s is not pending", putMsgID)
	}

	// SEAM A (dontguess-d53, LOAD-BEARING). The poll-loop fold already staged this
	// put into pendingPuts via state_put.go applyPut, which runs with ZERO trust
	// filter; the dispatch trust gate (engine_core.go) only gates handlePut and is
	// BYPASSED on this promotion path (it reads .Level for provenance below, never
	// .Check). So auto-accept promotion is the real choke: without this gate a
	// non-admitted seller's put would become operator-blessed, matchable inventory.
	// Check the seller BEFORE emitting any operator put-accept or touching the
	// match index; a non-admitted seller is counted into a DISTINCT promotion-gate
	// counter, LOUDLY alarmed (never a silent nil-drop, LOCKED-5), and the put is
	// rejected so it leaves pendingPuts (the ticker does not re-alarm every second).
	if e.opts.TrustChecker != nil {
		if terr := e.opts.TrustChecker.Check(putSellerKey, OperationPut, ""); terr != nil {
			reason := "dropped_unlisted"
			if errors.Is(terr, ErrLowReputation) {
				e.degradation.DroppedLowReputation.Add(1)
				reason = "dropped_low_reputation"
			} else {
				e.degradation.DroppedUnlisted.Add(1)
			}
			e.opts.log("SECURITY ALARM: auto-accept promotion BLOCKED for non-admitted seller: put=%s sender=%s reason=%s: %v",
				shortKey(putMsgID), shortKey(putSellerKey), reason, terr)
			// dontguess-327: a SEAM-A trust reject must PURGE the put's content hash
			// from contentHashIndex. applyPut (state_put.go) registered that hash
			// ZERO-TRUST during the fold; left in place it permanently squats the
			// hash and silently blocks a later ALLOWLISTED seller's byte-identical
			// put (the exchange's designed high-reuse happy path) with a bare return
			// at state_put.go dedup §2. Signal the fold to purge (purgeContentHash=
			// true, TRUST-gate path ONLY — QUALITY-gate rejects keep their anti-respam
			// hash persistence) and count the purge so the previously silent
			// squat-and-block lever is observable.
			e.degradation.DroppedDedupPoison.Add(1)
			if rerr := e.rejectPutLocked(putMsgID, "trust-gate: "+reason, true); rerr != nil {
				e.opts.log("engine: put-reject after trust block failed put=%s err=%v", shortKey(putMsgID), rerr)
			}
			return fmt.Errorf("auto-accept trust-gate rejected put %s (%s): %w", putMsgID, reason, terr)
		}
	}

	var expiresAtStr string
	if !expiresAt.IsZero() {
		expiresAtStr = expiresAt.UTC().Format(time.RFC3339)
	}

	payload, err := json.Marshal(map[string]any{
		"phase":      SettlePhaseStrPutAccept,
		"entry_id":   putMsgID,
		"price":      price,
		"expires_at": expiresAtStr,
		"guide":      "Your entry is now live in inventory and searchable by buyers. A compression task has been posted for you (check exchange:assign messages) — completing it earns 50% of token_cost in scrip. You earn residuals each time a buyer purchases your content (10% standard; 20% for high-reuse distilled artifacts: schema checklists, protocol/setup READMEs, CI path filters, language-level test patterns, migration recipes — put the distilled form, not session notes).",
	})
	if err != nil {
		return fmt.Errorf("encoding put-accept payload: %w", err)
	}

	tags := []string{
		TagSettle,
		TagPhasePrefix + SettlePhaseStrPutAccept,
		TagVerdictPrefix + "accepted",
	}
	antecedents := []string{putMsgID}

	// sendOperatorMessage returns the persisted record directly — no need to
	// re-query the store. This avoids the race where lastSentMessage could
	// return a concurrently-written message instead of the one we just sent.
	rec, err := e.sendOperatorMessage(payload, tags, antecedents)
	if err != nil {
		return err
	}

	// Apply immediately so state is consistent before the next poll.
	if rec != nil {
		e.state.Apply(rec)
	}

	// Record the seller's current trust level against the newly accepted entry,
	// so a later de-allowlisting can flag the entry for re-validation.
	if e.opts.TrustChecker != nil && putSellerKey != "" {
		level := int(e.opts.TrustChecker.Level(putSellerKey))
		e.state.SetEntryProvenanceLevel(putMsgID, level)
	}

	// Incrementally update the match index with the newly accepted entry.
	inv := e.state.Inventory()
	for _, entry := range inv {
		if entry.PutMsgID == putMsgID {
			e.matchIndex.Add(e.inventoryEntryToRankInput(entry))
			break
		}
	}

	// Hot compression offer.
	if pendingEntry != nil && pendingEntry.SellerKey != "" {
		if err := e.sendCompressionAssign(pendingEntry); err != nil {
			e.opts.log("engine: compression assign failed entry=%s err=%v", putMsgID, err)
		}
	}
	return nil
}

// RejectPut sends a settle(put-reject) for a pending put message, rejecting it
// from inventory. The put must be in the pending state. After rejection the put
// is no longer actionable and will be pruned from heldForReview on the next
// RunAutoAccept tick.
func (e *Engine) RejectPut(putMsgID string, reason string) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	// Refresh state before checking. In local mode this also dispatches any
	// buy appended since the last poll (dontguess-b84).
	if err := e.refreshBeforeOperatorOp(); err != nil {
		return fmt.Errorf("refresh before put-reject: %w", err)
	}
	// QUALITY / operator-initiated reject: purgeContentHash=false so the put's
	// content hash stays registered (anti-respam persistence, state_put.go dedup
	// §2). Only the SEAM-A trust-gate path (autoAcceptPutLocked) purges the hash.
	return e.rejectPutLocked(putMsgID, reason, false)
}

// rejectPutLocked emits a settle(put-reject) for a pending put and applies it.
// Callers must hold e.opMu AND must have refreshed state (refreshBeforeOperatorOp)
// beforehand. RejectPut is the public entrypoint (refresh + this); the Seam-A
// promotion gate in autoAcceptPutLocked calls this directly (it has already
// refreshed and holds opMu) so a trust-blocked put is removed from pendingPuts
// without a nested opMu acquisition or a redundant second refresh.
//
// purgeContentHash threads the SEAM-A trust-gate purge signal into the emitted
// settle(put-reject) payload (dontguess-327). When true, the fold
// (applySettlePutReject) additionally deletes the rejected put's content hash
// from contentHashIndex — undoing the zero-trust registration applyPut made
// during the fold. It is set ONLY by the trust-gate reject path; QUALITY-gate /
// operator rejects pass false so their anti-respam hash persistence is unchanged.
func (e *Engine) rejectPutLocked(putMsgID string, reason string, purgeContentHash bool) error {
	_, pending := e.state.GetPendingPut(putMsgID)
	if !pending {
		return fmt.Errorf("put %s is not pending", putMsgID)
	}
	return e.emitPutReject(putMsgID, reason, purgeContentHash)
}

// emitPutReject sends and applies an operator-signed settle(put-reject) for
// putMsgID — the emit half of rejectPutLocked, split out so the dispatch trust
// gate can reject a put that applyPut dropped at fold (never pending), which the
// client is waiting on and otherwise times out against (dontguess-39d). It is
// idempotent for a non-pending put (applySettlePutReject guards its purge and
// no-ops its delete). It takes no opMu: it only touches LocalStore + State (each
// self-locked), like handleBuy's match emit — and opMu here would deadlock the
// refresh->dispatch reentrancy path.
func (e *Engine) emitPutReject(putMsgID string, reason string, purgeContentHash bool) error {
	fields := map[string]any{
		"phase":    SettlePhaseStrPutReject,
		"entry_id": putMsgID,
		"reason":   reason,
	}
	if purgeContentHash {
		// Emitted ONLY on the trust-gate path so QUALITY-gate reject payloads are
		// byte-unchanged and their dedup persistence stays intact.
		fields["purge_content_hash"] = true
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("encoding put-reject payload: %w", err)
	}

	tags := []string{
		TagSettle,
		TagPhasePrefix + SettlePhaseStrPutReject,
		TagVerdictPrefix + "rejected",
	}
	antecedents := []string{putMsgID}

	rec, err := e.sendOperatorMessage(payload, tags, antecedents)
	if err != nil {
		return err
	}

	// Apply immediately so state is consistent before the next poll.
	if rec != nil {
		e.state.Apply(rec)
	}
	return nil
}

// RunAutoAccept processes pending puts for one auto-accept tick.
//
// For each pending put:
//   - If TokenCost <= max: call AutoAcceptPut (log success or error as before).
//   - If TokenCost > max and NOT in skippedPuts: log skip once, insert into
//     skippedPuts (log-once guard) AND call State.HoldPutForReview (in-memory
//     classification for the operator CLI via PutsHeldForReview).
//   - If TokenCost > max and already in skippedPuts: silently skip.
//
// Lazy prune: IDs in skippedPuts that are no longer in the pending snapshot are
// removed so that if a put is later accepted (or removed) and re-submitted, it
// is logged again. State.PruneHeldForReview is called with the same pending set
// to keep the two maps consistent.
//
// # Dual-map ownership split
//
// Two maps track over-cap puts, each serving a different consumer:
//
//	skippedPuts (caller-owned, not exported):
//	  Log-once guard. Lives in the ticker goroutine (serve.go). No mutex needed
//	  — it is never accessed from another goroutine. Its sole purpose is
//	  suppressing repeated "skipping put" log lines (one per tick → ~86,400/day
//	  without it). Pruned lazily when a put leaves the pending snapshot.
//
//	heldForReview (State-owned, mutex-protected, exported):
//	  State-level classification. Protected by State's internal mutex. Consumed
//	  by the operator socket handler goroutine so "dontguess operator status"
//	  can surface held puts for human review via PutsHeldForReview(). Pruned
//	  by State.PruneHeldForReview() on the same pending snapshot, keeping both
//	  maps in sync.
//
// Both maps record the same over-cap put IDs; they differ in ownership,
// synchronization, and the consumer they serve.
//
// # Thread safety
//
// skippedPuts is owned exclusively by the caller goroutine.
// opMu serializes the state-mutating body of this function against concurrent
// AutoAcceptPut/RejectPut calls from the operator socket handler goroutine.
// heldForReview lives on State and uses its own mutex.
func (e *Engine) RunAutoAccept(max int64, now time.Time, skippedPuts map[string]struct{}) {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	pending := e.State().PendingPuts()

	// Build a set of current pending IDs for O(1) prune lookups.
	pendingIDs := make(map[string]struct{}, len(pending))
	for _, entry := range pending {
		pendingIDs[entry.PutMsgID] = struct{}{}
	}

	// Lazy prune: remove stale entries from skippedPuts and heldForReview.
	for id := range skippedPuts {
		if _, ok := pendingIDs[id]; !ok {
			delete(skippedPuts, id)
		}
	}
	e.State().PruneHeldForReview(pendingIDs)

	// Process each pending put.
	for _, entry := range pending {
		if entry.TokenCost > max {
			if _, alreadyLogged := skippedPuts[entry.PutMsgID]; !alreadyLogged {
				e.opts.log("skipping put %s: token cost %d > max %d",
					shortKey(entry.PutMsgID), entry.TokenCost, max)
				skippedPuts[entry.PutMsgID] = struct{}{}
				// Also classify as held-for-review in State so the operator CLI
				// can surface it via PutsHeldForReview(). No campfire message.
				e.State().HoldPutForReview(entry.PutMsgID)
			}
			continue
		}
		// High-reuse artifacts earn a 15-point accept-price premium (85% vs 70% of token_cost).
		pricePct := StandardAcceptPriceNumerator
		if IsHighReuseArtifact(entry) {
			pricePct = HighReuseAcceptPriceNumerator
		}
		price := entry.TokenCost * pricePct / 100
		expires := now.Add(72 * time.Hour)
		// Call the locked variant — opMu is already held by this function.
		if err := e.autoAcceptPutLocked(entry.PutMsgID, price, expires); err != nil {
			e.opts.log("auto-accept put %s failed: %v", shortKey(entry.PutMsgID), err)
		} else {
			e.opts.log("auto-accepted put %s: price=%d (token_cost=%d, high_reuse=%v)",
				shortKey(entry.PutMsgID), price, entry.TokenCost, pricePct == HighReuseAcceptPriceNumerator)
		}
	}
}
