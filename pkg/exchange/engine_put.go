package exchange

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// handlePut processes an incoming exchange:put message.
//
// If a non-expired buy-miss standing offer exists for the put's task description
// (matched by SHA-256 hash), the engine auto-accepts the put at the offered price
// (token_cost * BuyMissOfferRate / 100) and pays the seller scrip immediately.
//
// If no standing offer matches, the put is left pending for normal operator review
// via AutoAcceptPut.
func (e *Engine) handlePut(msg *Message) error {
	// Determine the description from state (applyPut already validated and stored it).
	pending, ok := e.state.GetPendingPut(msg.ID)
	if !ok {
		return nil
	}

	if err := e.validatePutContentHash(pending); err != nil {
		return err
	}

	taskHash := TaskDescriptionHash(pending.Description)

	// Only the buyer who received the miss offer may fulfill it.
	offer := e.matchBuyMissOffer(msg.Sender, taskHash)
	if offer == nil {
		return nil // no matching offer — leave pending for normal operator review
	}

	return e.fulfillBuyMissOffer(msg, pending, offer, taskHash)
}

// validatePutContentHash checks that the pending put's content_hash has the
// required "sha256:" prefix.
func (e *Engine) validatePutContentHash(pending *InventoryEntry) error {
	if !strings.HasPrefix(pending.ContentHash, "sha256:") {
		return fmt.Errorf("buy-miss put rejected: content_hash %q does not have required sha256: prefix", pending.ContentHash)
	}
	return nil
}

// matchBuyMissOffer peeks and claims the buy-miss offer for the given sender and
// task hash. Returns nil if no matching offer exists or the sender doesn't match.
// Uses peek-then-atomic-claim to prevent TOCTOU double-accept.
func (e *Engine) matchBuyMissOffer(senderKey, taskHash string) *BuyMissOffer {
	peeked := e.state.GetBuyMissOffer(taskHash)
	if peeked == nil {
		return nil
	}
	if senderKey != peeked.BuyerKey {
		return nil // only the original buyer can fulfill their own miss offer
	}

	// Atomically claim to prevent TOCTOU double-accept.
	offer := e.state.ClaimBuyMissOffer(taskHash)
	if offer == nil {
		return nil // race lost — another concurrent put already claimed it
	}
	// TOCTOU guard: re-validate sender against the claimed offer.
	if offer.BuyerKey != senderKey {
		e.state.SetBuyMissOffer(offer) // restore the rightful buyer's offer
		return nil
	}
	return offer
}

// fulfillBuyMissOffer completes the buy-miss fulfillment: emits put-accept,
// pays the seller, indexes the entry, and posts a hot compression assign.
func (e *Engine) fulfillBuyMissOffer(msg *Message, pending *InventoryEntry, offer *BuyMissOffer, taskHash string) error {
	// Cap token_cost to prevent inflated scrip payouts from untrusted seller input.
	tokenCost := capTokenCost(pending.TokenCost, e.opts.maxTokenCost())

	offeredPrice := computeBuyMissOfferPrice(tokenCost)

	if err := e.emitPutAccept(msg, offeredPrice, pending, offer); err != nil {
		return err
	}

	e.paySellerForBuyMiss(msg, pending, offeredPrice, tokenCost)

	e.indexNewEntry(msg, pending)

	e.opts.log("engine: buy-miss fulfilled: put=%s seller=%s price=%d offer_task_hash=%s",
		msg.ID[:8], shortKey(pending.SellerKey), offeredPrice, taskHash[:16])
	return nil
}

// capTokenCost applies the max token_cost ceiling to prevent inflated payouts.
func capTokenCost(tokenCost, maxTokenCost int64) int64 {
	if tokenCost > maxTokenCost {
		return maxTokenCost
	}
	return tokenCost
}

// computeBuyMissOfferPrice computes the offered price from a token cost.
func computeBuyMissOfferPrice(tokenCost int64) int64 {
	price := tokenCost * BuyMissOfferRate / 100
	if price <= 0 {
		price = 1
	}
	return price
}

// emitPutAccept sends the settle(put-accept) message for a buy-miss fulfillment.
func (e *Engine) emitPutAccept(msg *Message, offeredPrice int64, pending *InventoryEntry, offer *BuyMissOffer) error {
	putAcceptPayload, err := e.marshal(map[string]any{
		"phase":      SettlePhaseStrPutAccept,
		"entry_id":   msg.ID,
		"price":      offeredPrice,
		"expires_at": "",
		"guide":      fmt.Sprintf("Buy-miss fulfillment accepted. Your entry filled a standing offer at %d%% of token_cost. It is now live in inventory — buyers searching for this topic will see it. A compression task has been posted; completing it earns additional scrip.", BuyMissOfferRate),
	})
	if err != nil {
		return fmt.Errorf("encoding buy-miss put-accept payload: %w", err)
	}

	// Tag synthetic put-accept responses so inventory metrics can exclude them.
	var putMetaPayload struct {
		Synthetic bool `json:"synthetic"`
	}
	_ = json.Unmarshal(msg.Payload, &putMetaPayload) // best-effort; error → false
	putSynthetic := isSyntheticRequest(pending.Description, putMetaPayload.Synthetic)
	tags := []string{
		TagSettle,
		TagPhasePrefix + SettlePhaseStrPutAccept,
		TagVerdictPrefix + "accepted",
		TagBuyMiss,
	}
	if putSynthetic {
		tags = append(tags, TagSynthetic)
	}
	antecedents := []string{msg.ID}

	rec, err := e.sendOperatorMessage(putAcceptPayload, tags, antecedents)
	if err != nil {
		return err
	}
	if rec != nil {
		e.state.Apply(rec)
	}
	return nil
}

// paySellerForBuyMiss pays the seller scrip for a buy-miss fulfillment and emits
// the scrip-put-pay convention message. Non-fatal: errors are logged only.
func (e *Engine) paySellerForBuyMiss(msg *Message, pending *InventoryEntry, offeredPrice, tokenCost int64) {
	if e.opts.ScripStore == nil {
		return
	}
	ctx := e.engineCtx()
	if _, _, err := e.opts.ScripStore.AddBudget(ctx, pending.SellerKey, scrip.BalanceKey, offeredPrice, ""); err != nil {
		e.opts.log("engine: buy-miss put-accept: AddBudget for seller %s: %v", shortKey(pending.SellerKey), err)
	}
	// result_hash is audit metadata only — the scrip ledger fold (applyPutPay)
	// reads Seller + Amount and IGNORES it. For a v2 confidential entry
	// (WrappedCEKOperator != "") pending.ContentHash is sha256(plaintext), the
	// operator-local dedup key; the scrip-put-pay (kind 3411) is a PUBLIC relay
	// event, so carrying it here re-broadcasts the §4.4 A1/P1 guess-confirmation
	// oracle. On the team tier every buy-miss fulfillment IS v2 (encryptedRequired
	// drops plaintext puts), so this path would leak on every payout. Use the
	// already-public CiphertextHash (sha256(ciphertext), random per entry — NOT an
	// oracle, §4.4 A7) instead. Individual-tier entries keep the plaintext hash.
	resultHash := pending.ContentHash
	if pending.WrappedCEKOperator != "" {
		resultHash = pending.CiphertextHash
	}
	// Emit scrip-put-pay so CampfireScripStore can replay the payment.
	payPayload, marshalErr := e.marshal(scrip.PutPayPayload{
		Seller:      pending.SellerKey,
		Amount:      offeredPrice,
		TokenCost:   tokenCost,
		DiscountPct: 100 - BuyMissOfferRate,
		ResultHash:  resultHash,
		PutMsg:      msg.ID,
	})
	if marshalErr == nil {
		if _, emitErr := e.sendOperatorMessage(payPayload,
			[]string{scrip.TagScripPutPay}, []string{msg.ID}); emitErr != nil {
			e.opts.log("engine: buy-miss put-accept: emit scrip-put-pay: %v", emitErr)
		}
	}
}

// indexNewEntry adds the newly accepted entry to the match index and posts a
// hot compression assign. Non-fatal: errors are logged only.
func (e *Engine) indexNewEntry(msg *Message, pending *InventoryEntry) {
	var acceptedEntry *InventoryEntry
	inv := e.state.Inventory()
	for _, entry := range inv {
		if entry.PutMsgID == msg.ID {
			e.matchIndex.Add(e.inventoryEntryToRankInput(entry))
			acceptedEntry = entry
			break
		}
	}

	// Hot compression offer.
	if acceptedEntry != nil && acceptedEntry.SellerKey != "" {
		if err := e.sendCompressionAssign(acceptedEntry); err != nil {
			e.opts.log("engine: buy-miss: compression assign failed entry=%s err=%v", msg.ID[:8], err)
		}
	}
}
