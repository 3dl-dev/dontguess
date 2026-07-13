package exchange

import (
	"github.com/3dl-dev/dontguess/pkg/matching"
)

// rebuildMatchIndex rebuilds the semantic match index from the current live inventory.
// Called after replay and when the inventory changes significantly.
func (e *Engine) rebuildMatchIndex() {
	inventory := e.state.Inventory()
	inputs := make([]matching.RankInput, 0, len(inventory))
	for _, entry := range inventory {
		// SEAM D (dontguess-d53, reload re-gate): rebuild re-indexes
		// state.Inventory() with ZERO trust filter, and NeedsRevalidation /
		// AcceptedProvenanceLevel are in-memory-only (reset to zero on Replay).
		// Without this re-gate, de-allowlisting a seller is ERASED by any restart —
		// their inventory silently re-enters the searchable index. Re-gate every
		// entry's SellerKey against the LIVE allowlist: a seller no longer at least
		// allowlisted (de-allowlisted → anonymous) is flagged NeedsRevalidation (so
		// findCandidates also withholds it) and skipped from the index. Membership
		// only — the reputation floor is a sell-side demotion enforced at promotion
		// (Seam A) and by findCandidates' minRep filter, not a reason to drop an
		// already-accepted allowlisted seller's inventory on reload. Nil checker
		// (individual/no-relay tier) → no filtering, byte-for-byte unchanged.
		if e.opts.TrustChecker != nil && e.opts.TrustChecker.Level(entry.SellerKey) < TrustAllowlisted {
			e.state.FlagEntryForRevalidation(entry.EntryID)
			continue
		}
		inputs = append(inputs, e.inventoryEntryToRankInput(entry))
	}
	e.matchIndex.Rebuild(inputs)
	// Refresh behavioral signals in the index after rebuild so the ranker sees
	// current consume counts and distinct buyer counts from state.
	e.matchIndex.SetBehavioralSignals(e.state.AllEntryBehavioralSignals())
}

// inventoryEntryToRankInput converts an InventoryEntry to a matching.RankInput.
// Price is computed by the engine's pricing logic so the ranker sees current ask price.
func (e *Engine) inventoryEntryToRankInput(entry *InventoryEntry) matching.RankInput {
	return matching.RankInput{
		EntryID:          entry.EntryID,
		SellerKey:        entry.SellerKey,
		Description:      entry.Description,
		ContentType:      entry.ContentType,
		Domains:          entry.Domains,
		TokenCost:        entry.TokenCost,
		Price:            e.computePrice(entry),
		SellerReputation: e.state.SellerReputation(entry.SellerKey),
		PutTimestamp:     entry.PutTimestamp,
	}
}
