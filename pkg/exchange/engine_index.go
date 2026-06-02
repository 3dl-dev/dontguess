package exchange

import (
	"github.com/campfire-net/dontguess/pkg/matching"
)

// rebuildMatchIndex rebuilds the semantic match index from the current live inventory.
// Called after replay and when the inventory changes significantly.
func (e *Engine) rebuildMatchIndex() {
	inventory := e.state.Inventory()
	inputs := make([]matching.RankInput, len(inventory))
	for i, entry := range inventory {
		inputs[i] = e.inventoryEntryToRankInput(entry)
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
