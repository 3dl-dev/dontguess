package exchange_test

// Cold compression integration tests.
//
// These verify Engine.PostOpenCompressionAssign — the public entry point that
// the medium loop's PostAssign callback targets. The method posts a non-exclusive
// compression assign at ColdCompressionBountyPct (20%) bounty.

import (
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// TestPostOpenCompressionAssign_PostsColdAssign verifies that
// PostOpenCompressionAssign posts a non-exclusive compression assign at 20%
// bounty for an accepted inventory entry with no active assign.
//
// dontguess-20e: the entry is seeded WITHOUT a hot assign (put-accept folded
// directly, not via AutoAcceptPut). PostOpenCompressionAssign now atomically defers
// to any active assign, so a pre-existing hot assign would (correctly) suppress the
// cold post — the exact double-post/double-pay case the fix closes. This test verifies
// the cold assign's shape from the no-active-assign state the medium loop posts from;
// the deferral behavior is proved by
// TestPostOpenCompressionAssign_ConcurrentDefersToActiveDispatchAssign.
func TestPostOpenCompressionAssign_PostsColdAssign(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	eng := h.newEngine()

	const tokenCost int64 = 10000
	const wantBounty int64 = tokenCost * exchange.ColdCompressionBountyPct / 100 // 2000

	// Put and accept an entry with NO active assign (see seedAcceptedEntryNoAssign).
	entryID := seedAcceptedEntryNoAssign(t, h, eng, "PostgreSQL optimization guide", tokenCost)

	// Post a cold compression assign via the public method.
	if err := eng.PostOpenCompressionAssign(entryID); err != nil {
		t.Fatalf("PostOpenCompressionAssign: %v", err)
	}

	// Verify exactly one (cold) assign message appeared.
	assigns := listAssignMessages(t, h)
	if len(assigns) != 1 {
		t.Fatalf("expected exactly 1 cold assign message, got %d", len(assigns))
	}

	var ap struct {
		EntryID         string `json:"entry_id"`
		TaskType        string `json:"task_type"`
		Reward          int64  `json:"reward"`
		ExclusiveSender string `json:"exclusive_sender"`
	}
	if err := json.Unmarshal(assigns[0].Payload, &ap); err != nil {
		t.Fatalf("parsing cold assign payload: %v", err)
	}

	if ap.EntryID != entryID {
		t.Errorf("entry_id = %s, want %s", ap.EntryID, entryID)
	}
	if ap.TaskType != "compress" {
		t.Errorf("task_type = %s, want compress", ap.TaskType)
	}
	if ap.Reward != wantBounty {
		t.Errorf("reward = %d, want %d (%d%% of %d)", ap.Reward, wantBounty, exchange.ColdCompressionBountyPct, tokenCost)
	}
	if ap.ExclusiveSender != "" {
		t.Errorf("exclusive_sender = %q, want empty (cold assigns are open)", ap.ExclusiveSender)
	}
}

// TestPostOpenCompressionAssign_BountyTiers verifies a cold assign carries the
// ColdCompressionBountyPct (20%) bounty and that the three compression tiers are
// strictly ordered hot (50%) > warm (30%) > cold (20%).
//
// dontguess-20e: the tiers can no longer COEXIST as active assigns on one entry —
// PostOpenCompressionAssign now atomically defers to any active assign, so a cold
// post never stacks on a hot/warm assign (that coexistence was the double-post the
// fix closes). This verifies the cold bounty on a no-active-assign entry (the state
// the medium loop posts from) plus the tier-constant ordering, rather than asserting
// hot+cold coexist.
func TestPostOpenCompressionAssign_BountyTiers(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	eng := h.newEngine()

	const tokenCost int64 = 20000
	entryID := seedAcceptedEntryNoAssign(t, h, eng, "Go concurrency patterns", tokenCost)

	if err := eng.PostOpenCompressionAssign(entryID); err != nil {
		t.Fatalf("PostOpenCompressionAssign: %v", err)
	}

	assigns := listAssignMessages(t, h)
	if len(assigns) != 1 {
		t.Fatalf("expected exactly 1 cold assign, got %d", len(assigns))
	}
	var ap struct {
		Reward int64 `json:"reward"`
	}
	if err := json.Unmarshal(assigns[0].Payload, &ap); err != nil {
		t.Fatalf("parsing cold assign payload: %v", err)
	}

	coldBounty := tokenCost * exchange.ColdCompressionBountyPct / 100 // 4000
	if ap.Reward != coldBounty {
		t.Errorf("cold reward = %d, want %d (%d%% of token_cost %d)",
			ap.Reward, coldBounty, exchange.ColdCompressionBountyPct, tokenCost)
	}

	// Tier ordering (the rate constants themselves): hot > warm > cold.
	if !(exchange.ColdCompressionBountyPct < exchange.WarmCompressionBountyPct &&
		exchange.WarmCompressionBountyPct < exchange.HotCompressionBountyPct) {
		t.Errorf("compression bounty tiers not strictly ordered: cold=%d warm=%d hot=%d (want cold < warm < hot)",
			exchange.ColdCompressionBountyPct, exchange.WarmCompressionBountyPct, exchange.HotCompressionBountyPct)
	}
}

// TestPostOpenCompressionAssign_EntryNotFound verifies that
// PostOpenCompressionAssign returns an error for a non-existent entry.
func TestPostOpenCompressionAssign_EntryNotFound(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	eng := h.newEngine()

	err := eng.PostOpenCompressionAssign("nonexistent-entry-id")
	if err == nil {
		t.Fatal("expected error for non-existent entry, got nil")
	}
}

// --- helpers ---

func listAssignMessages(t *testing.T, h *testHarness) []store.MessageRecord {
	t.Helper()
	msgs, err := h.st.ListMessages(h.cfID, 0, store.MessageFilter{
		Tags: []string{exchange.TagAssign},
	})
	if err != nil {
		t.Fatalf("listing assign messages: %v", err)
	}
	return msgs
}
