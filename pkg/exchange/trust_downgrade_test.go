package exchange_test

// Tests for trust downgrade behavior (re-expressed from provenance_downgrade_test.go,
// dontguess-lqp/3311).
//
// The former test dropped a seller's provenance level by revoking a campfire
// attestation (contactable→claimed). The trust-model analog is de-allowlisting:
// a fleet member removed from the NIP-42 allowlist drops from allowlisted (1) to
// anonymous (0). The downgrade SEMANTICS are unchanged: entries a seller put
// while trusted are NOT purged on downgrade — they are flagged NeedsRevalidation
// and excluded from buy match results until the operator clears the flag.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/campfire-net/campfire/cf-protocol/store"

	"github.com/campfire-net/dontguess/pkg/exchange"
)

const downgradeSellerKey = "key-fleet-seller"

// makeDowngradeChecker returns a checker where downgradeSellerKey is an
// allowlisted fleet member, plus the mutable KeySet so the test can de-allowlist
// them at runtime.
func makeDowngradeChecker(t *testing.T) (*exchange.TrustChecker, *exchange.KeySet) {
	t.Helper()
	fleet := exchange.NewKeySet(downgradeSellerKey)
	c, err := exchange.NewTrustChecker(keyOperator, fleet)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	return c, fleet
}

// TestTrustDowngrade_EntriesMarkedOnLevelDrop: when MarkStaleProvenanceEntries is
// called with a lower level after de-allowlisting, entries whose
// AcceptedProvenanceLevel exceeds the current level are flagged NeedsRevalidation.
func TestTrustDowngrade_EntriesMarkedOnLevelDrop(t *testing.T) {
	t.Parallel()
	checker, fleet := makeDowngradeChecker(t)
	h := newTestHarness(t)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:   h.cfID,
		Store:        h.st,
		ReadClient:   h.newOperatorClient(),
		WriteClient:  h.newOperatorClient(),
		TrustChecker: checker,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	// Send a put from the allowlisted seller (level 1 at time of put-accept).
	putMsg := h.sendMessage(h.seller,
		putPayload("Terraform module generator", "sha256:"+fmt.Sprintf("%064x", 99), "code", 8000, 12000),
		[]string{exchange.TagPut, "exchange:content-type:code"},
		nil,
	)
	_ = putMsg // discard signed put; use injected one below (seller override)

	putRec := injectPutMsg(t, h, downgradeSellerKey)

	msgs, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("listing messages: %v", err)
	}
	eng.State().Replay(exchange.FromStoreRecords(msgs))

	// Accept the put. The seller is allowlisted (level 1); AutoAcceptPut records
	// AcceptedProvenanceLevel=1 on the inventory entry.
	if err := eng.AutoAcceptPut(putRec.ID, 5000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	// Confirm entry is in inventory and not flagged yet.
	inv := eng.State().Inventory()
	var foundEntry *exchange.InventoryEntry
	for _, e := range inv {
		if e.EntryID == putRec.ID {
			cp := *e
			foundEntry = &cp
		}
	}
	if foundEntry == nil {
		t.Fatalf("entry %s not found in inventory after put-accept", putRec.ID)
	}
	if foundEntry.AcceptedProvenanceLevel != int(exchange.TrustAllowlisted) {
		t.Errorf("AcceptedProvenanceLevel = %d, want %d (TrustAllowlisted)",
			foundEntry.AcceptedProvenanceLevel, int(exchange.TrustAllowlisted))
	}
	if foundEntry.NeedsRevalidation {
		t.Error("NeedsRevalidation should be false before any downgrade")
	}

	// Downgrade: de-allowlist the seller → drops from level 1 to level 0.
	fleet.Remove(downgradeSellerKey)
	currentLevel := int(checker.Level(downgradeSellerKey))
	if currentLevel >= int(exchange.TrustAllowlisted) {
		t.Fatalf("expected level to drop below TrustAllowlisted after de-allowlist, got %d", currentLevel)
	}

	// Entries accepted at a higher level should now be flagged.
	flagged := eng.State().MarkStaleProvenanceEntries(downgradeSellerKey, currentLevel)
	if len(flagged) != 1 || flagged[0] != putRec.ID {
		t.Errorf("MarkStaleProvenanceEntries = %v, want [%s]", flagged, putRec.ID)
	}
	if !eng.State().EntryNeedsRevalidation(putRec.ID) {
		t.Error("EntryNeedsRevalidation should be true after downgrade mark")
	}
}

// TestTrustDowngrade_FlaggedEntryExcludedFromMatchResults: a NeedsRevalidation
// entry is not returned as a candidate for buy match results.
func TestTrustDowngrade_FlaggedEntryExcludedFromMatchResults(t *testing.T) {
	t.Parallel()
	checker, fleet := makeDowngradeChecker(t)
	h := newTestHarness(t)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:   h.cfID,
		Store:        h.st,
		ReadClient:   h.newOperatorClient(),
		WriteClient:  h.newOperatorClient(),
		TrustChecker: checker,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	putRec := injectPutMsg(t, h, downgradeSellerKey)
	msgs, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("listing messages: %v", err)
	}
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	if err := eng.AutoAcceptPut(putRec.ID, 5000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	if len(eng.State().Inventory()) == 0 {
		t.Fatal("expected non-empty inventory after put-accept")
	}

	// De-allowlist → seller drops to level 0.
	fleet.Remove(downgradeSellerKey)
	newLevel := int(checker.Level(downgradeSellerKey))

	// Send a buy that would match the flagged entry.
	buyMsg := h.sendMessage(h.buyer,
		buyPayload("test entry", 9999),
		[]string{exchange.TagBuy},
		nil,
	)

	// Mark entries stale. Do NOT replay after this — Replay would reset the
	// in-memory NeedsRevalidation flag (ephemeral operator signal, not persisted).
	eng.State().MarkStaleProvenanceEntries(downgradeSellerKey, newLevel)

	// Apply only the new buy message.
	msgs, err = h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("listing messages: %v", err)
	}
	eng.State().Apply(exchange.FromStoreRecord(&msgs[len(msgs)-1]))

	// Dispatch the buy — the engine emits a match message with zero results
	// because the only inventory entry is flagged for re-validation.
	if err := eng.DispatchForTest(buyMsg); err != nil {
		t.Errorf("DispatchForTest buy: %v", err)
	}

	matchMsgs, err := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})
	if err != nil {
		t.Fatalf("listing match messages: %v", err)
	}
	if len(matchMsgs) == 0 {
		t.Fatal("expected a match message (to fulfill the buy future), got none")
	}
	lastMatch := matchMsgs[len(matchMsgs)-1]
	var matchPayload struct {
		Results []struct {
			EntryID string `json:"entry_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(lastMatch.Payload, &matchPayload); err != nil {
		t.Fatalf("unmarshal match payload: %v", err)
	}
	if len(matchPayload.Results) != 0 {
		t.Errorf("expected 0 match results (all flagged), got %d (first entry_id: %s)",
			len(matchPayload.Results), matchPayload.Results[0].EntryID)
	}
}

// TestTrustDowngrade_NoFlagWhenLevelUnchanged: MarkStaleProvenanceEntries does
// not flag entries when the current level equals or exceeds the accepted level.
func TestTrustDowngrade_NoFlagWhenLevelUnchanged(t *testing.T) {
	t.Parallel()
	checker, _ := makeDowngradeChecker(t)
	h := newTestHarness(t)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:   h.cfID,
		Store:        h.st,
		ReadClient:   h.newOperatorClient(),
		WriteClient:  h.newOperatorClient(),
		TrustChecker: checker,
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	putRec := injectPutMsg(t, h, downgradeSellerKey)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	if err := eng.AutoAcceptPut(putRec.ID, 5000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	// Seller is still allowlisted (level 1) — no downgrade.
	currentLevel := int(checker.Level(downgradeSellerKey))
	flagged := eng.State().MarkStaleProvenanceEntries(downgradeSellerKey, currentLevel)
	if len(flagged) != 0 {
		t.Errorf("expected no entries flagged when level unchanged, got %v", flagged)
	}
	if eng.State().EntryNeedsRevalidation(putRec.ID) {
		t.Error("NeedsRevalidation should remain false when level unchanged")
	}
}
