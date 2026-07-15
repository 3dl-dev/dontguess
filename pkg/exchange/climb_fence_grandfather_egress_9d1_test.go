package exchange

// climb_fence_grandfather_egress_9d1_test.go — the done-gate for dontguess-9d1
// (climb egress fence — match/hash/deliver leg). See
// docs/design/content-confidentiality-envelope-541.md §4.4 (A1/P1) + design §6
// ADV-18.
//
// The LANDED e18d Outbox climb fence stops the RAW pre-climb plaintext PUT corpus
// from republishing to the relay, but the solo→fleet climb Replay GRANDFATHERS
// every pre-climb plaintext put into ACTIVE team inventory as an entry with
// WrappedCEKOperator=="" and LegacyPlaintext=true. Before this fix that
// grandfathered entry was still MATCHABLE by a relay buyer, still emitted its
// unsalted sha256(pre-climb plaintext) on the exchange:match wire (the §4.4 A1/P1
// plaintext-hash oracle), and was still DELIVERED as plaintext to a paying buyer.
//
// These are WHITE-BOX (package exchange) tests that drive the three real egress
// seams directly — findCandidates, emitMatchResponse, emitDeliverContent — each
// with a CONTROL genuinely-local plaintext entry (LegacyPlaintext=false,
// WrappedCEKOperator=="") proving the gate excludes ONLY the grandfathered entry
// and leaves individual/solo-tier local plaintext untouched. The genuinely-
// grandfathered-via-Replay path (a mixed historical log) is exercised end-to-end
// in climb_fence_grandfather_e2e_9d1_test.go.
//
// Proven:
//
//	(a) findCandidates EXCLUDES a grandfathered entry and INCLUDES the control;
//	(b) emitMatchResponse BLANKS content_hash for a grandfathered entry and keeps
//	    it for the control (the §4.4 A1/P1 plaintext-hash oracle never reaches the
//	    exchange:match wire);
//	(c) emitDeliverContent REFUSES to deliver a grandfathered entry's plaintext
//	    (returns nil,nil, emits nothing) while the control still delivers.

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// tagPresent reports whether tags contains want.
func tagPresent(tags []string, want string) bool {
	for _, tg := range tags {
		if tg == want {
			return true
		}
	}
	return false
}

// egressTestEngine builds an engine backed by a real on-disk LocalStore so the
// operator-egress seams (emitMatchResponse / emitDeliverContent) actually append
// their emitted messages where the test can read them back.
func egressTestEngine(t *testing.T) (*Engine, *dgstore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	ls, err := dgstore.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	t.Cleanup(func() { ls.Close() }) //nolint:errcheck
	operatorKey := newReservationID()
	eng := NewEngine(EngineOptions{
		CampfireID:        "local",
		LocalStore:        ls,
		OperatorPublicKey: operatorKey,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})
	if err := eng.replayAll(); err != nil {
		t.Fatalf("initial replayAll: %v", err)
	}
	return eng, ls, operatorKey
}

// injectInventory writes entry directly into the engine's live inventory map,
// mirroring seedSmallDisputeChain's white-box seam.
func injectInventory(eng *Engine, entry *InventoryEntry) {
	st := eng.State()
	st.mu.Lock()
	st.inventory[entry.EntryID] = entry
	st.mu.Unlock()
}

// grandfatheredEntry returns a LegacyPlaintext=true entry with a known plaintext.
func grandfatheredEntry(entryID, seller string, plaintext []byte) *InventoryEntry {
	return &InventoryEntry{
		EntryID:         entryID,
		PutMsgID:        entryID,
		SellerKey:       seller,
		Description:     "reusable go flock file-lock contention test pattern for concurrent access",
		ContentType:     "exchange:content-type:code",
		Domains:         []string{"go"},
		TokenCost:       4242,
		ContentSize:     int64(len(plaintext)),
		PutTimestamp:    time.Now().UnixNano(),
		Content:         plaintext,
		ContentHash:     sha256Ref(plaintext),
		LegacyPlaintext: true, // grandfathered pre-climb plaintext (team-tier climb Replay)
	}
}

// localPlaintextEntry returns the CONTROL: a genuinely-local (individual/solo-tier)
// plaintext entry — same shape but LegacyPlaintext=false. It must stay matchable,
// hashable, and deliverable (the fix must NOT touch the individual tier).
func localPlaintextEntry(entryID, seller string, plaintext []byte) *InventoryEntry {
	return &InventoryEntry{
		EntryID:         entryID,
		PutMsgID:        entryID,
		SellerKey:       seller,
		Description:     "reusable go mutex deadlock detection recipe for concurrent maps",
		ContentType:     "exchange:content-type:code",
		Domains:         []string{"go"},
		TokenCost:       4242,
		ContentSize:     int64(len(plaintext)),
		PutTimestamp:    time.Now().UnixNano(),
		Content:         plaintext,
		ContentHash:     sha256Ref(plaintext),
		LegacyPlaintext: false, // genuinely-local plaintext — never fenced
	}
}

// TestClimbFence_Grandfathered_FindCandidatesExcludes is assertion (a): a
// grandfathered entry is withheld from a relay/team buyer's candidate set while a
// genuinely-local control plaintext entry is returned.
func TestClimbFence_Grandfathered_FindCandidatesExcludes(t *testing.T) {
	t.Parallel()
	eng, _, _ := egressTestEngine(t)

	gf := grandfatheredEntry("gf-entry", newReservationID(), []byte("a pre-migration plaintext artifact already broadcast before the cutover"))
	ctrl := localPlaintextEntry("ctrl-entry", newReservationID(), []byte("a genuinely-local plaintext artifact that must stay matchable"))
	injectInventory(eng, gf)
	injectInventory(eng, ctrl)

	// Permissive filters: budget high, no reputation floor, no freshness/type/domain
	// constraint — so the ONLY thing that can withhold gf is the LegacyPlaintext fence.
	got := eng.findCandidates("buyer-key", 1_000_000, 0, 0, "", nil, "")

	ids := make(map[string]bool, len(got))
	for _, e := range got {
		ids[e.EntryID] = true
	}
	if ids[gf.EntryID] {
		t.Fatalf("(a) grandfathered entry %q is a candidate — a relay buyer can MATCH pre-climb plaintext (fence dead)", gf.EntryID)
	}
	if !ids[ctrl.EntryID] {
		t.Fatalf("(a) control genuinely-local plaintext entry %q was withheld — the fix wrongly touched the individual tier", ctrl.EntryID)
	}
}

// TestClimbFence_Grandfathered_MatchResponseBlanksHash is assertion (b): the
// exchange:match event carries NO content_hash for a grandfathered entry (the
// §4.4 A1/P1 plaintext-hash oracle stays off the wire) but keeps it for the
// control.
func TestClimbFence_Grandfathered_MatchResponseBlanksHash(t *testing.T) {
	t.Parallel()
	eng, ls, operatorKey := egressTestEngine(t)

	gf := grandfatheredEntry("gf-entry", newReservationID(), []byte("pre-migration plaintext whose sha256 must never touch the match wire"))
	ctrl := localPlaintextEntry("ctrl-entry", newReservationID(), []byte("genuinely-local plaintext whose hash may travel on the local wire"))
	injectInventory(eng, gf)
	injectInventory(eng, ctrl)

	buyBody, _ := json.Marshal(map[string]any{"task": "go flock contention test pattern", "budget": 1_000_000, "max_results": 3})
	buyMsg := &Message{
		ID:        newReservationID(),
		Sender:    "buyer-key",
		Tags:      []string{TagBuy},
		Payload:   buyBody,
		Timestamp: time.Now().UnixNano(),
	}
	semanticMatches := []rankedCandidate{
		{entry: gf, confidence: 0.9, similarity: 0.9, hasSemanticScore: true},
		{entry: ctrl, confidence: 0.9, similarity: 0.9, hasSemanticScore: true},
	}
	candidates := []*InventoryEntry{gf, ctrl}
	if err := eng.emitMatchResponse(buyMsg, "go flock contention test pattern", semanticMatches, candidates, false); err != nil {
		t.Fatalf("emitMatchResponse: %v", err)
	}

	// Locate the operator-emitted exchange:match message and parse its results.
	recs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("ls.ReadAll: %v", err)
	}
	var matchPayload []byte
	for i := range recs {
		m := &recs[i]
		if m.Sender != operatorKey {
			continue
		}
		if tagPresent(m.Tags, TagMatch) && !tagPresent(m.Tags, TagBuyMiss) {
			matchPayload = m.Payload
		}
	}
	if matchPayload == nil {
		t.Fatal("(b) no operator exchange:match message emitted")
	}
	var parsed struct {
		Results []struct {
			EntryID     string `json:"entry_id"`
			ContentHash string `json:"content_hash"`
		} `json:"results"`
	}
	if err := json.Unmarshal(matchPayload, &parsed); err != nil {
		t.Fatalf("(b) unmarshal match payload: %v", err)
	}
	seen := map[string]string{}
	for _, r := range parsed.Results {
		seen[r.EntryID] = r.ContentHash
	}
	if _, ok := seen[gf.EntryID]; !ok {
		t.Fatalf("(b) grandfathered entry missing from match results — expected present with a blanked hash")
	}
	if seen[gf.EntryID] != "" {
		t.Fatalf("(b) grandfathered entry emitted content_hash=%q on the exchange:match wire — the §4.4 A1/P1 plaintext-hash oracle leaked", seen[gf.EntryID])
	}
	if seen[ctrl.EntryID] == "" {
		t.Fatalf("(b) control genuinely-local plaintext entry had its content_hash blanked — the fix wrongly touched the individual tier")
	}
	// The raw plaintext hash of the grandfathered entry must appear NOWHERE in ANY
	// message emitted by this emitMatchResponse call — not the match payload, and
	// not a warm-compression exchange:assign (which also embeds ContentHash).
	gfHashHex := strings.TrimPrefix(gf.ContentHash, "sha256:")
	for i := range recs {
		if strings.Contains(string(recs[i].Payload), gfHashHex) {
			t.Fatalf("(b) sha256(grandfathered plaintext) found in an emitted message (tags=%v) — plaintext-hash oracle leaked on the wire", recs[i].Tags)
		}
	}
}

// TestClimbFence_Grandfathered_DeliverNoPlaintext is assertion (c): a settle
// (deliver) for a grandfathered entry emits NO content (returns nil,nil) while
// the control still delivers its bytes.
func TestClimbFence_Grandfathered_DeliverNoPlaintext(t *testing.T) {
	t.Parallel()
	eng, ls, operatorKey := egressTestEngine(t)

	gfPlain := []byte("pre-migration PLAINTEXT that a paying relay buyer must NEVER receive")
	ctrlPlain := []byte("genuinely-local plaintext that the individual tier still delivers")
	gf := grandfatheredEntry("gf-entry", newReservationID(), gfPlain)
	ctrl := localPlaintextEntry("ctrl-entry", newReservationID(), ctrlPlain)

	trigger := &Message{
		ID:        newReservationID(),
		Sender:    operatorKey,
		Tags:      []string{TagSettle, TagPhasePrefix + SettlePhaseStrDeliver},
		Timestamp: time.Now().UnixNano(),
	}

	// Grandfathered entry: deliver must be DECLINED (nil message, nil error).
	gfMsg, err := eng.emitDeliverContent(trigger, gf, "buyer-key")
	if err != nil {
		t.Fatalf("(c) emitDeliverContent(grandfathered) returned error: %v", err)
	}
	if gfMsg != nil {
		t.Fatalf("(c) emitDeliverContent DELIVERED a grandfathered entry — pre-climb plaintext egressed to a buyer")
	}

	// Control: deliver must PROCEED (non-nil message emitted).
	ctrlMsg, err := eng.emitDeliverContent(trigger, ctrl, "buyer-key")
	if err != nil {
		t.Fatalf("(c) emitDeliverContent(control) returned error: %v", err)
	}
	if ctrlMsg == nil {
		t.Fatalf("(c) emitDeliverContent DECLINED a genuinely-local plaintext entry — the fix wrongly touched the individual tier")
	}

	// The grandfathered PLAINTEXT (raw or base64) must appear in NO emitted message.
	recs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("ls.ReadAll: %v", err)
	}
	gfB64 := base64.StdEncoding.EncodeToString(gfPlain)
	ctrlB64 := base64.StdEncoding.EncodeToString(ctrlPlain)
	sawCtrl := false
	for i := range recs {
		raw := string(recs[i].Payload)
		if strings.Contains(raw, gfB64) || strings.Contains(raw, string(gfPlain)) {
			t.Fatalf("(c) grandfathered plaintext found in an emitted message — deliver leaked pre-climb plaintext")
		}
		if strings.Contains(raw, ctrlB64) {
			sawCtrl = true
		}
	}
	if !sawCtrl {
		t.Fatalf("(c) control plaintext was never delivered — the individual-tier deliver path regressed")
	}
}
