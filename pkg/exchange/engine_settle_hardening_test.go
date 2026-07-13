package exchange

// Internal-package hardening tests for dontguess-471 (consolidated engine
// hardening). These live in package exchange (not exchange_test) so they can
// seed unexported State maps directly and call unexported Engine methods
// (handleSettleSmallContentDispute, restoreExistingHold, performScripSettlement,
// handleDeadlineMissRefund) with an injectable in-memory ScripStore — no full
// campfire buy→match→deliver cycle needed.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/campfire-net/dontguess/pkg/scrip"
)

// errInjected is returned by memSpendingStore when a failure toggle is set.
var errInjected = errors.New("injected store failure")

// memSpendingStore is a minimal in-memory scrip.SpendingStore with per-operation
// failure injection, used by the dontguess-471 error-branch tests. Delegating
// methods keep balances/reservations in maps so a refund/restore is observable.
type memSpendingStore struct {
	mu           sync.Mutex
	balances     map[string]int64
	reservations map[string]scrip.Reservation

	addCalls     int
	saveCalls    int
	consumeCalls int
	lastSaved    *scrip.Reservation

	failAdd     bool
	failSave    bool
	failConsume bool
}

func newMemSpendingStore() *memSpendingStore {
	return &memSpendingStore{
		balances:     make(map[string]int64),
		reservations: make(map[string]scrip.Reservation),
	}
}

func (s *memSpendingStore) DecrementBudget(_ context.Context, pk, _ string, amount int64, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.balances[pk] -= amount
	return s.balances[pk], "etag", nil
}

func (s *memSpendingStore) GetBudget(_ context.Context, pk, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.balances[pk], "etag", nil
}

func (s *memSpendingStore) AddBudget(_ context.Context, pk, _ string, amount int64, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failAdd {
		return 0, "", errInjected
	}
	s.addCalls++
	s.balances[pk] += amount
	return s.balances[pk], "etag", nil
}

func (s *memSpendingStore) SaveReservation(_ context.Context, r scrip.Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return errInjected
	}
	s.saveCalls++
	cp := r
	s.lastSaved = &cp
	s.reservations[r.ID] = r
	return nil
}

func (s *memSpendingStore) GetReservation(_ context.Context, id string) (scrip.Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reservations[id]
	if !ok {
		return scrip.Reservation{}, scrip.ErrReservationNotFound
	}
	return r, nil
}

func (s *memSpendingStore) DeleteReservation(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reservations[id]; !ok {
		return scrip.ErrReservationNotFound
	}
	delete(s.reservations, id)
	return nil
}

func (s *memSpendingStore) ConsumeReservation(_ context.Context, id string) (scrip.Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumeCalls++
	if s.failConsume {
		return scrip.Reservation{}, errInjected
	}
	r, ok := s.reservations[id]
	if !ok {
		return scrip.Reservation{}, scrip.ErrReservationNotFound
	}
	delete(s.reservations, id)
	return r, nil
}

func (s *memSpendingStore) hasReservation(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.reservations[id]
	return ok
}

func (s *memSpendingStore) addBudgetCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addCalls
}

func (s *memSpendingStore) consumeReservationCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumeCalls
}

func (s *memSpendingStore) saveReservationCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveCalls
}

// hardeningEngine builds an engine wired to the given ScripStore with a test
// logger. No transport clients — the tested methods are called directly.
func hardeningEngine(t *testing.T, store scrip.SpendingStore) *Engine {
	t.Helper()
	return NewEngine(EngineOptions{
		OperatorPublicKey: "operator-key",
		ScripStore:        store,
		Logger:            func(format string, args ...any) { t.Logf("[engine] "+format, args...) },
	})
}

// seedSmallDisputeChain wires state so entryForDeliver(deliverID) resolves to a
// small-content entry, and stores a reservation owned by buyerKey with amount.
func seedSmallDisputeChain(eng *Engine, deliverID, matchID, entryID, buyerKey, resID string, amount int64, store *memSpendingStore) {
	st := eng.State()
	st.mu.Lock()
	st.deliverToMatch[deliverID] = matchID
	st.matchToEntry[matchID] = entryID
	st.inventory[entryID] = &InventoryEntry{
		EntryID:     entryID,
		TokenCost:   100, // < SmallContentThreshold (500) → small content
		ContentSize: 100,
	}
	st.mu.Unlock()
	store.reservations[resID] = scrip.Reservation{
		ID:       resID,
		AgentKey: buyerKey,
		RK:       scrip.BalanceKey,
		Amount:   amount,
	}
}

func smallDisputeMsg(id, sender, deliverID, reservationID, buyerKey string) *Message {
	payload, _ := json.Marshal(map[string]string{
		"reservation_id": reservationID,
		"buyer_key":      buyerKey,
	})
	return &Message{
		ID:          id,
		Sender:      sender,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrSmallContentDispute},
		Antecedents: []string{deliverID},
		Payload:     payload,
		Timestamp:   time.Now().UnixNano(),
	}
}

// TestSmallContentDispute_NonBuyer_RejectedNoScripLoss verifies the HIGH+MED
// unauthenticated-refund fix (dontguess-471 fix #1): a settle(small-content-
// dispute) whose SIGNED sender is not the reservation owner is rejected even
// when the attacker sets buyer_key to the victim's own key (which satisfied the
// old payload-only check). Post dontguess-35c the reservation is never consumed
// (ownership is peeked with a non-consuming read first), so it remains intact and
// no refund (AddBudget) is issued.
func TestSmallContentDispute_NonBuyer_RejectedNoScripLoss(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)

	const (
		deliverID = "deliver-1"
		matchID   = "match-1"
		entryID   = "entry-1"
		buyerA    = "buyerA-victim"
		attacker  = "buyerB-attacker"
		resID     = "res-1"
	)
	seedSmallDisputeChain(eng, deliverID, matchID, entryID, buyerA, resID, 300, store)

	// Attacker forges the dispute, setting buyer_key = the victim's key (public,
	// and equal to the reservation owner — this is what defeated the old check).
	msg := smallDisputeMsg("dispute-1", attacker, deliverID, resID, buyerA)

	err := eng.handleSettleSmallContentDispute(msg)
	if err == nil {
		t.Fatal("expected error for non-owner small-content-dispute, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may be issued for an unauthorized dispute; AddBudget called %d times", store.addBudgetCalls())
	}
	// The victim's reservation must be preserved (restored after the atomic consume).
	if !store.hasReservation(resID) {
		t.Error("victim reservation must be restored after an unauthorized dispute — griefing/ledger-corruption guard")
	}
	if got := store.balances[buyerA]; got != 0 {
		t.Errorf("victim balance must be untouched, got %d", got)
	}
}

// TestSmallContentDispute_NonOwner_NeverTouchesReservation verifies the
// dontguess-35c timing-griefing fix: a non-owner's forged small-content-dispute
// must NEVER consume (and therefore never need to restore) the victim's live
// reservation. The prior consume->restore shape deleted the reservation for the
// duration of the ownership check, opening a window in which a concurrent legit
// settle(complete) for the SAME reservation observed not-found and no-op'd,
// leaving the seller unpaid until expiry. The fix peeks ownership with a
// non-consuming GetReservation first, so an unauthorized dispute performs ZERO
// ConsumeReservation and ZERO SaveReservation calls — the live reservation is
// wholly untouched and a racing settle(complete) can still find it.
func TestSmallContentDispute_NonOwner_NeverTouchesReservation(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)

	const (
		deliverID = "deliver-nt"
		matchID   = "match-nt"
		entryID   = "entry-nt"
		victim    = "buyer-victim-nt"
		attacker  = "buyer-attacker-nt"
		resID     = "res-nt"
	)
	seedSmallDisputeChain(eng, deliverID, matchID, entryID, victim, resID, 300, store)

	// Attacker forges the dispute with buyer_key set to the victim's own key.
	msg := smallDisputeMsg("dispute-nt", attacker, deliverID, resID, victim)

	err := eng.handleSettleSmallContentDispute(msg)
	if err == nil {
		t.Fatal("expected error for non-owner small-content-dispute, got nil")
	}
	// The core assertion: the live reservation is never consumed, so it never has
	// to be restored — a concurrent settle(complete) would still find it.
	if got := store.consumeReservationCalls(); got != 0 {
		t.Errorf("non-owner dispute must NEVER consume the victim's reservation; ConsumeReservation called %d times", got)
	}
	if got := store.saveReservationCalls(); got != 0 {
		t.Errorf("non-owner dispute must NEVER restore (SaveReservation) the reservation — it was never consumed; called %d times", got)
	}
	if !store.hasReservation(resID) {
		t.Error("victim reservation must remain intact after an unauthorized dispute")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may be issued for an unauthorized dispute; AddBudget called %d times", store.addBudgetCalls())
	}

	// Ground-source the race property: after the rejected dispute, the legit owner's
	// settle(complete)-style consume of the SAME reservation still succeeds and
	// returns the intact reservation (owner unpaid griefing window is closed).
	res, cErr := store.ConsumeReservation(context.Background(), resID)
	if cErr != nil {
		t.Fatalf("owner's post-dispute consume must succeed (griefing window closed), got: %v", cErr)
	}
	if res.AgentKey != victim || res.Amount != 300 {
		t.Errorf("owner's reservation must be intact: got agent=%s amount=%d, want %s/300", res.AgentKey, res.Amount, victim)
	}
}

// TestSmallContentDispute_Buyer_RefundsAndConsumes is the positive control: the
// real reservation owner (matching msg.Sender) gets refunded and the reservation
// is consumed.
func TestSmallContentDispute_Buyer_RefundsAndConsumes(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)

	const (
		deliverID = "deliver-2"
		matchID   = "match-2"
		entryID   = "entry-2"
		buyer     = "buyer-real"
		resID     = "res-2"
	)
	seedSmallDisputeChain(eng, deliverID, matchID, entryID, buyer, resID, 300, store)

	msg := smallDisputeMsg("dispute-2", buyer, deliverID, resID, buyer)
	if err := eng.handleSettleSmallContentDispute(msg); err != nil {
		t.Fatalf("legit owner dispute should succeed, got: %v", err)
	}
	if store.addBudgetCalls() != 1 {
		t.Errorf("expected exactly one refund AddBudget, got %d", store.addBudgetCalls())
	}
	if got := store.balances[buyer]; got != 300 {
		t.Errorf("buyer refund: got %d, want 300", got)
	}
	if store.hasReservation(resID) {
		t.Error("reservation must be consumed after a successful refund")
	}
}

// TestSmallContentDispute_NilEntry_RejectsRefund verifies fix #1's mandatory
// small-content restriction at the engine layer: when entryForDeliver cannot
// resolve an entry (expired/unknown), the auto-refund is REFUSED (the engine
// cannot prove the content is below-threshold). The reservation is left intact
// and no refund is issued.
func TestSmallContentDispute_NilEntry_RejectsRefund(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)

	const (
		deliverID = "deliver-3"
		buyer     = "buyer-3"
		resID     = "res-3"
	)
	// Deliberately do NOT seed deliverToMatch/matchToEntry/inventory → entry is nil.
	store.reservations[resID] = scrip.Reservation{ID: resID, AgentKey: buyer, RK: scrip.BalanceKey, Amount: 300}

	msg := smallDisputeMsg("dispute-3", buyer, deliverID, resID, buyer)
	if err := eng.handleSettleSmallContentDispute(msg); err != nil {
		t.Fatalf("nil-entry dispute should be a benign drop (nil error), got: %v", err)
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may be issued when the entry cannot be proven small; AddBudget called %d times", store.addBudgetCalls())
	}
	if !store.hasReservation(resID) {
		t.Error("reservation must be left intact when a nil-entry dispute is refused")
	}
}

// TestSmallContentDispute_MarshalFailure_RestoresReservation verifies the
// marshal-failure branch: the refund payload marshal fails AFTER the atomic
// consume, so the reservation is restored and no refund is issued (no scrip loss).
func TestSmallContentDispute_MarshalFailure_RestoresReservation(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)
	eng.marshalFunc = func(any) ([]byte, error) { return nil, errInjected }

	const (
		deliverID = "deliver-4"
		matchID   = "match-4"
		entryID   = "entry-4"
		buyer     = "buyer-4"
		resID     = "res-4"
	)
	seedSmallDisputeChain(eng, deliverID, matchID, entryID, buyer, resID, 300, store)

	msg := smallDisputeMsg("dispute-4", buyer, deliverID, resID, buyer)
	err := eng.handleSettleSmallContentDispute(msg)
	if err == nil {
		t.Fatal("expected marshal-failure error, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may occur on marshal failure; AddBudget called %d times", store.addBudgetCalls())
	}
	if !store.hasReservation(resID) {
		t.Error("reservation must be restored after marshal failure (no scrip loss)")
	}
}

// TestSmallContentDispute_MarshalAndRestoreFail_LoudError verifies the CRITICAL
// double-failure branch: marshal fails AND the restore SaveReservation also
// fails. The engine returns a loud "reservation lost" error and issues no
// refund — the held scrip is neither refunded nor credited elsewhere (ledger
// conserved; the loud error is the manual-reconciliation signal).
func TestSmallContentDispute_MarshalAndRestoreFail_LoudError(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)
	eng.marshalFunc = func(any) ([]byte, error) { return nil, errInjected }

	const (
		deliverID = "deliver-5"
		matchID   = "match-5"
		entryID   = "entry-5"
		buyer     = "buyer-5"
		resID     = "res-5"
	)
	seedSmallDisputeChain(eng, deliverID, matchID, entryID, buyer, resID, 300, store)
	store.failSave = true // restore will also fail

	msg := smallDisputeMsg("dispute-5", buyer, deliverID, resID, buyer)
	err := eng.handleSettleSmallContentDispute(msg)
	if err == nil {
		t.Fatal("expected loud reservation-lost error, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may occur on double-failure; AddBudget called %d times", store.addBudgetCalls())
	}
}

// --- deadline-miss refund error branches (fix #5 coverage) ---

func completeMsgForSettle(id, sender, deliverID string) *Message {
	return &Message{
		ID:          id,
		Sender:      sender,
		Tags:        []string{TagSettle, TagPhasePrefix + SettlePhaseStrComplete},
		Antecedents: []string{deliverID},
		Payload:     []byte(`{"price":100}`),
		Timestamp:   time.Now().UnixNano(),
	}
}

// TestDeadlineMissRefund_ConsumeFailure_NoCredit verifies that when the atomic
// ConsumeReservation fails, no refund credit occurs and the error surfaces.
func TestDeadlineMissRefund_ConsumeFailure_NoCredit(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)
	store.reservations["res-dm1"] = scrip.Reservation{ID: "res-dm1", AgentKey: "buyer-dm1", RK: scrip.BalanceKey, Amount: 500}
	store.failConsume = true

	msg := completeMsgForSettle("complete-dm1", "buyer-dm1", "deliver-dm1")
	err := eng.handleDeadlineMissRefund(context.Background(), msg, "match-dm1", "res-dm1", 500)
	if err == nil {
		t.Fatal("expected consume-failure error, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may occur when consume fails; AddBudget called %d times", store.addBudgetCalls())
	}
}

// TestDeadlineMissRefund_MarshalAndRestoreFail_LoudError verifies the CRITICAL
// double-failure branch: the refund payload marshal fails AND the restore also
// fails — a loud error, no credit.
func TestDeadlineMissRefund_MarshalAndRestoreFail_LoudError(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)
	eng.marshalFunc = func(any) ([]byte, error) { return nil, errInjected }
	store.reservations["res-dm2"] = scrip.Reservation{ID: "res-dm2", AgentKey: "buyer-dm2", RK: scrip.BalanceKey, Amount: 500}
	store.failSave = true

	msg := completeMsgForSettle("complete-dm2", "buyer-dm2", "deliver-dm2")
	err := eng.handleDeadlineMissRefund(context.Background(), msg, "match-dm2", "res-dm2", 500)
	if err == nil {
		t.Fatal("expected loud marshal+restore-failed error, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no refund may occur on double-failure; AddBudget called %d times", store.addBudgetCalls())
	}
}

// TestPerformScripSettlement_MarshalAndRestoreFail_LoudError verifies the
// performScripSettlement double-failure branch: marshalSettlePayloads fails AND
// the restore SaveReservation fails → loud "reservation lost" error, no seller/
// operator credit.
func TestPerformScripSettlement_MarshalAndRestoreFail_LoudError(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)
	eng.marshalFunc = func(any) ([]byte, error) { return nil, errInjected }
	store.reservations["res-ps1"] = scrip.Reservation{ID: "res-ps1", AgentKey: "buyer-ps1", RK: scrip.BalanceKey, Amount: 1100}
	store.failSave = true

	msg := completeMsgForSettle("complete-ps1", "buyer-ps1", "deliver-ps1")
	err := eng.performScripSettlement(context.Background(), msg, "seller-ps1", "match-ps1", "res-ps1", nil)
	if err == nil {
		t.Fatal("expected loud marshal+restore-failed error, got nil")
	}
	if store.addBudgetCalls() != 0 {
		t.Errorf("no seller/operator credit may occur on double-failure; AddBudget called %d times", store.addBudgetCalls())
	}
}

// --- fix #4: restore original hold amount on restart ---

// TestRestoreExistingHold_UsesOriginalAmount verifies that restoreExistingHold
// restores the EXACT amount recorded in the durable scrip-buy-hold event, not a
// recomputation from the current dynamic price. Pre-fix, the amount was
// recomputed from the entry price (or 0 when the entry was absent), so a price
// drift between hold and restart moved the wrong scrip.
func TestRestoreExistingHold_UsesOriginalAmount(t *testing.T) {
	store := newMemSpendingStore()
	eng := hardeningEngine(t, store)

	const (
		matchID   = "match-rh1"
		buyer     = "buyer-rh1"
		resID     = "res-rh1"
		origAmt   = int64(7777) // the amount actually held at buyer-accept time
	)
	store.balances[buyer] = 100000

	// Apply a durable scrip-buy-hold recording the ORIGINAL held amount.
	holdPayload, _ := json.Marshal(scrip.BuyHoldPayload{
		Buyer:         buyer,
		Amount:        origAmt,
		Price:         7000,
		Fee:           777,
		ReservationID: resID,
		BuyMsg:        matchID,
	})
	eng.State().Apply(&Message{
		ID:        "buyhold-rh1",
		Sender:    "operator-key",
		Tags:      []string{scrip.TagScripBuyHold},
		Payload:   holdPayload,
		Timestamp: time.Now().UnixNano(),
	})

	// Sanity: the state index carries the original amount.
	if amt, ok := eng.State().GetBuyHoldAmount(matchID); !ok || amt != origAmt {
		t.Fatalf("GetBuyHoldAmount(%s) = (%d, %v), want (%d, true)", matchID, amt, ok, origAmt)
	}

	// Restore. There is deliberately NO inventory entry, so the pre-fix recompute
	// path would have produced 0 — restoring the durable original is the only way
	// to get origAmt.
	msg := &Message{ID: "accept-rh1", Sender: buyer, Timestamp: time.Now().UnixNano()}
	if err := eng.restoreExistingHold(msg, matchID, resID); err != nil {
		t.Fatalf("restoreExistingHold: %v", err)
	}
	if store.lastSaved == nil {
		t.Fatal("restoreExistingHold did not save a reservation")
	}
	if store.lastSaved.Amount != origAmt {
		t.Errorf("restored reservation amount = %d, want %d (the ORIGINAL held amount, not a recompute)",
			store.lastSaved.Amount, origAmt)
	}
	// The engine-side mapping must be re-established.
	if got, ok := eng.reservationFor(matchID); !ok || got != resID {
		t.Errorf("reservationFor(%s) = (%q, %v), want (%q, true)", matchID, got, ok, resID)
	}
}
