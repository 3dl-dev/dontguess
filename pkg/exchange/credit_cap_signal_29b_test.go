package exchange_test

// dontguess-29b wave-7 fix, item 3 (SILENT CUTOFF AT THE CREDIT CAP).
//
// Before this fix, a borrower who reached creditMaxOutstandingPerBuyer
// (engine_credit.go) was permanently cut off from further deliver-on-credit
// with NOTHING operator-visible beyond a log line the caller
// (handleSettleBuyerAcceptScrip) may not be watching: no counter, no
// queryable state. Nothing transitions the loan to Defaulted, accrues vig, or
// writes DebtorScore either — that collection policy is intentionally NOT
// built here; it is gated on dontguess-4c1. This file proves only the
// observability fix:
//
//   - TestEnsureCreditForShortfall_OverCapIncrementsDegradationCounter: the
//     "verified and over cap" refusal increments
//     Engine.DegradationSnapshot().CreditCapRefused exactly once per refusal.
//   - TestEnsureCreditForShortfall_UnverifiableScripStoreFailsClosedAndCounts:
//     the FAIL-CLOSED branch — a ScripStore that does not implement the
//     loan-query surface (scripLoanQuerier: LoansByBorrower/GetLoan), i.e.
//     NOT a *scrip.LocalScripStore — causes ensureCreditForShortfall to
//     REFUSE credit (non-nil error, no scrip:loan-mint), and increments
//     Engine.DegradationSnapshot().CreditCapUnverifiable exactly once. Before
//     this test, NO test in the suite ever exercised this branch: every other
//     credit test constructs a *scrip.LocalScripStore (via
//     newCampfireScripStore), which always satisfies scripLoanQuerier, so the
//     !capOK path was reachable in production but never proven in tests.
//
// Mutation guard: deleting either e.degradation.CreditCap*.Add(1) call, or
// reverting the `!capOK` branch's fail-closed error return, makes the
// corresponding test below fail.

import (
	"context"
	"sync"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// loanUnawareScripStore is a minimal scrip.SpendingStore implementation that
// deliberately does NOT implement scripLoanQuerier (no LoansByBorrower /
// GetLoan) — the fail-closed branch of ensureCreditForShortfall
// (borrowerOutstandingPrincipal's type assertion to scripLoanQuerier) exists
// specifically for a ScripStore shaped like this one: anything that is not a
// *scrip.LocalScripStore. Every other credit test in this package constructs
// a real *scrip.LocalScripStore (via newCampfireScripStore), which always
// satisfies scripLoanQuerier, so this fixture is the only way to exercise
// that branch.
type loanUnawareScripStore struct {
	mu           sync.Mutex
	balances     map[string]int64
	addCalls     int
	reservations map[string]scrip.Reservation
}

func newLoanUnawareScripStore() *loanUnawareScripStore {
	return &loanUnawareScripStore{
		balances:     make(map[string]int64),
		reservations: make(map[string]scrip.Reservation),
	}
}

func (s *loanUnawareScripStore) GetBudget(_ context.Context, pk, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.balances[pk], "etag", nil
}

func (s *loanUnawareScripStore) AddBudget(_ context.Context, pk, _ string, amount int64, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addCalls++
	s.balances[pk] += amount
	return s.balances[pk], "etag", nil
}

func (s *loanUnawareScripStore) DecrementBudget(_ context.Context, pk, _ string, amount int64, _ string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.balances[pk] < amount {
		return 0, "", scrip.ErrBudgetExceeded
	}
	s.balances[pk] -= amount
	return s.balances[pk], "etag", nil
}

func (s *loanUnawareScripStore) SaveReservation(_ context.Context, r scrip.Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reservations[r.ID] = r
	return nil
}

func (s *loanUnawareScripStore) GetReservation(_ context.Context, id string) (scrip.Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reservations[id]
	if !ok {
		return scrip.Reservation{}, scrip.ErrReservationNotFound
	}
	return r, nil
}

func (s *loanUnawareScripStore) DeleteReservation(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.reservations, id)
	return nil
}

func (s *loanUnawareScripStore) ConsumeReservation(_ context.Context, id string) (scrip.Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reservations[id]
	if !ok {
		return scrip.Reservation{}, scrip.ErrReservationNotFound
	}
	delete(s.reservations, id)
	return r, nil
}

func (s *loanUnawareScripStore) addBudgetCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addCalls
}

// TestEnsureCreditForShortfall_OverCapIncrementsDegradationCounter seeds a
// buyer already AT the per-buyer cap (mirroring
// TestEnsureCreditForShortfall_PerBuyerCapRefusesFurtherCredit's setup) and
// asserts the refusal is durably counted, not merely logged.
func TestEnsureCreditForShortfall_OverCapIncrementsDegradationCounter(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	buyerKey := h.buyer.PublicKeyHex()

	const capAmt = exchange.CreditMaxOutstandingPerBuyerForTest
	addScripLoanMintMsg(t, h, buyerKey, "loan-signal-precap", capAmt)

	cs := newCampfireScripStore(t, h)
	if err := cs.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	// The loan-mint credited the buyer's balance by `cap` too (applyLoanMint).
	// Simulate that the borrowed scrip was already spent (mirrors
	// TestEnsureCreditForShortfall_PerBuyerCapRefusesFurtherCredit) so the
	// balance check inside ensureCreditForShortfall doesn't short-circuit
	// with "no credit needed" before ever reaching the cap check.
	ctx := context.Background()
	bal, etag, err := cs.GetBudget(ctx, buyerKey, scrip.BalanceKey)
	if err != nil {
		t.Fatalf("GetBudget: %v", err)
	}
	if bal != capAmt {
		t.Fatalf("test setup: buyer balance after loan-mint = %d, want %d (== capAmt)", bal, capAmt)
	}
	if _, _, err := cs.DecrementBudget(ctx, buyerKey, scrip.BalanceKey, bal, etag); err != nil {
		t.Fatalf("test setup: DecrementBudget: %v", err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        h.st,
		OperatorPublicKey: h.operator.PublicKeyHex(),
		ScripStore:        cs,
		Logger:            func(string, ...any) {},
	})

	before := eng.DegradationSnapshot()
	if before.CreditCapRefused != 0 {
		t.Fatalf("test setup: CreditCapRefused = %d before any refusal, want 0", before.CreditCapRefused)
	}

	if err := eng.EnsureCreditForShortfallForTest(buyerKey, 1, "buyer-accept-signal-test", "match-signal-test"); err == nil {
		t.Fatal("expected ensureCreditForShortfall to refuse credit at the per-buyer cap")
	}

	after := eng.DegradationSnapshot()
	if after.CreditCapRefused != before.CreditCapRefused+1 {
		t.Errorf("CreditCapRefused after over-cap refusal = %d, want %d", after.CreditCapRefused, before.CreditCapRefused+1)
	}
	if after.CreditCapUnverifiable != before.CreditCapUnverifiable {
		t.Errorf("CreditCapUnverifiable changed on an over-cap (verified) refusal = %d, want unchanged %d",
			after.CreditCapUnverifiable, before.CreditCapUnverifiable)
	}
}

// TestEnsureCreditForShortfall_UnverifiableScripStoreFailsClosedAndCounts
// drives ensureCreditForShortfall against loanUnawareScripStore — a
// SpendingStore implementation that does NOT implement scripLoanQuerier (no
// LoansByBorrower/GetLoan), i.e. anything that is not a
// *scrip.LocalScripStore. borrowerOutstandingPrincipal's type assertion to
// scripLoanQuerier fails, so ensureCreditForShortfall must refuse credit
// fail-closed rather than risk unbounded credit. Before this test, NO test in
// the suite ever constructed a non-loan-aware ScripStore for this path: every
// other credit test uses a real *scrip.LocalScripStore, which always
// satisfies scripLoanQuerier.
func TestEnsureCreditForShortfall_UnverifiableScripStoreFailsClosedAndCounts(t *testing.T) {
	t.Parallel()

	// Sanity: loanUnawareScripStore must NOT satisfy scripLoanQuerier —
	// otherwise this test would not actually be exercising the fail-closed
	// branch it claims to.
	if _, ok := any(newLoanUnawareScripStore()).(interface {
		LoansByBorrower(string) []string
		GetLoan(string) (*scrip.LoanRecord, bool)
	}); ok {
		t.Fatal("test invariant broken: loanUnawareScripStore now implements scripLoanQuerier — this test no longer exercises the fail-closed !capOK branch")
	}

	store := newLoanUnawareScripStore()
	// Give the buyer a low balance so a shortfall exists and the cap-check
	// code path is actually reached (ensureCreditForShortfall returns early,
	// with no credit needed, if the balance already covers holdAmount).
	store.balances["buyer-under-test"] = 0

	eng := exchange.NewEngine(exchange.EngineOptions{
		OperatorPublicKey: "test-operator",
		ScripStore:        store,
		Logger:            func(string, ...any) {},
	})

	before := eng.DegradationSnapshot()

	err := eng.EnsureCreditForShortfallForTest("buyer-under-test", 5000, "buyer-accept-unverifiable-test", "match-unverifiable-test")
	if err == nil {
		t.Fatal("expected ensureCreditForShortfall to refuse credit fail-closed when the ScripStore does not support loan queries")
	}
	t.Logf("got expected fail-closed refusal error: %v", err)

	after := eng.DegradationSnapshot()
	if after.CreditCapUnverifiable != before.CreditCapUnverifiable+1 {
		t.Errorf("CreditCapUnverifiable after unverifiable-store refusal = %d, want %d", after.CreditCapUnverifiable, before.CreditCapUnverifiable+1)
	}
	if after.CreditCapRefused != before.CreditCapRefused {
		t.Errorf("CreditCapRefused changed on an unverifiable (not over-cap) refusal = %d, want unchanged %d",
			after.CreditCapRefused, before.CreditCapRefused)
	}

	// No loan should have been minted — the refusal must be a true no-op on
	// scrip state, not a partial credit extension.
	if store.addBudgetCalls() != 0 {
		t.Errorf("AddBudget was called %d times on a fail-closed refusal, want 0 (no partial credit)", store.addBudgetCalls())
	}
}
