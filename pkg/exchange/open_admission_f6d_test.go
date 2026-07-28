package exchange_test

// open_admission_7a2_test.go — enforcement proof for dontguess-f6d: an unknown
// sender is ADMITTED ON DEMAND at fleet tier instead of having its work dropped
// `not-allowlisted`, and the fences that keep that from becoming a hole hold.
//
// The fences are the point of this file. Granting admission is one line; the
// value is in what it refuses. Each of the four is tested separately, because a
// single "it still rejects bad things" assertion would pass with any one of them
// silently removed.
//
// The operator-authority fence is the load-bearing one: admission may only ever
// satisfy TrustAllowlisted. If it could satisfy TrustOperator, any key reaching
// the relay could forge put-accepts, delivers and settlements — i.e. mint scrip
// and hand itself content. That is a different universe from being allowed to
// sell, and TestOpenAdmission_NeverGrantsOperatorAuthority is what keeps them
// apart.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// admissionFixture is a team-tier engine whose allowlist starts EMPTY, so any
// sender is an unknown one.
type admissionFixture struct {
	h         *testHarness
	eng       *exchange.Engine
	keys      *exchange.KeySet
	persisted []string
}

func newAdmissionFixture(t *testing.T, openAdmission bool, federation bool) *admissionFixture {
	t.Helper()
	h := newTestHarness(t)
	ks := exchange.NewKeySet() // deliberately empty: nobody is admitted
	tc, err := exchange.NewTrustChecker(h.operator.pubKeyHex, ks)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}
	f := &admissionFixture{h: h, keys: ks}
	f.eng = h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.TrustChecker = tc
		o.OpenAdmission = openAdmission
		o.FederationGuardEnabled = federation
		o.AdmitMember = func(hexKey string) error {
			f.persisted = append(f.persisted, hexKey)
			return nil
		}
	})
	return f
}

// dispatchPut folds and dispatches a put from sender through the REAL dispatch
// trust gate — the single seam every admission-gated operation passes through.
func (f *admissionFixture) dispatchPut(t *testing.T, sender *testAgent) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"description":  "open-admission fixture entry",
		"content":      "b3BlbiBhZG1pc3Npb24gdGVzdCBjb250ZW50IHBhZGRpbmcgcGFkZGluZw==",
		"token_cost":   int64(9000),
		"content_type": "code",
		"domains":      []string{"go"},
	})
	msg := f.h.sendMessage(sender, payload, []string{exchange.TagPut, "exchange:content-type:code"}, nil)
	rec, err := f.h.st.GetMessage(msg.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if derr := f.eng.DispatchForTest(exchange.FromStoreRecord(rec)); derr != nil {
		t.Fatalf("DispatchForTest(put): %v", derr)
	}
}

// TestOpenAdmission_UnknownSenderIsAdmittedAndItsWorkLands is the core case: the
// exact scenario that dropped 47 distinct agent keys' real work on the live
// exchange.
func TestOpenAdmission_UnknownSenderIsAdmittedAndItsWorkLands(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, false)
	newcomer := newTestAgent(t)

	if f.keys.Allowed(newcomer.pubKeyHex) {
		t.Fatal("fixture broken: the newcomer is already allowlisted")
	}

	f.dispatchPut(t, newcomer)

	if !f.keys.Allowed(newcomer.pubKeyHex) {
		t.Fatal("an unknown sender was NOT admitted on demand — its work is dropped not-allowlisted, which is the whole defect (dontguess-f6d)")
	}
	// Durable, not just live: otherwise every restart silently re-refuses.
	if len(f.persisted) != 1 || f.persisted[0] != newcomer.pubKeyHex {
		t.Fatalf("admission was not persisted: got %v, want [%s]", f.persisted, newcomer.pubKeyHex)
	}
	if got := f.eng.DegradationSnapshot().OpenAdmissionGranted; got != 1 {
		t.Fatalf("OpenAdmissionGranted = %d, want 1", got)
	}
}

// TestOpenAdmission_NeverGrantsOperatorAuthority is the fence that matters most.
// An operator-level operation (settle put-accept) must be refused even with open
// admission on: admission may only ever satisfy TrustAllowlisted. Were this to
// pass, any key on the relay could forge settlements and mint itself scrip.
func TestOpenAdmission_NeverGrantsOperatorAuthority(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, false)
	impostor := newTestAgent(t)

	acceptPayload, _ := json.Marshal(map[string]any{
		"phase":      "put-accept",
		"entry_id":   "some-entry",
		"price":      int64(1),
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	msg := f.h.sendMessage(impostor, acceptPayload,
		[]string{exchange.TagSettle, exchange.TagPhasePrefix + exchange.SettlePhaseStrPutAccept, exchange.TagVerdictPrefix + "accepted"},
		nil)
	rec, _ := f.h.st.GetMessage(msg.ID)
	if err := f.eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Fatalf("DispatchForTest: %v", err)
	}

	if f.keys.Allowed(impostor.pubKeyHex) {
		t.Fatal("SECURITY: open admission admitted a sender attempting an OPERATOR-level settle. Admission must only ever satisfy TrustAllowlisted — otherwise any key on the relay can forge put-accepts, delivers and settlements, i.e. mint scrip and hand itself content")
	}
	if len(f.persisted) != 0 {
		t.Fatalf("SECURITY: an operator-level attempt was persisted to the allowlist: %v", f.persisted)
	}
	if got := f.eng.DegradationSnapshot().OpenAdmissionGranted; got != 0 {
		t.Fatalf("OpenAdmissionGranted = %d, want 0", got)
	}
}

// TestOpenAdmission_NeverAtFederation pins the tier gate: where a peer is not the
// operator's own agent, admission is a real trust decision and stays manual.
func TestOpenAdmission_NeverAtFederation(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, true) // FederationGuardEnabled
	newcomer := newTestAgent(t)

	f.dispatchPut(t, newcomer)

	if f.keys.Allowed(newcomer.pubKeyHex) {
		t.Fatal("open admission fired at FEDERATION — a peer that is not the operator's own agent was auto-admitted (dontguess-5a3 territory)")
	}
	if len(f.persisted) != 0 {
		t.Fatalf("federation admission was persisted: %v", f.persisted)
	}
}

// TestOpenAdmission_NeverResurrectsARevokedSeller: a seller de-allowlisted FOR
// CAUSE carries a durable tombstone. If open admission cleared it, revocation
// would mean nothing — the very next event would re-admit.
func TestOpenAdmission_NeverResurrectsARevokedSeller(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, false)
	bad := newTestAgent(t)

	// Admitted once, then revoked for cause.
	f.dispatchPut(t, bad)
	if !f.keys.Allowed(bad.pubKeyHex) {
		t.Fatal("fixture broken: first admission did not take")
	}
	f.eng.DeAllowlistSeller(bad.pubKeyHex)
	f.keys.Remove(bad.pubKeyHex)
	f.persisted = nil

	// It comes straight back with new work.
	f.dispatchPut(t, bad)

	if f.keys.Allowed(bad.pubKeyHex) {
		t.Fatal("open admission RE-ADMITTED a seller revoked for cause — revocation is meaningless if the next event undoes it")
	}
	if len(f.persisted) != 0 {
		t.Fatalf("a revoked seller's re-admission was persisted: %v", f.persisted)
	}
}

// TestOpenAdmission_Disabled_RestoresManualAllowlist proves the opt-out is real,
// and that every assertion above is actually caused by open admission rather than
// by the fixture admitting everyone anyway.
func TestOpenAdmission_Disabled_RestoresManualAllowlist(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, false, false)
	newcomer := newTestAgent(t)

	f.dispatchPut(t, newcomer)

	if f.keys.Allowed(newcomer.pubKeyHex) {
		t.Fatal("OpenAdmission=false still admitted an unknown sender — the opt-out does nothing")
	}
	if len(f.persisted) != 0 {
		t.Fatalf("admission persisted with OpenAdmission=false: %v", f.persisted)
	}
}
