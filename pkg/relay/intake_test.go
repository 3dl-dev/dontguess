package relay

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// signEvent builds a real BIP-340 Schnorr-signed wire nostr.Event via
// identity.SignEvent (a real secp256k1 signature over the NIP-01 id). No stubbed
// verifier is used anywhere in these tests — every signature the Intake checks is
// produced and verified by the real crypto path, so a "valid signature" in a test
// is a genuinely-valid signature.
func signEvent(t *testing.T, signer identity.Signer, kind int, tags [][]string, content string) *nostr.Event {
	t.Helper()
	ie := &identity.Event{
		CreatedAt: 1_720_000_000,
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
	if err := identity.SignEvent(signer, ie); err != nil {
		t.Fatalf("SignEvent(kind=%d): %v", kind, err)
	}
	return &nostr.Event{
		ID:        ie.ID,
		PubKey:    ie.PubKey,
		CreatedAt: ie.CreatedAt,
		Kind:      ie.Kind,
		Tags:      ie.Tags,
		Content:   ie.Content,
		Sig:       ie.Sig,
	}
}

// newTestIntake wires a real Sequencer + a real on-disk Store (temp file) so the
// "never persisted" assertions read the ACTUAL store, not a mock. The alarm sink
// records every class it was called with so tests can assert loud degradation.
func newTestIntake(t *testing.T, operatorKey string) (*Intake, *IntakeMetrics, *store.Store, *[]string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "intake.log"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var alarms []string
	seq := exchange.NewSequencer(0)
	m := &IntakeMetrics{}
	in := NewIntake(seq, st, operatorKey, m, func(class string, _ error, _ *nostr.Event) {
		alarms = append(alarms, class)
	})
	return in, m, st, &alarms
}

// storeLen reads the real store back and returns the number of persisted records.
func storeLen(t *testing.T, st *store.Store) int {
	t.Helper()
	recs, err := st.ReadAll()
	if err != nil {
		t.Fatalf("store ReadAll: %v", err)
	}
	return len(recs)
}

func phaseTag(p string) []string { return []string{"phase", p} }
func opTag(op string) []string   { return []string{"op", op} }

// TestIntake_BadSignatureAnyKindDroppedPreIngest is table-(a): an event with an
// INVALID signature of ANY kind — including the non-operator put/buy kinds that
// VerifyOperatorAuthorship deliberately does not govern — is dropped at STEP 0
// (dropped_unsigned), BEFORE Sequencer.Ingest, and never persists. This is the
// D1 CRITICAL: without the universal floor, put/buy rode in with an unbound
// attacker-controlled sender.
func TestIntake_BadSignatureAnyKindDroppedPreIngest(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	in, m, st, alarms := newTestIntake(t, op.PubKeyHex())

	// Cover a non-operator kind (put) AND an operator kind (match) — the floor is
	// universal, so a broken signature must drop regardless of kind.
	cases := []struct {
		name string
		kind int
		tags [][]string
	}{
		{"put", nostr.KindPut, nil},
		{"buy", nostr.KindBuy, nil},
		{"match", nostr.KindMatch, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := signEvent(t, op, tc.kind, tc.tags, "body")
			// Tamper the content AFTER signing: the id no longer matches the
			// content and the signature no longer verifies — a bad-sig event.
			ev.Content = ev.Content + "-tampered"

			err := in.HandleEvent(ev)
			if err == nil {
				t.Fatalf("bad-sig %s was accepted", tc.name)
			}
		})
	}

	if got := m.DroppedUnsigned.Load(); got != 3 {
		t.Fatalf("DroppedUnsigned = %d, want 3", got)
	}
	if got := m.Received.Load(); got != 3 {
		t.Fatalf("Received = %d, want 3", got)
	}
	// Never reached the operator-authorship step, the sequencer, or the store.
	if got := m.DroppedForged.Load(); got != 0 {
		t.Fatalf("DroppedForged = %d, want 0 (must not reach operator gate)", got)
	}
	if got := m.Persisted.Load(); got != 0 {
		t.Fatalf("Persisted = %d, want 0", got)
	}
	if n := storeLen(t, st); n != 0 {
		t.Fatalf("store has %d records, want 0 — a bad-sig event must NEVER persist", n)
	}
	for _, a := range *alarms {
		if a != "dropped_unsigned" {
			t.Fatalf("unexpected alarm class %q, want only dropped_unsigned", a)
		}
	}
	if len(*alarms) != 3 {
		t.Fatalf("alarm count = %d, want 3 (loud on every drop)", len(*alarms))
	}
}

// TestIntake_ForgedOperatorEventDroppedForged is table-(b): a right-KIND
// wrong-AUTHOR operator event (a match validly self-signed by an attacker) passes
// the universal signature floor but is dropped at STEP 2 (dropped_forged) and
// never persists.
func TestIntake_ForgedOperatorEventDroppedForged(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate attacker: %v", err)
	}
	in, m, st, alarms := newTestIntake(t, op.PubKeyHex())

	// Attacker validly signs a match (operator-only kind) under its OWN key: the
	// signature is internally valid, only the author is wrong.
	ev := signEvent(t, attacker, nostr.KindMatch, nil, "forged-match")
	if verr := nostr.VerifyEventSignature(ev); verr != nil {
		t.Fatalf("attacker event should be self-consistently signed: %v", verr)
	}

	err = in.HandleEvent(ev)
	if err == nil {
		t.Fatal("forged operator match was accepted")
	}
	if !errors.Is(err, nostr.ErrForgedOperatorEvent) {
		t.Fatalf("forged match dropped with wrong error type: %v", err)
	}
	if got := m.DroppedForged.Load(); got != 1 {
		t.Fatalf("DroppedForged = %d, want 1", got)
	}
	if got := m.DroppedUnsigned.Load(); got != 0 {
		t.Fatalf("DroppedUnsigned = %d, want 0 (signature was valid)", got)
	}
	if got := m.Persisted.Load(); got != 0 {
		t.Fatalf("Persisted = %d, want 0", got)
	}
	if n := storeLen(t, st); n != 0 {
		t.Fatalf("store has %d records, want 0 — a forged operator event must NEVER persist", n)
	}
	if len(*alarms) != 1 || (*alarms)[0] != "dropped_forged" {
		t.Fatalf("alarms = %v, want exactly [dropped_forged]", *alarms)
	}
}

// TestIntake_ValidNonOperatorEventFolds is table-(c): a genuinely-signed
// non-operator event (a seller's put) passes all three gates, is sequenced, and
// is persisted with Origin="relay" and the assigned Seq.
func TestIntake_ValidNonOperatorEventFolds(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate seller: %v", err)
	}
	in, m, st, alarms := newTestIntake(t, op.PubKeyHex())

	ev := signEvent(t, seller, nostr.KindPut, nil, "genuine-put")
	if err := in.HandleEvent(ev); err != nil {
		t.Fatalf("valid non-operator put rejected: %v", err)
	}

	if got := m.Persisted.Load(); got != 1 {
		t.Fatalf("Persisted = %d, want 1", got)
	}
	if got := m.DroppedUnsigned.Load() + m.DroppedForged.Load() + m.DroppedSmuggled.Load(); got != 0 {
		t.Fatalf("unexpected drops = %d, want 0", got)
	}
	if len(*alarms) != 0 {
		t.Fatalf("alarms = %v, want none for a clean fold", *alarms)
	}

	recs, err := st.ReadAll()
	if err != nil {
		t.Fatalf("store ReadAll: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("store has %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Origin != "relay" {
		t.Fatalf("record Origin = %q, want %q", r.Origin, "relay")
	}
	if r.ID != ev.ID {
		t.Fatalf("record ID = %q, want %q (the wire event id)", r.ID, ev.ID)
	}
	if r.Sender != seller.PubKeyHex() {
		t.Fatalf("record Sender = %q, want seller pubkey %q", r.Sender, seller.PubKeyHex())
	}
	if r.Seq != 0 {
		t.Fatalf("record Seq = %d, want 0 (first sequenced event)", r.Seq)
	}
}

// TestIntake_ForgedEventNeverReachesBatchAppend is table-(d), the D4 structural
// assertion: after driving a mix of forged and unsigned events through the Intake,
// the store — read back from disk — is EMPTY. Steps 0-2 all precede
// Ingest/BatchAppend, so a forged/unsigned event is structurally incapable of
// reaching the store (the dontguess-553 fails-toward-silent mode is closed).
func TestIntake_ForgedEventNeverReachesBatchAppend(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate attacker: %v", err)
	}
	in, m, st, _ := newTestIntake(t, op.PubKeyHex())

	// (1) A forged operator settle(failed) — D5's newly-guarded phase, signed by
	// the attacker. Valid signature, wrong author -> dropped_forged.
	forgedSettle := signEvent(t, attacker, nostr.KindSettle,
		[][]string{phaseTag(exchange.SettlePhaseStrFailed)}, "forged-settle-failed")
	// (2) A forged operator assign-auction-close, signed by the attacker.
	forgedAssign := signEvent(t, attacker, nostr.KindAssign,
		[][]string{opTag(exchange.TagAssignAuctionClose)}, "forged-auction-close")
	// (3) A bad-signature put (tampered after signing) -> dropped_unsigned.
	badSig := signEvent(t, attacker, nostr.KindPut, nil, "put")
	badSig.Content += "-tampered"

	for _, ev := range []*nostr.Event{forgedSettle, forgedAssign, badSig} {
		if err := in.HandleEvent(ev); err == nil {
			t.Fatalf("kind %d forged/unsigned event was accepted", ev.Kind)
		}
	}

	// The authoritative assertion: nothing was ever appended to the real store.
	if n := storeLen(t, st); n != 0 {
		t.Fatalf("store has %d records, want 0 — no forged/unsigned event may EVER reach BatchAppend", n)
	}
	if got := m.Persisted.Load(); got != 0 {
		t.Fatalf("Persisted = %d, want 0", got)
	}
	if got := m.DroppedForged.Load(); got != 2 {
		t.Fatalf("DroppedForged = %d, want 2 (settle-failed + auction-close)", got)
	}
	if got := m.DroppedUnsigned.Load(); got != 1 {
		t.Fatalf("DroppedUnsigned = %d, want 1 (tampered put)", got)
	}
}

// TestIntake_ProjectionKindDroppedSmuggled asserts the adapter-boundary drop
// class: a validly-signed 30401 inventory projection (never folded as source of
// truth) is dropped at STEP 1 (dropped_smuggled) and never persists.
func TestIntake_ProjectionKindDroppedSmuggled(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	in, m, st, alarms := newTestIntake(t, op.PubKeyHex())

	ev := signEvent(t, op, nostr.KindInventoryProjection, nil, "projection")
	// The signature is valid; the adapter rejects the kind.
	if verr := nostr.VerifyEventSignature(ev); verr != nil {
		t.Fatalf("projection event should be validly signed: %v", verr)
	}

	if err := in.HandleEvent(ev); err == nil {
		t.Fatal("30401 projection was accepted")
	}
	if got := m.DroppedSmuggled.Load(); got != 1 {
		t.Fatalf("DroppedSmuggled = %d, want 1", got)
	}
	if n := storeLen(t, st); n != 0 {
		t.Fatalf("store has %d records, want 0", n)
	}
	if len(*alarms) != 1 || (*alarms)[0] != "dropped_smuggled" {
		t.Fatalf("alarms = %v, want exactly [dropped_smuggled]", *alarms)
	}
}
