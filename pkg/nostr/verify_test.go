package nostr

import (
	"errors"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// signEvent builds a real BIP-340 Schnorr-signed nostr wire event with the given
// signer. It goes through identity.SignEvent (which computes the NIP-01 id and a
// real secp256k1 signature), then copies the signed fields into the wire
// nostr.Event the verify primitive consumes. No stubbed verifier is used
// anywhere — every signature in these tests is produced and checked by the real
// secp256k1 code path.
func signEvent(t *testing.T, signer identity.Signer, kind int, tags [][]string, content string) *Event {
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
	return &Event{
		ID:        ie.ID,
		PubKey:    ie.PubKey,
		CreatedAt: ie.CreatedAt,
		Kind:      ie.Kind,
		Tags:      ie.Tags,
		Content:   ie.Content,
		Sig:       ie.Sig,
	}
}

func opTag(op string) []string   { return []string{tagOp, op} }
func phaseTag(p string) []string { return []string{tagPhase, p} }

// TestVerifyOperatorAuthorship_AllowsRealOperatorOps is the ALLOW test: for every
// operator-only (kind, sub-op/phase), an event genuinely signed by the operator
// key passes the gate.
func TestVerifyOperatorAuthorship_AllowsRealOperatorOps(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	opHex := op.PubKeyHex()

	cases := []struct {
		name string
		kind int
		tags [][]string
	}{
		{"match", KindMatch, nil},
		{"settle/put-accept", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrPutAccept)}},
		{"settle/put-reject", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrPutReject)}},
		{"settle/preview", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrPreview)}},
		{"settle/deliver", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrDeliver)}},
		{"assign", KindAssign, [][]string{opTag(exchange.TagAssign)}},
		{"assign-accept", KindAssign, [][]string{opTag(exchange.TagAssignAccept)}},
		{"assign-reject", KindAssign, [][]string{opTag(exchange.TagAssignReject)}},
		{"assign-expire", KindAssign, [][]string{opTag(exchange.TagAssignExpire)}},
		{"assign-auction-close", KindAssign, [][]string{opTag(exchange.TagAssignAuctionClose)}},
		{"scrip-mint", KindScrip, [][]string{opTag(scrip.TagScripMint)}},
		{"scrip-put-pay", KindScrip, [][]string{opTag(scrip.TagScripPutPay)}},
		{"scrip-burn", KindScrip, [][]string{opTag(scrip.TagScripBurn)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := signEvent(t, op, tc.kind, tc.tags, "body-"+tc.name)
			if err := VerifyOperatorAuthorship(ev, opHex); err != nil {
				t.Fatalf("operator-signed %s rejected: %v", tc.name, err)
			}
			// Same op, addressed to the operator by its npub form, still passes.
			if err := VerifyOperatorAuthorship(ev, op.Npub()); err != nil {
				t.Fatalf("operator-signed %s rejected when operator given as npub: %v", tc.name, err)
			}
		})
	}
}

// TestVerifyOperatorAuthorship_RejectsForgedOperatorKind is the REJECT test: an
// event of an operator-only kind that is signed by a NON-operator key (a real,
// valid signature — just the wrong author) is rejected LOUD with
// ErrForgedOperatorEvent.
func TestVerifyOperatorAuthorship_RejectsForgedOperatorKind(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate attacker: %v", err)
	}
	opHex := op.PubKeyHex()

	cases := []struct {
		name string
		kind int
		tags [][]string
	}{
		{"match", KindMatch, nil},
		{"settle/put-accept", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrPutAccept)}},
		{"settle/deliver", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrDeliver)}},
		{"assign", KindAssign, [][]string{opTag(exchange.TagAssign)}},
		{"assign-auction-close", KindAssign, [][]string{opTag(exchange.TagAssignAuctionClose)}},
		{"scrip-mint", KindScrip, [][]string{opTag(scrip.TagScripMint)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Attacker validly signs an operator-only kind under its OWN key.
			ev := signEvent(t, attacker, tc.kind, tc.tags, "forged-"+tc.name)
			// Sanity: the forged event's signature is internally valid — the ONLY
			// thing wrong is the author is not the operator. This proves the gate
			// rejects on authorship, not on a broken signature.
			if verr := identity.VerifyEvent(toIdentityEvent(ev)); verr != nil {
				t.Fatalf("attacker event should be self-consistently signed: %v", verr)
			}
			err := VerifyOperatorAuthorship(ev, opHex)
			if err == nil {
				t.Fatalf("forged operator-kind %s (signed by attacker) was ACCEPTED", tc.name)
			}
			if !errors.Is(err, ErrForgedOperatorEvent) {
				t.Fatalf("forged %s rejected with wrong error type: %v", tc.name, err)
			}
		})
	}
}

// TestVerifyOperatorAuthorship_SettleFailedIsOperatorOnly is the D5 regression:
// settle(failed), if authored, is operator-only, but was MISSING from
// operatorSettlePhases, so a non-operator could forge a relay-delivered failure
// notice a client might trust. It must be gated regardless of whether any engine
// path currently emits settle(failed) (dontguess-4be removed the settle-complete
// emitter): attacker-signed settle(failed) -> ErrForgedOperatorEvent, and a
// genuine operator-signed settle(failed) passes.
func TestVerifyOperatorAuthorship_SettleFailedIsOperatorOnly(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate attacker: %v", err)
	}
	opHex := op.PubKeyHex()

	// Attacker validly self-signs a settle(failed) — valid signature, wrong author.
	forged := signEvent(t, attacker, KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrFailed)}, "forged-failed")
	if verr := identity.VerifyEvent(toIdentityEvent(forged)); verr != nil {
		t.Fatalf("attacker settle(failed) should be self-consistently signed: %v", verr)
	}
	err = VerifyOperatorAuthorship(forged, opHex)
	if err == nil {
		t.Fatal("forged operator settle(failed) was ACCEPTED — D5 gap still open")
	}
	if !errors.Is(err, ErrForgedOperatorEvent) {
		t.Fatalf("forged settle(failed) rejected with wrong error type: %v", err)
	}

	// The genuine operator-signed settle(failed) still passes.
	genuine := signEvent(t, op, KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrFailed)}, "genuine-failed")
	if err := VerifyOperatorAuthorship(genuine, opHex); err != nil {
		t.Fatalf("operator-signed settle(failed) rejected: %v", err)
	}
}

// TestVerifyEventSignature_UniversalFloor covers the D1 universal signature floor:
// a validly-signed event of ANY kind passes; a tampered (bad-sig) event of ANY
// kind — including the non-operator put/buy kinds VerifyOperatorAuthorship does
// not govern — fails. This is the primitive the Intake runs FIRST for every kind.
func TestVerifyEventSignature_UniversalFloor(t *testing.T) {
	signer, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	for _, kind := range []int{KindPut, KindBuy, KindMatch, KindSettle, KindAssign, KindScrip} {
		ev := signEvent(t, signer, kind, nil, "body")
		if err := VerifyEventSignature(ev); err != nil {
			t.Fatalf("validly-signed kind %d rejected by floor: %v", kind, err)
		}
		// Tamper the content after signing: id no longer matches, sig no longer verifies.
		bad := signEvent(t, signer, kind, nil, "body")
		bad.Content += "-tampered"
		if err := VerifyEventSignature(bad); err == nil {
			t.Fatalf("tampered kind %d event passed the signature floor", kind)
		}
	}
	if err := VerifyEventSignature(nil); err == nil {
		t.Fatal("nil event should be rejected by the floor")
	}
}

// TestVerifyOperatorAuthorship_RejectsSpoofedPubkey covers the subtler forgery:
// an attacker sets the operator's pubkey in the author field but cannot produce a
// signature that verifies for it. The signature/id-integrity check (step 2) must
// catch this even though the author field matches the operator.
func TestVerifyOperatorAuthorship_RejectsSpoofedPubkey(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	attacker, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate attacker: %v", err)
	}
	opHex := op.PubKeyHex()

	// Attacker signs a match under its own key, then swaps the author field to the
	// operator's pubkey — leaving the attacker's id and signature in place.
	ev := signEvent(t, attacker, KindMatch, nil, "spoof")
	ev.PubKey = opHex

	err = VerifyOperatorAuthorship(ev, opHex)
	if err == nil {
		t.Fatal("spoofed-pubkey match was ACCEPTED")
	}
	if !errors.Is(err, ErrForgedOperatorEvent) {
		t.Fatalf("spoofed pubkey rejected with wrong error type: %v", err)
	}
}

// TestVerifyOperatorAuthorship_AllowsNonOperatorKinds asserts the gate does NOT
// touch authorship for kinds/sub-ops that are legitimately authored by buyers,
// sellers, or workers — a blanket operator-only rule on the shared kinds would
// reject all of these.
func TestVerifyOperatorAuthorship_AllowsNonOperatorKinds(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	buyer, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate buyer: %v", err)
	}
	opHex := op.PubKeyHex()

	cases := []struct {
		name string
		kind int
		tags [][]string
	}{
		{"put", KindPut, nil},
		{"buy", KindBuy, nil},
		{"settle/preview-request", KindSettle, [][]string{phaseTag("preview-request")}},
		{"settle/buyer-accept", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrBuyerAccept)}},
		{"settle/buyer-reject", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrBuyerReject)}},
		{"settle/complete", KindSettle, [][]string{phaseTag(exchange.SettlePhaseStrComplete)}},
		{"assign-claim", KindAssign, [][]string{opTag(exchange.TagAssignClaim)}},
		{"assign-complete", KindAssign, [][]string{opTag(exchange.TagAssignComplete)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Signed by a NON-operator (buyer/worker) — this is legitimate.
			ev := signEvent(t, buyer, tc.kind, tc.tags, "legit-"+tc.name)
			if err := VerifyOperatorAuthorship(ev, opHex); err != nil {
				t.Fatalf("non-operator kind %s (legitimately buyer/worker-authored) was rejected: %v", tc.name, err)
			}
		})
	}
}

// TestVerifyOperatorAuthorship_InputGuards covers the loud-failure guards on bad
// inputs.
func TestVerifyOperatorAuthorship_InputGuards(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}

	if err := VerifyOperatorAuthorship(nil, op.PubKeyHex()); err == nil {
		t.Fatal("nil event should be rejected")
	}

	// Operator-only event but an empty operator key is a caller error, not a pass.
	ev := signEvent(t, op, KindMatch, nil, "x")
	if err := VerifyOperatorAuthorship(ev, ""); err == nil {
		t.Fatal("empty operator key on an operator-only event should error")
	}

	// A non-operator event with an empty operator key still passes — the gate
	// never consults the operator key for kinds it does not govern.
	buy := signEvent(t, op, KindBuy, nil, "x")
	if err := VerifyOperatorAuthorship(buy, ""); err != nil {
		t.Fatalf("non-operator event should pass regardless of operator key: %v", err)
	}
}
