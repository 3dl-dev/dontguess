package exchange_test

// encrypted_required_scripless_adv7_test.go — the dontguess-e18d / ADV-7 done-gate
// (design §6 + §9 Gate A/P4): encryptedRequired is DECOUPLED from scrip. It is
// armed on relay-attachment ALONE (OperatorSigner != nil), independent of
// ScripStore.
//
// The latent leak this closes: the pre-decouple gate was
// `encryptedRequired = ScripStore != nil && OperatorSigner != nil` — confidentiality
// ANDed with payment. Any future relay-attached-but-SCRIPLESS rung (an operator
// that can sign for a relay but keeps no scrip ledger) would therefore have
// encryptedRequired == false and would silently BROADCAST plaintext puts to the
// relay in cleartext. The moment an operator can sign for a relay it MUST require
// ciphertext, whether or not it charges scrip.
//
// This is the ground-source assertion the item names: ScripStore nil +
// OperatorSigner != nil ⇒ encryptedRequired fires (plaintext dropped, no plaintext
// broadcast), proven against a same-content individual-tier control that DOES fold
// the plaintext (no signer ⇒ encryptedRequired off) — so the drop is provably
// caused by the signer-armed gate, not by anything intrinsic to the put. Nothing
// is mocked: real secp256k1 identities, real NIP-44 v2 envelope for the v2 arm.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

func TestEncryptedRequired_ScriplessRelayRung_DropsPlaintext(t *testing.T) {
	t.Parallel()
	h := newTestHarness(t)
	operator, seller, _ := useSecpIdentities(t, h)

	// Relay-attached-but-SCRIPLESS rung: OperatorSigner set, ScripStore left nil.
	// This is the exact configuration ADV-7 guards — it must be fail-closed.
	engScriplessTeam := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
		// o.ScripStore deliberately unset (nil) — the scripless rung.
	})

	// A v2 confidential put (must still fold — encryptedRequired blocks PLAINTEXT,
	// never ciphertext) and a legacy PLAINTEXT put (must be dropped).
	const v2Desc = "postgres autovacuum tuning runbook with worked thresholds"
	v2Plain := []byte("SECRET-ADV7-V2-" + strings.Repeat("autovacuum-threshold-", 8) + "END")
	v2Payload, _ := buildV2PutPayload(t, seller, operator.PubKeyHex(), v2Desc, v2Plain, 7000)
	v2Put := h.sendMessage(h.seller, v2Payload,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	const plainDesc = "redis cluster slot migration step-by-step guide"
	plaintextPut := h.sendMessage(h.seller,
		putPayload(plainDesc, "sha256:"+fmt.Sprintf("%064x", 9), "code", 6000, 2048),
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)

	all, _ := h.st.ListMessages(h.cfID, 0)
	engScriplessTeam.State().Replay(exchange.FromStoreRecords(all))

	// The v2 (encrypted) put must fold — otherwise the drop assertion below is
	// vacuous (an engine that dropped EVERYTHING would trivially "pass").
	if err := engScriplessTeam.AutoAcceptPut(v2Put.ID, 4000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("v2 put must fold on the scripless team tier (encryptedRequired blocks plaintext, not ciphertext): %v", err)
	}

	// The plaintext put must have been fail-closed dropped by applyPut: it never
	// folded into pendingPuts, so AutoAcceptPut cannot promote it.
	if err := engScriplessTeam.AutoAcceptPut(plaintextPut.ID, 4000, time.Now().Add(72*time.Hour)); err == nil {
		t.Fatal("ADV-7 REGRESSION: a scripless relay-attached engine (OperatorSigner set, ScripStore nil) ACCEPTED a plaintext put — encryptedRequired is still coupled to scrip, so this rung would silently broadcast cleartext")
	}

	var sawV2, sawPlaintext bool
	for _, e := range engScriplessTeam.State().Inventory() {
		switch e.PutMsgID {
		case v2Put.ID:
			sawV2 = true
		case plaintextPut.ID:
			sawPlaintext = true
		}
	}
	if !sawV2 {
		t.Fatal("v2 put did not fold on the scripless team tier — encryptedRequired must not block ENCRYPTED puts")
	}
	if sawPlaintext {
		t.Fatal("ADV-7 REGRESSION: the plaintext put folded into scripless-team-tier inventory (would be broadcast in cleartext)")
	}

	// ── CONTROL: individual tier (NO signer, NO scrip). The byte-identical
	//    plaintext put MUST fold here, proving the drop above is attributable to the
	//    OperatorSigner-armed encryptedRequired — not to the put content, the seller,
	//    or the absence of scrip (both engines are scripless). This is the load-
	//    bearing half: it isolates OperatorSigner as the single variable that arms
	//    the gate.
	h2 := newTestHarness(t)
	op2, _, _ := useSecpIdentities(t, h2)
	engIndiv := h2.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = op2.PubKeyHex()
		// No OperatorSigner, no ScripStore — individual tier.
	})
	ctrlPut := h2.sendMessage(h2.seller,
		putPayload(plainDesc, "sha256:"+fmt.Sprintf("%064x", 9), "code", 6000, 2048),
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)
	all2, _ := h2.st.ListMessages(h2.cfID, 0)
	engIndiv.State().Replay(exchange.FromStoreRecords(all2))
	if err := engIndiv.AutoAcceptPut(ctrlPut.ID, 4000, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("individual-tier control: the SAME plaintext put must fold (no signer ⇒ encryptedRequired off): %v", err)
	}
	var sawCtrl bool
	for _, e := range engIndiv.State().Inventory() {
		if e.PutMsgID == ctrlPut.ID {
			sawCtrl = true
		}
	}
	if !sawCtrl {
		t.Fatal("individual-tier control plaintext put did not fold — cannot attribute the scripless-team drop to the signer")
	}
}
