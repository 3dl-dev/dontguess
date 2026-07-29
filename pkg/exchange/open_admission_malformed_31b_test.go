package exchange_test

// open_admission_malformed_31b_test.go — dontguess-31b, the durable-state fence
// on open admission.
//
// Open admission (dontguess-f6d) does not merely admit a sender live; it PERSISTS
// the key into Config.FleetAllowlist so the admission survives a restart. That
// makes it a writer of durable state, and it had no validation. A sender key that
// is not a point on the secp256k1 curve was admitted, written to config, and then
// refused by the boot loader — which aborted startup. The exchange took itself
// down and could not be restarted until the config was hand-edited.
//
// 45% of this exchange's historical senders are such keys (dead campfire-era
// ed25519 identities that replay off the relay on every restart), so this was not
// an exotic input — it was a matter of time.

import (
	"encoding/json"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// offCurveSender is a real sender key from the live event log: well-formed
// 64-char hex that is NOT on the secp256k1 curve. This exact value bricked the
// operator.
const offCurveSender = "e53a88d79ef658a13d2befffb7312b7256563b5f94f0a240340f6580c68e3686"

// TestOpenAdmission_RefusesMalformedSenderKey is the regression proper: the
// sender that took the exchange down must be refused admission, and above all
// must never reach durable state.
func TestOpenAdmission_RefusesMalformedSenderKey(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, false)

	f.dispatchPutFromRawSender(t, offCurveSender)

	if f.keys.Allowed(offCurveSender) {
		t.Fatal("open admission admitted a sender key that is not a valid secp256k1 point")
	}
	// THE ONE THAT MATTERS. Live admission of a junk key is merely useless;
	// PERSISTING it is what refuses the next boot and takes the exchange down.
	if len(f.persisted) != 0 {
		t.Fatalf("a malformed key was persisted to the durable allowlist: %v — this is precisely what bricked the operator (dontguess-31b)", f.persisted)
	}
	if got := f.eng.DegradationSnapshot().OpenAdmissionGranted; got != 0 {
		t.Fatalf("OpenAdmissionGranted = %d, want 0", got)
	}
	// Counted, not merely logged: a rising count is the early warning that the
	// legacy-sender backlog is being re-ingested.
	if got := f.eng.DegradationSnapshot().OpenAdmissionMalformedKey; got != 1 {
		t.Fatalf("OpenAdmissionMalformedKey = %d, want 1 — a refusal that is not counted is invisible in `dontguess status`", got)
	}
}

// TestOpenAdmission_MalformedRefusalDoesNotBlockValidSenders proves the fence is
// narrow. A junk sender arriving before a real one must not disturb admission of
// the real one — otherwise the fix trades an outage for a subtler one.
func TestOpenAdmission_MalformedRefusalDoesNotBlockValidSenders(t *testing.T) {
	t.Parallel()
	f := newAdmissionFixture(t, true, false)

	f.dispatchPutFromRawSender(t, offCurveSender)
	newcomer := newTestAgent(t)
	f.dispatchPut(t, newcomer)

	if !f.keys.Allowed(newcomer.pubKeyHex) {
		t.Fatal("a valid newcomer was not admitted after a malformed sender was refused — the fence must be narrow")
	}
	if len(f.persisted) != 1 || f.persisted[0] != newcomer.pubKeyHex {
		t.Fatalf("persisted = %v, want exactly [%s]", f.persisted, newcomer.pubKeyHex)
	}
	snap := f.eng.DegradationSnapshot()
	if snap.OpenAdmissionGranted != 1 || snap.OpenAdmissionMalformedKey != 1 {
		t.Fatalf("granted = %d (want 1), malformedKey = %d (want 1)", snap.OpenAdmissionGranted, snap.OpenAdmissionMalformedKey)
	}
}

// dispatchPutFromRawSender dispatches a put whose Sender is an arbitrary hex
// string rather than a generated agent — the only way to model the legacy
// non-secp256k1 identities that actually appear in the live event log.
func (f *admissionFixture) dispatchPutFromRawSender(t *testing.T, senderHex string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"description":  "legacy non-secp256k1 sender entry",
		"content":      "bGVnYWN5IHNlbmRlciB0ZXN0IGNvbnRlbnQgcGFkZGluZyBwYWRkaW5n",
		"token_cost":   int64(9000),
		"content_type": "code",
		"domains":      []string{"go"},
	})
	msg := f.h.sendMessage(&testAgent{pubKeyHex: senderHex}, payload,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)
	rec, err := f.h.st.GetMessage(msg.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if derr := f.eng.DispatchForTest(exchange.FromStoreRecord(rec)); derr != nil {
		t.Fatalf("DispatchForTest(put): %v", derr)
	}
}
