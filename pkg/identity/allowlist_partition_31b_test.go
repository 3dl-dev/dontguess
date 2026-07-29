package identity

// allowlist_partition_31b_test.go — dontguess-31b.
//
// THE OUTAGE THIS PINS. Open admission wrote a sender key into
// Config.FleetAllowlist without checking it was a real pubkey. The next operator
// boot loaded that config through NewAllowlist, which DOES check, refused the
// entry, and returned an error that aborted startup. The live exchange stayed
// down for ~80 minutes and could not be repaired with `dontguess allowlist
// remove`, because that command validated the very key it was asked to delete.
//
// Two rules come out of it, and this file pins both:
//
//	1. An admission path may never be laxer than the load path
//	   (NormalizeAllowlistEntry is now the single shared decision).
//	2. Loading must fail closed on the ENTRY, not on the SERVICE
//	   (NewAllowlistPartition quarantines instead of aborting).

import (
	"strings"
	"testing"
)

// offCurveHex is a real sender key from the live event log: 64 valid hex
// characters whose value is NOT a point on the secp256k1 curve. It is the exact
// entry that bricked the operator. Roughly half of all 32-byte values fail this
// way, which is why the exchange's dead campfire-era ed25519 identities keep
// producing them.
const offCurveHex = "e53a88d79ef658a13d2befffb7312b7256563b5f94f0a240340f6580c68e3686"

func TestNormalizeAllowlistEntry_RejectsOffCurveHex(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeAllowlistEntry(offCurveHex); err == nil {
		t.Fatal("NormalizeAllowlistEntry accepted an off-curve 32-byte value. This is the shared gate every admission path now calls; if it accepts, open admission can once again persist an entry that the boot loader refuses, and the operator will not start")
	}
}

func TestNormalizeAllowlistEntry_AcceptsRealKeyInBothForms(t *testing.T) {
	t.Parallel()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	hexKey := id.PubKeyHex()

	got, err := NormalizeAllowlistEntry(hexKey)
	if err != nil {
		t.Fatalf("NormalizeAllowlistEntry(hex) rejected a real key: %v", err)
	}
	if got != strings.ToLower(hexKey) {
		t.Fatalf("hex form normalized to %q, want %q", got, strings.ToLower(hexKey))
	}

	npub, err := EncodeNpubHex(hexKey)
	if err != nil {
		t.Fatalf("EncodeNpubHex: %v", err)
	}
	gotNpub, err := NormalizeAllowlistEntry(npub)
	if err != nil {
		t.Fatalf("NormalizeAllowlistEntry(npub) rejected a real key: %v", err)
	}
	// npub and hex forms of one key MUST collapse to the same hex, or a remove
	// by one form silently fails to match an entry stored in the other.
	if gotNpub != got {
		t.Fatalf("npub form normalized to %q but hex form to %q — the two forms of one key must agree", gotNpub, got)
	}
}

// TestNewAllowlistPartition_QuarantinesInsteadOfFailing is the core boot-survival
// case: one poisoned entry among good ones must cost exactly that entry, never
// the whole allowlist.
func TestNewAllowlistPartition_QuarantinesInsteadOfFailing(t *testing.T) {
	t.Parallel()
	good1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	good2, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Poison deliberately placed FIRST, so a short-circuiting implementation
	// that gives up on the first bad entry loses both good keys and is caught.
	entries := []string{offCurveHex, good1.PubKeyHex(), good2.PubKeyHex()}

	// The old behaviour, retained for explicit operator acts — and the exact
	// call that aborted startup.
	if _, err := NewAllowlist(entries...); err == nil {
		t.Fatal("NewAllowlist accepted an off-curve entry; the hard-error contract for explicit operator input has regressed")
	}

	allow, unusable := NewAllowlistPartition(entries...)
	if len(unusable) != 1 || unusable[0] != offCurveHex {
		t.Fatalf("unusable = %v, want exactly [%s]", unusable, offCurveHex)
	}
	if allow.Len() != 2 {
		t.Fatalf("allowlist retained %d members, want 2 — a single poisoned entry must not cost the good ones (that is the outage)", allow.Len())
	}
	for _, g := range []*Secp256k1Identity{good1, good2} {
		if !allow.Allowed(g.PubKeyHex()) {
			t.Fatalf("valid key %s was not admitted after partitioning around a poisoned entry", g.PubKeyHex())
		}
	}
}

// TestNewAllowlistPartition_QuarantinedEntryAdmitsNobody is the safety half of
// the argument. Quarantining is only defensible because a dropped entry could
// never have authorized anyone: Allowed() is asked about signature-verified
// event pubkeys, which are always valid curve points. Dropping is therefore
// never more permissive than keeping — assert that directly rather than trusting
// the comment.
func TestNewAllowlistPartition_QuarantinedEntryAdmitsNobody(t *testing.T) {
	t.Parallel()
	allow, unusable := NewAllowlistPartition(offCurveHex)
	if len(unusable) != 1 {
		t.Fatalf("unusable = %v, want 1 entry", unusable)
	}
	if allow.Len() != 0 {
		t.Fatalf("allowlist Len = %d, want 0", allow.Len())
	}
	if allow.Allowed(offCurveHex) {
		t.Fatal("SECURITY: the quarantined value is reported as Allowed — quarantine must never fail OPEN")
	}
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if allow.Allowed(id.PubKeyHex()) {
		t.Fatal("SECURITY: an unrelated valid key is Allowed against an allowlist built only from a quarantined entry")
	}
}

func TestNewAllowlistPartition_NoPoisonIsIdenticalToNewAllowlist(t *testing.T) {
	t.Parallel()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Blank entries are skipped by both constructors, not quarantined.
	entries := []string{id.PubKeyHex(), "", "   "}

	strict, err := NewAllowlist(entries...)
	if err != nil {
		t.Fatalf("NewAllowlist on clean input: %v", err)
	}
	lenient, unusable := NewAllowlistPartition(entries...)
	if len(unusable) != 0 {
		t.Fatalf("clean input reported unusable entries: %v", unusable)
	}
	if lenient.Len() != strict.Len() {
		t.Fatalf("partition Len = %d, strict Len = %d — the two must agree exactly when no entry is poisoned", lenient.Len(), strict.Len())
	}
	if !lenient.Allowed(id.PubKeyHex()) {
		t.Fatal("partition did not admit the valid key")
	}
}
