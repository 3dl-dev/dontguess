package main

// individual_senderkey_ab6_test.go — dontguess-ab6.
//
// The individual tier mints a throwaway sender key per put/buy ("zero identity
// ceremony"). It used to mint 32 RAW RANDOM BYTES and use them as an x-only
// secp256k1 pubkey. Only about half of all 32-byte values are points on that
// curve, so roughly every other individual-tier record was authored by a key
// that cannot exist.
//
// Measured on the live exchange before the fix: 74 of 145 such records (51% —
// exactly the coin flip) carried unusable senders, one distinct key each.
//
// The consequences were real and were misdiagnosed twice:
//
//   - Those senders can never be admitted, so genuine work was rejected
//     `not-allowlisted` and lost, and the agent retried with another bad key.
//   - Before the dontguess-31b fence, such a key could be admitted and PERSISTED
//     to the fleet allowlist, which bricked the operator's boot for 80 minutes.
//   - The records look identical to the dead campfire-era ed25519 corpus — 64
//     hex, off-curve, unadmittable — so they were repeatedly blamed on campfire
//     residue. They were minted by this binary, today.
//
// A single generated key passing is a 50/50 coin flip, so the test below MUST
// generate many and require ALL of them valid, or it would pass half the time on
// the broken implementation.

import (
	"testing"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

func TestRandomLocalSenderKey_IsAlwaysAValidPubkey(t *testing.T) {
	t.Parallel()

	const n = 200 // broken impl survives this with probability 2^-200
	seen := map[string]struct{}{}
	for i := 0; i < n; i++ {
		key, err := randomLocalSenderKey()
		if err != nil {
			t.Fatalf("randomLocalSenderKey: %v", err)
		}
		if _, err := identity.NormalizeAllowlistEntry(key); err != nil {
			t.Fatalf("iteration %d produced a key that is not a valid secp256k1 pubkey: %v\n"+
				"This is the dontguess-ab6 defect: such a sender can never be admitted by ANY "+
				"admission mechanism, so the work it authors is rejected and lost.", i, err)
		}
		if _, dup := seen[key]; dup {
			t.Fatalf("iteration %d repeated a key — the tier's contract is a FRESH key per call", i)
		}
		seen[key] = struct{}{}
	}
}

// TestRandomLocalID_StaysOpaque pins the other half of the split: a record ID is
// not a key and must not be forced onto the curve. Requiring it to be a valid
// pubkey would halve the id space for no reason.
func TestRandomLocalID_StaysOpaque(t *testing.T) {
	t.Parallel()

	id, err := randomLocalID()
	if err != nil {
		t.Fatalf("randomLocalID: %v", err)
	}
	if len(id) != 64 {
		t.Fatalf("record id = %d hex chars, want 64 (32 bytes)", len(id))
	}
	// Distinctness is the only real requirement.
	other, err := randomLocalID()
	if err != nil {
		t.Fatalf("randomLocalID: %v", err)
	}
	if id == other {
		t.Fatal("two record ids collided")
	}
}
