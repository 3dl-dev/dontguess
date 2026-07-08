package relay

import "sync/atomic"

// Metrics holds the Intake authentication-pipeline counters
// (docs/design/relay-transport.md §2.4a D4 + §3). Each rejection class is a
// DISTINCT, separately-alarmed counter: bad-signature, right-signature-wrong-
// author, and smuggled/reserved-tag are different attack classes with different
// triage paths and MUST NOT be collapsed. No rejection path may return nil
// silently (LOCKED-5) — every increment here is paired with a loud alarm at the
// call site.
//
// All counters are goroutine-safe (atomic.Int64) so the async cache-warm ingest
// leg may be driven concurrently without a lock.
type IntakeMetrics struct {
	// Received counts every wire event handed to the Intake, before any check.
	Received atomic.Int64
	// DroppedUnsigned counts events dropped at STEP 0 (VerifyEventSignature):
	// the universal Schnorr+id floor failed. All kinds. (D1)
	DroppedUnsigned atomic.Int64
	// DroppedForged counts events dropped at the operator-authorship step:
	// an operator-only kind whose author/signature is not the operator's
	// (errors.Is(err, nostr.ErrForgedOperatorEvent)). (existing dropped_forged)
	DroppedForged atomic.Int64
	// DroppedSmuggled counts events dropped at the adapter boundary
	// (FromNostrEvent): a reserved projection kind (30401) or, once dontguess-c22
	// lands, a reserved ["x", …] tag smuggled past the ACL. (D2 dropped_smuggled_op)
	DroppedSmuggled atomic.Int64
	// Persisted counts records durably appended to the local store with
	// Origin="relay" (STEP 5). Orphans NEVER contribute — they never persist.
	Persisted atomic.Int64
	// OrphanOverflow counts Drain returning ErrOrphanBufferOverflow: too many
	// buffered pending-antecedent events. Loud — the operator investigates. (§3)
	OrphanOverflow atomic.Int64
}
