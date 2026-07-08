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

// WatchdogMetrics holds the reconnection / gap-recovery counters
// (docs/design/relay-transport.md §2.5 + §3). Like IntakeMetrics, each is a
// DISTINCT atomic.Int64 so the watchdog's background goroutines can update them
// without a lock, and every increment is paired with a loud alarm at the call
// site (LOCKED-5) — none is a silent internal-only signal.
type WatchdogMetrics struct {
	// IntakeDisconnected counts live-subscription drops the watchdog reacted to
	// by re-issuing the reconnect backfill (REQ since=watermark−slack). (§3
	// intake_disconnected)
	IntakeDisconnected atomic.Int64
	// OrphanPending is a GAUGE (Store, not Add): the number of events currently
	// held in the sequencer's orphan buffer, sampled on each CheckOrphans pass.
	// A recoverable causal gap — the targeted e-tag refetch may still fill it. (§3
	// orphan_pending)
	OrphanPending atomic.Int64
	// OrphanUnrecoverable counts orphan CHAINS quarantined because a targeted
	// REQ ["ids", <antecedent>] came back empty — the antecedent is provably
	// unrecoverable (relay-pruned). Incremented once per quarantined chain; the
	// chain's dependents stall (correct), every other chain keeps draining. (§3
	// orphan_unrecoverable)
	OrphanUnrecoverable atomic.Int64
	// OrphanRefetch counts targeted e-tag refetch REQs the watchdog issued for a
	// pending antecedent (whether or not they recovered it). Diagnostic.
	OrphanRefetch atomic.Int64
	// ResyncMismatch counts events the periodic since=0 audit found on the relay
	// but absent from the local store AND still unfetchable after the audit fed
	// them through the Intake (an orphan or a rejected event) — a loud
	// reconcile-impossible signal. (§3 resync_mismatch)
	ResyncMismatch atomic.Int64
	// ResyncRepublished counts local-only operator events the since=0 audit found
	// the relay lacked and handed to the Outbox catch-up for re-publish. (§2.5)
	ResyncRepublished atomic.Int64
}
