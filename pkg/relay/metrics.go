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
	// With the LIVE LRU occupancy bound (Sequencer.IngestLive, §2.5a) this can no
	// longer fire on the live path — occupancy is capped before Drain — but the
	// counter stays as a defense-in-depth signal on the shared Drain residual.
	OrphanOverflow atomic.Int64
	// OrphanEvicted counts orphans the LIVE ingest path evicted (LRU by ingest
	// order) to keep TOTAL buffer occupancy within bound (§2.5a). An eviction is
	// a LOUD cache-warm delay, never money loss: the evicted event is still
	// served by the relay and re-delivered by the resync audit / re-subscription.
	// A rising rate means the buffer is under sustained orphan pressure (a
	// chained-flood attack or a badly-lagging antecedent) and the operator should
	// investigate the source. (§2.5a)
	OrphanEvicted atomic.Int64
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
	// OrphanUnrecoverable counts targeted refetches that came back EMPTY — the
	// missing antecedent was not served by the relay on this pass (currently
	// unrecoverable, e.g. relay-pruned). The watchdog holds NO quarantine set
	// (§2.5a): it makes no ingest-admission decision, so this is a loud RECOVERY
	// diagnostic, not a censorship primitive. A stuck orphan is bounded by the
	// Sequencer's LRU occupancy eviction and reconciled by the resync audit — the
	// watchdog does not permanently give up on any antecedent. (§3
	// orphan_unrecoverable)
	OrphanUnrecoverable atomic.Int64
	// OrphanRefetch counts targeted e-tag refetch REQs the watchdog actually
	// issued for a pending antecedent (whether or not they recovered it). Each
	// distinct antecedent costs one relay REQ (ADV-6). Diagnostic.
	OrphanRefetch atomic.Int64
	// OrphanRefetchThrottled counts refetch attempts the token-bucket rate limit
	// DEFERRED this pass (no relay REQ issued): the missing antecedent stays
	// pending and is retried on a later pass once the bucket refills. Loud — a
	// rising rate means orphan pressure is outrunning the refetch budget (a
	// chained-flood attack or a lagging relay). (§2.5a, ADV-6)
	OrphanRefetchThrottled atomic.Int64
	// ResyncMismatch counts events the periodic since=0 audit found on the relay
	// but absent from the local store AND still unfetchable after the audit fed
	// them through the Intake (an orphan or a rejected event) — a loud
	// reconcile-impossible signal. (§3 resync_mismatch)
	ResyncMismatch atomic.Int64
	// ResyncRepublished counts local-only operator events the since=0 audit found
	// the relay lacked and handed to the Outbox catch-up for re-publish. (§2.5)
	ResyncRepublished atomic.Int64
}
