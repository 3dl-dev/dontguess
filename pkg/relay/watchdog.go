package relay

// watchdog.go is the RECONNECTION / GAP-RECOVERY leg of the single-relay
// transport — docs/design/relay-transport.md §2.5 (build outcome 7). It closes
// the three failure paths a dumb, memoryless relay opens once the Intake (§2.4)
// and Outbox (§2.3) are live:
//
//	1. Live disconnect. A dropped subscription loses the relay's memory of the
//	   REQ. On reconnect the watchdog re-issues REQ since=(watermark − slack);
//	   the Sequencer's id-dedup absorbs the overlap for free, so correctness
//	   never depends on `slack` being exact (§2.5, ADV-9). Loud: intake_disconnected.
//
//	2. Orphan-age gap. An ingested event referencing an unreleased antecedent
//	   sits in the Sequencer's bounded orphan buffer. The watchdog issues ONE
//	   targeted REQ ["ids", <antecedent>]; if the refetch comes back empty the
//	   antecedent is provably unrecoverable (relay-pruned) and the watchdog
//	   QUARANTINES that chain with a loud alert — every OTHER chain keeps
//	   draining. The orphan-buffer overflow itself fails loud in the Sequencer
//	   (ErrOrphanBufferOverflow), surfaced by the Intake, not swallowed.
//
//	3. Structural drift. A periodic low-cadence full-resync audit (REQ since=0)
//	   diffs the relay id-set against the local id-set: a local-only OPERATOR
//	   event the relay lacks is re-published via the Outbox catch-up; a relay
//	   event the local store lacks and still cannot fetch is a loud resync_mismatch.
//	   This is the backstop for the ADV-9 unreferenced-far-past-root cache-warm gap.
//
// Every degradation is LOUD (LOCKED-5): each row bumps a DISTINCT WatchdogMetrics
// counter and calls the alarm sink. No recovery path returns a silent nil.
//
// Seams. The watchdog owns none of the wire: it drives three collaborator
// interfaces — a Subscriber (issue one REQ, feed every returned EVENT through the
// Intake, report the delivered ids), an orphanSource (the Sequencer's read-only
// orphan view), a localReader (the store id-set), and a Republisher (the Outbox
// catch-up). Production wires these to Conn+frames+Intake / *exchange.Sequencer /
// *store.Store / the Outbox; tests inject in-process fakes that drive the REAL
// Sequencer + Intake + Store pipeline.

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/campfire-net/dontguess/pkg/nostr"
	"github.com/campfire-net/dontguess/pkg/store"
)

// defaultAlarm is the standard loud-degradation sink used when a caller passes a
// nil AlarmFunc: it logs the rejection class, the wire event's kind/id if any,
// and the error. Every watchdog and intake drop still degrades LOUDLY, never
// silently, even under a misconfigured caller (LOCKED-5).
func defaultAlarm(class string, err error, ev *nostr.Event) {
	kind := -1
	id := ""
	if ev != nil {
		kind = ev.Kind
		id = ev.ID
	}
	log.Printf("relay ALARM class=%s kind=%d id=%s err=%v", class, kind, id, err)
}

// DefaultReconnectSlack is the number of seconds subtracted from the local
// high-water mark when re-issuing the reconnect backfill REQ. It covers clock
// skew between the operator and the relay plus a generous reconnect window;
// correctness does not depend on it being exact — the Sequencer's id-dedup
// absorbs any overlap (§2.5). 5 minutes is intentionally generous: a redundant
// refetch is free, a missed event is a cache gap.
const DefaultReconnectSlack int64 = 300

// Subscriber issues ONE REQ with the given filter, feeds every EVENT the relay
// returns through the Intake (§2.4 auth pipeline — that is where dedup + causal
// ordering + persistence happen), and returns the ids the relay delivered before
// EOSE. It is the single seam the watchdog uses for all three of its REQs:
// reconnect backfill (Since), targeted orphan refetch (IDs), and the periodic
// resync audit (Since=0). Returning the delivered id-set — rather than the
// watchdog re-reading the wire itself — keeps the watchdog off the frame codec
// and lets it reason about "did the antecedent arrive?" / "what does the relay
// hold?" purely in terms of ids.
type Subscriber interface {
	Query(ctx context.Context, f Filter) (deliveredIDs []string, err error)
}

// orphanSource is the read-only slice of the Sequencer the watchdog needs:
// the current orphan count (a gauge) and the missing-antecedent → dependents
// map that names each targeted refetch. *exchange.Sequencer satisfies it via
// PendingCount / PendingAntecedents (both lock-guarded, mutation-free).
type orphanSource interface {
	PendingCount() int
	PendingAntecedents() map[string][]string
}

// localReader is the store read-surface the resync audit diffs against. It is
// the read half only — the watchdog never appends to the store directly (the
// Intake owns that write path). *store.Store satisfies it.
type localReader interface {
	ReadAll() ([]store.Record, error)
}

// Republisher hands local-only operator records the relay was found to be
// missing back to the Outbox catch-up for re-publish (§2.5). It is a seam so the
// watchdog depends on "publish these records" without owning the Outbox's cursor
// or signer. The Outbox's tail-and-publish is idempotent (content-hash id ⇒ the
// relay re-ACKs), so re-handing an already-published record is safe.
type Republisher interface {
	Republish(ctx context.Context, recs []store.Record) error
}

// WatchdogOption customises a Watchdog.
type WatchdogOption func(*Watchdog)

// WithReconnectSlack overrides the reconnect-backfill slack window (seconds).
func WithReconnectSlack(seconds int64) WatchdogOption {
	return func(w *Watchdog) {
		if seconds >= 0 {
			w.slack = seconds
		}
	}
}

// WithWatchdogLogf overrides the loud-degradation logger (default log.Printf via
// the alarm sink; this is the secondary human log line).
func WithWatchdogLogf(logf func(format string, args ...interface{})) WatchdogOption {
	return func(w *Watchdog) {
		if logf != nil {
			w.logf = logf
		}
	}
}

// Watchdog runs the §2.5 reconnection / gap-recovery logic for one exchange
// domain. Its methods are safe for concurrent use; the only mutable state is the
// quarantine set, guarded by mu.
type Watchdog struct {
	sub     Subscriber
	orphans orphanSource
	local   localReader
	repub   Republisher
	metrics *WatchdogMetrics
	alarm   AlarmFunc
	logf    func(format string, args ...interface{})
	slack   int64

	mu          sync.Mutex
	quarantined map[string]struct{} // missing-antecedent ids already given up on
}

// NewWatchdog constructs a Watchdog. sub, orphans, local, and metrics must be
// non-nil. repub may be nil — the resync audit then only ALARMS on relay-missing
// local events instead of republishing them (still loud, never silent). A nil
// alarm defaults to the same standard-log sink NewIntake uses so a misconfigured
// caller still degrades loudly.
func NewWatchdog(sub Subscriber, orphans orphanSource, local localReader, repub Republisher, metrics *WatchdogMetrics, alarm AlarmFunc, opts ...WatchdogOption) *Watchdog {
	if alarm == nil {
		alarm = defaultAlarm
	}
	w := &Watchdog{
		sub:         sub,
		orphans:     orphans,
		local:       local,
		repub:       repub,
		metrics:     metrics,
		alarm:       alarm,
		logf:        log2Printf,
		slack:       DefaultReconnectSlack,
		quarantined: make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Reconnect re-issues the backfill subscription after a live disconnect
// (§2.5 path 1). It bumps intake_disconnected, alarms + loud-logs, then issues
// REQ since=(watermark − slack). The returned events flow through the Intake,
// whose id-dedup absorbs the reconnect-window overlap; a gap opened while
// disconnected is filled by the same pass. watermark is the operator's local
// high-water mark expressed in the RELAY's created_at unit (NIP-01 seconds),
// since it feeds Filter.Since directly; slack is likewise seconds. A negative
// computed `since` is clamped to 0 (fetch from the beginning).
func (w *Watchdog) Reconnect(ctx context.Context, watermark int64) error {
	w.metrics.IntakeDisconnected.Add(1)
	w.alarm("intake_disconnected", fmt.Errorf("live subscription dropped; re-issuing backfill from watermark %d", watermark), nil)
	w.logf("relay/watchdog: reconnect backfill since=%d (watermark=%d slack=%d)", w.since(watermark), watermark, w.slack)

	since := w.since(watermark)
	if _, err := w.sub.Query(ctx, Filter{Since: &since}); err != nil {
		w.alarm("intake_disconnected", fmt.Errorf("reconnect backfill REQ failed: %w", err), nil)
		return fmt.Errorf("watchdog: reconnect backfill: %w", err)
	}
	return nil
}

// since computes the backfill floor: watermark − slack, clamped to 0.
func (w *Watchdog) since(watermark int64) int64 {
	s := watermark - w.slack
	if s < 0 {
		s = 0
	}
	return s
}

// CheckOrphans runs the orphan-age gap recovery pass (§2.5 path 2). It samples
// orphan_pending (a gauge), then for each distinct missing antecedent it has not
// already quarantined it issues ONE targeted REQ ["ids", <antecedent>]. If the
// refetch delivers the antecedent, the Intake releases the dependent chain on
// the same pass and the orphan drains — nothing more to do. If the refetch comes
// back empty (or the antecedent is still pending afterward), the chain is
// QUARANTINED: orphan_unrecoverable is bumped once for that chain and a loud
// alert fires, while every other chain keeps draining. A quarantined antecedent
// is remembered so the watchdog does not refetch it again on later passes.
//
// It returns the number of chains quarantined on this pass (0 = fully recovered
// or nothing pending). A per-antecedent Query error is alarmed and skipped (the
// chain is retried next pass), never fatal to the other chains.
func (w *Watchdog) CheckOrphans(ctx context.Context) (quarantined int, err error) {
	w.metrics.OrphanPending.Store(int64(w.orphans.PendingCount()))

	pending := w.orphans.PendingAntecedents()
	for ante, dependents := range pending {
		if w.isQuarantined(ante) {
			continue
		}

		w.metrics.OrphanRefetch.Add(1)
		delivered, qerr := w.sub.Query(ctx, Filter{IDs: []string{ante}})
		if qerr != nil {
			// A transport error on THIS refetch is loud but not fatal: leave the
			// chain pending (not quarantined) so a later pass retries it once the
			// relay is reachable again.
			w.alarm("orphan_refetch_failed", fmt.Errorf("targeted REQ ids=[%s] failed: %w", shortID(ante), qerr), nil)
			continue
		}

		// The refetch is "empty" for THIS antecedent if the relay delivered no
		// event carrying that id. (It may deliver other events; what matters is
		// whether the missing antecedent itself arrived.) After feeding the
		// delivery through the Intake, re-check the live orphan view: if the
		// antecedent is still an outstanding key, the chain is unrecoverable.
		if delivered := containsID(delivered, ante); delivered {
			// Antecedent arrived; the Intake released + persisted the chain. Done.
			continue
		}
		if _, stillPending := w.orphans.PendingAntecedents()[ante]; !stillPending {
			// Some concurrent pass or a transitive delivery released it. Done.
			continue
		}

		// Provably unrecoverable: per-chain quarantine, loud.
		w.markQuarantined(ante)
		w.metrics.OrphanUnrecoverable.Add(1)
		quarantined++
		w.alarm("orphan_unrecoverable",
			fmt.Errorf("antecedent %s unrecoverable after targeted refetch (empty); quarantining %d dependent event(s)",
				shortID(ante), len(dependents)), nil)
		w.logf("relay/watchdog: QUARANTINE chain on missing antecedent %s (%d dependents stalled)", shortID(ante), len(dependents))
	}
	// Re-sample the gauge after any recovery so it reflects the post-pass buffer.
	w.metrics.OrphanPending.Store(int64(w.orphans.PendingCount()))
	return quarantined, nil
}

// ResyncAudit runs the periodic full-resync structural-drift pass (§2.5 path 3),
// intended at a LOW cadence. It issues REQ since=0 (through the Intake, so any
// relay event the local store lacks and CAN be reconciled is absorbed on the
// same pass), then diffs the relay id-set against the local id-set:
//
//   - local-only OPERATOR event (Origin local/"") the relay lacks → hand it to
//     the Outbox catch-up for re-publish (ResyncRepublished); if no Republisher
//     is wired, alarm resync_republish_unwired (still loud).
//   - relay event still absent from the local store after the audit fed it
//     through the Intake (an orphan, or an event the Intake rejected) → cannot be
//     reconciled here → loud resync_mismatch, one per event.
//
// It returns the number of resync_mismatch events found. A since=0 REQ that
// fails is loud and returned (the audit could not run).
func (w *Watchdog) ResyncAudit(ctx context.Context) (mismatches int, err error) {
	zero := int64(0)
	relayIDs, qerr := w.sub.Query(ctx, Filter{Since: &zero})
	if qerr != nil {
		w.alarm("resync_mismatch", fmt.Errorf("since=0 resync REQ failed: %w", qerr), nil)
		return 0, fmt.Errorf("watchdog: resync audit REQ: %w", qerr)
	}

	// Read the local store AFTER the audit fed the relay events through the
	// Intake, so a relay event that was reconcilable is now local and does not
	// count as a mismatch.
	recs, rerr := w.local.ReadAll()
	if rerr != nil {
		w.alarm("resync_mismatch", fmt.Errorf("resync local read failed: %w", rerr), nil)
		return 0, fmt.Errorf("watchdog: resync audit local read: %w", rerr)
	}

	localSet := make(map[string]store.Record, len(recs))
	for _, r := range recs {
		localSet[r.ID] = r
	}
	relaySet := make(map[string]struct{}, len(relayIDs))
	for _, id := range relayIDs {
		relaySet[id] = struct{}{}
	}

	// (a) local-only operator events the relay lacks → Outbox catch-up.
	var toRepublish []store.Record
	for id, r := range localSet {
		if _, onRelay := relaySet[id]; onRelay {
			continue
		}
		if isRelayOrigin(r.Origin) {
			// A relay-ingested record the relay no longer serves is NOT ours to
			// re-publish (ping-pong / authorship); it is a relay-side prune we do
			// not own. Skip — never republish a foreign record.
			continue
		}
		toRepublish = append(toRepublish, r)
	}
	if len(toRepublish) > 0 {
		if w.repub == nil {
			w.alarm("resync_republish_unwired",
				fmt.Errorf("%d local-only operator event(s) the relay lacks, but no Outbox catch-up is wired", len(toRepublish)), nil)
		} else if perr := w.repub.Republish(ctx, toRepublish); perr != nil {
			w.alarm("resync_republish_failed", fmt.Errorf("Outbox catch-up of %d event(s) failed: %w", len(toRepublish), perr), nil)
		} else {
			w.metrics.ResyncRepublished.Add(int64(len(toRepublish)))
			w.logf("relay/watchdog: resync re-published %d local-only operator event(s) the relay lacked", len(toRepublish))
		}
	}

	// (b) relay events the local store still lacks and could not fetch → loud.
	for _, id := range relayIDs {
		if _, local := localSet[id]; local {
			continue
		}
		mismatches++
		w.metrics.ResyncMismatch.Add(1)
		w.alarm("resync_mismatch",
			fmt.Errorf("relay holds event %s the local store lacks and could not reconcile (orphaned or rejected on ingest)", shortID(id)), nil)
	}
	return mismatches, nil
}

func (w *Watchdog) isQuarantined(ante string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.quarantined[ante]
	return ok
}

func (w *Watchdog) markQuarantined(ante string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.quarantined[ante] = struct{}{}
}

// containsID reports whether id is in ids.
func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// shortID trims a long hex event id for readable logs/alarms without pulling in
// the exchange package's shortKey. It keeps the head, which is enough to
// disambiguate in practice.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "…"
}
