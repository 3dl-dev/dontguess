package relay

// intake.go is the INGEST leg of the single-relay transport — the ratified
// authentication pipeline of docs/design/relay-transport.md §2.4a (the amendment
// that CORRECTS and SUPERSEDES §2.4 step 1). For every received ["EVENT", ev] the
// Intake runs, IN ORDER, these steps — and every one of steps 0-2 runs BEFORE the
// event can reach Sequencer.Ingest, let alone the LocalStore (D4):
//
//	0. VerifyEventSignature(ev)        universal Schnorr+id re-derive, ALL kinds → dropped_unsigned
//	1. FromNostrEvent(ev) -> msg       reserved 30401 / (c22) smuggled x-tags     → dropped_smuggled
//	2. VerifyOperatorAuthorship(ev,K)  operator-only kind author == operator      → dropped_forged
//	3. Sequencer.IngestLive(msg)       dedup by id; LRU-evict oldest orphan if full (§2.5a)
//	4. Sequencer.Drain()               release causally-ready in canonical Seq order
//	5. LocalStore.BatchAppend(...)     Origin="relay"; orphans NEVER persist
//
// Two structural guarantees, by construction:
//
//   - A forged or unsigned event is structurally IMPOSSIBLE to silently persist:
//     steps 0-2 all precede Ingest/BatchAppend, so a drop happens strictly before
//     any byte can touch the store (the dontguess-553 "fails-toward-silent" mode
//     is closed). Every drop increments a DISTINCT counter and alarms LOUD
//     (LOCKED-5) — no rejection path returns nil.
//
//   - The write path takes ONLY the store mutex (via LocalStore.BatchAppend); it
//     NEVER takes the engine's localMu. Foreign (Origin="relay") records have no
//     emitter-side State.Apply, so there is no double-apply hazard, and a backfill
//     storm cannot serialize behind the buy/match dispatch lock (§2.4, ADV-11).
//     Intake does NOT touch pollLocalStore or engine_core.go — the existing poll
//     loop folds the new canonical tail via its unchanged length cursor.

import (
	"fmt"
	"log"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/nostr"
	"github.com/3dl-dev/dontguess/pkg/store"
)

// recordAppender is the store surface the Intake needs: the single-fsync,
// all-or-nothing batch append. *store.Store satisfies it. It is an interface so
// the write boundary is explicit and independently testable, and so the Intake
// cannot reach for any engine-side (localMu-guarded) path — the store mutex is
// its ONLY write lock (§2.4).
type recordAppender interface {
	BatchAppend([]store.Record) error
}

// AlarmFunc is the loud-degradation sink (LOCKED-5): every dropped/failed event
// is reported here with its rejection class, the underlying error, and the
// offending wire event. The default sink logs; an operator wires this to real
// alerting. It is called AFTER the corresponding distinct counter is bumped.
type AlarmFunc func(class string, err error, ev *nostr.Event)

// Intake is the per-event authentication + persist pipeline for one exchange
// domain. It is safe for concurrent use to the extent its collaborators are:
// Sequencer and *store.Store are each internally locked, and Metrics is atomic.
type Intake struct {
	seq         *exchange.Sequencer
	store       recordAppender
	operatorKey string // operator npub or hex; passed through to VerifyOperatorAuthorship
	metrics     *IntakeMetrics
	alarm       AlarmFunc
}

// NewIntake constructs an Intake. seq, st, and metrics must be non-nil.
// operatorKey is the exchange operator's key (npub or hex) used by the STEP 2
// operator-authorship gate. A nil alarm defaults to a standard-log sink so a
// misconfigured caller still degrades LOUDLY, never silently.
func NewIntake(seq *exchange.Sequencer, st recordAppender, operatorKey string, metrics *IntakeMetrics, alarm AlarmFunc) *Intake {
	if alarm == nil {
		alarm = func(class string, err error, ev *nostr.Event) {
			kind := -1
			id := ""
			if ev != nil {
				kind = ev.Kind
				id = ev.ID
			}
			log.Printf("relay/intake ALARM class=%s kind=%d id=%s err=%v", class, kind, id, err)
		}
	}
	return &Intake{seq: seq, store: st, operatorKey: operatorKey, metrics: metrics, alarm: alarm}
}

// HandleEvent runs the §2.4a pipeline for a single received wire event. It
// returns nil once the event has been absorbed (folded into the sequencer and,
// if now causally ready, persisted with Origin="relay"); it returns a non-nil
// error on any drop or persist failure — always AFTER bumping the matching
// distinct counter and alarming LOUD. A dropped event never reaches Ingest and
// therefore never touches the store.
func (in *Intake) HandleEvent(ev *nostr.Event) error {
	in.metrics.Received.Add(1)

	// STEP 0 — UNIVERSAL SIGNATURE FLOOR (D1). Run FIRST, for EVERY kind, on the
	// RAW wire event so the NIP-01 id is recomputed from the wire fields. This is
	// what binds msg.Sender == ev.PubKey to a valid signature for every kind and
	// closes the non-operator sender-spoof CRITICAL. An invalid/absent signature
	// is dropped here, before FromNostrEvent ever sees the event.
	if err := nostr.VerifyEventSignature(ev); err != nil {
		in.metrics.DroppedUnsigned.Add(1)
		in.alarm("dropped_unsigned", err, ev)
		return fmt.Errorf("intake: drop unsigned event: %w", err)
	}

	// STEP 1 — ADAPTER. Rejects the 30401 projection (never folded as source of
	// truth) and, once dontguess-c22 lands, reserved ["x", …] tag smuggling. Any
	// adapter-boundary rejection is the dropped_smuggled class.
	msg, err := nostr.FromNostrEvent(ev)
	if err != nil {
		in.metrics.DroppedSmuggled.Add(1)
		in.alarm("dropped_smuggled", err, ev)
		return fmt.Errorf("intake: drop smuggled/reserved event: %w", err)
	}

	// STEP 2 — OPERATOR AUTHORSHIP. For operator-only kinds (match, scrip, the
	// operator settle phases incl. settle(failed) per D5, and the operator assign
	// sub-ops) the author must BE the operator, with a verifying signature.
	// Non-operator kinds return nil here — STEP 0 already bound their sender.
	if err := nostr.VerifyOperatorAuthorship(ev, in.operatorKey); err != nil {
		in.metrics.DroppedForged.Add(1)
		in.alarm("dropped_forged", err, ev)
		return fmt.Errorf("intake: drop forged operator event: %w", err)
	}

	// STEP 3 — SEQUENCER LIVE INGEST (dedup by event id). The LIVE path bounds
	// TOTAL buffer OCCUPANCY and, when full, EVICTS the oldest orphan (LRU by
	// ingest order) rather than REJECTING the new well-formed event (§2.5a): a
	// new event is never wedged out by a chained-orphan flood. msg.ID is a
	// non-empty content hash (STEP 0 recomputed and matched it), so the empty-id
	// guard cannot trip here; handle its error loudly regardless (never silent).
	evicted, err := in.seq.IngestLive(*msg)
	if err != nil {
		in.alarm("ingest_rejected", err, ev)
		return fmt.Errorf("intake: sequencer rejected event: %w", err)
	}
	// Evictions are a LOUD cache-warm delay (never a silent drop, LOCKED-5): the
	// evicted orphan is still served by the relay and re-delivered by the resync
	// audit / re-subscription. Meter + alarm every eviction so sustained orphan
	// pressure (a chained-flood attack) is visible to the operator.
	if len(evicted) > 0 {
		in.metrics.OrphanEvicted.Add(int64(len(evicted)))
		in.alarm("orphan_evicted", fmt.Errorf("live ingest of %s evicted %d oldest orphan(s) to bound buffer occupancy", ev.ID, len(evicted)), ev)
	}

	// STEP 4 — DRAIN to canonical Seq order. On overflow the sequencer still
	// returns the events released before the overflow (see below); orphans stay
	// buffered in memory and NEVER touch the store.
	released, drainErr := in.seq.Drain()

	// STEP 5 — PERSIST released with Origin="relay" and the assigned Seq, under
	// the store mutex only (single fsync). Orphans never persist.
	if len(released) > 0 {
		recs := make([]store.Record, len(released))
		for i := range released {
			recs[i] = sequencedToRelayRecord(released[i])
		}
		if err := in.store.BatchAppend(recs); err != nil {
			in.alarm("persist_failed", err, ev)
			return fmt.Errorf("intake: persist released batch: %w", err)
		}
		in.metrics.Persisted.Add(int64(len(recs)))
	}

	if drainErr != nil {
		// ErrOrphanBufferOverflow: the causally-ready prefix was persisted above;
		// the excess orphans remain in the sequencer's buffer (never persisted).
		// This is a loud signal for the operator to stop ingest and investigate.
		in.metrics.OrphanOverflow.Add(1)
		in.alarm("orphan_overflow", drainErr, ev)
		return fmt.Errorf("intake: drain: %w", drainErr)
	}
	return nil
}

// sequencedToRelayRecord converts a released Sequenced event into a store.Record
// stamped Origin="relay" and carrying the operator-assigned monotonic Seq. Every
// message field is carried verbatim; Origin/Seq are the store-local provenance +
// fold-order markers (not part of the proto.Message wire shape — ToMessage drops
// them, docs/design/relay-transport.md §2.1).
func sequencedToRelayRecord(s exchange.Sequenced) store.Record {
	m := s.Msg
	return store.Record{
		ID:          m.ID,
		CampfireID:  m.CampfireID,
		Sender:      m.Sender,
		Payload:     m.Payload,
		Tags:        m.Tags,
		Antecedents: m.Antecedents,
		Timestamp:   m.Timestamp,
		Instance:    m.Instance,
		Origin:      "relay",
		Seq:         s.Seq,
	}
}
