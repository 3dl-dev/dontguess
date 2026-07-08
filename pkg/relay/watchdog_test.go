package relay

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/campfire-net/dontguess/pkg/identity"
	"github.com/campfire-net/dontguess/pkg/nostr"
	"github.com/campfire-net/dontguess/pkg/store"
)

// --- in-process fake relay -------------------------------------------------
//
// fakeRelay is a durable event log the watchdog drives its three REQs against.
// It is NOT a mock of the Intake: its Query implementation feeds every matching
// event through the REAL Intake (real Sequencer + real Store), so the dedup,
// causal-ordering, and persistence the watchdog relies on are exercised end to
// end. Only the wire (Conn + frame codec) is faked — the auth/sequencing/persist
// pipeline under test is real.
type fakeRelay struct {
	held   []*nostr.Event // everything the relay currently serves, in publish order
	intake *Intake        // where delivered events are fed

	// serveNone, when set for a specific antecedent id, makes an IDs-filtered
	// REQ for that id return empty even though a matching event is "held" — it
	// models a relay that has PRUNED the antecedent (the poison case).
	pruned map[string]struct{}

	queries []Filter // every REQ issued, for assertions
}

func (r *fakeRelay) Query(ctx context.Context, f Filter) ([]string, error) {
	r.queries = append(r.queries, f)
	var delivered []string
	for _, ev := range r.held {
		if !r.match(f, ev) {
			continue
		}
		// Feed through the REAL Intake — this is where dedup + persist happen.
		// An ingest drop (forged/unsigned/orphan-overflow) is the Intake's loud
		// business, not the relay's; the relay still reports it as delivered.
		_ = r.intake.HandleEvent(ev)
		delivered = append(delivered, ev.ID)
	}
	return delivered, nil
}

// match applies the subset of NIP-01 filter semantics the watchdog uses:
// IDs (exact-id targeted refetch) and Since (created_at floor). A pruned id is
// never delivered to an IDs query, modelling a relay that no longer serves it.
func (r *fakeRelay) match(f Filter, ev *nostr.Event) bool {
	if len(f.IDs) > 0 {
		hit := false
		for _, id := range f.IDs {
			if id == ev.ID {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
		if _, gone := r.pruned[ev.ID]; gone {
			return false
		}
	}
	if f.Since != nil && ev.CreatedAt < *f.Since {
		return false
	}
	return true
}

// --- test helpers ----------------------------------------------------------

// signEventAt is signEvent with a caller-chosen created_at so tests can drive
// the Since backfill floor. Signature is a real BIP-340 signature.
func signEventAt(t *testing.T, signer identity.Signer, kind int, createdAt int64, tags [][]string, content string) *nostr.Event {
	t.Helper()
	ie := &identity.Event{
		CreatedAt: createdAt,
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
	if err := identity.SignEvent(signer, ie); err != nil {
		t.Fatalf("SignEvent(kind=%d): %v", kind, err)
	}
	return &nostr.Event{
		ID:        ie.ID,
		PubKey:    ie.PubKey,
		CreatedAt: ie.CreatedAt,
		Kind:      ie.Kind,
		Tags:      ie.Tags,
		Content:   ie.Content,
		Sig:       ie.Sig,
	}
}

// eTag builds the NIP-01 reply e-tag that FromNostrEvent maps to
// Message.Antecedents[0] (adapter.go) — the causal edge the sequencer orphans on.
func eTag(anteID string) []string { return []string{"e", anteID, "", "reply"} }

// newWatchdogHarness wires a real Store + Sequencer + Intake + fakeRelay + a
// Watchdog whose Subscriber is that relay. Alarm classes are recorded.
func newWatchdogHarness(t *testing.T) (*Watchdog, *fakeRelay, *store.Store, *exchange.Sequencer, *WatchdogMetrics, *[]string, identity.Signer) {
	t.Helper()
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "watchdog.log"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	seq := exchange.NewSequencer(0)
	im := &IntakeMetrics{}
	intake := NewIntake(seq, st, op.PubKeyHex(), im, nil)

	relay := &fakeRelay{intake: intake, pruned: map[string]struct{}{}}

	var alarms []string
	wm := &WatchdogMetrics{}
	wd := NewWatchdog(relay, seq, st, nil, wm, func(class string, _ error, _ *nostr.Event) {
		alarms = append(alarms, class)
	})
	return wd, relay, st, seq, wm, &alarms, op
}

func storeIDs(t *testing.T, st *store.Store) []string {
	t.Helper()
	recs, err := st.ReadAll()
	if err != nil {
		t.Fatalf("store ReadAll: %v", err)
	}
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return ids
}

// --- TEST 1: reconnect with dedup-absorbed overlapping backfill -------------

// TestWatchdog_ReconnectDedupAbsorbedBackfill exercises §2.5 path 1: a live
// disconnect, then Reconnect re-issues REQ since=(watermark−slack). The relay
// re-delivers the events seen before the drop (the overlap) AND a new event that
// arrived while disconnected (the gap). The Sequencer's id-dedup must absorb the
// overlap — every event persists EXACTLY once — and the gap event must land.
func TestWatchdog_ReconnectDedupAbsorbedBackfill(t *testing.T) {
	wd, relay, st, _, wm, alarms, op := newWatchdogHarness(t)
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate seller: %v", err)
	}

	// Three independent puts arrive live (root events, no antecedents), then the
	// subscription drops. Timestamps ascend so the backfill floor is meaningful.
	e1 := signEventAt(t, seller, nostr.KindPut, 1000, nil, "put-1")
	e2 := signEventAt(t, seller, nostr.KindPut, 1010, nil, "put-2")
	e3 := signEventAt(t, seller, nostr.KindPut, 1020, nil, "put-3")
	relay.held = []*nostr.Event{e1, e2, e3}
	// Live delivery of all three (simulating the pre-drop subscription).
	for _, ev := range relay.held {
		if herr := relay.intake.HandleEvent(ev); herr != nil {
			t.Fatalf("live ingest of %s: %v", ev.ID, herr)
		}
	}
	if got := storeIDs(t, st); len(got) != 3 {
		t.Fatalf("pre-drop store has %d records, want 3", len(got))
	}
	watermark := int64(1020) // max created_at seen

	// While disconnected, a NEW put (the gap) is published to the relay with a
	// created_at INSIDE the slack window below the watermark — proving the
	// backfill floor (watermark−slack) actually re-scans the overlap region.
	gap := signEventAt(t, seller, nostr.KindPut, 1015, nil, "put-gap")
	relay.held = append(relay.held, gap)

	// Reconnect (default slack 300) → since = 1020 − 300 = 720, sweeping
	// e1..e3 (1000-1020) + gap (1015).
	if err := wd.Reconnect(context.Background(), watermark); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	last := relay.queries[len(relay.queries)-1]
	if last.Since == nil || *last.Since != 720 {
		t.Fatalf("reconnect REQ since = %v, want 720 (watermark−slack)", last.Since)
	}
	_ = alarms

	// Dedup absorbed the overlap: exactly four distinct records, no duplicates.
	got := storeIDs(t, st)
	want := []string{e1.ID, e2.ID, e3.ID, gap.ID}
	sort.Strings(want)
	if len(got) != 4 {
		t.Fatalf("post-reconnect store has %d records, want 4 (3 overlap deduped + 1 gap)", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("store id[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if wm.IntakeDisconnected.Load() != 1 {
		t.Fatalf("IntakeDisconnected = %d, want 1", wm.IntakeDisconnected.Load())
	}
	// op is unused beyond harness wiring for this path.
	_ = op
}

// --- TEST 2: poison antecedent → targeted refetch empty → loud quarantine ---

// TestWatchdog_PoisonAntecedentQuarantine exercises §2.5 path 2: an ingested
// event references an antecedent the relay has PRUNED. The event orphans in the
// Sequencer (never persists). CheckOrphans issues ONE targeted REQ ["ids",
// <antecedent>]; the refetch is empty; the chain is QUARANTINED with a loud
// orphan_unrecoverable alarm, while an INDEPENDENT healthy event keeps draining.
func TestWatchdog_PoisonAntecedentQuarantine(t *testing.T) {
	wd, relay, st, seq, wm, alarms, _ := newWatchdogHarness(t)
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate seller: %v", err)
	}

	// A dangling antecedent id the relay will NEVER serve (pruned).
	poisonAnte := signEventAt(t, seller, nostr.KindPut, 500, nil, "pruned-root").ID
	relay.pruned[poisonAnte] = struct{}{}

	// Orphan: a buy that e-tags the pruned root. It ingests but cannot release.
	orphan := signEventAt(t, seller, nostr.KindBuy, 600, [][]string{eTag(poisonAnte)}, "orphaned-buy")
	if herr := relay.intake.HandleEvent(orphan); herr != nil {
		t.Fatalf("ingest orphan: %v", herr)
	}
	// A healthy INDEPENDENT put that must keep folding despite the poison chain.
	healthy := signEventAt(t, seller, nostr.KindPut, 610, nil, "healthy-put")
	if herr := relay.intake.HandleEvent(healthy); herr != nil {
		t.Fatalf("ingest healthy: %v", herr)
	}

	// The orphan never persisted; the healthy event did.
	if ids := storeIDs(t, st); len(ids) != 1 || ids[0] != healthy.ID {
		t.Fatalf("pre-check store = %v, want only healthy %s", ids, healthy.ID)
	}
	if seq.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1 (the orphan)", seq.PendingCount())
	}
	// The Sequencer names the exact missing antecedent for the targeted refetch.
	pend := seq.PendingAntecedents()
	if deps, ok := pend[poisonAnte]; !ok || len(deps) != 1 || deps[0] != orphan.ID {
		t.Fatalf("PendingAntecedents[%s] = %v, want [%s]", poisonAnte, pend[poisonAnte], orphan.ID)
	}

	// Run the orphan watchdog. Targeted REQ ["ids", poisonAnte] returns empty
	// (pruned) → quarantine.
	q, err := wd.CheckOrphans(context.Background())
	if err != nil {
		t.Fatalf("CheckOrphans: %v", err)
	}
	if q != 1 {
		t.Fatalf("quarantined chains = %d, want 1", q)
	}
	// Exactly one targeted refetch was issued, an IDs filter for the antecedent.
	var refetch *Filter
	for i := range relay.queries {
		if len(relay.queries[i].IDs) == 1 && relay.queries[i].IDs[0] == poisonAnte {
			refetch = &relay.queries[i]
		}
	}
	if refetch == nil {
		t.Fatalf("no targeted REQ ids=[%s] was issued; queries=%v", poisonAnte, relay.queries)
	}
	if wm.OrphanUnrecoverable.Load() != 1 {
		t.Fatalf("OrphanUnrecoverable = %d, want 1", wm.OrphanUnrecoverable.Load())
	}
	if wm.OrphanPending.Load() != 1 {
		t.Fatalf("OrphanPending gauge = %d, want 1 (orphan still buffered post-quarantine)", wm.OrphanPending.Load())
	}
	if !containsID(*alarms, "orphan_unrecoverable") {
		t.Fatalf("alarms = %v, want an orphan_unrecoverable", *alarms)
	}

	// A SECOND pass must NOT re-refetch the quarantined antecedent (remembered).
	refetchCountBefore := wm.OrphanRefetch.Load()
	if _, err := wd.CheckOrphans(context.Background()); err != nil {
		t.Fatalf("CheckOrphans (2nd): %v", err)
	}
	if wm.OrphanRefetch.Load() != refetchCountBefore {
		t.Fatalf("OrphanRefetch grew on 2nd pass (%d→%d); quarantined chain must not be refetched again",
			refetchCountBefore, wm.OrphanRefetch.Load())
	}
	if wm.OrphanUnrecoverable.Load() != 1 {
		t.Fatalf("OrphanUnrecoverable double-counted = %d, want 1", wm.OrphanUnrecoverable.Load())
	}
}

// TestWatchdog_OrphanRecoveredByRefetch is the positive half of path 2: the
// antecedent is NOT pruned, so the targeted refetch delivers it, the Intake
// releases the whole chain, and NOTHING is quarantined.
func TestWatchdog_OrphanRecoveredByRefetch(t *testing.T) {
	wd, relay, st, seq, wm, alarms, _ := newWatchdogHarness(t)
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate seller: %v", err)
	}

	root := signEventAt(t, seller, nostr.KindPut, 700, nil, "recoverable-root")
	orphan := signEventAt(t, seller, nostr.KindBuy, 710, [][]string{eTag(root.ID)}, "buy-on-root")
	// The relay HOLDS the root (serveable), but only the orphan was delivered live.
	relay.held = []*nostr.Event{root, orphan}
	if herr := relay.intake.HandleEvent(orphan); herr != nil {
		t.Fatalf("ingest orphan: %v", herr)
	}
	if seq.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1", seq.PendingCount())
	}

	q, err := wd.CheckOrphans(context.Background())
	if err != nil {
		t.Fatalf("CheckOrphans: %v", err)
	}
	if q != 0 {
		t.Fatalf("quarantined = %d, want 0 (antecedent was recoverable)", q)
	}
	// Refetch delivered the root → chain released → BOTH events now persisted.
	ids := storeIDs(t, st)
	if len(ids) != 2 {
		t.Fatalf("store has %d records, want 2 (root + released orphan)", len(ids))
	}
	if seq.PendingCount() != 0 {
		t.Fatalf("PendingCount = %d, want 0 (chain drained)", seq.PendingCount())
	}
	if wm.OrphanUnrecoverable.Load() != 0 {
		t.Fatalf("OrphanUnrecoverable = %d, want 0", wm.OrphanUnrecoverable.Load())
	}
	if containsID(*alarms, "orphan_unrecoverable") {
		t.Fatalf("unexpected quarantine alarm on a recoverable chain: %v", *alarms)
	}
}

// --- TEST 3: resync audit id-set diff --------------------------------------

// TestWatchdog_ResyncAuditIDSetDiff exercises §2.5 path 3. It sets up BOTH diff
// directions in one audit:
//
//   - a local-only OPERATOR event the relay lacks  → handed to Outbox catch-up
//   - a relay event the local store cannot reconcile (an orphan) → resync_mismatch
//
// and a reconcilable relay event that the since=0 audit absorbs (NOT a mismatch).
func TestWatchdog_ResyncAuditIDSetDiff(t *testing.T) {
	op, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate operator: %v", err)
	}
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate seller: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "resync.log"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	seq := exchange.NewSequencer(0)
	intake := NewIntake(seq, st, op.PubKeyHex(), &IntakeMetrics{}, nil)
	relay := &fakeRelay{intake: intake, pruned: map[string]struct{}{}}

	// (1) A local-only OPERATOR event the relay does NOT hold → must be
	// republished. Written directly to the store with Origin="local" (operator
	// authored; the relay lacks it, e.g. a crash between fold and publish).
	localOnly := signEventAt(t, op, nostr.KindMatch, 800, nil, "operator-match")
	if aerr := st.Append(store.Record{
		ID: localOnly.ID, Sender: op.PubKeyHex(), Timestamp: 800 * 1_000_000_000,
		Origin: "local", Payload: []byte("operator-match"),
	}); aerr != nil {
		t.Fatalf("seed local-only record: %v", aerr)
	}

	// (2) A reconcilable relay event (a root put) the local store lacks — the
	// since=0 audit will feed it through the Intake and it WILL persist, so it is
	// NOT a mismatch.
	reconcilable := signEventAt(t, seller, nostr.KindPut, 810, nil, "reconcilable-put")

	// (3) A relay orphan (buy e-tagging a never-served root) the audit CANNOT
	// reconcile → resync_mismatch.
	// The antecedent is simply never added to relay.held, so the since=0 audit
	// cannot fetch it — a true unrecoverable gap. (No IDs refetch happens in the
	// resync path; the orphan just stays orphaned and unpersisted.)
	prunedRoot := signEventAt(t, seller, nostr.KindPut, 815, nil, "never-served-root").ID
	orphanOnRelay := signEventAt(t, seller, nostr.KindBuy, 820, [][]string{eTag(prunedRoot)}, "relay-orphan")

	// The relay serves the reconcilable put and the orphan buy (its antecedent is
	// absent from the relay entirely — a true unrecoverable gap).
	relay.held = []*nostr.Event{reconcilable, orphanOnRelay}

	var alarms []string
	var republished [][]store.Record
	wm := &WatchdogMetrics{}
	wd := NewWatchdog(relay, seq, st,
		republisherFunc(func(_ context.Context, recs []store.Record) error {
			republished = append(republished, recs)
			return nil
		}),
		wm,
		func(class string, _ error, _ *nostr.Event) { alarms = append(alarms, class) },
	)

	mismatches, err := wd.ResyncAudit(context.Background())
	if err != nil {
		t.Fatalf("ResyncAudit: %v", err)
	}

	// The audit issued a since=0 REQ.
	if len(relay.queries) == 0 || relay.queries[0].Since == nil || *relay.queries[0].Since != 0 {
		t.Fatalf("resync REQ since = %v, want 0", func() interface{} {
			if len(relay.queries) == 0 {
				return "none"
			}
			return relay.queries[0].Since
		}())
	}

	// (2) reconcilable put absorbed → now local.
	if ids := storeIDs(t, st); !containsID(ids, reconcilable.ID) {
		t.Fatalf("reconcilable relay put not absorbed by audit; store=%v", ids)
	}

	// (1) local-only operator event handed to the Outbox catch-up exactly once.
	if len(republished) != 1 || len(republished[0]) != 1 || republished[0][0].ID != localOnly.ID {
		t.Fatalf("republished = %v, want exactly [[%s]]", republished, localOnly.ID)
	}
	if wm.ResyncRepublished.Load() != 1 {
		t.Fatalf("ResyncRepublished = %d, want 1", wm.ResyncRepublished.Load())
	}

	// (3) the relay orphan the audit could not reconcile → exactly one mismatch.
	if mismatches != 1 {
		t.Fatalf("mismatches = %d, want 1 (the unreconcilable relay orphan)", mismatches)
	}
	if wm.ResyncMismatch.Load() != 1 {
		t.Fatalf("ResyncMismatch = %d, want 1", wm.ResyncMismatch.Load())
	}
	if !containsID(alarms, "resync_mismatch") {
		t.Fatalf("alarms = %v, want a resync_mismatch", alarms)
	}
}

// --- small test seams ------------------------------------------------------

// republisherFunc adapts a func to the Republisher interface.
type republisherFunc func(ctx context.Context, recs []store.Record) error

func (f republisherFunc) Republish(ctx context.Context, recs []store.Record) error {
	return f(ctx, recs)
}
