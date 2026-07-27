package main

// reprice_migration_test.go proves the dontguess-b2b wave-6 rejection finding
// 2 fix end to end: `dontguess reprice-migration` is a REAL, wired caller of
// exchange.RepriceInventoryForRuling / PreviewRepriceInventoryForRuling, not
// an unreachable library function. This test never constructs the engine
// directly — it drives runRepriceMigration (the RunE body) against a bare
// DG_HOME directory, exactly as the cobra command does, and verifies effects
// by reopening the on-disk local store as an ENTIRELY SEPARATE Engine
// instance afterward (a "cold restart" check), so a bug that only fooled an
// in-memory State object without durably persisting the reprice event would
// not be masked.

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// seedOneAcceptedEntry writes a real put + put-accept pair directly to
// dgHome's local store (mirroring serve_local_test.go's
// TestServeLocal_PutBuyMatch_NoCampfire fixture setup) using the SAME
// standing nostr operator identity buildRepriceEngine resolves
// (loadOrCreateNostrOperatorIdentity), then closes the store — so the
// migration command under test reopens the file cold, exactly as it would
// against a real DG_HOME between two separate process invocations.
func seedOneAcceptedEntry(t *testing.T, dgHome, putID string, tokenCost int64) {
	t.Helper()
	operatorIdentity, err := loadOrCreateNostrOperatorIdentity(dgHome)
	if err != nil {
		t.Fatalf("loadOrCreateNostrOperatorIdentity: %v", err)
	}

	ls, err := dgstore.Open(filepath.Join(dgHome, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	defer ls.Close() //nolint:errcheck

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        ls,
		OperatorPublicKey: operatorIdentity.PubKeyHex(),
	})

	sellerKey := randomLocalMsgID(t)
	if err := ls.Append(dgstore.Record{
		ID:         putID,
		CampfireID: "local",
		Sender:     sellerKey,
		Payload:    localPutPayload("reprice-migration fixture entry", tokenCost),
		Tags:       []string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"},
		Timestamp:  time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("appending put: %v", err)
	}
	if err := eng.StartupReplayForTest(); err != nil {
		t.Fatalf("StartupReplayForTest (pre-accept): %v", err)
	}
	if err := eng.AutoAcceptPut(putID, tokenCost*70/100, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
}

// findTagInStore re-reads dgHome's local store COLD (a fresh dgstore.Open,
// independent of any engine under test) and reports whether any message
// carries tag — the durable, on-disk ground truth a dry-run must NOT create
// and a real run MUST.
func findTagInStore(t *testing.T, dgHome, tag string) bool {
	t.Helper()
	ls, err := dgstore.Open(filepath.Join(dgHome, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open (cold read): %v", err)
	}
	defer ls.Close() //nolint:errcheck
	msgs, err := ls.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll (cold read): %v", err)
	}
	for _, m := range msgs {
		for _, tg := range m.Tags {
			if tg == tag {
				return true
			}
		}
	}
	return false
}

// TestRepriceMigration_DryRunEmitsNothing proves --dry-run reports the
// correct preview (one entry, old/new price populated) while writing
// NOTHING to the local store — verified by a cold re-read, not by
// introspecting in-memory state the command itself produced.
func TestRepriceMigration_DryRunEmitsNothing(t *testing.T) {
	dgHome := t.TempDir()
	const putID = "reprice-migration-dryrun-put"
	seedOneAcceptedEntry(t, dgHome, putID, 8000)

	if findTagInStore(t, dgHome, exchange.TagReprice) {
		t.Fatalf("setup: a reprice event already exists before running anything")
	}

	var buf bytes.Buffer
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	if err := runRepriceMigration(dgHome, exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit, true, &buf); err != nil {
		t.Fatalf("runRepriceMigration (dry-run): %v", err)
	}

	var report RepriceMigrationReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v\nraw: %s", err, buf.String())
	}
	if !report.DryRun {
		t.Errorf("report.DryRun = false, want true")
	}
	if len(report.Repriced) != 1 {
		t.Fatalf("report.Repriced = %d entries, want 1", len(report.Repriced))
	}
	if report.Repriced[0].EntryID != putID {
		t.Errorf("report.Repriced[0].EntryID = %q, want %q", report.Repriced[0].EntryID, putID)
	}
	if report.Repriced[0].NewPrice >= report.Repriced[0].OldPrice {
		t.Errorf("preview NewPrice=%d not below OldPrice=%d — amortization should reduce it",
			report.Repriced[0].NewPrice, report.Repriced[0].OldPrice)
	}
	if len(report.Skipped) != 0 {
		t.Errorf("report.Skipped = %d, want 0 on a first dry run", len(report.Skipped))
	}

	// The whole point of --dry-run: nothing durable was written.
	if findTagInStore(t, dgHome, exchange.TagReprice) {
		t.Fatalf("--dry-run wrote a reprice event to the local store — it must write nothing")
	}
}

// TestRepriceMigration_RealRunPersistsAcrossColdRestart is the end-to-end
// proof for wave-6 finding 2: a REAL (non-dry-run) invocation emits a
// durable exchange:reprice event that a completely separate, later Engine
// instance (built by reopening the same on-disk store — modeling the next
// `dontguess serve` startup, or a second `reprice-migration` invocation)
// observes via State.Reprices/HasReprice, and re-running the migration
// against that same store is idempotent (reports the entry as skipped, not
// re-repriced).
func TestRepriceMigration_RealRunPersistsAcrossColdRestart(t *testing.T) {
	dgHome := t.TempDir()
	const putID = "reprice-migration-real-put"
	seedOneAcceptedEntry(t, dgHome, putID, 60000)

	var buf1 bytes.Buffer
	if err := runRepriceMigration(dgHome, exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit, false, &buf1); err != nil {
		t.Fatalf("runRepriceMigration (real run): %v", err)
	}

	if !findTagInStore(t, dgHome, exchange.TagReprice) {
		t.Fatalf("real run did not persist a reprice event to the local store")
	}

	// A COLD restart: brand new Engine, reopened store, nothing shared with
	// the command invocation above except the file on disk.
	operatorIdentity, err := loadOrCreateNostrOperatorIdentity(dgHome)
	if err != nil {
		t.Fatalf("loadOrCreateNostrOperatorIdentity: %v", err)
	}
	ls, err := dgstore.Open(filepath.Join(dgHome, "events.jsonl"))
	if err != nil {
		t.Fatalf("dgstore.Open: %v", err)
	}
	defer ls.Close() //nolint:errcheck
	coldEng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        ls,
		OperatorPublicKey: operatorIdentity.PubKeyHex(),
	})
	if err := coldEng.StartupReplayForTest(); err != nil {
		t.Fatalf("cold StartupReplayForTest: %v", err)
	}
	recs := coldEng.State().Reprices(putID)
	if len(recs) != 1 {
		t.Fatalf("cold restart: got %d reprice records for %s, want 1", len(recs), putID)
	}
	if recs[0].RulingRef != exchange.RepriceRulingRef96e || recs[0].Basis != exchange.RepriceBasisTwoUnit {
		t.Errorf("cold restart: reprice record = %+v, wrong ruling_ref/basis", recs[0])
	}

	// Re-running the migration against the SAME store must be idempotent:
	// the entry is reported as skipped (already repriced for this ruling),
	// not repriced a second time.
	var buf2 bytes.Buffer
	if err := runRepriceMigration(dgHome, exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit, false, &buf2); err != nil {
		t.Fatalf("runRepriceMigration (second real run): %v", err)
	}
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	var buf3 bytes.Buffer
	if err := runRepriceMigration(dgHome, exchange.RepriceRulingRef96e, exchange.RepriceBasisTwoUnit, false, &buf3); err != nil {
		t.Fatalf("runRepriceMigration (third real run, json): %v", err)
	}
	var report3 RepriceMigrationReport
	if err := json.Unmarshal(buf3.Bytes(), &report3); err != nil {
		t.Fatalf("unmarshal third report: %v\nraw: %s", err, buf3.String())
	}
	if len(report3.Repriced) != 0 {
		t.Fatalf("third run: got %d NEW repriced entries, want 0 (idempotent)", len(report3.Repriced))
	}
	if len(report3.Skipped) != 1 || report3.Skipped[0].EntryID != putID {
		t.Fatalf("third run: skipped = %+v, want exactly [%s]", report3.Skipped, putID)
	}
	if report3.Skipped[0].Reason != exchange.RepriceSkipReasonAlreadyRepriced {
		t.Errorf("third run: skip reason = %q, want %q", report3.Skipped[0].Reason, exchange.RepriceSkipReasonAlreadyRepriced)
	}
}
