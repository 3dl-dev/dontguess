package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
	"github.com/spf13/cobra"
)

// reprice_migration.go — dontguess-b2b wave-6 rejection finding 2: prior waves
// built RepriceInventoryForRuling/EmitReprice (pkg/exchange/reprice.go) with
// ZERO production callers — no CLI subcommand, no serve hook — so the item's
// outcome ("every one of the 166 entries has a repricing event") was
// UNREACHABLE; nothing could ever invoke the mechanism outside a unit test.
// `dontguess reprice-migration` is that missing caller: a real,
// operator-invocable CLI command with a --dry-run mode that reports what
// WOULD change without emitting anything.
//
// SCOPE: this command is LOCAL-STORE-ONLY. It opens $DG_HOME/events.jsonl
// directly (like `dontguess status`'s loadLocalMessages, and like
// runServeLocal itself), replays it into a fresh, non-polling Engine via
// StartupReplayForTest (the exact synchronous body of Engine.Start, minus the
// poll loop — see engine_core.go), and — for a REAL (non-dry-run) invocation —
// calls the existing, already-tested exchange.Engine.RepriceInventoryForRuling,
// which appends operator-authored exchange:reprice(3407) events straight to
// LocalStore via the same unsigned local-egress path put-accept/settle use
// (sendLocalOperatorMessage; pkg/store has no cross-process locking — M1's
// single-writer invariant, pkg/store/store.go's package doc). Concretely this
// means:
//
//   - Individual tier (no relay attached): running this IS the whole migration
//     — the events land in the log an operator restart replays, exactly like
//     any other locally-emitted operator record.
//   - Fleet/team tier (relay attached): this command does NOT itself publish
//     the emitted reprice events to the relay — only a LIVE `serve` process
//     with an attached relay leg's Outbox does that (OnLocalAppend). Run this
//     while `serve` is STOPPED (to honor the single-writer invariant, since
//     `serve` also holds a write handle on the same file), then start `serve`
//     so its startup replay folds the new local records; relay propagation of
//     THOSE specific records still requires further wiring that is out of
//     THIS item's scope (dontguess-b2b fixes the migration mechanism + its
//     invocation surface, not relay backfill of admin-appended records) — flag
//     to the operator via the command's own printed caveat below, and file a
//     new item if fleet-tier propagation is actually needed before this runs
//     against a relay-attached exchange.
//
// This command never touches the live *running* operator process (no IPC, no
// socket) — it is an offline maintenance tool, matching the item's own
// framing ("an OPERATOR step at upgrade time, not a subagent action").
var (
	repriceRulingRef string
	repriceBasis     string
	repriceDryRun    bool
)

var repriceMigrationCmd = &cobra.Command{
	Use:   "reprice-migration",
	Short: "Run (or preview) the dontguess-96e retroactive token_cost repricing migration",
	Long: `Reinterprets every existing inventory entry's declared token_cost under the
operator ruling dontguess-96e (token_cost := output tokens), emitting one
auditable exchange:reprice(3407) event per entry (old_price, new_price,
basis, ruling ref) — never mutating any price in place. The migration is
idempotent: an entry that already carries a reprice event for --ruling-ref is
skipped and reported, not re-priced.

Use --dry-run first: it reports exactly what WOULD be emitted (and what
would be skipped, and why) without writing anything.

STOP a running 'dontguess serve' against the same DG_HOME before running this
for real — pkg/store performs no cross-process file locking, and the
single-writer invariant (one process owns events.jsonl) is an operational
contract, not something this command enforces for you.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRepriceMigration(resolveDGHome(), repriceRulingRef, repriceBasis, repriceDryRun, cmd.OutOrStdout())
	},
}

func init() {
	repriceMigrationCmd.Flags().StringVar(&repriceRulingRef, "ruling-ref", exchange.RepriceRulingRef96e, "rd item ID of the operator ruling authorizing this migration")
	repriceMigrationCmd.Flags().StringVar(&repriceBasis, "basis", exchange.RepriceBasisTwoUnit, "human-readable repricing basis recorded on every emitted event")
	repriceMigrationCmd.Flags().BoolVar(&repriceDryRun, "dry-run", false, "report what would change without emitting any reprice events")
	rootCmd.AddCommand(repriceMigrationCmd)
}

// RepriceMigrationReport is the machine-readable (--json) and
// human-readable summary runRepriceMigration prints, covering both the
// --dry-run preview and a real run.
type RepriceMigrationReport struct {
	DryRun    bool                     `json:"dry_run"`
	RulingRef string                   `json:"ruling_ref"`
	Basis     string                   `json:"basis"`
	Repriced  []exchange.RepriceRecord `json:"repriced"`
	Skipped   []exchange.RepriceSkip   `json:"skipped"`
}

// buildRepriceEngine opens dgHome's LocalStore, loads/creates the standing
// nostr operator identity (the same one `serve`/`up` use — dontguess-ed5's
// atomic create-or-load, so a fresh DG_HOME converges on the identical key a
// subsequent `serve` would), and brings a fresh, NON-POLLING Engine to the
// exact post-Start replay state via StartupReplayForTest — the synchronous
// portion of Engine.Start (replay + fold-cursor seed), used here instead of a
// hand-rolled State.Replay call so this command can never silently drift from
// what production startup actually does. No poll loop, no relay legs, no
// embedder: this command never calls Search/dispatch, only the reprice
// migration's State-level accessors and computePrice/legacyComputePrice,
// which read only e.state and e.opts.densityMarkupFactor() (safe zero
// value). Caller must Close() the returned store when done.
func buildRepriceEngine(dgHome string) (*exchange.Engine, *dgstore.Store, error) {
	operatorIdentity, err := loadOrCreateNostrOperatorIdentity(dgHome)
	if err != nil {
		return nil, nil, fmt.Errorf("reprice-migration: nostr operator identity: %w", err)
	}

	localStorePath := filepath.Join(dgHome, "events.jsonl")
	localStore, err := dgstore.Open(localStorePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reprice-migration: opening local store %s: %w", localStorePath, err)
	}

	eng := exchange.NewEngine(exchange.EngineOptions{
		LocalStore:        localStore,
		OperatorPublicKey: operatorIdentity.PubKeyHex(),
	})
	if err := eng.StartupReplayForTest(); err != nil {
		localStore.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("reprice-migration: replaying local store: %w", err)
	}
	return eng, localStore, nil
}

// runRepriceMigration is the RunE body, split out for direct testing without
// going through cobra flag parsing.
func runRepriceMigration(dgHome, rulingRef, basis string, dryRun bool, out io.Writer) error {
	eng, localStore, err := buildRepriceEngine(dgHome)
	if err != nil {
		return err
	}
	defer localStore.Close() //nolint:errcheck

	report := RepriceMigrationReport{
		DryRun:    dryRun,
		RulingRef: rulingRef,
		Basis:     basis,
	}

	if dryRun {
		previews, skipped := eng.PreviewRepriceInventoryForRuling(rulingRef)
		report.Skipped = skipped
		report.Repriced = make([]exchange.RepriceRecord, 0, len(previews))
		for _, p := range previews {
			report.Repriced = append(report.Repriced, exchange.RepriceRecord{
				EntryID:   p.EntryID,
				OldPrice:  p.OldPrice,
				NewPrice:  p.NewPrice,
				Basis:     basis,
				RulingRef: rulingRef,
			})
		}
	} else {
		records, skipped, err := eng.RepriceInventoryForRuling(rulingRef, basis)
		if err != nil {
			return fmt.Errorf("reprice-migration: %w", err)
		}
		report.Repriced = records
		report.Skipped = skipped
	}

	printRepriceMigrationReport(report, out)
	return nil
}

// printRepriceMigrationReport renders report as JSON (--json) or a
// human-readable summary sorted by EntryID for deterministic output.
func printRepriceMigrationReport(report RepriceMigrationReport, out io.Writer) {
	sort.Slice(report.Repriced, func(i, j int) bool { return report.Repriced[i].EntryID < report.Repriced[j].EntryID })
	sort.Slice(report.Skipped, func(i, j int) bool { return report.Skipped[i].EntryID < report.Skipped[j].EntryID })

	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(report) //nolint:errcheck
		return
	}

	mode := "REAL RUN (events emitted)"
	if report.DryRun {
		mode = "DRY RUN (nothing emitted)"
	}
	fmt.Fprintf(out, "=== reprice-migration: %s ===\n", mode)
	fmt.Fprintf(out, "ruling_ref: %s\n", report.RulingRef)
	fmt.Fprintf(out, "basis:      %s\n\n", report.Basis)

	fmt.Fprintf(out, "repriced (%d):\n", len(report.Repriced))
	for _, r := range report.Repriced {
		fmt.Fprintf(out, "  %-40s old=%-10d new=%-10d\n", r.EntryID, r.OldPrice, r.NewPrice)
	}
	if len(report.Skipped) > 0 {
		fmt.Fprintf(out, "\nskipped (%d):\n", len(report.Skipped))
		for _, s := range report.Skipped {
			fmt.Fprintf(out, "  %-40s reason=%s\n", s.EntryID, s.Reason)
		}
	}
	if report.DryRun {
		fmt.Fprintln(out, "\nnothing was written — re-run without --dry-run to emit these events.")
	}
	fmt.Fprintln(out, "\nNOTE (fleet/team tier only): this command writes to the local store ONLY.")
	fmt.Fprintln(out, "Relay propagation of the events it emits requires a live 'serve' process's")
	fmt.Fprintln(out, "own Outbox wiring — stop 'serve' before running this for real, then restart")
	fmt.Fprintln(out, "it afterward so its startup replay folds the new records.")
}
