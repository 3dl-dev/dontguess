package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/campfire-net/dontguess/pkg/exchange"
	"github.com/spf13/cobra"
)

var initForce bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the DontGuess operator home (campfire-free)",
	Long: `Bootstrap this operator's own DontGuess home under $DG_HOME:

  1. operator identity — a persistent secp256k1 (nostr) key at
     $DG_HOME/nostr-operator.key, minted on first run and reused thereafter.
  2. local event store — the append-only log at $DG_HOME/events.jsonl.
  3. config — records the operator pubkey and the relay URLs the operator
     serves (from DONTGUESS_RELAY_URLS / DONTGUESS_RELAY_URL).

This is campfire-free: no campfire, beacon, naming registry, or convention
promotion. init is idempotent — the operator key is never overwritten. Running
'dontguess serve' also bootstraps the same identity + store on first run, so
'init' is optional; use it to provision (and inspect) the operator home ahead
of time.

  dontguess init
  DONTGUESS_RELAY_URLS=ws://relay.a:7777,ws://relay.b:7777 dontguess init`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "rewrite the config even if it already exists (never overwrites the operator key)")
	rootCmd.AddCommand(initCmd)
}

func runInit(_ *cobra.Command, _ []string) error {
	dgHome := resolveDGHome()

	cfg, err := exchange.Init(exchange.InitOptions{
		DGHome:    dgHome,
		RelayURLs: resolveRelayURLs(),
		Force:     initForce,
	})
	if err != nil {
		return fmt.Errorf("init failed: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	}

	fmt.Printf("DontGuess operator home initialized (campfire-free)\n")
	fmt.Printf("  home:     %s\n", dgHome)
	fmt.Printf("  operator: %s\n", cfg.OperatorKeyHex)
	fmt.Printf("  npub:     %s\n", cfg.OperatorNpub)
	fmt.Printf("  store:    %s\n", cfg.StorePath)
	if len(cfg.RelayURLs) > 0 {
		fmt.Printf("  relays:   %v\n", cfg.RelayURLs)
	} else {
		fmt.Printf("  relays:   (none — set DONTGUESS_RELAY_URLS to federate)\n")
	}
	fmt.Printf("\nNext: dontguess serve\n")
	return nil
}
