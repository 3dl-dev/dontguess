package main

// buy.go is item ed2-B: the team-tier `dontguess buy` cobra command. It wires
// pkg/relayclient's buy-await protocol to the CLI — sign with the AGENT key
// (never the operator key), subscribe-first, publish the buy direct to the
// relay, and await a discriminated outcome (match / buy-miss / leaked-assign /
// ambiguous-timeout) on a bounded, re-subscribing ctx (design
// docs/design/nostr-first-client-ed2.md §3.2).
//
// SCOPE: this command SURFACES a real match (entry id, price, seller) and stops
// at the seam ed2-C extends — it does NOT yet drive buyer-accept -> deliver ->
// complete (that pulls full content and moves scrip). Individual tier (zero
// relay, socket IPC to a local serve) is item ed2-E and out of scope here.

import (
	"context"
	"fmt"

	"github.com/campfire-net/dontguess/pkg/identity"
	"github.com/campfire-net/dontguess/pkg/relayclient"
	"github.com/spf13/cobra"
)

// newBuyCmd builds the buy cobra command. Extracted from init() so tests can
// construct an isolated instance per case rather than mutating the package-level
// singleton's flag state.
func newBuyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "buy",
		Short: "Buy cached inference from the team exchange (await a match)",
		Long: `buy publishes an exchange:buy event directly to the team relay, signed with
the AGENT key from AGENT_CF_HOME (never the operator key), after SUBSCRIBING
FIRST for the operator's response so a fast match cannot be missed.

It then awaits a discriminated outcome within a bounded timeout:
  - MATCH      a hit — surfaces entry id, price, seller (settle is ed2-C)
  - BUY-MISS   nobody has this yet — prints the demand-signal guide
  - AMBIGUOUS  timed out — enumerates the actionable causes (NEVER "no cache")

Requires DONTGUESS_RELAY_URLS (team tier). Individual tier (no relay) is not
yet wired to this command.`,
		RunE: runBuy,
	}
	cmd.Flags().String("task", "", "task description — what you need (required)")
	cmd.Flags().Int64("budget", 0, "scrip budget you are willing to spend")
	cmd.Flags().String("content_type", "", "full exchange content-type tag filter (optional)")
	cmd.Flags().StringSlice("domains", nil, "domain tags to filter on (comma-separated)")
	cmd.Flags().Int("min_reputation", 0, "minimum seller reputation")
	cmd.Flags().Int("freshness_hours", 0, "max age of cached content in hours (0 = any)")
	cmd.Flags().Int("max_results", 0, "max ranked results to return (0 = operator default)")
	cmd.Flags().String("relay", "", "relay websocket URL (default: first of DONTGUESS_RELAY_URLS)")
	cmd.Flags().String("operator-npub", "", "operator npub to require as response author (optional, belt-and-suspenders)")
	cmd.Flags().Duration("timeout", relayclient.DefaultBuyTimeout, "bounded end-to-end timeout (dial, subscribe, publish, await)")
	cmd.Flags().Bool("relay-auth", false, "opt into the NIP-42 client AUTH handshake (default: WithoutClientAuth)")
	return cmd
}

var buyCmd = newBuyCmd()

func init() {
	rootCmd.AddCommand(buyCmd)
}

func runBuy(cmd *cobra.Command, args []string) error {
	task, _ := cmd.Flags().GetString("task")
	budget, _ := cmd.Flags().GetInt64("budget")
	contentType, _ := cmd.Flags().GetString("content_type")
	domains, _ := cmd.Flags().GetStringSlice("domains")
	minRep, _ := cmd.Flags().GetInt("min_reputation")
	freshness, _ := cmd.Flags().GetInt("freshness_hours")
	maxResults, _ := cmd.Flags().GetInt("max_results")
	relayURL, _ := cmd.Flags().GetString("relay")
	operatorNpub, _ := cmd.Flags().GetString("operator-npub")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	relayAuth, _ := cmd.Flags().GetBool("relay-auth")

	if task == "" {
		return fmt.Errorf("buy: --task is required")
	}
	if budget < 0 {
		return fmt.Errorf("buy: --budget must be non-negative")
	}

	if relayURL == "" {
		urls := resolveRelayURLs()
		if len(urls) == 0 {
			return fmt.Errorf("buy: no relay configured — set DONTGUESS_RELAY_URLS (team tier) or pass --relay. Individual-tier (zero-relay) buy is not yet wired to this command")
		}
		relayURL = urls[0]
	}

	var operatorPubKey string
	if operatorNpub != "" {
		raw, err := identity.DecodeNpub(operatorNpub)
		if err != nil {
			return fmt.Errorf("buy: --operator-npub is not a valid npub: %w", err)
		}
		operatorPubKey = fmt.Sprintf("%x", raw)
	}

	signer, err := loadAgentSigner()
	if err != nil {
		return fmt.Errorf("buy: %w", err)
	}

	conn := relayclient.NewConn(relayURL, signer, relayclient.WithRelayAuth(relayAuth))
	defer conn.Close()

	base := cmd.Context()
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, timeout)
	defer cancel()

	result, err := relayclient.Buy(ctx, conn, signer, relayclient.BuyRequest{
		Task:           task,
		Budget:         budget,
		ContentType:    contentType,
		Domains:        domains,
		MinReputation:  minRep,
		FreshnessHours: freshness,
		MaxResults:     maxResults,
		OperatorPubKey: operatorPubKey,
	})
	if err != nil {
		return fmt.Errorf("buy failed: %w", err)
	}

	relayclient.WriteOutcome(cmd.OutOrStdout(), result)

	// A hit is the only success; every other outcome exits non-zero so a script
	// or agent wrapping `dontguess buy` can branch on the exit code, while the
	// human-facing detail is already printed above.
	switch result.Outcome {
	case relayclient.BuyOutcomeMatch:
		return nil
	case relayclient.BuyOutcomeMiss:
		return fmt.Errorf("buy %s: no match (buy-miss) — see demand-signal guide above", result.BuyID)
	case relayclient.BuyOutcomeBrokered:
		return fmt.Errorf("buy %s: unexpected brokered assign — not settling", result.BuyID)
	default:
		return fmt.Errorf("buy %s: ambiguous timeout — see enumerated causes above", result.BuyID)
	}
}
