package main

// assign.go is item dontguess-d26 (#2 AGENT DOOR). The assign lifecycle exists
// engine-side (pkg/exchange/state_assign.go, dispatched by engine_core.go
// regardless of transport) but had NO CLI verb — a posted assign (e.g. the
// warm-compression offer engine_buy.go's sendWarmCompressionAssign fires on a
// buy match) had no door for an agent to discover, claim, or complete it. This
// file adds three verbs, signed as the walk-up .dg agent identity exactly like
// buy/put do (never the operator key):
//
//	dontguess assigns                                  list open/claimable tasks
//	dontguess assign claim <assign-id>                  claim one
//	dontguess assign complete <claim-id> --content <b64> submit the result
//
// Team tier (relay configured) discovers tasks by REQ-subscribing the relay
// directly (pkg/relayclient.FetchOpenAssigns) — an exchange:assign is an
// OPERATOR broadcast already flowing to the relay via the Outbox, so no
// operator IPC is needed. The individual (zero-relay) tier has no such relay to
// subscribe, so `assigns` there reads the local engine's live State over the
// operator socket (OpListAssigns, individual_ops.go). Claim/complete are
// TEAM-TIER ONLY: the individual tier's "zero identity ceremony" design mints
// a FRESH random sender key on every CLI call (individual_ops.go), which
// cannot satisfy applyAssignComplete's msg.Sender==ClaimantKey binding across
// two separate invocations — there is no persisted identity to carry a claim
// forward on that tier.
//
// `assign complete`'s <id> argument is the CLAIM event id (printed by `assign
// claim` on success) — NOT the assign id. This mirrors the engine exactly:
// applyAssignComplete resolves the assign via the claim antecedent
// (state_assign.go), so the wire message that MUST e-tag is the claim, and the
// claim's nostr event id is already deterministic and known to the caller the
// moment `assign claim` returns — no extra relay round trip is needed (or
// possible against a lightweight test relay that does not replay a client's
// own just-published events — a real relay does, but this CLI never depends on
// that).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/relay"
	"github.com/3dl-dev/dontguess/pkg/relayclient"
	"github.com/spf13/cobra"
)

// newAssignsCmd builds the `assigns` (list) cobra command.
func newAssignsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assigns",
		Short: "List open exchange:assign tasks this agent may claim",
		Long: `assigns lists open/claimable assign tasks: exclusive_sender=="" (open to
anyone) or exclusive_sender==this agent's own key.

Team tier (relay configured): REQ-subscribes the relay directly for every
exchange:assign* event and folds them locally — no operator IPC needed, since
an exchange:assign is an operator broadcast the Outbox already publishes to
the relay like any other operator record.

Individual tier (no relay): reads the local engine's live State over the
operator socket.`,
		RunE: runAssigns,
	}
	cmd.Flags().String("relay", "", "relay websocket URL (default: first of DONTGUESS_RELAY_URLS)")
	cmd.Flags().String("as", "", "override the identity: sign as .dg/agents/<name> (default: the .dg/ found by walk-up)")
	cmd.Flags().String("agent-home", "", "override the identity home directory (advanced/tests; bypasses .dg/ walk-up)")
	cmd.Flags().String("operator-npub", "", "operator npub (team tier: pins the fold to genuine operator-authored assigns)")
	cmd.Flags().Duration("timeout", relayclient.DefaultAssignListTimeout, "bounded end-to-end timeout for the discovery fetch")
	cmd.Flags().Bool("relay-auth", false, "opt into the NIP-42 client AUTH handshake (default: WithoutClientAuth)")
	return cmd
}

var assignsCmd = newAssignsCmd()

func init() {
	rootCmd.AddCommand(assignsCmd)
}

func runAssigns(cmd *cobra.Command, args []string) error {
	relayURL, _ := cmd.Flags().GetString("relay")
	agentName, _ := cmd.Flags().GetString("as")
	agentHome, _ := cmd.Flags().GetString("agent-home")
	operatorNpubFlag, _ := cmd.Flags().GetString("operator-npub")
	operatorNpub := resolveOperatorNpub(operatorNpubFlag)
	timeout, _ := cmd.Flags().GetDuration("timeout")
	relayAuth, _ := cmd.Flags().GetBool("relay-auth")

	signer, err := loadAgentSigner(agentName, agentHome)
	if err != nil {
		return fmt.Errorf("assigns: %w", err)
	}

	if relayURL == "" {
		urls := resolveRelayURLs()
		if len(urls) == 0 {
			return runAssignsIndividual(cmd, signer)
		}
		relayURL = urls[0]
	}

	var operatorPubKey string
	if operatorNpub != "" {
		raw, derr := identity.DecodeNpub(operatorNpub)
		if derr != nil {
			return fmt.Errorf("assigns: --operator-npub is not a valid npub: %w", derr)
		}
		operatorPubKey = fmt.Sprintf("%x", raw)
	}

	conn := relayclient.NewConn(relayURL, signer, relayclient.WithRelayAuth(relayAuth))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(cmdContext(cmd), timeout)
	defer cancel()

	open, err := relayclient.FetchOpenAssigns(ctx, conn, operatorPubKey, signer.PubKeyHex())
	if err != nil {
		return fmt.Errorf("assigns: %w", err)
	}
	printOpenAssigns(cmd, open)
	return nil
}

// runAssignsIndividual is the individual-tier (zero-relay) assigns listing
// path: it dials the operator socket and issues OpListAssigns. signer is
// resolved (even though individual tier has no persisted per-call identity of
// its own) so this agent's OWN key can still filter in a task exclusively
// addressed to it, if any (e.g. a task an operator-side process posted
// naming this .dg identity directly).
func runAssignsIndividual(cmd *cobra.Command, signer identity.Signer) error {
	conn := dialSocket()
	defer conn.Close()

	var resp opListAssignsResponse
	if err := sendRequest(conn, map[string]any{
		"op":         OpListAssigns,
		"caller_key": signer.PubKeyHex(),
	}, &resp); err != nil {
		return fmt.Errorf("assigns: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("assigns: %s", resp.Error)
	}
	open := make([]relayclient.OpenAssign, 0, len(resp.Assigns))
	for _, a := range resp.Assigns {
		open = append(open, relayclient.OpenAssign{
			AssignID:        a.AssignID,
			EntryID:         a.EntryID,
			TaskType:        a.TaskType,
			Reward:          a.Reward,
			Status:          a.Status,
			ExclusiveSender: a.ExclusiveSender,
			Description:     a.Description,
		})
	}
	printOpenAssigns(cmd, open)
	return nil
}

func printOpenAssigns(cmd *cobra.Command, open []relayclient.OpenAssign) {
	if jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		enc.Encode(open) //nolint:errcheck
		return
	}
	if len(open) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No open assigns claimable right now.")
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%-14s  %-12s  %8s  %-14s  %s\n", "AssignID", "TaskType", "Reward", "ExclusiveTo", "Status")
	fmt.Fprintf(cmd.OutOrStdout(), "%-14s  %-12s  %8s  %-14s  %s\n", "--------", "--------", "------", "-----------", "------")
	for _, a := range open {
		excl := "-"
		if a.ExclusiveSender != "" {
			excl = short(a.ExclusiveSender)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-14s  %-12s  %8d  %-14s  %s\n", short(a.AssignID), a.TaskType, a.Reward, excl, a.Status)
		if a.Description != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", a.Description)
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "\nclaim:    dontguess assign claim <AssignID>")
	fmt.Fprintln(cmd.OutOrStdout(), "complete: dontguess assign complete <ClaimID> --content <b64>  (ClaimID is printed by `assign claim`)")
}

// --- `dontguess assign claim` / `dontguess assign complete` -----------------

// newAssignCmd builds the `assign` parent command (claim/complete children).
func newAssignCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "assign",
		Short: "Claim and complete exchange:assign tasks (team tier)",
	}
}

var assignCmd = newAssignCmd()

func newAssignClaimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim <assign-id>",
		Short: "Claim an open assign task",
		Long: `claim signs an exchange:assign-claim(3405) event e-tagging <assign-id> with
the AGENT key (never the operator key) and publishes it to the team relay.

A relay OK is a TRANSPORT RECEIPT ONLY (mirrors put/buy's discipline) — it is
NOT proof the engine's fold admitted the claim (an exclusive-sender mismatch or
an already-claimed task silently no-ops in the fold). Run 'dontguess assigns'
again to confirm the claim shows this agent's key as claimant.

Prints the claim's event id on success — pass it as <id> to
'dontguess assign complete' (NOT the assign id: applyAssignComplete resolves
the assign via the claim antecedent).

Requires DONTGUESS_RELAY_URLS (team tier) — the individual tier has no
persisted per-call identity to carry a claim across separate invocations.`,
		Args: cobra.ExactArgs(1),
		RunE: runAssignClaim,
	}
	cmd.Flags().String("relay", "", "relay websocket URL (default: first of DONTGUESS_RELAY_URLS)")
	cmd.Flags().String("as", "", "override the identity: sign as .dg/agents/<name> (default: the .dg/ found by walk-up)")
	cmd.Flags().String("agent-home", "", "override the identity home directory (advanced/tests; bypasses .dg/ walk-up)")
	cmd.Flags().Duration("timeout", relayclient.DefaultAssignActionTimeout, "bounded end-to-end timeout (dial, publish, await OK)")
	cmd.Flags().Bool("relay-auth", false, "opt into the NIP-42 client AUTH handshake (default: WithoutClientAuth)")
	return cmd
}

var assignClaimCmd = newAssignClaimCmd()

func runAssignClaim(cmd *cobra.Command, args []string) error {
	assignID := args[0]
	relayURL, _ := cmd.Flags().GetString("relay")
	if relayURL == "" {
		urls := resolveRelayURLs()
		if len(urls) == 0 {
			return fmt.Errorf("assign claim: requires DONTGUESS_RELAY_URLS (team tier) — the individual (zero-relay) tier has no persisted identity to carry a claim across separate CLI invocations")
		}
		relayURL = urls[0]
	}
	agentName, _ := cmd.Flags().GetString("as")
	agentHome, _ := cmd.Flags().GetString("agent-home")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	relayAuth, _ := cmd.Flags().GetBool("relay-auth")

	signer, err := loadAgentSigner(agentName, agentHome)
	if err != nil {
		return fmt.Errorf("assign claim: %w", err)
	}

	conn := relayclient.NewConn(relayURL, signer, relayclient.WithRelayAuth(relayAuth))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(cmdContext(cmd), timeout)
	defer cancel()

	res, err := relayclient.AssignClaim(ctx, conn, signer, assignID)
	if err != nil {
		return fmt.Errorf("assign claim failed: %w", err)
	}
	if !res.Accepted {
		return fmt.Errorf("assign claim %s: relay did not accept the event: %s", res.EventID, res.OKMessage)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "claimed assign %s -> claim %s\n", short(assignID), res.EventID)
	fmt.Fprintf(cmd.OutOrStdout(), "complete it with: dontguess assign complete %s --content <b64>\n", res.EventID)
	return nil
}

func newAssignCompleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "complete <claim-id>",
		Short: "Submit the result for a claimed assign task",
		Long: `complete signs an exchange:assign-complete(3405) event e-tagging <claim-id>
(the event id 'dontguess assign claim' printed — NOT the assign id) with the
AGENT key and publishes it to the team relay. --content is the completed work,
base64-encoded.

YOUR WORK IS ENCRYPTED BEFORE IT LEAVES THIS PROCESS (dontguess-7e21). An
assign-complete is a PUBLIC signed relay event, so submitting the compressed
bytes inline would publish your work in the clear. Instead this command first
publishes --content as an ordinary 'dontguess put' — which the §541 envelope
encrypts end to end, CEK wrapped to the operator — and then submits a completion
that merely REFERENCES that put. The operator validates against the copy it
decrypts itself.

That means completing a compression also LISTS it: the compressed derivative
becomes your inventory entry, you are credited for the put, and you earn
residuals every time it sells — on top of the bounty. Pass --description
(the work order prints the original's, so the derivative answers the same
queries) and --token-cost (your real compression spend; it defaults to the
compressed byte count, which is a floor, not an estimate).

A relay OK is a transport receipt only — see 'assign claim's doc. Payment
(assign-accept, operator-only) is a separate step this CLI does not perform;
run 'dontguess savings' to confirm a bounty landed once the operator accepts.`,
		Args: cobra.ExactArgs(1),
		RunE: runAssignComplete,
	}
	cmd.Flags().String("content", "", "base64-encoded completed content (required)")
	cmd.Flags().String("description", "", "description for the derivative listing (default: the claim id; pass the original's description so the derivative matches the same queries)")
	cmd.Flags().Int64("token-cost", 0, "your whole compression spend in tokens (default: the compressed byte count, a floor)")
	cmd.Flags().String("content-type", "code", "content type of the derivative listing")
	cmd.Flags().String("operator-npub", "", "operator npub (team tier: wraps the derivative's CEK to the operator)")
	cmd.Flags().Bool("inline-plaintext", false, "submit the work INLINE and IN THE CLEAR instead of as an encrypted put — only for an exchange with no confidentiality (individual tier); a confidential operator refuses this shape")
	cmd.Flags().String("relay", "", "relay websocket URL (default: first of DONTGUESS_RELAY_URLS)")
	cmd.Flags().String("as", "", "override the identity: sign as .dg/agents/<name> (default: the .dg/ found by walk-up)")
	cmd.Flags().String("agent-home", "", "override the identity home directory (advanced/tests; bypasses .dg/ walk-up)")
	cmd.Flags().Duration("timeout", relayclient.DefaultAssignActionTimeout, "bounded end-to-end timeout (dial, publish, await OK)")
	cmd.Flags().Bool("relay-auth", false, "opt into the NIP-42 client AUTH handshake (default: WithoutClientAuth)")
	return cmd
}

var assignCompleteCmd = newAssignCompleteCmd()

func runAssignComplete(cmd *cobra.Command, args []string) error {
	claimID := args[0]
	contentB64, _ := cmd.Flags().GetString("content")
	if contentB64 == "" {
		return fmt.Errorf("assign complete: --content is required (base64-encoded)")
	}
	content, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return fmt.Errorf("assign complete: --content is not valid base64: %w", err)
	}

	relayURL, _ := cmd.Flags().GetString("relay")
	if relayURL == "" {
		urls := resolveRelayURLs()
		if len(urls) == 0 {
			return fmt.Errorf("assign complete: requires DONTGUESS_RELAY_URLS (team tier) — the individual (zero-relay) tier has no persisted identity to carry a claim across separate CLI invocations")
		}
		relayURL = urls[0]
	}
	agentName, _ := cmd.Flags().GetString("as")
	agentHome, _ := cmd.Flags().GetString("agent-home")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	relayAuth, _ := cmd.Flags().GetBool("relay-auth")

	signer, err := loadAgentSigner(agentName, agentHome)
	if err != nil {
		return fmt.Errorf("assign complete: %w", err)
	}

	conn := relayclient.NewConn(relayURL, signer, relayclient.WithRelayAuth(relayAuth))
	defer conn.Close()

	ctx, cancel := context.WithTimeout(cmdContext(cmd), timeout)
	defer cancel()

	// Publish the work as an encrypted put FIRST, then reference it (dontguess-7e21).
	// This is what keeps the submission confidential: the put path performs the
	// whole §541 envelope (per-entry CEK, ChaCha20-Poly1305, CEK wrapped to the
	// operator), so the compressed plaintext never touches the wire. Submitting it
	// inline instead would publish the work in the clear, and the operator rejects
	// that shape outright on a confidential exchange.
	//
	// --inline-plaintext is the explicit opt-out, for an exchange that has no
	// confidentiality to preserve (individual tier: no operator key, no envelope,
	// nothing to wrap a CEK to). It is deliberately opt-IN: the safe shape is what
	// you get by default, and a misconfigured agent that forces this against a real
	// confidential exchange is still refused by the operator rather than quietly
	// accepted after the fact.
	inlinePlaintext, _ := cmd.Flags().GetBool("inline-plaintext")
	var result []byte
	if inlinePlaintext {
		fmt.Fprintln(cmd.OutOrStdout(), "WARNING: --inline-plaintext submits your work UNENCRYPTED on a public event.")
		result, err = relayclient.BuildAssignResult(content)
		if err != nil {
			return fmt.Errorf("assign complete: encode result: %w", err)
		}
	} else {
		putID, perr := publishCompletionAsPut(ctx, cmd, conn, signer, content, claimID)
		if perr != nil {
			return perr
		}
		result, err = relayclient.BuildAssignResultForPut(putID)
		if err != nil {
			return fmt.Errorf("assign complete: encode result: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "published derivative as put %s (encrypted; you are its seller and earn residuals on it)\n", short(putID))
	}

	res, err := relayclient.AssignComplete(ctx, conn, signer, claimID, result)
	if err != nil {
		return fmt.Errorf("assign complete failed: %w", err)
	}
	if !res.Accepted {
		return fmt.Errorf("assign complete %s: relay did not accept the event: %s", res.EventID, res.OKMessage)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "submitted completion %s for claim %s\n", res.EventID, short(claimID))
	fmt.Fprintln(cmd.OutOrStdout(), "awaiting operator assign-accept to be paid; check with: dontguess savings")
	return nil
}

func init() {
	assignCmd.AddCommand(assignClaimCmd)
	assignCmd.AddCommand(assignCompleteCmd)
	rootCmd.AddCommand(assignCmd)
}

// cmdContext returns cmd.Context(), falling back to context.Background() when
// nil (cmd.Context() is nil unless the command was run through
// (Execute|ExecuteContext) — unit tests calling runXxx directly don't thread a
// context through cobra's Execute machinery). Mirrors buy.go/put.go's inline
// guard, extracted here since assigns/claim/complete all need it.
func cmdContext(cmd *cobra.Command) context.Context {
	if base := cmd.Context(); base != nil {
		return base
	}
	return context.Background()
}

// publishCompletionAsPut publishes the completed work as an ordinary encrypted
// put and returns its event id, for `assign complete` to reference
// (dontguess-7e21).
//
// This exists so a compression worker never has to think about confidentiality:
// the command it runs is unchanged (`assign complete <claim> --content <b64>`),
// but the bytes leave this process inside the same §541 envelope every put uses,
// rather than inline on a public assign-complete event. It also means the
// derivative is a first-class listing under the worker's own key — content,
// teaser, ciphertext hash and CEK wrap all correct by construction, so a buyer
// can actually be delivered the compressed version.
//
// Defaults are chosen so the one-liner works without extra flags:
//   - description falls back to naming the claim, which is poor for matching;
//     the work order prints the original's description precisely so the worker
//     can pass it through and have the derivative answer the same queries.
//   - token-cost falls back to the compressed byte count. That is a FLOOR (you
//     generated at least that many bytes), not an estimate of the real spend —
//     pass --token-cost with what the compression actually cost you.
func publishCompletionAsPut(ctx context.Context, cmd *cobra.Command, conn *relay.Conn, signer identity.Signer, content []byte, claimID string) (string, error) {
	description, _ := cmd.Flags().GetString("description")
	if description == "" {
		description = "compressed derivative (assign claim " + short(claimID) + ")"
	}
	tokenCost, _ := cmd.Flags().GetInt64("token-cost")
	if tokenCost <= 0 {
		tokenCost = int64(len(content))
	}
	contentType, _ := cmd.Flags().GetString("content-type")
	operatorNpubFlag, _ := cmd.Flags().GetString("operator-npub")
	operatorNpub := resolveOperatorNpub(operatorNpubFlag)
	if operatorNpub == "" {
		return "", fmt.Errorf("assign complete: no operator npub configured — a team-tier submission must wrap its content key to the operator; pass --operator-npub or set it in .dg/config.json")
	}
	raw, err := identity.DecodeNpub(operatorNpub)
	if err != nil {
		return "", fmt.Errorf("assign complete: --operator-npub is not a valid npub: %w", err)
	}

	res, err := relayclient.Put(ctx, conn, signer, relayclient.PutRequest{
		Description:    description,
		Content:        content,
		TokenCost:      tokenCost,
		ContentType:    contentType,
		OperatorPubKey: fmt.Sprintf("%x", raw),
		BlobStore:      newSellerBlobStore(),
	})
	if err != nil {
		return "", fmt.Errorf("assign complete: publishing the derivative as a put failed: %w", err)
	}
	if res.Rejected {
		return "", fmt.Errorf("assign complete: the derivative put was REJECTED by the operator: %s (ask the operator to run: dontguess allowlist add %s)", res.RejectReason, signer.Npub())
	}
	if res.PutID == "" {
		return "", fmt.Errorf("assign complete: the derivative put returned no event id — nothing to reference")
	}
	return res.PutID, nil
}
