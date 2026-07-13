package exchange

import (
	"fmt"
	"time"

	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// scripApplier is the live-fold surface of a scrip store. LocalScripStore
// satisfies it (ApplyMessage). The engine holds scrip.SpendingStore (which does
// not expose ApplyMessage), so MintScrip type-asserts to fold a freshly emitted
// operator scrip-mint into the running process's in-memory balances — otherwise
// the credit would only appear after a restart Replay of the durable log.
type scripApplier interface {
	ApplyMessage(*Message)
}

// MintScrip is the operator genesis-funding god-button (design §4). It funds an
// agent's scrip balance so the first team-tier buy does not deadlock on
// ErrBudgetExceeded (a fresh LocalScripStore folds zero balances and no other
// scrip-mint emitter exists).
//
// It emits a DURABLE scrip-mint operator message via sendOperatorMessage — its
// Sender is the operator key, so it passes the LocalScripStore operator gate
// (relay_store.go: reject scrip ops whose Sender != OperatorKey) and, on a relay
// leg, is republished to peers. It THEN folds the same message into the live
// ScripStore (via applyMint: credits the recipient balance AND totalSupply, so
// the ledger-conservation invariant holds live, not just after Replay).
//
// Operator-only: MintScrip is reachable solely through the operator IPC socket,
// which lives in a 0700 directory inside the process trust boundary. Every mint
// is audit-logged. Returns an error on the individual/no-relay tier
// (ScripStore == nil) — scrip accounting is disabled there by design.
func (e *Engine) MintScrip(recipient string, amount int64) error {
	if e.opts.ScripStore == nil {
		return fmt.Errorf("mint: scrip accounting is disabled (individual tier — no relays attached, ScripStore=nil)")
	}
	if recipient == "" {
		return fmt.Errorf("mint: recipient required")
	}
	if amount <= 0 {
		return fmt.Errorf("mint: amount must be > 0, got %d", amount)
	}

	// Serialize against the auto-accept ticker and other operator-socket ops.
	e.opMu.Lock()
	defer e.opMu.Unlock()

	payload, err := e.marshal(scrip.MintPayload{
		Recipient: recipient,
		Amount:    amount,
		X402TxRef: fmt.Sprintf("operator-mint-%d", time.Now().UnixNano()),
		Rate:      1000,
	})
	if err != nil {
		return fmt.Errorf("mint: encoding scrip-mint payload: %w", err)
	}

	msg, err := e.sendOperatorMessage(payload, []string{scrip.TagScripMint}, nil)
	if err != nil {
		return fmt.Errorf("mint: emitting durable scrip-mint: %w", err)
	}

	// Fold into the live in-memory balance state. The durable message above
	// re-derives the same credit on the next Replay, so this is not the source
	// of truth — it only makes the running process see the balance immediately.
	if applier, ok := e.opts.ScripStore.(scripApplier); ok {
		applier.ApplyMessage(msg)
	}

	e.opts.log("OPERATOR MINT (audit): minted %d scrip to %s via scrip-mint msg %s", amount, shortKey(recipient), msg.ID)
	return nil
}
