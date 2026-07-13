# test/demo

Runnable, narrated walkthroughs of the DontGuess exchange (nostr-first).

## `01-individual-tier.sh`

The complete campfire-free basic lifecycle on the **individual tier**
(`DONTGUESS_RELAY_URLS` unset): a single operator `init`s an exchange, starts the
engine (`serve`), accepts a `put` over the local IPC socket, processes a `buy`, and
returns the cached content inline — no `cf`, no campfire, no relay. Builds the
operator from source (never trusts a possibly-stale system binary), runs in an
isolated temp `DG_HOME`, and exits non-zero if the buy is not an inline HIT.

```sh
bash test/demo/01-individual-tier.sh
```

## Retired cf-era demos (dontguess-ed2 §6 item 9)

The eight cf-era demos (`01-solo-operator` … `08-hosted-multi-machine`) drove the
exchange through `cf --cf-home <campfire-id> put/buy` against a hosted campfire that
no longer exists. They were deleted with the nostr-first cutover. Their coverage is
replaced by:

- **`01-individual-tier.sh`** — the campfire-free single-operator put→buy→match
  lifecycle (successor to `01-solo-operator`).
- **Gated in-process round-trip test** (`cmd/dontguess` `TestE2E*`, design ed2-G) —
  the team-tier / multi-agent wire path: allowlisted-put matchable, minted
  buy→match→settle moves scrip + delivers content, non-allowlisted put → LOUD
  put-reject, underfunded buyer-accept → LOUD reject received, underfunded deliver →
  no content. This is the nostr-first replacement for the multi-agent, auto-accept,
  residuals, assign-work, and hosted demos.
