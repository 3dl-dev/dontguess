# Decision: Per-Agent Identities for Cross-Agent Convergence Measurement

**Item:** dontguess-35d  
**Track:** C / V4  
**Type:** SPIKE-FIRST — design only, no implementation  
**Date:** 2026-06-02  
**Status:** IMPLEMENT — with the recommended model below

---

## 1. The Problem

From `exchange-matching-measurement-review.md §2`:

> **Single identity:** every buyer and seller key is `cd41913b` — the heritage
> "cross-agent convergence" trust signal (3+ distinct agents succeed with one entry)
> cannot be measured.

The exchange already tracks `EntryBuyerMap` (distinct buyers per entry) in
`SellerStats` to compute the `+3 reputation bonus` when `len(buyers) >= 3`.
The mechanism exists. The signal is dead because all buys and puts arrive from the
same Ed25519 key (`cd41913b6a…`).

---

## 2. Identity Model Spike Findings

### 2.1 How the wrapper pins one identity today

The `dontguess` wrapper (`~/.local/bin/dontguess`) enforces:

```sh
DG_HOME="${DG_HOME:-${HOME}/.cf}"
# ...
exec "$CF" --cf-home "$DG_HOME" "$XCFID" "$@"
```

Every `dontguess buy` and `dontguess put` is sent with `--cf-home $DG_HOME`,
resolving to `~/.cf`. That directory holds `identity.json` with the operator key
(`cd41913b6a…`). All messages are signed with that single Ed25519 key.
`msg.Sender` is always `cd41913b6a…` in `state.go` (lines 1133, 1178).

The cf SDK identity cascade (`CF_HOME > ~/.cf`) is bypassed at the wrapper level
because the wrapper hardcodes `--cf-home $DG_HOME`. A subagent that sets its own
`CF_HOME` still reaches the exchange as `cd41913b6a…`.

### 2.2 What the protocol already supports

`TestMode3_Team` (passing, `test/scale_test.go:436`) demonstrates exactly the target
state: Alice and Bob each have distinct identities (separate `cfHome` dirs, separate
Ed25519 keys), they both operate on the same exchange campfire (admit → join → put →
buy → match), and the exchange attributes operations to their respective keys.

The protocol, state machine, and campfire SDK already support N distinct identities
on one exchange. The gap is entirely in how the wrapper delivers operations: it
collapses N agents to 1 key.

### 2.3 How msg.Sender flows through the exchange

`msg.Sender` (`pkg/proto/message.go:25`) is the hex-encoded Ed25519 public key of
the signer. It is set by the campfire SDK from `identity.json` in the config dir
resolved by `--cf-home`. It is cryptographically enforced (signature covers payload;
a forged Sender fails verification at campfire ingress).

`InventoryEntry.SellerKey` = `msg.Sender` for the put message (`state.go:1133`).  
`ActiveOrder.BuyerKey` = `msg.Sender` for the buy message (`state.go:1178`).  
`EntryBuyerMap[entryID][buyerKey]` accumulates distinct buyers per entry (`state.go:1524-1530`).

The convergence signal (`+3 reputation bonus`, `state.go:482-486`) fires when
`len(EntryBuyerMap[entry]) >= 3`. With one shared key, `len` is always ≤ 1,
regardless of how many logical agents use the exchange.

---

## 3. Proposed Identity Model

### Core decision: per-session AGENT_CF_HOME, wrapper-level env override

Each agent session gets its own `CF_HOME` pointing to a directory with its own
`identity.json`. The wrapper currently passes `--cf-home $DG_HOME` — redirecting
the signing home per-agent is sufficient to give each agent its own identity on
the exchange.

The wrapper comment already documents the design intent: `DG_HOME pins all singleton
exchange state, independent of CF_HOME. Subagents with per-session CF_HOME still find
the real exchange here.` The current design intentionally collapses identity for
simplicity. The fix introduces a second env var to separate concerns.

**Proposed model:**

```
DG_HOME=~/.cf                       # exchange state only (campfire DB, PID, logs,
                                    # operator identity for operator operations)

AGENT_CF_HOME=~/.cf/agents/<name>/  # per-agent identity.json (generated once,
                                    # persistent; agent admitted to exchange campfire)
```

Two env vars, two concerns:
- `DG_HOME` — exchange routing state (campfire ID, operator PID). Stays shared.
- `AGENT_CF_HOME` — signing identity for buy/put operations. One per agent.

The wrapper change is one line:

```sh
# Before:
exec "$CF" --cf-home "$DG_HOME" "$XCFID" "$@"

# After:
_SIGNING_HOME="${AGENT_CF_HOME:-$DG_HOME}"
exec "$CF" --cf-home "$_SIGNING_HOME" "$XCFID" "$@"
```

If `AGENT_CF_HOME` is unset, behavior is identical to today (backward compatible).

**Admission flow for a new agent identity:**

1. Generate identity: `cf --cf-home $AGENT_CF_HOME init`
2. Operator admits to exchange: `cf admit $XCFID <agent-pubkey>`
3. Agent joins: `cf --cf-home $AGENT_CF_HOME join $XCFID`
4. Agent exports `AGENT_CF_HOME` in its shell env; all `dontguess` ops carry its key.

This is the same flow as `TestMode3_Team` (Bob = agent, Alice = operator). The e2e
infrastructure already validates it end-to-end.

**Provenance gating:**

`serve.go:138` calls `provenanceStore.SetSelfClaimed(m.MemberPubkey)` for every
campfire member at startup. Any admitted agent automatically reaches `LevelClaimed`
(required for buy-accept, complete, dispute per `provenance.go:82-85`). `LevelPresent`
operations (put-accept, deliver, match) remain operator-only. No provenance code changes.

---

## 4. Blast Radius

### 4.1 Wrapper — one line change

File: `~/.local/bin/dontguess` (shell script; not in-repo, installed via `dontguess.ai/install.sh`).

Change: `AGENT_CF_HOME` override for signing home (1 line + 2 lines env var docs).

The attempt log `caller` attribution (`_attempt_log_write`) already reads identity
from `DG_HOME/identity.json` as a fallback. With `AGENT_CF_HOME` set, the caller
attribution should prefer `AGENT_CF_HOME/identity.json` so telemetry correctly records
which agent made the call. This is a 5-line update to `_attempt_log_write`.

Backward compatibility: unset `AGENT_CF_HOME` = current behavior. No migration.

### 4.2 DG_HOME handling — no change

`DG_HOME` continues to point at `~/.cf`. Exchange config (`dontguess-exchange.json`),
PID file, operator log, and start lock all remain there. No path conflict with agent
identity dirs.

### 4.3 cf join/identity — operator tooling only

Each agent must be admitted and joined once (one-time per agent, not per session).
Agent identities are long-lived (cfHome dir is persistent, like a machine key).
No changes to the campfire SDK or convention declarations.

A new `dontguess agent-init <name>` subcommand (see §7) wraps the three admission
steps into one command to reduce operator friction.

### 4.4 Scrip ledger — no change, already correct

`pkg/scrip/campfire_store.go` keys balances by `msg.Sender` (agent public key).
With per-agent identities, each agent has its own scrip balance. This is correct
behavior: agents earn and spend independently. `scrip.Reservation.AgentKey` is
already `msg.Sender` from the buy-hold message. Settlement keys are derived from
inventory entries (not buyer-supplied), so no scrip logic changes are needed.

### 4.5 Settlement keys — no change

`state.go:2486`: "Never trust a buyer-supplied seller_key field in the settle
payload." The engine derives seller key from `inventory[entry].SellerKey` (line 2516).
Multi-agent puts create entries with distinct seller keys; settlement continues to
pay the correct seller. No changes needed.

### 4.6 Convergence measurement — this is the win

With per-agent identities:
- `EntryBuyerMap[entryID]` accumulates distinct agent keys
- 3 agents buying the same entry triggers `+3 reputation bonus`
- `AllSellerKeys()` (`state.go:2755`) returns multiple distinct keys
- Hit-rate reporter can compute per-agent hit rates and convergence counts

No state machine changes required. The engine already handles this correctly.

### 4.7 Operator identity — no change

The operator's identity at `DG_HOME/identity.json` remains the campfire
creator/owner, signing put-accept, match, deliver, and mint/burn operations.

### 4.8 pkg/exchange/engine.go — not touched

Per swarm constraint (5 other items edit engine.go). Not needed for this item.

---

## 5. What Does NOT Change

- `pkg/exchange/engine.go` (swarm constraint, not needed)
- `pkg/exchange/state.go` (already handles multiple buyer/seller keys correctly)
- `pkg/scrip/` (already keyed by sender pubkey)
- `docs/convention/` (no convention changes)
- Campfire SDK (no changes)
- Exchange campfire ID (agents join the existing campfire)
- Operator's DG_HOME layout

---

## 6. Feasibility Assessment

**Verdict: feasible with narrow blast radius. No architecture fork. No adversarial-design escalation warranted.**

The campfire SDK, exchange state machine, scrip ledger, provenance checker, and
settlement logic already handle multiple distinct identities correctly. `TestMode3_Team`
proves the multi-identity path end-to-end. The only gap is in how the wrapper routes
messages: one line change plus operator admission steps.

Non-trivial work:

1. **Wrapper change** — add `AGENT_CF_HOME` env support + telemetry update (~15 lines)
2. **Agent provisioning** — `dontguess agent-init` subcommand (new Go file, ~80 lines)
3. **Convergence field** — `cross_agent_convergence` in hitrate reporter (~20 lines + test)

This is config-and-tooling work, not architecture work. Deferring it means the
convergence trust signal remains permanently unmeasurable, degrading the reputation
system's integrity indefinitely. The cost of deferral is high; the cost of implementing
is low.

---

## 7. Implementation Sub-Item Tree

### dontguess-35d-w1 — Wrapper: AGENT_CF_HOME support

**Done condition:** `dontguess buy` and `dontguess put` use `AGENT_CF_HOME` for signing
when set; `DG_HOME` continues to route to the exchange. Attempt log records the actual
signing identity (not always the operator key). Wrapper with `AGENT_CF_HOME` unset
is identical to current behavior.

**Scope:** Wrapper shell script only. No Go code changes. Update the installer script
to document the new env var.

**Test (real path, not mocked):** Integration test or verified shell script that:
1. Creates two dirs (`alice_cf`, `bob_cf`) with distinct `cf init` identities
2. Admits both to a filesystem-transport test exchange
3. Puts with `AGENT_CF_HOME=alice_cf`; buys with `AGENT_CF_HOME=bob_cf`
4. Reads exchange state; asserts `seller_key = alice's pubkey`, `buyer_key = bob's pubkey`,
   and `EntryBuyerMap` contains bob's key, not alice's

### dontguess-35d-w2 — Agent provisioning: `dontguess agent-init` subcommand

**Done condition:** `dontguess agent-init <name>` creates `~/.cf/agents/<name>/`,
generates an Ed25519 identity (via `protocol.Init`), admits the key to the exchange
campfire, joins, and prints the `export AGENT_CF_HOME=...` line. Idempotent: if
identity already exists, prints the export line without regenerating.

**Scope:** New subcommand in `cmd/dontguess/agent_init.go`. One Go file.

**Test:** `TestAgentInit_GeneratesDistinctIdentity` — two calls with different names
produce different public keys.

**Dependency:** Blocks dontguess-35d-w3 (w3 can be written/tested with synthetic keys,
but real convergence data requires admitted agents from w2).

### dontguess-35d-w3 — Measurement: convergence field in hit-rate reporter

**Done condition:** `dontguess hit-rate` JSON output includes
`"cross_agent_convergence": <N>` — count of inventory entries where ≥3 distinct buyer
keys have completed. Field is 0 today and rises as agents gain distinct identities.

**Scope:** `pkg/exchange/hitrate.go` and `hitrate_test.go`. No `engine.go` changes.

**Test:** `TestHitRate_CrossAgentConvergence` — seeds state with 3 distinct buyer keys
completing on one entry; asserts `convergence_count == 1`.

**Depends on:** dontguess-35d-w1 (for the wrapper to supply distinct keys; the code
change itself can land earlier and be verified with unit-test synthetic keys).

---

## 8. Dependency Wiring

```
dontguess-35d (this design item — done on commit)
├── dontguess-35d-w1 (wrapper AGENT_CF_HOME) — can start immediately
├── dontguess-35d-w2 (agent-init subcommand) — can start immediately, parallel with w1
└── dontguess-35d-w3 (convergence field in hit-rate) — depends on w1 + w2
```

w1 and w2 are independent and can run in parallel. w3 requires both.

---

## 9. Deferred Scope (explicit non-goals)

- **Cross-machine agent identities** — each machine generates its own agent key;
  cross-machine sharing (e.g., same Claude session across two hosts using one key)
  is out of scope. Each machine is a distinct buyer/seller; that is sufficient.
- **Key rotation / revocation** — agent keys are long-lived. Rotation is a future
  concern once the basic multi-agent path is proven.
- **Scrip transfer between agent identities** — scrip earned by one agent key stays
  with that key. Cross-identity scrip pooling is an economics question for later.
- **Automatic agent discovery** — the operator manually admits agents. A campfire
  webhook / auto-admit flow is post-MVP.
