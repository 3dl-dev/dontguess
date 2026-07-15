# CLAUDE.md — DontGuess Project Instructions

## Project

**DontGuess**: Token-work exchange — a marketplace where agents buy and sell cached inference results. An operator buys inference results from sellers at a discount (scrip), dynamically prices them, sells them to buyers (scrip), and pays residuals to original authors. Agents earn scrip by selling work or performing assigned tasks (context compression, validation, freshness checks). Anyone can operate an exchange; exchanges may federate for global liquidity with trust semantics.

Previously a tool discovery engine (see `docs/heritage/`). The thesis survived the pivot: reduce agent token waste through better discovery. Old: discover the right tool. New: discover pre-computed work someone already paid for.

**Domain:** dontguess.ai. "Don't guess — look it up."

## Architecture

**DontGuess is nostr-first (as of v0.7.0).** `serve` is campfire-free. Exchange operations are
nostr events (kinds `3401` put, `3402` buy, `3403` match, `3404` settle, etc.), signed by
secp256k1 operator/agent keys, relayed through a strfry-compatible relay for team/fleet tiers or
kept entirely local (no relay) at solo tier. State is derived from the event log. Campfire is
retired from this project's runtime path — do not point new agents at `cf join`/`cf init` for
exchange participation; see the "Install / join" section below for the current onboarding flow.

**Scaling ladder:** SOLO (one machine, local, no relay, no scrip) → FLEET (one operator, `--relay`,
team-tier envelope encryption, live-admit allowlist) → FEDERATION (multiple operators, bilateral
trust, ROUTER-mode default confidentiality — **OPEN**, gated on design item P9, do not implement
`dontguess federate` against undesigned wire mechanics). Full design:
`docs/design/onboarding-tiered-scaling-federation.md`. Federation trust/confidentiality model:
`docs/design/federation.md`. Deployment tiers (nostr-rewritten): `docs/design/federation-modes.md`.

### Three Systems

1. **Convention** — Defines exchange operations (put, buy, match, settle, dispute, assign) as nostr event kinds. Historical convention-on-campfire spec lives in `docs/convention/` (heritage reference; the nostr event schemas are the current wire format — see `pkg/convention/`).
2. **Matching engine** — Semantic similarity search over cached inference. Matches buyer task descriptions to seller inventory. Uses vector embeddings (all-MiniLM-L6-v2, 384-dim).
3. **Pricing engine** — Dynamic pricing via three feedback loops (fast/medium/slow). Behavioral signals drive price, not preferences.

### Integration Points

- **Nostr relay** (strfry or compatible) — all team/fleet-tier exchange state lives on the relay as signed events. Puts, buys, matches, settlements are nostr events. Solo tier has no relay — state is local-only.
- **Forge** — metering backbone. Tracks scrip balances, spending limits, token-cost attribution. Scrip is denominated in inference token cost.
- **x402** — settlement rail for cross-operator transactions (USDC). Not required for single-operator use; required for un-graduated cross-operator federation settlement (pre-funded escrow, never trailing credit — see `docs/design/federation.md` §3.3).

### The Publisher Model

DontGuess is a publisher, not a broker:

1. Agent does inference, sells result to the exchange for scrip (upfront, discounted % of token cost)
2. Exchange owns the result, prices it dynamically based on demand signals
3. Original author earns residuals in scrip as copies sell
4. Buyers spend scrip earned from selling their own work or doing assigned tasks
5. Assigned tasks (context compression, validation, freshness checks) are exchange maintenance paid in scrip
6. Every transaction is a signed nostr event

### §8.9 Informed consent (mandatory disclosure — §541)

Read this before putting or federating anything:

> **Your home operator can read your plaintext content.** Team-tier content is envelope-encrypted,
> but the home operator holds the CEK to service matches (§541).
>
> **Federating for resale (custodial mode) extends that trust to the remote peer.** Router mode
> (the default) never does — a router peer sees only metadata and ciphertext hashes, never the CEK.
> Custodial resale is an explicit per-entry seller opt-in, never a side effect of discovery.
>
> **There is no forward secrecy.** One operator-key leak decrypts that operator's entire historical
> corpus offline from data already scraped off the relay and Blossom (§541 A4/P5).
>
> **There is no content revocation once public.** Ciphertext, once published, is append-only.
>
> Full language and rationale: `docs/design/federation.md` §8.9.

### Scrip

Scrip is denominated in token cost. It is not redeemable for cash. It is only exchangeable for other cached inference on the marketplace. New scrip enters the system via x402 purchase or labor (assigned work). Matching fees burn scrip (deflationary pressure).

### The Three Loops (Heritage from toolrank)

| Loop | Cadence | Reads | Writes | Purpose |
|------|---------|-------|--------|---------|
| **Fast** | 5 min | Purchase events, cache hit/miss | Price adjustments | Demand velocity, price elasticity |
| **Medium** | 1 hr | Accumulated adjustments, disputes | Residual settlements, reputation updates | Market correction, seller trust |
| **Slow** | 4 hr | Historical price/volume, buyer satisfaction | Market parameters, commission structure | Structural optimization |

### The 4-Layer Value Stack (Heritage from toolrank)

Each layer gates the ones above it. Layer 0 rejects any change that regresses correctness.

```
Layer 0  CORRECTNESS GATE    task_completion_rate       No loop owns this — validation only
Layer 1  TRANSACTION EFFICIENCY  tokens_saved / price    Fast loop target
Layer 2  VALUE COMPOSITE     completion + efficiency + recency + diversity   Medium loop gate
Layer 3  MARKET NOVELTY      buyer_count / competing_entries * discovery    Slow loop target
Layer 4  META                oscillation_frequency     Adapts slow loop step size
```

**Behavioral signals over preference signals.** Don't trust ratings. Measure: did the cached inference actually complete the buyer's task? Did they search again? Did they come back to the same seller?

## Source of Truth Hierarchy

1. **Convention spec** (`docs/convention/`) — what exchange operations mean
2. **This CLAUDE.md** — project instructions
3. **Heritage docs** (`docs/heritage/`) — design principles from toolrank that survive the pivot
4. **Source code** — implementation

## Repo Structure

```
dontguess/
  CLAUDE.md                    # This file
  docs/
    convention/                # Exchange convention spec (the authority)
    design/                    # Active design docs
    heritage/                  # Transferred design principles from toolrank
  cmd/                         # CLI entry points (Go)
  pkg/                         # Go packages
    matching/                  # Semantic matching engine
    pricing/                   # Dynamic pricing (fast/medium/slow loops)
    convention/                # Exchange convention declarations
    scrip/                     # Scrip ledger integration with Forge
  test/                        # Integration and E2E tests
```

## Heritage

DontGuess was previously a tool discovery engine (17K LOC Python, ~/projects/toolrank). The codebase is not reused, but key design principles transfer:

- **4-layer value stack** — correctness gates everything, behavioral signals over preferences
- **Three feedback loops** — fast (demand), medium (correction), slow (structural optimization)
- **Semantic matching** — vector embeddings for similarity search
- **Cross-agent convergence** — the ungameable trust signal (3+ agents succeed with same cache entry)
- **Observational boundary** — you can't see downstream task success, only proxies (completion, retry, return rate)
- **Escape velocity** — the point where dynamic pricing outperforms static baseline without manual intervention

See `docs/heritage/` for the original design docs that informed this architecture.

## DontGuess — cached inference exchange

`dontguess` is a shared cache of pre-computed inference results across Third Division Labs projects. When you're about to spend tokens deriving domain knowledge, check the exchange first — another agent in another project may have already computed it. When you finish computing something reusable, sell it so others don't re-derive it.

`dontguess` is a nostr-native CLI (v0.7.0+) — every command signs and relays nostr events itself; there is no campfire dependency. Scrip is the internal currency (1 scrip = 1 token at list price). You earn scrip by selling cached work and spend it buying others'.

### Install (run once)
curl -fsSL https://dontguess.ai/install.sh | sh

### Upgrade (v0.5.0+)
dontguess upgrade
# Or: curl -fsSL https://dontguess.ai/install.sh | sh

### Bootstrap or join an exchange (run once)
dontguess up                      # SOLO — local, no relay (auto-detects rung from state)
dontguess up --relay              # FLEET — promotes the SAME operator to team tier
dontguess invite <name>           # operator: mint a one-paste join token for a new member
dontguess join <token>            # member: one paste, self-provisions + admits to the fleet
# See docs/design/onboarding-tiered-scaling-federation.md §1 for the full ladder and transcripts.
# `dontguess federate <peer-beacon>` (cross-operator federation) is OPEN — do not depend on it
# until docs/design/federation.md's P9 wire-protocol design item closes.

### Before expensive inference, check the exchange
result=$(dontguess buy --task "describe what you need" --budget 5000)
# If a match comes back, the content is delivered to you automatically.
# No match? Do the work yourself, then sell it:

### After computing something, sell it
dontguess put --description "what you computed" \
  --token_cost <token-count> --content_type exchange:content-type:code --content <base64-result>
# You get paid in scrip immediately. You earn 10% residual every time
# someone else buys your work. The exchange handles everything else —
# pricing, compression, settlement. Every response tells you what
# happened and what to do next.

### Per-agent identity (v0.5.0+)
# Each subagent can sign with its own Ed25519 key. The exchange campfire stays
# on DG_HOME; only signing changes. Unset AGENT_CF_HOME = identical prior behavior.
eval $(dontguess agent-init my-agent --fleet-member)   # provision identity + set AGENT_CF_HOME
# --fleet-member is required for a persistent agent (fail-closed: no default
# identity is minted). An ephemeral subagent uses --parent <fleet-member> instead.
# Then: buy/put/settle signed by my-agent's key, not the operator key.
# See docs/UPGRADING.md for full details and backward-compat guarantee.

### Domain tags for this project
matching, exchange, pricing, reputation, trust, economics

### The high-value put class — what the exchange actually optimizes for

Live exchange analysis (2026-06-02, §4 of `docs/design/exchange-matching-measurement-review.md`)
shows real reuse concentrates in **reusable engineering artifacts** — things that answer "how do I
do X" across many sessions and projects, not one-off session derivations. Top performers by reuse:

| Entry | Reuses | Pattern |
|-------|--------|---------|
| `legion.tools v1.2 schema correctness checklist` | 37 | Protocol-agnostic checklist usable across any schema design |
| `cf-protocol README CF_NO_PINS` | 30 | Cross-project setup knowledge — saved every time a new repo is configured |
| `GateEvaluator conformance CI path filter` | 19 | Reusable CI config fragment — plug-and-play across any project's CI |
| `flock contention test pattern for Go` | 16 | Language-level idiom — applies whenever flock is used in Go |
| `cf migrate-store --cf-home symlink bridge` | 15 | One-time migration fix that every migrating project needs |

**Put these, not session ephemera.** A checklist, a CI pattern, a Go idiom, a migration recipe —
these are reusable 12-37 times. A session-specific analysis or a per-request derivation is not.
The higher the reuse potential, the longer the residual stream you earn.

**Before putting, ask:** "Would another agent working a different item in a different project derive
this same thing from scratch?" If yes, put it. If it's specific to this session's context, skip it.

### What to cache from this project
- Inventory snapshots with embeddings (data, 4hr TTL)
- Price adjustment deltas / fast loop output (data, 5min TTL)
- Reputation digest / medium loop output (data, 1hr TTL)
- Market parameters / slow loop output (data, 4hr TTL)
- Semantic embeddings for common task descriptions (code, 24hr TTL)
- 4-layer value stack computation logic (analysis, 7d TTL)
- Matching engine tuning decisions with reproducible fixture results (analysis, 7d TTL)
- Conformance test patterns for convention validation (code, 7d TTL)

### What NOT to cache
- **Session ephemera** — per-request derivations, one-off analysis that doesn't generalize across projects
- **Junk puts** — "test", smoke-test entries, upgrade-verification outputs; token_cost < 500 is a red flag
- **Synthetic traffic** — load-test puts, regression-parallel-* entries; tag with `exchange:synthetic` if needed for testing, do not submit to exchange inventory
- Per-request ephemera, mutable user state, RNG outputs, raw git history
- Per-transaction settlement messages (ephemeral, high cardinality)
- Individual match results (low reuse, task-specific)
