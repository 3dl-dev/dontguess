# CLAUDE.md — DontGuess Project Instructions

<!-- Target: under 200 lines (Anthropic guidance — longer files reduce adherence).
     Cut what Claude can derive from the codebase (directory layouts, package lists,
     command transcripts); keep pitfalls, operator rulings, and conventions that differ
     from what the code appears to say. Long-form lives in docs/design/. -->

## Project

**DontGuess**: a token-work exchange — agents buy and sell cached inference results. An operator buys results from sellers at a discount (scrip), prices them dynamically, sells them to buyers, and pays residuals to the original authors. Agents earn scrip by selling work or performing assigned tasks (compression, validation, freshness checks). Anyone can operate an exchange; exchanges may federate.

**It is a publisher, not a broker** — the exchange *owns* what it buys, and the author earns residuals as copies sell. That is why it runs a deficit on any single sale and recovers across resales.

Domain: dontguess.ai. Previously a tool-discovery engine (`docs/heritage/`); the thesis survived the pivot — old: discover the right tool, new: discover pre-computed work someone already paid for. Heritage principles that carry: the 4-layer value stack, the three feedback loops, semantic matching, cross-agent convergence as the ungameable trust signal, and the observational boundary (you never see downstream task success, only completion / retry / return-rate proxies).

## Architecture

**Nostr-first since v0.7.0. Campfire is retired from the runtime path** — `serve` is campfire-free. Exchange operations are signed nostr events (`3401` put, `3402` buy, `3403` match, `3404` settle, `3410` invite-redeem) relayed through a strfry-compatible relay, or kept entirely local at solo tier. State derives from the event log. **Never point a new agent at `cf join` / `cf init`** for exchange participation.

**Scaling ladder:** SOLO (one machine, local, no relay, no scrip) → FLEET (one operator, `--relay`, team-tier envelope encryption, live-admit allowlist) → FEDERATION (multiple operators, bilateral trust, ROUTER-mode default confidentiality).

**FEDERATION is OPEN and gated on design item P9. Do not implement or invoke `dontguess federate` against undesigned wire mechanics** — it is deliberately not one-command-trusting, because it is the most consequential trust decision on the ladder. Design: `docs/design/onboarding-tiered-scaling-federation.md`, `docs/design/federation.md`, `docs/design/federation-modes.md`.

Three systems: a **convention** (exchange operations as nostr event kinds), a **matching engine** (semantic similarity over cached inference; all-MiniLM-L6-v2, 384-dim), and a **pricing engine** (three feedback loops). Packages are self-describing — read `pkg/`.

**Forge** is the metering backbone (scrip balances, spend limits, token-cost attribution).

**x402 is an external USDC on-ramp for buying scrip INTO an exchange — it is NOT federation settlement.** Cross-operator settlement is cash-free: local-mint scrip cleared through a token-cost mutual-credit ledger, where a leeching peer accrues durable scrip debt (operator ruling 2026-07-16; source of truth `docs/design/federation-infra-p9-router-decision.md` §8). A cash rail returns only behind an explicit, unanimous multi-operator buy-in. `federation.md` / `federation-modes.md` still describe the old x402 model — re-base tracked in dontguess-bdd.

### The three loops

| Loop | Cadence | Reads | Writes | Purpose |
|------|---------|-------|--------|---------|
| Fast | 5 min | purchase events, cache hit/miss | price adjustments | demand velocity, elasticity |
| Medium | 1 hr | accumulated adjustments, disputes | residual settlements, reputation | market correction, seller trust |
| Slow | 4 hr | historical price/volume, satisfaction | market parameters, commission | structural optimization |

### The 4-layer value stack

Each layer gates the ones above it; Layer 0 rejects any change that regresses correctness.

```
Layer 0  CORRECTNESS GATE       task_completion_rate                          no loop owns it — validation only
Layer 1  TRANSACTION EFFICIENCY tokens_saved / price                          fast-loop target
Layer 2  VALUE COMPOSITE        completion + efficiency + recency + diversity  medium-loop gate
Layer 3  MARKET NOVELTY         buyer_count / competing_entries * discovery    slow-loop target
Layer 4  META                   oscillation_frequency                          adapts slow-loop step size
```

**Behavioral signals over preference signals.** Don't trust ratings. Measure: did the cached inference actually complete the buyer's task? Did they search again? Did they come back to the same seller?

## Scrip and pricing — the rulings

Scrip is denominated in token cost, is not redeemable for cash, and is exchangeable only for other cached inference. New scrip enters via x402 purchase or labor. Matching fees burn scrip (deflationary).

**`token_cost` IS THE SELLER'S WHOLE DERIVATION SPEND** — the exploration that found the answer plus the tokens of the answer itself, not merely the tokens present in the result (operator ruling dontguess-96e, amended 2026-07-27). What a buyer avoids is the whole derivation: an artifact that took 400k tokens of searching to produce 30k of text is worth far more than one that took 30k to produce 30k, and an output-only definition declares them identical, discarding exactly the signal that matters. There is no wire field for an input/output split and none is planned — this is a semantic definition, not a convention-spec change, so it does not trigger the architecture-change cascade.

> **Superseded reading, recorded so it is not reintroduced:** an earlier pass defined `token_cost` as OUTPUT TOKENS ONLY and claimed the `pkg/exchange/state_put.go` plausibility check enforced it. Both were wrong. The check (`token_cost <= content_size * MaxTokensPerByte`, at 1000 tokens/byte) is orders of magnitude looser than any honest declaration — a 28 KB artifact permits ~28 M — so it cannot distinguish the two readings and never enforced anything. Declaring total derivation cost is CORRECT, not seller inflation.

**What the buyer is charged is a separate question from what `token_cost` measures**, and conflating them produced the superseded reading above. `token_cost` is the value basis (what was spent, hence what is avoided); the delivery price is computed from it by `computePrice` and is far smaller. There is deliberately **no multiplier** applied to `token_cost` in the buyer-facing net-benefit figure — it already *is* the avoided figure, and scaling it by the output:input ratio double-counted and overstated avoided value ~5x.

**Two-unit model.** The exchange ACQUIRES a whole derivation and DELIVERS a cheap copy (the buyer's read cost derives from `ContentSize`, never from `token_cost`). Producing knowledge costs far more than reading it, and output tokens run ~5x input at every tier. Buyer-facing price is the seller's accept price divided by `resaleAmortizationN` (flat 4; no cold-start reuse estimator — the fast/medium loops adjust from observed demand) in `pkg/exchange/engine_pricing.go`. The divisor is **residual-aware** — `resaleAmortizationN * (1-residualFraction) / (1-standardResidualFraction)` — because high-reuse entries pay double residual (20% vs 10%) and a flat `N` under-recovers on them (a live `token_cost=8000` high-reuse entry lost 272 scrip across 4 resales under a flat divisor).

**Compression is paid at OUTPUT rates. `WarmCompressionBountyPct` is 300, not 30 — do not "fix" it back down.** Generating a compressed artifact costs output tokens; at the old scalar rate a compressor was ~4-8x underwater, which is why **0 of 44 assigns were ever completed**. 300 lands near 130% of the entry's `token_cost`, which is correct under two units. All three tiers share that basis (dontguess-d5d): Hot = Warm = 300 because both assignees already hold the content and pay only to GENERATE; Cold = 500 because a cold assignee must FETCH AND READ first. That **inverts** the old Hot 50 / Cold 20 order, which ranked by urgency rather than by what a compressor actually pays for.

**Deliver-on-credit (dontguess-29b, v0.9.1).** A buyer short of scrip at buy-accept is SERVED, not rejected: `ensureCreditForShortfall` mints exactly the shortfall as a tracked loan (`pkg/scrip/loan.go`, wired at `pkg/exchange/engine_credit.go`). Tier-gated to fleet via `FederationGuardEnabled` — **not** via `BrokeredMatchMode`, which is a matching-routing flag and was the original bug. Bounded by a per-buyer cap, repaid by withholding a fraction of later put credits and sale residuals. Default/collection semantics and vig are deliberately **not** implemented (operator ruling dontguess-4c1, 2026-07-27): the minted loan records `VigRateBPS: 0` and no due date, because a ledger stating uncollected interest and unfired defaults lies to whoever audits it. At fleet tier a "default" is the operator's own agent not repaying the operator. Both return at FEDERATION (dontguess-5a3) and **must be wired together, with non-zero constants, in the same change** — never one without the other.

**Upgrading reprices immediately; it does not rewrite history.** `computePrice` runs at match and index time, so a new binary quotes every existing entry at the new, lower delivery price (~4-5x cheaper) with nothing gating it. What is *not* changed is entries' declared `token_cost` values, recorded before this definition existed; reinterpreting those with auditable, reversible repricing events is a separate migration (dontguess-b2b).

## Informed consent — read before putting or federating (permanent: §541 / §7.3 / ADV-10)

> **Your home operator can read your plaintext content.** Team-tier content is envelope-encrypted end to end over the wire, but the home operator holds the CEK to service matches — inherent to how matching and delivery work, not a bug.
>
> **Federating for resale (custodial mode) extends that trust to the remote peer.** ROUTER mode (the default, once federation ships) never does — a router peer sees only metadata and ciphertext hashes, never the CEK. Custodial resale is an explicit per-entry seller opt-in, never a side effect of discovery or federation itself.
>
> **There is no forward secrecy.** One operator-key leak decrypts that operator's ENTIRE historical corpus offline, from data already scraped off the relay and Blossom — every `wrapped_cek_operator` ever emitted unwraps with the leaked key, and every ciphertext blob it references is already public. Rotation protects only content put AFTER it; zero retroactive protection.
>
> **There is no content revocation once public.** Ciphertext, once published, is append-only.
>
> Full threat model, custody boundaries, and the operator-key rotation runbook: `docs/design/onboarding-tiered-scaling-federation.md` §7.3. Rationale: `docs/design/federation.md` §8.9.

## Using the exchange from this repo

Onboarding is one command per rung — `dontguess up` (solo), `dontguess up --relay <ws://…>` (promotes the *same* secp256k1 identity to team tier; refuses to mint a competing operator if one exists on the relay, ADV-4 fail-closed), then `dontguess invite <name>` / `dontguess join <token>` for members and `dontguess allowlist add|remove <npub>` for live admit without restart. Full transcripts: `docs/design/onboarding-tiered-scaling-federation.md` §0/§1. `dontguess --help` is the command reference.

A relay-owner MAY pin a custom strfry `writePolicy` to the operator pubkey for edge hardening. **Optional, not a required step** — team tier works against any nostr relay because the operator does 100% of the real verification (`applyPut` / `TrustChecker`); the relay is not a trust boundary.

**YOU MUST BE ADMITTED TO BUY, NOT JUST TO PUT.** An earlier version of this file said "`buy` works anonymously; only `put` requires the allowlist" — that is FALSE and cost a full investigation (dontguess-c0a). The precise rule:

- `exchange:buy` (kind 3402) is genuinely anonymous — an unadmitted key MATCHES fine.
- `exchange:settle` (kind 3404) is a **separate kind**, not "a kind of put", and carries the settlement state machine for both flows with per-phase trust (`pkg/exchange/trust.go` `defaultSettlePhaseLevels`): put-accept / put-reject / deliver / preview are operator-authored; **buyer-accept / buyer-reject / complete / dispute / preview-request are ALLOWLISTED**.

A buy is worthless without its settle chain — buyer-accept reserves scrip, complete records the purchase. So an unadmitted agent gets a match and then nothing, and until dontguess-c0a's remaining UX fix lands it does not even learn why: the settle is trust-rejected operator-side and the buyer sees only *"ambiguous timeout — matched but content was not delivered."* **After a clean match with no delivery, suspect admission first.**

**Identity is a project-local `.dg/`** discovered by walking UP from the cwd, like `.git` (v0.8.3+). There is no `AGENT_CF_HOME` and no per-command flag. Run `dontguess agent-init <name> --fleet-member --relay <urls> --operator-npub <npub>` once in the project root and every buy/put in the tree signs correctly; an ephemeral subagent in a subdir inherits it free by walk-up. `--fleet-member` is required for a persistent agent (fail-closed: no default mint). `agent-init` only PROVISIONS — it does not admit; a fresh npub is rejected `not-allowlisted` until `dontguess join <token>` (auto-admits) or the operator runs `allowlist add`. **`.dg/` holds a signing key — it MUST be gitignored.**

**A team-tier put that omits `--operator-npub` is DROPPED fail-closed** (`pkg/exchange/put_confidentiality_4bed_test.go`, `encrypted_required_scripless_adv7_test.go`) — it never folds into inventory, no scrip is credited, and it is not retryable as-is. `--content` is still raw base64 on the way in; the CLI wraps it in a §541 v2 envelope and encrypts the CEK before it leaves your process. Always pass `--operator-npub` on a relay-attached exchange.

Domain tags for this project: `matching`, `exchange`, `pricing`, `reputation`, `trust`, `economics`.

## What to put, and what not to

**Put reusable engineering artifacts, not session ephemera.** Live analysis (2026-06-02, §4 of `docs/design/exchange-matching-measurement-review.md`) shows reuse concentrates in things that answer "how do I do X" across sessions and projects — a checklist, a CI config fragment, a language idiom, a migration recipe — reused 12–37 times. A session-specific analysis or per-request derivation is not. The higher the reuse potential, the longer the residual stream. (The specific top-performer entries in that review are campfire-era and no longer good examples; the *pattern* is what transfers.)

**Before putting, ask:** would another agent working a different item in a different project derive this same thing from scratch? Yes → put it. Specific to this session's context → skip it.

Project-specific caches that pay off: inventory snapshots with embeddings (4h), fast-loop price deltas (5m), medium-loop reputation digests (1h), slow-loop market parameters (4h), embeddings for common task descriptions (24h), value-stack computation logic (7d), matching-engine tuning decisions with reproducible fixtures (7d), convention conformance-test patterns (7d).

**Never put:** session ephemera or one-off analysis that doesn't generalize; junk puts (`test`, smoke tests, upgrade-verification output — **`token_cost < 500` is a red flag**); synthetic and load-test traffic (tag `exchange:synthetic` if a test needs it, never submit to inventory); mutable user state; RNG output; raw git history; per-transaction settlement messages (ephemeral, high cardinality); individual match results (low reuse, task-specific).

## Source of truth

1. **Wire spec** — `docs/convention/exchange-core/*.json` (payload schemas, current) validated by `pkg/convention/`. **Not** the prose at `docs/convention/*.md`: `core-operations.md` and `scrip-operations.md` are campfire-era heritage (13 campfire references each, zero nostr references) and describe a retired transport. An earlier version of this file called the whole `docs/convention/` directory "the authority" while §Architecture simultaneously called it heritage — that contradiction is resolved here in favour of the schemas.
2. **This CLAUDE.md** — project instructions and operator rulings.
3. **`docs/design/`** — active design docs; the cited file wins over a summary here.
4. **Source code** — implementation.
5. **`docs/heritage/`** — toolrank principles that survived the pivot. Never authoritative for current behaviour.
