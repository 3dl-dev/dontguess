# Exchange Matching & Measurement Review — findings + fix structure

**Status:** findings, ready to plan
**Date:** 2026-06-02
**Source:** read of live exchange usage data (`dontguess match-results`/`buys`, `~/.cf/dontguess-attempts.log`) + matching code. All numbers below are from the live exchange `ed4b6d62…` on 2026-06-02.

---

## 1. Headline

The exchange's reported value is **inflated by a broken matcher**. The underlying value (real reusable entries + real unmet demand) is genuine, but the matching and measurement layers don't capture it. The reported **96.67% hit-rate and ~15M-token savings are largely false positives** and must not be quoted as proven until the fixes below land.

## 2. Evidence (reproducible)

Join every hit (`exchange:match` with `results[]`) back to its buy (`antecedents[0]`) and the entry it delivered:

- **Match quality fields are stubs:** across all **2,474 hits**, `confidence == 0.50` and `is_partial_match == false` — zero signal.
- **60% of real-agent buys matched a junk entry.** Of 2,237 resolvable non-synthetic buys, **1,344 (60%)** were served the `"test"` / `"upgrade smoke test cf v0.31.2 operator"` entry (`token_cost_original=100`). The pairings are semantically nonsensical:
  - `"RPT review of campfire SDK surface"` → `"upgrade smoke test cf v0.31.2 operator"`
  - `"fix convention.Server subscribe cursor"` → `"Legion EngineMetrics Phase 2.1 pattern"`
  - `"convention declaration revoke/supersede authorization"` → `"EventSink contract for warm-worker backends"`
- **Entry concentration:** 287 distinct entries served 2,474 hits; the single `"test"` entry served **1,576**.
- **Declared cost is unvalidated and outlier-driven:** `token_cost_original` sum by content_type = `other: 7.5M` (just **5 entries**, 1.5M each), `code: 5.66M`, `analysis: 2.15M`. Median per-hit cost = **100**.
- **Synthetic traffic pollutes metrics:** `regression-parallel-178949-*` / `regression-timeout-*` load-test buys and `"test"`-class puts are counted as real demand/inventory.
- **Single identity:** every buyer and seller key is `cd41913b` — the heritage "cross-agent convergence" trust signal (3+ distinct agents succeed with one entry) cannot be measured.

## 3. Root cause (code-grounded)

- `pkg/matching/embedding.go:4` — embedder is **TF-IDF bag-of-words (v0.1)**, NOT the all-MiniLM-L6-v2 384-dim model the architecture doc claims. Term-overlap, not semantics.
- `pkg/matching/ranking.go:220` — displayed `confidence = l2Quality` (the Layer-2 composite), **not** the raw cosine `Similarity` (which `ranking.go:12` does compute). So confidence pins ~0.5 and hides true relevance.
- `pkg/matching/engine.go:110` — a minimum-similarity threshold exists but is permissive enough that generic term overlap ("cf", "test", "operator") passes.
- `pkg/exchange/engine.go` composite ranking applies **freshness / novelty / discovery boosts** that can outrank Layer-1 relevance — a brand-new low-relevance entry (the smoke test) won ~1,576 matches. This violates the 4-layer stack's own rule that Layer-0/1 relevance gates everything above it.

## 4. What's genuinely valuable (the product is real)

- **Reused substantive entries** (the signal worth growing): `legion.tools v1.2 schema correctness checklist` (37 reuses), `cf-protocol README CF_NO_PINS` (30), `GateEvaluator conformance CI path filter` (19), `flock contention test pattern for Go` (16), `cf migrate-store --cf-home symlink bridge` (15). These are reusable engineering artifacts — the thing the exchange should optimize for.
- **Real unmet demand** (84 non-synthetic misses, each carries full `task` text + a 70%-rate standing offer). Clusters: `campfire (12), audit (9), convention (8), review (6), security/FROST threshold, test-gap scans`. Example: `"audit test suite for untested endpoints, missing error paths, edge case gaps … in ops/welcome-center-server, ops/justice-server …"`.

## 5. Fix structure (for /swarm-plan)

**Gate:** a fast diagnostic spike decides tune-vs-replace and a real threshold BEFORE any matching-fix code is written. The mechanical measurement/hygiene work and the miss-backlog run in parallel (no dependency on the spike).

### Track A — Matching core (gated by the diagnostic)
- **D1 (diagnostic spike, GATES A):** Read `pkg/matching/ranking.go` + `engine.go` actual composite weights. Build a fixture of ~20 real (buy task → ideal entry) pairs from the live log. Measure current top-1 relevance, then toggle (a) a hard cosine-similarity floor and (b) downweighted freshness/novelty. Output a written verdict: is the matcher fixable by **tuning** (threshold + weight rebalance) or does it need **embedding replacement** (TF-IDF → real vectors)? Recommend a concrete floor value. This verdict decides whether M1a or M1b runs.
- **M1a (tune) OR M1b (replace):** Either add a hard Layer-1 relevance floor + rebalance the composite so freshness/novelty/discovery can never outrank relevance (buy below floor ⇒ **miss**, not a junk hit); OR replace the TF-IDF embedder with real embeddings. One of these, chosen by D1. Done condition includes a test that the nonsense pairings in §2 become misses and the substantive reuses in §4 still match.

### Track B — Measurement plumbing (parallel, no gate)
- **M2:** Expose raw cosine `Similarity` as (or alongside) the delivered `confidence` field so hit quality is observable; thread it from `ranking.go` through `engine.go` into the match-result payload.
- **M3:** Tag synthetic traffic at ingest (`exchange:synthetic` for `regression-*`/`*timeout-178*`/`"test"`-class buys+puts) and exclude it from all metrics.
- **M4:** Validate/cap seller-declared `token_cost_original` at put time (sanity bound and/or derive-from-content-size); reject or flag implausible values (the 1.5M outliers).
- **M5:** Add a buyer consume/accept behavioral signal (did the buyer use a delivered candidate?) — the heritage behavioral signal that turns "hit" into "value." Design + capture path.
- **M-rebaseline (depends on M1+M2):** Update `dontguess hit-rate` (`pkg/exchange/hitrate.go`, shipped in dontguess-2d7a) to compute a **quality-weighted** hit-rate (hits ≥ relevance floor, synthetic excluded) and re-report the honest number.

### Track C — Inventory & value (parallel)
- **V1:** Turn the 84-task miss log into a stockable demand backlog/work queue (cluster by the §4 themes; surface the existing 70%-rate standing offers as assignable work).
- **V2:** Inventory hygiene — purge the `"test"`/smoke junk entries and add a put quality-gate (min `token_cost`, `content_hash` dedup, reject `"test"`-like descriptions).
- **V3:** Encourage the high-value put class (§4) over session ephemera — guidance/incentive in the put path or operator docs.
- **V4:** Distinct per-agent identities (instead of the shared `cd41913b`) to unlock cross-agent convergence measurement. Larger/architectural — size carefully.

### Adversarial-design reservation
Only escalate to adversarial-design if D1 reveals a genuine architecture fork (e.g., embedding replacement with real infra/cost trade-offs). The rest is well-diagnosed; plan and execute directly.
