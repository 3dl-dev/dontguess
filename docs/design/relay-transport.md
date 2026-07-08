<!-- source: adversarial-design Workflow (campfire-free); rd dontguess-f58 -->

# M2 Relay Transport — Build-Ready Design

Status: RULED. Feeds a follow-on swarm. Supersedes the `pollLocalStore` M2 scope-note
in `pkg/exchange/engine_core.go` and the `NewLocalScripStore` escrow-timeout TODO in
`pkg/scrip/relay_store.go`.

This document specifies how the exchange engine PUBLISHES and SUBSCRIBES exchange events
(put/buy/match/settle/assign kinds 3401–3405, scrip 3411, inventory projection 30401
addressable) over a SINGLE live NIP-42-authed relay at team tier, and rules on open
questions A–F. It resolves or explicitly constrains all 14 adversary attacks.

The four disposition analyses converge on one architecture, stated three ways:
the domain-purist's **sequencer-at-the-ingest-boundary (F2)**, the creative's
**fold-log sandwich (CRE-1..4)**, and the systems-pragmatist's **new `pkg/relay`
behind `LocalStore`**. The adversary's 14 attacks are the acceptance checklist, not a
veto: every one is closed by putting the sequencer UPSTREAM of the store rather than
inside a fold path, or is recorded below as a permanent constraint with a monitored
mitigation.

---

## 0. Locked invariants (design AROUND — held, not relitigated)

1. **Relay reads are async cache-warming; NEVER on the hot path of a buy or match.**
   The buy/match RESPONSE (semantic ANN search + return, <50 ms p99) reads the operator's
   local match index and `State` only. No relay round-trip, no orphan-buffer wait, ever sits
   inside a buy response.
2. **Operator is the SOLE authoritative sequencer per domain.** Relay ingest order is NOT
   fold order. A local monotonic sequence number assigned at operator ingest IS fold order.
3. **Team = ONE NIP-42-authed relay.** Relay = durable event log (RF≈2 replica); the
   operator's local fold = authoritative order + RF≈1 primary. On any divergence, **the local
   fold wins for ORDER and is the source of truth**; the relay is durability, never authority.
4. **Embeddings never on the wire.** Big content via Blossom pointer + verify-on-fetch.
   `pkg/nostr.ToNostrEvent` already never emits a vector and rejects kind 30401 on read.
5. **Loud degradation on every relay read/publish/reconnect failure** (dontguess-553 lesson).
   Every drop, rejection, orphan-timeout, and publish failure is COUNTED and ALARMED — never a
   silent `nil` return.

---

## 1. Rulings on the open questions A–F

### A. Publish path — RULING: fold-then-publish via a crash-durable outbox; local is unconditionally source of truth.

Operator egress in relay mode does **not** use the campfire `WriteClient.Send`
publish-then-mirror path (that path publishes to the relay FIRST and mirrors to the local
fold SECOND — ADV-2's torn window, writing the source of truth second). Instead M2 runs the
engine with `WriteClient == nil, LocalStore != nil`, so `sendOperatorMessage` routes to
`sendLocalOperatorMessage` → `appendLocalRecord`. The commit is:

1. `appendLocalRecord`: append to `LocalStore` (durable fsync) + fold into `State` +
   `Sequencer.MarkEmitted(id)` (see D/echo). This is the commit. **Local is now source of
   truth. RF=1 achieved synchronously.**
2. The **Outbox** (§2 Publish path) tails the same fsynced log, sees the new `Origin=local`
   record, publishes an `["EVENT", ev]` frame, and advances a crash-durable publish cursor
   only on relay `OK`. **RF=2 achieved asynchronously, off the hot path.**
3. On publish failure: loud-log + retry with backoff from the durable cursor. The record is
   already locally durable; the relay is behind, not divergent.

There is no "published-but-not-folded" state (publish is strictly AFTER local fold), which is
exactly why ADV-3's echo-vs-recovery contradiction dissolves: the operator never has a
relay-only event it must re-fetch. **Sync-on-relay-ack is a HARD REJECT** — it puts a network
round-trip on the write path (violates LOCKED-1) and makes relay ack the gate on fold progress
(inverts LOCKED-2).

### B. Subscribe + backfill — RULING: relay reads feed the Sequencer, never `State.Apply` directly, never the buy-response path.

Startup backfill and the live subscription both deliver into `Sequencer.Ingest`, NOT into
`State.Apply` and NOT into `LocalStore` directly. The Sequencer releases causally-ready events
in canonical order; the Intake appends ONLY released events to `LocalStore`; the existing
`pollLocalStore` loop then folds+dispatches the new tail. This is background cache-warming of
the operator's own local fold; the matcher never reads the relay. `since/until` cursors are a
coarse FETCH HINT only — correctness comes from causal closure + id-dedup, not from the
timestamp (see ADV-9 ruling). Startup: `REQ since=(local high-water − slack)`; feed all results
through Intake; `Seal` once the bounded catch-up EOSEs to fail loud on an already-broken history
chain (per-chain quarantine, not a boot brick — see ADV-8).

### C. Reconnection + gap recovery — RULING: re-run backfill from the durable high-water mark with overlap; dedup absorbs the overlap; causal gaps are re-fetched by e-tag; unrecoverable = loud.

Reconnect is backfill invoked a second time — not a distinct state machine. Re-issue
`REQ since=(watermark − slack)`; every event flows through `Sequencer.Ingest`, whose
dedup-by-id makes the overlap free. A folded event referencing an unreleased antecedent is held
in the orphan buffer; the **orphan-age watchdog** (§2) issues ONE targeted `REQ` by the missing
e-tag id; if that also comes back empty the chain is **quarantined with a loud
`ErrUnrecoverableAntecedent`-shaped alert** for that chain only — every other chain keeps
draining. Recovery NEVER replays scrip deltas onto live balances: the scrip store re-derives by
`Replay()` (reset-and-refold) from the canonical `LocalStore`, so reconnect cannot reopen the
double-spend window (§E). The double-spend window stays closed because the log it re-derives
from is canonical-by-construction (§F).

### D. Delivery semantics — RULING: `Sequencer` dedup-by-event-id is sufficient for honest at-least-once, on BOTH legs. Non-dup re-signing is an operator-key discipline invariant, not a transport guarantee.

Nostr event id is the content hash, so relay redelivery is a true byte-duplicate absorbed by
`Sequencer.Ingest` (emitted+buffered id sets). On the WRITE leg, publish-timeout retries resend
the identical signed event → identical id → relay re-ACKs `OK` (no write-side dedup needed).
The residual — a *re-signed* logical duplicate (same op, new `created_at` → new id) — is NOT a
relay problem: for operator-authored kinds it is single-writer discipline (an honest operator
never re-signs a mint/settle); for foreign kinds it is caught by the operator-key re-verify at
Intake (§E, ADV-14). Document this boundary; do not try to make the transport idempotent against
re-signing.

### E. Scrip over relay — RULING: 3411 rides the SAME single operator sequence; balances are mutated live by exactly ONE writer (the engine's synchronous ETag-guarded `SpendingStore` calls); 3411 events are durability/replay records only and are NEVER live-folded.

Two facts close A3/A9 concretely for the single-relay team case:

- **All 3411 events are operator-authored** (the operator is the only party that mints, holds,
  settles, pays, burns). `relay_store.go` already rejects non-operator senders. Therefore no
  scrip-balance mutation is ever causally-concurrent with another — the operator emits them in a
  definite total order.
- **There is exactly one live balance writer.** Today the engine mutates balances via direct
  `DecrementBudget/AddBudget/ConsumeReservation` (synchronous, `gen`-ETag-guarded, at decision
  time) and *also* emits a 3411 message for durability. The 3411 message is folded ONLY by
  `CampfireScripStore.Replay()` on cold rebuild — never by a live `ApplyMessage`. **M2 keeps
  this: relay-ingested 3411 events are NOT wired into `ScripStore.ApplyMessage`.** They land in
  `LocalStore` (operator appended them; the relay echo is deduped) and are re-folded in Seq order
  on the next `Replay()`. This is the single-deterministic-writer replay the `gen` ETag depends
  on (LOCKED-2), now guaranteed because `LocalStore` is canonical-by-construction (§F).

MUST-ENFORCE (build guards): (1) the operator's emitted-event timestamp source is
**monotonic non-decreasing** so `(Timestamp,ID)` batch order reproduces emission order on a
Seq-less DR rebuild; (2) fix `performScripSettlement` to **emit-durable-then-mutate** (it
currently mutates in-memory first, then emits — ADV-12), matching the correct ordering
`handleDeadlineMissRefund` already uses; (3) move the reservation-already-consumed idempotency
check BEFORE `emitConsumeSignal` (ADV-7 defense-in-depth). These are code fixes, not
architecture — see Build outcomes.

### F. The seam — RULING: NEW `pkg/relay` package that SANDWICHES `LocalStore`; the Sequencer sits at the INGEST boundary (F2), NOT inside `pollLocalStore` (F1). `SpendingStore` and `proto.Message` signatures are byte-identical.

The scope-note's "`pollLocalStore` needs the same sequencing seam" is satisfied WITHOUT touching
`pollLocalStore`: everything WRITTEN to `LocalStore` is already sequenced, so `pollLocalStore`'s
length-cursor (dontguess-b84/-90d discipline) stays correct by construction and unchanged. F1
(sequencer inside the poll path) is rejected — the purist scorecard (P12) rates it PARTIAL: it
leaves the scrip store a second un-sequenced fold authority and exposes an incremental-vs-batch
`Drain` determinism divergence. F2 makes ONE order authority (the Intake sequencer) feed ONE
canonical store that the engine fold, the live poll, AND the scrip store all read unchanged.

---

## 2. Component / seam design

### 2.1 Package layout

```
pkg/relay/                       # NEW. ~500–700 LOC + ~400–600 test LOC.
  conn.go        # websocket lifecycle: dial, NIP-42 handshake (reuse identity.ClientAuthenticate),
                 #   reconnect/backoff. A *websocket.Conn already satisfies identity.FrameConn.
  frames.go      # NIP-01 codec: REQ / EVENT / EOSE / CLOSE / OK / NOTICE encode+parse.
  intake.go      # SUBSCRIBE leg: recv EVENT -> operator-key ACL filter -> nostr.FromNostrEvent
                 #   -> Sequencer.Ingest -> Drain -> LocalStore.BatchAppend (Origin=relay, Seq set).
  outbox.go      # PUBLISH leg: tail LocalStore -> skip Origin=relay -> nostr.ToNostrEvent -> sign
                 #   -> EVENT frame -> advance durable publish cursor on OK.
  watchdog.go    # orphan-age watchdog: targeted REQ-by-e-tag; loud per-chain quarantine.
  metrics.go     # counters: dropped_forged, provenance_rejected, orphan_pending, orphan_unrecoverable,
                 #   publish_retry, publish_lag, resync_mismatch.

pkg/nostr/       # UNCHANGED. ToNostrEvent/FromNostrEvent already lossless over proto.Message.
pkg/identity/    # UNCHANGED. ClientAuthenticate + FrameConn + secp256k1 sign/verify already exist.
pkg/exchange/    # sequencer.go UNCHANGED. engine_core.go: additive OnOperatorEmit hook only (below).
pkg/scrip/       # relay_store.go UNCHANGED (already reads LocalStore in fold order).
pkg/store/       # additive: Record.Origin, Record.Seq fields; BatchAppend([]Record) (one fsync).
```

Additive-only changes outside `pkg/relay`:

- `pkg/store.Record`: add `Origin string` (`""`/`"local"` = operator-authored, `"relay"` =
  ingested) and `Seq int64` (operator-assigned monotonic fold order, persisted). Both JSON
  fields with `omitempty`; `ToMessage` ignores them (no `proto.Message` change).
- `pkg/store.Store`: add `BatchAppend(recs []Record) error` — appends N records under one store-mutex
  hold and ONE fsync (ADV-11 backfill-storm mitigation). Single-writer append-order preserved.
- `pkg/exchange.EngineOptions`: add `OnOperatorEmit func(ids ...string)`. `appendLocalRecord`
  calls it after a successful append. `pkg/relay` wires it to `Sequencer.MarkEmitted` so the
  operator's own events dedup against their relay echo (§D). Nil = today's behavior exactly.

No signature of `scrip.SpendingStore` or `proto.Message` changes — confirmed against
`spending_store.go` and `pkg/store/store.go`.

### 2.2 The single per-domain Sequencer (already merged; wired at the boundary)

`pkg/relay` owns ONE long-lived `*exchange.Sequencer` per operator-domain, fed EVERY kind
(3401–3405 AND 3411) together. Rationale (creative CRE-2b): a 3411 buy-hold e-tags the 3402/3403
that triggered it; a per-kind sequencer would strand it in a different orphan buffer than the one
holding its antecedent, permanently. One sequencer, all kinds, is why scrip "rides the same
sequence" for free.

On startup the sequencer is **seeded**: `Replay()` the existing `LocalStore`,
`Sequencer.MarkEmitted(all existing ids)`, set the fetch watermark to `max(Timestamp)`. The log
is its own checkpoint — no separate checkpoint store (creative CRE-4).

### 2.3 Publish path (Outbox)

- Durable cursor: a one-line fsynced sidecar next to the log recording the count of
  `Origin=local` records published+ACKed. Same atomic-write discipline as `store.Append`.
- Each tick (and on new-local-append signal): `Replay()`; skip records at/below the cursor; skip
  `Origin=relay` (this is what prevents relay ping-pong — no separate dedup structure needed);
  for each remaining `Origin=local` record: `nostr.ToNostrEvent` → sign (secp256k1) → `EVENT`
  frame → await `OK`; advance cursor.
- Publish failure: loud-log, increment `publish_retry`, retry with backoff. Never blocks the
  engine. `publish_lag = log_len(local) − cursor` is exported and alarmed above a threshold
  (RF has dropped to 1 for those events — the exact case relay durability exists for).
- Crash between local-fold and publish: cursor < log length; on restart the Outbox resumes from
  the durable cursor and republishes. Content-hash id ⇒ idempotent ⇒ relay re-ACKs. RF restored,
  no divergence (ADV-2 closed).

### 2.4 Subscribe / backfill / live path (Intake)

For every received `["EVENT", ev]`:

1. **Operator-key ACL filter (pre-Ingest, ADV-14/CRE-6).** If `ev.kind` implies operator-only
   authorship (3403 match, 3404 settle, 3405 assign operator sub-ops, 3411 scrip) and
   `ev.pubkey != operator npub` **or the schnorr signature fails `identity.Verify`**, DROP before
   the fold, increment `dropped_forged`, alarm. A dumb relay will not enforce this; the reader
   must. This is the transport's (kind, pubkey, signature) gate — the deeper web-of-trust is the
   separate provenance workstream (explicit boundary, not smuggled into M2).
2. `nostr.FromNostrEvent(ev)` → `proto.Message`. (Rejects kind 30401 — the projection is never
   folded as source of truth.)
3. `Sequencer.Ingest(msg)` — dedup-by-id absorbs at-least-once + echo + reconnect overlap.
4. `Sequencer.Drain()` — release causally-ready events in canonical order, each stamped with the
   next monotonic `Seq`.
5. `LocalStore.BatchAppend(released with Origin="relay", Seq=<assigned>)` — one fsync per drained
   batch. Orphans stay in the sequencer's in-memory buffer and **NEVER touch the store**.
6. The existing `pollLocalStore` loop, on its next tick, folds+dispatches the new canonical tail
   via its unchanged length cursor. Foreign buys get matched; foreign settles reconstruct
   `matchToReservation` through the normal `handleSettleBuyerAcceptScrip` dispatch (ADV-4 closed —
   we do NOT "fold-only" the settle; we dispatch it through the operator's normal work loop, which
   is off the buy-RESPONSE hot path but is where matches/settles are supposed to be processed).

Intake writes to `LocalStore` via the store mutex only; it does NOT take the engine's `localMu`.
Foreign records have no emitter-side `State.Apply`, so there is no double-apply hazard
(dontguess-90d applies only to operator records the emitter also applies) — the poll loop folds
them exactly once via the cursor. This also keeps the ingest write path off `localMu`, so a
backfill storm cannot serialize behind the buy/match dispatch lock (ADV-11 mitigation, combined
with `BatchAppend`'s single fsync).

### 2.5 Reconnection / gap recovery

- Live disconnect detected → loud-log, `intake_disconnected` alarm, backoff-reconnect.
- On reconnect: `REQ since=(watermark − slack)`. `slack` covers clock skew + a generous
  reconnect window; correctness does not depend on it being exact (dedup absorbs overlap).
- Causal gap (orphan referencing an unreleased antecedent): watchdog issues one targeted
  `REQ ["ids", <antecedent>]`. If empty → per-chain quarantine + loud alert. Bounded orphan
  buffer (`DefaultMaxOrphans` ≈ 1000) fails loud on overflow (`ErrOrphanBufferOverflow`) — a DoS
  and a correctness hazard, surfaced not swallowed.
- Periodic full-resync audit (`REQ since=0`, low cadence): diff the relay id-set against the
  local id-set; any local-only operator event that the relay lacks → re-publish (Outbox
  catch-up); any relay event the local lacks and cannot fetch → loud `resync_mismatch`. This is
  the backstop for ADV-9's unreferenced-far-past-root miss (a cache-warm gap, not a money bug).

### 2.6 The `pollLocalStore` → sequencer seam (the scope-note, resolved)

UNCHANGED. The scope-note is discharged by the F2 ruling: the sequencer is upstream of the store,
so `pollLocalStore`'s premise "append order == fold order" is restored as a construction
guarantee rather than a single-writer accident. The only engine touch is the additive
`OnOperatorEmit` hook. This deliberately preserves every dontguess-b84/-90d cursor fix verbatim.

---

## 3. Failure / degradation model (LOCKED-5)

| Failure | Detection | Response | Alarm counter |
|---|---|---|---|
| Relay unreachable / handshake fail | dial/`ClientAuthenticate` error | backoff-reconnect; operator keeps serving from local fold (RF=1) | `intake_disconnected` |
| Publish `OK=false` / timeout | Outbox await | retry from durable cursor; RF stays 1 for lagging events | `publish_retry`, `publish_lag` |
| Redelivered / echoed event | `Sequencer.Ingest` dedup | no-op | (silent by design; deduped count optional) |
| Forged operator-kind event | Intake ACL + sig verify | DROP pre-fold | `dropped_forged` |
| Provenance-rejected op | existing gate (now counted) | DROP; **replace silent `nil` return with a counted alarm** | `provenance_rejected` |
| Orphan antecedent (recoverable) | orphan buffer | targeted re-fetch by e-tag | `orphan_pending` |
| Orphan antecedent (pruned/unrecoverable) | watchdog timeout / `Seal` | per-chain quarantine, chain's dependents stall (correct) | `orphan_unrecoverable` |
| Orphan buffer overflow | `Drain` returns `ErrOrphanBufferOverflow` | stop ingest, alarm, operator investigates | `orphan_overflow` |
| Crash between fold and publish | Outbox cursor < log len on restart | resume publish (idempotent) | — |
| Local/relay id-set drift | periodic resync audit | re-publish local-only; alarm relay-only-unfetchable | `resync_mismatch` |

Degradation is always toward "operator serves correct results from its local fold with the relay
behind," never toward "silently wrong." The buy hit path is unaffected by every row above.

---

## 4. Adversary attack disposition

| # | Attack | Disposition |
|---|---|---|
| ADV-1 | Sequencer only in startup replay; live path length-cursor + no id-dedup | **RESOLVED.** Sequencer at ingest boundary; only sequenced, deduped, canonical events reach the store; poll cursor valid by construction (§F). |
| ADV-2 | Publish/fold non-atomic, no outbox | **RESOLVED.** Fold-then-publish; crash-durable Outbox cursor; idempotent republish (§2.3, §A). |
| ADV-3 | Echo-suppress vs crash-recovery contradiction | **RESOLVED.** Local is always folded-before-published ⇒ no relay-only operator events to recover; `MarkEmitted` handles echo, Outbox cursor handles crash — orthogonal (§A/§D). |
| ADV-4 | `matchToReservation` rebuilt only on dispatch; backfilled settle burns scrip | **RESOLVED.** Ingested settles are DISPATCHED through the normal poll loop (not fold-only), reconstructing the reservation index; exactly-once via id-dedup + cursor (§2.4). |
| ADV-5 | Scrip store un-sequenced; reorder mints from nothing | **RESOLVED.** 3411 rides the one sequence; scrip store never live-folds relay events; `Replay()` in canonical Seq order (§E). |
| ADV-6 | Two scrip writers (direct mutation + fold) double-credit | **RESOLVED.** Single live writer = engine's synchronous ETag-guarded calls; 3411 = durability/replay-only, never live-folded (§E). |
| ADV-7 | `emitConsumeSignal` before idempotency check double-counts | **RESOLVED** (exactly-once dispatch) + **HARDENED** (move consumed-check before emit — Build outcome). |
| ADV-8 | Poison antecedent bricks boot | **RESOLVED.** Orphans never persist to the store; boot reads a canonical store with no re-Seal; DR-backfill quarantines the one broken chain (watchdog), never bricks (§C, §2.5). |
| ADV-9 | `created_at` cursor unsound | **RESOLVED for money; CONSTRAINT for cache-warm.** Cursor is a fetch hint only; correctness via causal closure + id-dedup; residual unreferenced-far-past-root miss is a cache gap caught by the resync audit, not a scrip bug (§B, §2.5). |
| ADV-10 | Live-vs-restart order divergence; wall-clock in fold | **RESOLVED.** Persist `Seq`; restart reads stored Seq order (no re-sequence, no divergence). Wall-clock handlers: see CONSTRAINT below + Build outcome to derive session/expiry windows from event timestamps. |
| ADV-11 | Ingest write contends buy/match `localMu`+fsync | **MITIGATED (monitored constraint).** Intake off `localMu`; `BatchAppend` one fsync per batch. Residual: operator match-EMIT append still fsyncs under `localMu`; match COMPUTATION is lock-free. Monitor `dispatch_lock_wait`; if it regresses, split the outbox/intake into a separate store segment. |
| ADV-12 | Scrip emit-failure swallowed after in-memory mutate | **RESOLVED (Build outcome).** Reorder `performScripSettlement` to emit-durable-then-mutate (like `handleDeadlineMissRefund`); emit failure is loud + retried via Outbox. |
| ADV-13 | Attacker controls `(Timestamp,ID)` sort keys for foreign events | **CONSTRAINT (neutralized at team tier).** NIP-42 allowlist bounds authorship to fleet; foreign kinds are only put/buy; every order-sensitive money/authority decision (assign first-writer, Vickrey close) is resolved by the operator's single-writer emission, not by foreign relative order. Enforce `dg_ts` always emitted so ties never mass-collapse to grindable ids. |
| ADV-14 | Silent provenance/forgery drops; match absent from dispatch switch | **RESOLVED.** Intake operator-key ACL + schnorr re-verify pre-fold; all drops counted+alarmed; no relay-ingested event claiming operator authorship reaches a state mutation without verification (§2.4, §3). |

Permanent constraints (cannot be engineered to zero, only bounded):
**ADV-11** (fsync/lock coupling on operator emit — monitored), **ADV-13** (foreign tie-break is
biasable — neutralized by allowlist + operator-authored resolution), and the **ADV-9 cache-warm
residual** (bounded-window backfill can miss an unreferenced far-past root — audited, not
money-affecting).

---

## 5. Determinism & double-spend argument (what the test strategy must PROVE)

Claim 1 — **Fold-order stability.** The operator-assigned `Seq`, persisted with each record, is
the authoritative fold order (LOCKED-2). Restart reads records in stored Seq order and does NOT
re-sequence, so pre- and post-restart state are identical (closes ADV-10 restart divergence).

Claim 2 — **Batch determinism for recovery/audit.** `SequenceForFold` over a causally-CLOSED set
is a pure function of the set and its antecedent DAG (canonical `(Timestamp,ID)` linear
extension). A full re-fold — the DR-rebuild-from-relay path and the audit path — is byte-identical
across any permutation/duplication of a closed set.

Claim 3 — **Incremental ≠ batch only for causally-CONCURRENT independent roots, which carry no
money.** Live `Drain` may release two causally-concurrent foreign roots (independent puts/buys) in
an order a from-scratch batch would invert. This NEVER touches the double-spend guard: every
scrip-balance mutation is operator-authored and totally ordered by the operator's own emission
(§E), so no two balance mutations are concurrent. Terminal Layer-0..4 state is invariant because
independent concurrent events commute on terminal state. Any handler that is order-sensitive among
concurrent events must tie-break on a reproducible in-event key — enforced by test.

Claim 4 — **Double-spend guard survives.** The `gen` ETag needs one deterministic replay order per
domain. It has exactly that: the persisted Seq order (live/restart) and the canonical batch order
(DR/audit), both single-writer for all scrip. `ConsumeReservation` is atomic; balances cannot go
negative in live mode; redelivery is deduped; the scrip store never live-folds relay echoes.

### Test strategy (proves the above under reorder / redelivery / reconnect)

Property and scenario tests, each mapped to the attack it closes. All run against the real
`Sequencer` + `LocalStore` + engine fold + `NewLocalScripStore` — no mocks at the fold boundary.

1. **Reorder/dedup determinism (Claim 2, ADV-1/5/13).** Generate a causally-closed event set
   (puts, buys, matches, settles, scrip). For N random permutations WITH random duplicates fed
   through Intake, assert: terminal scrip balances, `totalSupply/totalBurned/totalLoanPrincipal`,
   and terminal exchange `State` are byte-identical across all permutations and equal to the batch
   `SequenceForFold` fold. Property test (extend `sequencer_property_test.go` precedent).
2. **No mint-from-nothing (Claim 4, ADV-5/6).** Invariant over every permutation: `Σ balances +
   totalBurned == totalMinted (+ loan principal accounting)`, and no balance < 0 in live mode.
   Include settle-delivered-before-its-buy-hold: assert the settle orphans until the buy-hold
   releases, then folds correctly — never underflow-drops the hold while landing the credit.
3. **Redelivery exactly-once side effects (ADV-4/7).** Deliver each settle(complete) 1..k times
   (at-least-once). Assert `emitConsumeSignal`'s durable consume count == number of distinct
   settle events (not deliveries), reservations consumed exactly once, buyer debited once, seller
   paid once.
4. **Reconnect with overlap (ADV-4/9, §C).** Run a workload; sever Intake at a random point;
   reconnect with `since=(watermark − slack)` (forcing overlap); compare final state to a
   no-disconnect control run — must be identical, with zero double-dispatch (consume counts,
   balances, reservation ledger all exact).
5. **Poison antecedent (ADV-8).** Inject an event with a dangling e-tag. Assert: (a) it never
   reaches `LocalStore` (stays in orphan buffer); (b) the operator boots normally on restart; (c)
   the watchdog re-fetches once, then quarantines that chain with a loud alert while other chains
   fold; (d) `orphan_overflow` fires on a 1001-orphan flood without corrupting folded state.
6. **Echo suppression (ADV-3/7).** Operator emits events; relay echoes them back; assert
   `MarkEmitted` dedups every echo — no scrip re-credit, no consume double-count, no duplicate
   `LocalStore` record.
7. **Crash between fold and publish (ADV-2).** Kill after `appendLocalRecord`, before Outbox ACK.
   On restart assert the Outbox resumes from the durable cursor and the relay eventually holds the
   event (idempotent republish), with local state unchanged.
8. **DR rebuild determinism (Claim 2).** Wipe `LocalStore`; backfill everything from the relay
   (`since=0`) through a fresh Sequencer; assert the rebuilt terminal state (balances + exchange
   State) equals the pre-wipe terminal state.
9. **Hot-path isolation (LOCKED-1, ADV-11).** Under a concurrent backfill storm, assert buy-match
   response p99 < 50 ms and that `BatchAppend` uses one fsync per drained batch; measure and bound
   `dispatch_lock_wait`.
10. **Acceptance gate (the done-condition).** The existing 32,209-LOC `pkg/exchange` suite AND the
    `pkg/scrip` suite pass UNCHANGED against the relay-fed `LocalStore`. A test needing a rewrite
    means the adapter changed semantics — a regression, not a migration.

---

## 6. Build outcomes

Outcome-scoped, one-session-sized items for the follow-on swarm. Each has a verifiable done
condition; sequential deps noted. Wire under a parent M2-relay-transport item.

1. **`pkg/store` carries operator order and batch-appends.** `Record` gains `Origin` and `Seq`
   (JSON `omitempty`, ignored by `ToMessage`); `Store.BatchAppend([]Record)` appends N records
   under one mutex hold + one fsync; `Replay()` returns records in stored order with `Origin/Seq`
   preserved. Existing `pkg/store` and `pkg/exchange`/`pkg/scrip` suites still pass. *(No deps.)*

2. **`pkg/relay` connects and authenticates to one relay.** `conn.go` dials a websocket, completes
   NIP-42 via `identity.ClientAuthenticate`, and reconnects with backoff on drop. A live-relay (or
   in-process fake-relay) integration test authenticates and survives a forced disconnect. *(No
   deps.)*

3. **`pkg/relay` frame codec round-trips NIP-01.** `frames.go` encodes/parses REQ, EVENT, EOSE,
   CLOSE, OK, NOTICE. Table-driven tests cover malformed frames (loud reject, never panic).
   *(No deps.)*

4. **Intake warms the local fold from the relay, sequenced and ACL-filtered.** `intake.go`:
   EVENT → operator-key ACL + schnorr verify → `FromNostrEvent` → `Sequencer.Ingest` → `Drain` →
   `BatchAppend(Origin="relay")`; orphans never persist. Property test #1 and #2 pass; forged
   operator-kind events are dropped and counted. *(Deps: 1, 2, 3.)*

5. **Outbox publishes operator events fold-then-publish with a durable cursor.** `outbox.go` tails
   `LocalStore`, skips `Origin="relay"`, publishes `Origin="local"` records, advances an fsynced
   cursor on OK, retries loud on failure. Crash-between-fold-and-publish test (#7) passes;
   `publish_lag` exported. *(Deps: 1, 2, 3.)*

6. **Operator echo dedup via `OnOperatorEmit`.** `EngineOptions.OnOperatorEmit` added;
   `appendLocalRecord` calls it; `pkg/relay` wires it to `Sequencer.MarkEmitted`. Echo test (#6)
   passes; nil hook reproduces today's behavior exactly. *(Deps: 4.)*

7. **Reconnect + orphan watchdog + resync audit.** `watchdog.go`: targeted e-tag re-fetch,
   per-chain quarantine on unrecoverable, periodic `since=0` id-set audit. Reconnect (#4) and
   poison-antecedent (#5) tests pass; `orphan_*` and `resync_mismatch` counters exported.
   *(Deps: 4.)*

8. **Scrip correctness fixes (emit-durable-then-mutate + monotonic clock + idempotency order).**
   Reorder `performScripSettlement` to emit-then-mutate; guarantee monotonic non-decreasing emitted
   timestamps; move the reservation-consumed check before `emitConsumeSignal`. `pkg/scrip` suite +
   property tests #2/#3 pass. *(No deps; can run parallel.)*

9. **Loud-degradation counters replace silent drops.** Provenance rejection and forgery drops become
   counted+alarmed (no bare `nil` return); metrics surface in the CLI/status path. Test asserts a
   forged-op probe increments the counter. *(Deps: 4.)*

10. **Wall-clock-in-fold audit (ADV-10 residual).** Enumerate fold-affecting `time.Now()` sites
    (`recordBuyerSettlement`, reservation `CreatedAt/ExpiresAt`, `stagePredictions` deadlines);
    derive each from the event's own timestamp (or document why replay-invariant). Determinism
    test #8 passes with no wall-clock dependence in terminal state. *(No deps; parallel.)*

11. **M2 wiring + acceptance gate.** `cmd/dontguess/serve.go` runs the engine with
    `WriteClient=nil, LocalStore set`, Intake+Outbox attached, one relay URL + allowlist. The full
    `pkg/exchange` (32,209 LOC) and `pkg/scrip` suites pass UNCHANGED; hot-path isolation test #9
    passes. *(Deps: 4, 5, 6, 7, 8.)*
