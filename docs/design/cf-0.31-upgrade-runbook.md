# cf v0.17→v0.31 Reconciliation & Upgrade Runbook

**Status:** design / awaiting approval
**Date:** 2026-06-01
**Method:** adversarial-design (adversary + creative + systems-pragmatist + domain-purist), ground-truth verified on disk.
**Scope:** THIS machine (baron's primary). Not portfolio-wide.

<!-- design-campfire: cee9b2d50561882edf95325ace2e28a26b6e0edf1405c701db5e288bfe56b142 -->

---

## 0. Reframing — the premise was wrong

The task began as "upgrade cf v0.19.3 → v0.31.2." Ground-truth investigation overturned that. There is no single "cf version" on this machine — there are **three different things** conflated:

| Layer | What it actually is | State |
|---|---|---|
| **cf CLI on PATH** | `~/.local/bin/cf` → `~/projects/os/bin/cf` | A **v0.31.2 dev build** (`cf version dev`, git `v0.31.2-4-gfbb9e0cc`). Effectively already upgraded — just **untagged**. |
| **Vestigial cf binary** | `~/.local/lib/cf/cf` (`.version`=v0.19.3) | **Off PATH. Irrelevant.** Stale self-install. Source of the original misread. |
| **dontguess-operator** | `~/.local/bin/dontguess-operator` (long-running, PID since May 29) | Built against **campfire v0.17.0 SDK**. Writes **flat** layout. **This is the real laggard.** |

So the CLI "upgrade" is essentially done. The actual work is: **(a) reconcile a live mixed-layout store, (b) pin the CLI to a tagged release, (c) port the dontguess Go code/operator from the v0.17.0 SDK to v0.31.2.**

---

## 1. The real problems (ranked by urgency)

### P0 — The live exchange store is in an inconsistent mixed layout *now*
`~/.cf/transport/ed4b6d62…/messages/` holds **7,114 flat `.cbor` + 277 bucketed `.cbor`**. Flat files are still being written this minute (newest 19:48 today) by the v0.17.0-SDK operator; the 277 buckets were written ~May 17–27 by a bucket-aware (v0.31 dev) binary. Two writers, two layouts, one directory.

- `detectLayout` → `layoutInconsistent` → `cf migrate-store` returns `MigrationInconsistentLayoutError` and refuses. **The naive "just run migrate-store" path cannot execute.**
- v0.32 removes flat dual-read. This store becomes a ticking problem.
- **Root cause:** two binary versions own the same on-disk transport dir. This must end (guardrail G2).

### P1 — dontguess Go code won't build against v0.31.2 (BC-1)
`dontguess/go.mod` pins `campfire v0.17.0`. **47 Go files** import packages deleted in v0.30 (`pkg/campfire`, `pkg/convention`, `pkg/encoding`, `pkg/transport/fs`, `pkg/protocol`, `pkg/store`). No forwarding shims exist. Removed API surface (`WithNoWalkUp()`, `JoinSession`, `RecenterClaim`, `present_as`, `cfs1_`) needs call-site fixes. Until ported, the operator **cannot be rebuilt** — so it keeps writing flat, perpetuating P0.

### P2 — The CLI binary is an untagged `dev` build
`cf version dev` is unacceptable for live-store surgery. A `dev` binary writing this store is the most likely cause of P0's mixed state. Pin to a tagged v0.31.2 (release download or stamped build) so one known version owns the directory.

### P3 (opportunity) — Observability is blind
From the usage audit: all 1,723 wrapper invocations tag `success` (a buy *miss* exits 0 = "success", so hit-rate is invisible) and `caller` is always null (it reads `CF_HOME/identity.json` but exchange ops use `DG_HOME`). Both are fixable in the shell wrapper with no cf dependency. Fold in or run separately (see §4 decision).

---

## 2. What is NOT at risk (so we don't over-engineer)

- **Wire format is frozen** (CI-gated: `wireverify_test.go`, `test/demo/20-wire-format-freeze.sh`). v0.19/v0.31 peers exchange identical CBOR. **Federation/network skew is safe in both directions.** The danger is *co-located disk access*, not wire skew.
- **rd stores need no migration here.** Project `.campfire/` dirs hold only beacons; rd syncs via p2p-http, with **no local filesystem transport store**. Only `~/.cf/transport/*` dirs migrate.
- **migrate-store never touches identity/membership/grants** (`snapshotOtherState`/`assertOtherStateUnchanged`). It cannot silently elevate authority. Signatures survive (byte-for-byte copy, leaf filename preserved, no CBOR re-encode).
- **No live `cfs1_` swarm sessions** detected. cfs1→cfs2 is a checklist item for any stored tokens, not a migration step.

---

## 3. Non-negotiable guardrails (encode in every stage)

- **G0 — Reconcile mixed layout BEFORE any migrate-store.** Quiesce ALL writers first. Full-hash (sha256 of **all** 7,114+277 messages, not the tool's 64-file sample) into an inventory, and **tar the entire campfire dir** as a cold backup, before touching anything.
- **G1 — Pin the binary.** Install a tagged v0.31.2; confirm `cf version` reports it; confirm the wrapper resolves to that exact binary. No `dev` build writes this store again.
- **G2 — One binary version owns a transport dir at a time.** Never run a pre-bucketing writer (the v0.17.0 operator) against this store again once reconciled. A v0.19.3 peer may federate over the *wire* but must not share the on-disk `messages/`.
- **G3 — `--dry-run` first; real run WITHOUT `--force`; keep `messages.old/`.** `--force` is disaster-recovery only. Do **not** `--finalize` (it `os.RemoveAll`s the backup) until round-trip buy/put/read are green AND the G0 full-hash inventory matches.
- **G4 — Do NOT blind-`rm ~/.cf/trust/pins.json` on a BC-17 HMAC failure.** Record current pins out-of-band, then *re-pin against known-good keys*. A blind rm is a silent TOFU reset / MITM window. (Note: `~/.cf/trust/` does not currently exist, so this likely won't fire — but encode it.)
- **G5 — Trust only a build with green wire-freeze + public-API gates.** Confirm CI was green on the v0.31.2 tag.
- **G6 — Lookback is a correctness knob.** Leave `CF_FS_SYNC_LOOKBACK_MS` at default (2s) during/after migration; do not set strict-cursor (0).
- **G7 — Verify a v0.31.2 health-probe doesn't block on relay.** The exchange beacon embeds a relay; v0.31.2 `Subscribe` syncs all transports. Confirm the wrapper's `buys --json` probe doesn't hang on relay HTTP before committing (adversary A13). Test against the live relay first.

---

## 4. Operator decisions (RESOLVED 2026-06-01)

1. **P0 reconciliation strategy → (b) Stop v0.17 operator, adopt buckets.** Permanently retire the v0.17.0 operator (no restart on the old build), make the pinned v0.31.2 binary the sole writer, reconcile the 277 vs 7,114 by hash, and finalize on the bucketed layout. **This makes P1 a prerequisite** — there must be a v0.31-SDK writer to take over before the old operator is retired.
2. **P1 port → NOW, as part of this work.** Port the 47-file dontguess Go code + operator to the v0.31.2 SDK (BC-1 import map + dead-symbol removal), bump `go.mod`, rebuild and install the operator. This is what permanently closes P0.
3. **P3 observability → FOLD IN.** The ~30-line wrapper patch (buy_hit/buy_miss tagging + `DG_HOME` caller attribution) ships as a stage of this work so observability is live from day one on the pinned binary.

**Resulting hard ordering:** Backup/quiesce + pin CLI → **port operator (P1)** → retire v0.17 operator & reconcile to buckets (P0) → migrate remaining stores → wrapper obs + probe verify → 24h soak → finalize. The port (P1) and the backup (Stage A) can run in parallel, but the operator must NOT be retired until the v0.31 build is green.

---

## 5. Staged runbook (after decisions in §4)

> Each stage has an explicit rollback. The risky switches (PATH pin, operator restart, `--finalize`) are **human-gated** — automation stops before them.

**Stage A — Backup & inventory (G0).** Quiesce: stop operator (`kill -SIGTERM $(cat ~/.cf/dontguess.pid)`, wait for exit) and ensure no agent calls `dontguess`. `tar czf ~/cf-exchange-backup-$(date +%s).tgz ~/.cf/transport/ed4b6d62…`. sha256 every message into `inventory.txt`. *Rollback: none needed — read-only.*

**Stage B — Pin the CLI (G1, G5).** Install tagged v0.31.2 (release `cf_linux_amd64.tar.gz` w/ checksum, or `go build -ldflags "-X main.Version=v0.31.2"` from `~/projects/campfire`). Back up current `os/bin/cf` first. Verify `cf version` == v0.31.2. *Rollback: restore `os/bin/cf.bak.pre-v0.31.2`.*

**Stage C — Reconcile mixed layout (P0, per §4.1 decision).** Hash-verified. Confirm result is a single consistent layout. *Rollback: restore from Stage A tarball.*

**Stage D — `migrate-store` exchange (G3).** `--dry-run`, inspect, then real run (no `--force`). Verify bucket walk count == inventory count. Do **not** `--finalize`. *Rollback: `mv messages messages.broken; mv messages.old messages`.*

**Stage E — `migrate-store` the ~30 small session stores.** Scripted, idempotent, resumable via a state file; `--force` acceptable for own session stores lacking membership records. *Rollback: per-store `messages.old/`.*

**Stage F — (if §4.2 = port) Port dontguess to v0.31.2 SDK (P1).** Separate item tree; BC-1 import rewrite + dead-symbol fixes + `go.mod` bump. Rebuild operator, install. *Rollback: keep v0.17.0 operator binary.*

**Stage G — Wrapper/health-probe verification (G7).** Confirm `dontguess buy/put/read` round-trip green against pinned binary; confirm probe doesn't block on relay. *Rollback: prior wrapper.*

**Stage H — Soak 24h, then `--finalize` (G3).** Only after green soak AND hash match. Removes `messages.old/`. *Rollback: none after this — the point of no return.*

**Stage I — (P3, optional) Wrapper observability patch.** buy_hit/buy_miss tagging from stdout; caller from `DG_HOME/identity.json`. Independent of cf version.

---

## 6. Adversary attacks → disposition

Top attacks and how the runbook answers them (full list in design campfire):
- **A2/A10 — operator writes / SQLite schema race during migration** → Stage A quiesce + operator stop is mandatory before any v0.31 cf command.
- **A3 — wrong rollback binary** (`.bak` was v0.17, not the live version) → Stage B backs up the *actual current* binary by name.
- **A9 / domain-purist G0 — store already mixed** → confirmed true; P0 + Stage C address it; naive migrate-store explicitly rejected.
- **A13 — relay sync blocks health probe** → G7 pre-flight test.
- **A8 — orphaned cfs1_ sessions** → none live; checklist item only.
- **A14 — 64-sample verify is shallow** → G0 full-hash inventory supersedes the tool's spot-check as the acceptance gate.

---

## 7. Proposed work-item tree (for /swarm-plan)

- **Parent:** "Exchange store on a single pinned cf version, no mixed layout, operator on v0.31 SDK"
  - Stage A+B+C: "Exchange store reconciled to one consistent layout under a tagged v0.31.2 binary, full backup taken" (P0+P2)
  - Stage D+E: "All `~/.cf/transport` stores migrated to bucketed, backups retained" (blocked by above)
  - Stage F: "dontguess Go code + operator build green against campfire v0.31.2" (P1, parallelizable)
  - Stage G+H: "Exchange round-trips green on pinned binary; backups finalized after 24h soak"
  - Stage I: "dontguess wrapper logs buy hit/miss and real caller" (P3, independent)
