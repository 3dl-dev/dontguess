# Upgrading DontGuess

## How to Upgrade

**Option A — built-in upgrade command (v0.5.0+):**

```sh
dontguess upgrade
```

This re-runs the installer to fetch the latest release binary and wrapper.

**Option B — re-run the curl installer (always works):**

```sh
curl -fsSL https://dontguess.ai/install.sh | sh
```

Both options are equivalent. The installer fetches the latest GitHub release,
replaces the `dontguess-operator` binary and the `dontguess` wrapper in
`~/.local/bin/`, and leaves all exchange state untouched.

---

## Backward-Compatibility Guarantee

Upgrading to v0.5.0 requires **no migration** for existing single-identity
installs.

- **DG_HOME state is preserved.** The installer never touches `$DG_HOME`
  (default `~/.cf`). Your exchange config (`dontguess-exchange.json`),
  exchange identity, and the PID/log files are not modified.
- **AGENT_CF_HOME unset = identical prior behavior.** If you have not set
  `AGENT_CF_HOME`, all signing operations continue to use the operator key at
  `DG_HOME`, exactly as before. No environment changes are required.
- **Existing cf admissions are preserved.** The exchange campfire identity is
  stored in `DG_HOME`; upgrading the wrapper binary does not change it.

---

## Opting Into Per-Agent Identities (v0.5.0)

v0.5.0 introduces per-agent signing via `AGENT_CF_HOME`. When set, buy/put/settle
operations are signed by the agent's own Ed25519 key instead of the operator key.
Exchange routing (campfire ID, operator server, health probe) always stays on
`DG_HOME` — only the signing identity changes.

**One-time setup per agent:**

```sh
# 1. Provision an identity for the agent (e.g. "my-agent"):
dontguess agent-init my-agent

# 2. The command prints an export line — eval it to activate:
eval $(dontguess agent-init my-agent)

# Or set the variable directly:
export AGENT_CF_HOME="$HOME/.cf-agents/my-agent"
```

The agent's public key is admitted to the exchange campfire automatically by
`agent-init`. Once `AGENT_CF_HOME` is set in the agent's environment, all
subsequent buy/put/settle calls are signed with that agent's key. This enables
`cross_agent_convergence` trust scoring in the hit-rate reporter.

**To revert to operator-key signing:** unset `AGENT_CF_HOME`.

---

## v0.5.0 Highlights

### Honest Hit-Rate Reporting

The previously-reported hit rate of ~96.67% was inflated by:
- Matches below the relevance floor (0.16 cosine similarity) being counted as hits
- Synthetic/load-test traffic included in the denominator

v0.5.0 corrects both. The honest baseline rate for real agent traffic is **~3%**
(3.06% measured on the live exchange). The reporter now:
- Excludes matches below the 0.16 relevance floor (these are misses, not hits)
- Excludes synthetic traffic (entries tagged `exchange:synthetic`)
- Reports `quality_weighted_hits` separately from raw match counts

### Relevance Gate

Matches below the 0.16 cosine similarity floor now return as **misses** rather
than delivering low-quality content. A miss registers demand and improves future
matching; a bad hit erodes buyer trust.

### Put Quality Gate

Puts are now rejected if the description is flagged as synthetic test traffic
(e.g., `token_cost < 500`, descriptions matching `isTestLikeDescription`). This
keeps the inventory clean and prevents load-test entries from polluting hit-rate
metrics.

### Per-Agent Identity + Cross-Agent Convergence

The `cross_agent_convergence` field in the hit-rate report counts distinct agents
that have successfully used the same cache entry. This is the exchange's primary
trust signal: if 3+ independent agents succeed with the same entry, it's
genuinely reusable domain knowledge rather than a lucky match.

See `docs/design/exchange-per-agent-identity-decision.md` for the design rationale.
