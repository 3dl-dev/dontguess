# scripts/

## savings-report.py — token-savings + fiat valuation

Repeatable report over a live exchange's event log. Answers: **how many real inference tokens
has reuse saved, and what is that worth in fiat?**

```bash
# default: Opus 4.8 rates, reads $DG_HOME/events.jsonl (~/.dontguess/events.jsonl)
python3 scripts/savings-report.py

# value against a different model's rates
python3 scripts/savings-report.py --model sonnet-4.6
python3 scripts/savings-report.py --in-rate 3 --out-rate 15

# machine-readable
python3 scripts/savings-report.py --json
```

### What it measures

- **Realized net savings (headline)** — avoided regeneration from *actual* cross-agent reuses
  (a buyer received another agent's work instead of re-deriving it), using the authoritative
  `token_cost_original` from match results, minus a small consumption cost. This is money
  already off the Anthropic bill.
- **Latent savings** — the stocked-but-unused inventory valued at one reuse each. The pool of
  future savings, kept strictly separate from the headline.
- **Internal economy** — scrip minted / paid. Reported for completeness; scrip is a coordination
  token, **not** an API cost, and is never counted as token savings.

### Why fiat ≠ tokens × one rate

The value the report exposes rests on two facts the raw "tokens sold" number hides:

1. **What was sold ≠ what it saves.** The `token_cost` on a put is the cost to *generate* the
   work. Reuse avoids regenerating it (large) and only pays to read it back (small). The gap is
   the saving.
2. **Input and output tokens are priced very differently** (Opus 4.8: $5 vs $25 / MTok). Avoided
   regeneration is a mix of input+output; consumption is pure input. So the report splits every
   avoided regeneration and values the parts separately.

### Tunable assumptions (the levers)

| flag | default | meaning |
|---|---|---|
| `--in-rate` / `--out-rate` | 5 / 25 (Opus 4.8) | model $/MTok, or use `--model {opus-4.8,sonnet-4.6,haiku-4.5,fable-5}` |
| `--gen-output-frac` | 0.30 | fraction of a generation's tokens that were OUTPUT — the biggest lever; tune to your workload |
| `--consume-frac` | 0.05 | cost to read cached work back, as a fraction of what it cost to generate |

Tests: `python3 scripts/test_savings_report.py` (no deps).
