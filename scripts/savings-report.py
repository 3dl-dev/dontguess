#!/usr/bin/env python3
"""
savings-report.py — repeatable token-savings + fiat valuation report for a DontGuess exchange.

Reads the operator event log ($DG_HOME/events.jsonl, default ~/.dontguess/events.jsonl) and
answers the only question that matters for the exchange's value proposition:

    How many real inference tokens has reuse saved, and what is that worth in fiat?

WHY THIS IS NOT JUST "tokens sold":
  - The token_cost a seller reports is the cost to GENERATE the work. When a buyer reuses it
    they avoid regenerating it (big) and instead pay only to read it back into context (small).
    The gap between those two is the real saving.
  - Input and output tokens are priced very differently (Opus 4.8: $5 vs $25 per MTok — output
    is 5x). Avoided regeneration is a mix of input+output; consumption is pure input. So the
    fiat saving is NOT tokens x a single rate — the output share of avoided work is worth 5x.
    We therefore split every avoided regeneration into an input part and an output part and
    value them separately. All split/rate assumptions are CLI-tunable (see --help).

REALIZED vs LATENT:
  - REALIZED savings come from matches that actually delivered another agent's work to a buyer.
    This is money already off the Anthropic bill. It is the headline.
  - LATENT savings value the stocked-but-not-yet-reused inventory at one reuse each — the pool
    of future savings sitting on the shelf. Clearly separated; never mixed into the headline.

Scrip/price is INTERNAL economy accounting (a coordination token), not an API cost, so it is
reported separately and never counted as token savings.
"""
import argparse
import base64
import collections
import json
import os
import sys
import datetime

# ---- valuation defaults (all overridable on the CLI) --------------------------------------
# Model rates in USD per million tokens. Default: Opus 4.8 (claude-opus-4-8).
DEFAULT_IN_RATE = 5.0     # $/MTok input
DEFAULT_OUT_RATE = 25.0   # $/MTok output
# Of the tokens burned GENERATING a reusable artifact, what fraction were OUTPUT (generation)
# tokens vs INPUT (context/reads)? An agentic derivation is input-heavy; the valuable artifact
# is the output minority. This is the single biggest lever — tune it to your workload.
DEFAULT_GEN_OUTPUT_FRAC = 0.30
# What does it cost to CONSUME cached work, as a fraction of what it cost to generate? Reading a
# delivered artifact back into context is pure input and far cheaper than re-deriving it.
DEFAULT_CONSUME_FRAC = 0.05

MODEL_RATES = {
    # id: (in $/MTok, out $/MTok)
    "opus-4.8":   (5.0, 25.0),
    "sonnet-4.6": (3.0, 15.0),
    "haiku-4.5":  (1.0, 5.0),
    "fable-5":    (10.0, 50.0),
}


def dg_home():
    return os.environ.get("DG_HOME", os.path.join(os.path.expanduser("~"), ".dontguess"))


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def payload(e):
    try:
        return json.loads(base64.b64decode(e["payload"]))
    except Exception:
        return {}


def op(e):
    tags = e.get("tags") or [""]
    return tags[0]


def as_list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return []
    return []


def as_dict(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return {}


def ts_dt(e):
    return datetime.datetime.fromtimestamp(e["timestamp"] / 1e9, datetime.timezone.utc)


def collect(events):
    """Reduce the raw event log into the structures the report needs."""
    by_id = {e["id"]: e for e in events}
    r = {
        "by_op": collections.Counter(),
        "senders": collections.Counter(),
        "puts": [],           # list of dicts: token_cost, content_type, description, seller
        "buys": [],           # task, budget, synthetic(bool)
        "misses": [],         # task, synthetic(bool)
        "reuses": [],         # realized cross-agent deliveries
        "mints": [],          # scrip minted
        "compress_rewards": 0,
        "first": None, "last": None,
    }
    for e in events:
        o = op(e)
        r["by_op"][o] += 1
        r["senders"][e["sender"][:12]] += 1
        dt = ts_dt(e)
        if r["first"] is None or dt < r["first"]:
            r["first"] = dt
        if r["last"] is None or dt > r["last"]:
            r["last"] = dt
        p = payload(e)
        if o == "exchange:put":
            r["puts"].append({
                "token_cost": int(p.get("token_cost", 0) or 0),
                "content_type": (p.get("content_type", "") or "").replace("exchange:content-type:", ""),
                "description": p.get("description", ""),
                "seller": e["sender"][:12],
            })
        elif o == "exchange:buy":
            task = p.get("task", "")
            r["buys"].append({"task": task, "budget": int(p.get("budget", 0) or 0),
                              "synthetic": _synthetic(task)})
        elif o == "exchange:buy-miss":
            task = p.get("task", "")
            r["misses"].append({"task": task, "synthetic": _synthetic(task)})
        elif o == "exchange:match":
            meta = as_dict(p.get("search_meta", {}))
            # The match event is emitted by the OPERATOR on the buyer's behalf, so e["sender"]
            # is the operator, not the buyer. Resolve the real buyer through the antecedent
            # buy event this match answers.
            buyer = ""
            for a in e.get("antecedents", []):
                ae = by_id.get(a)
                if ae and op(ae) == "exchange:buy":
                    buyer = ae["sender"][:12]
                    break
            for res in as_list(p.get("results", [])):
                tco = int(res.get("token_cost_original", 0) or 0)
                seller = (res.get("seller_key", "") or "")[:12]
                # A realized cross-agent reuse: delivered content whose seller differs from the
                # buyer, and which came from a non-trivial candidate pool (not a self-seeded
                # smoke test). We keep total_candidates so the caller can judge.
                r["reuses"].append({
                    "when": ts_dt(e).isoformat(),
                    "buyer": buyer,
                    "seller": seller,
                    "cross_agent": bool(seller and buyer and seller != buyer),
                    "candidates": int(meta.get("total_candidates", 0) or 0),
                    "token_cost_original": tco,
                    "price_scrip": int(res.get("price", 0) or 0),
                    "similarity": res.get("similarity"),
                    "description": res.get("description", ""),
                })
        elif o in ("dontguess:scrip-mint", "dontguess:scrip-buy-hold"):
            r["mints"].append(int(p.get("amount", 0) or 0))
        elif o == "exchange:assign":
            if p.get("task_type") == "compress":
                r["compress_rewards"] += int(p.get("reward", 0) or 0)
    return r


def _synthetic(task):
    t = (task or "").lower()
    return ("heartbeat" in t) or ("keepalive" in t) or ("smoke" in t)


def value_reuse(tc, gen_out_frac, consume_frac, in_rate, out_rate):
    """Value one avoided regeneration of `tc` tokens.

    Returns (net_tokens_saved, net_fiat_saved, breakdown).
    Avoided regeneration splits into input+output; consumption is pure input we still pay.
    """
    gen_out = tc * gen_out_frac                 # expensive output tokens avoided
    gen_in = tc * (1.0 - gen_out_frac)          # cheaper input tokens avoided
    consume_in = tc * consume_frac              # input tokens we DO spend to read it back
    net_in = gen_in - consume_in
    net_out = gen_out
    net_tokens = net_in + net_out
    net_fiat = net_in * in_rate / 1e6 + net_out * out_rate / 1e6
    return net_tokens, net_fiat, {
        "avoided_output_tokens": gen_out, "avoided_input_tokens": gen_in,
        "consume_input_tokens": consume_in,
        "net_input_tokens": net_in, "net_output_tokens": net_out,
    }


def build_report(r, args):
    in_rate, out_rate = args.in_rate, args.out_rate
    gof, cf = args.gen_output_frac, args.consume_frac

    span_h = 0.0
    if r["first"] and r["last"]:
        span_h = (r["last"] - r["first"]).total_seconds() / 3600.0

    # --- inventory (latent) ---
    subst_puts = [p for p in r["puts"] if p["token_cost"] >= 500]
    junk_puts = [p for p in r["puts"] if p["token_cost"] < 500]
    inv_tc = sum(p["token_cost"] for p in subst_puts)
    latent_tokens, latent_fiat, _ = value_reuse(inv_tc, gof, cf, in_rate, out_rate)

    # --- realized reuse (headline) ---
    real_reuses = [x for x in r["reuses"] if x["cross_agent"] and x["candidates"] > 1]
    trivial_reuses = [x for x in r["reuses"] if not (x["cross_agent"] and x["candidates"] > 1)]
    realized_tokens = realized_fiat = 0.0
    realized_avoided_tc = 0
    for x in real_reuses:
        nt, nf, _ = value_reuse(x["token_cost_original"], gof, cf, in_rate, out_rate)
        realized_tokens += nt
        realized_fiat += nf
        realized_avoided_tc += x["token_cost_original"]

    real_buys = [b for b in r["buys"] if not b["synthetic"]]
    real_misses = [m for m in r["misses"] if not m["synthetic"]]
    hit_rate = (len(real_reuses) / len(real_buys)) if real_buys else 0.0

    return {
        "generated_at": None,  # stamped by caller (no clock in-report for determinism)
        "window": {
            "first_event": r["first"].isoformat() if r["first"] else None,
            "last_event": r["last"].isoformat() if r["last"] else None,
            "span_hours": round(span_h, 1),
        },
        "valuation_assumptions": {
            "model_in_rate_usd_per_mtok": in_rate,
            "model_out_rate_usd_per_mtok": out_rate,
            "gen_output_frac": gof,
            "consume_frac": cf,
            "note": "avoided regeneration split into input+output and valued separately; "
                    "consumption is pure input; scrip/price excluded (internal economy).",
        },
        "activity": {
            "ops": dict(r["by_op"].most_common()),
            "distinct_participants": len(r["senders"]),
            "distinct_sellers": len({p["seller"] for p in r["puts"]}),
            "puts_substantive": len(subst_puts),
            "puts_junk_under_500": len(junk_puts),
            "buys_real": len(real_buys),
            "buys_synthetic": len(r["buys"]) - len(real_buys),
            "misses_real": len(real_misses),
        },
        "realized_savings": {
            "reuse_events": len(real_reuses),
            "trivial_or_self_reuses_excluded": len(trivial_reuses),
            "real_content_hit_rate": round(hit_rate, 3),
            "avoided_regeneration_tokens": realized_avoided_tc,
            "net_tokens_saved": round(realized_tokens),
            "net_fiat_saved_usd": round(realized_fiat, 2),
            "detail": [
                {
                    "when": x["when"], "buyer": x["buyer"], "seller": x["seller"],
                    "avoided_tokens": x["token_cost_original"],
                    "price_scrip": x["price_scrip"],
                    "similarity": round(x["similarity"], 3) if isinstance(x["similarity"], (int, float)) else None,
                    "description": x["description"][:80],
                }
                for x in real_reuses
            ],
        },
        "latent_savings": {
            "note": "value of stocked inventory IF each entry is reused once; upper-bound pool, not realized.",
            "inventory_entries": len(subst_puts),
            "inventory_avoided_regeneration_tokens": inv_tc,
            "net_tokens_saved_if_each_reused_once": round(latent_tokens),
            "net_fiat_saved_if_each_reused_once_usd": round(latent_fiat, 2),
        },
        "internal_economy": {
            "note": "scrip is a coordination token, not an API cost; shown for completeness only.",
            "scrip_minted": sum(r["mints"]),
            "compression_reward_scrip_posted": r["compress_rewards"],
            "reuse_scrip_paid_by_buyers": sum(x["price_scrip"] for x in real_reuses),
        },
    }


def fmt_usd(x):
    return f"${x:,.2f}"


def fmt_tok(x):
    return f"{int(round(x)):,}"


def render_text(rep):
    A = rep["activity"]
    R = rep["realized_savings"]
    L = rep["latent_savings"]
    V = rep["valuation_assumptions"]
    W = rep["window"]
    E = rep["internal_economy"]
    out = []
    p = out.append
    p("=" * 72)
    p("  DontGuess — Token-Savings Report")
    p("=" * 72)
    p(f"  window        : {W['first_event']}  ->  {W['last_event']}")
    p(f"                  ({W['span_hours']} h of activity)")
    p(f"  valued at     : ${V['model_in_rate_usd_per_mtok']}/MTok in, "
      f"${V['model_out_rate_usd_per_mtok']}/MTok out   "
      f"(gen_output_frac={V['gen_output_frac']}, consume_frac={V['consume_frac']})")
    p("")
    p("-- Activity " + "-" * 60)
    p(f"  participants  : {A['distinct_participants']} keys ({A['distinct_sellers']} sellers stocked inventory)")
    p(f"  inventory     : {A['puts_substantive']} substantive puts, {A['puts_junk_under_500']} junk (<500)")
    p(f"  buys          : {A['buys_real']} real  +  {A['buys_synthetic']} synthetic(heartbeat)")
    p(f"  ops           : " + ", ".join(f"{k}={v}" for k, v in rep['activity']['ops'].items()))
    p("")
    p("== REALIZED NET SAVINGS (already off the bill) " + "=" * 25)
    p(f"  reuse events        : {R['reuse_events']}   "
      f"(real-content hit rate {R['real_content_hit_rate']*100:.0f}%; "
      f"{R['trivial_or_self_reuses_excluded']} trivial/self excluded)")
    p(f"  avoided regeneration: {fmt_tok(R['avoided_regeneration_tokens'])} tokens")
    p(f"  NET TOKENS SAVED    : {fmt_tok(R['net_tokens_saved'])}")
    p(f"  NET FIAT SAVED      : {fmt_usd(R['net_fiat_saved_usd'])}")
    if R["detail"]:
        p("  breakdown:")
        for d in R["detail"]:
            p(f"    - {d['when'][:16]}  {fmt_tok(d['avoided_tokens'])} tok  "
              f"sim={d['similarity']}  {d['seller']}->{d['buyer']}")
            p(f"        {d['description']}")
    p("")
    p("-- Latent savings (inventory on the shelf) " + "-" * 29)
    p(f"  {L['inventory_entries']} entries = {fmt_tok(L['inventory_avoided_regeneration_tokens'])} avoidable tokens")
    p(f"  if each reused once: {fmt_tok(L['net_tokens_saved_if_each_reused_once'])} tokens "
      f"= {fmt_usd(L['net_fiat_saved_if_each_reused_once_usd'])}")
    p("")
    p("-- Internal economy (not token savings) " + "-" * 32)
    p(f"  scrip minted={E['scrip_minted']:,}  "
      f"compression-reward scrip posted={E['compression_reward_scrip_posted']:,}  "
      f"reuse scrip paid={E['reuse_scrip_paid_by_buyers']:,}")
    p("=" * 72)
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Token-savings + fiat valuation report for a DontGuess exchange.")
    ap.add_argument("--events", default=None, help="path to events.jsonl (default $DG_HOME/events.jsonl)")
    ap.add_argument("--model", choices=sorted(MODEL_RATES), default=None,
                    help="preset in/out rates for a model (overrides --in-rate/--out-rate defaults)")
    ap.add_argument("--in-rate", type=float, default=None, help=f"input $/MTok (default {DEFAULT_IN_RATE}=Opus 4.8)")
    ap.add_argument("--out-rate", type=float, default=None, help=f"output $/MTok (default {DEFAULT_OUT_RATE}=Opus 4.8)")
    ap.add_argument("--gen-output-frac", type=float, default=DEFAULT_GEN_OUTPUT_FRAC,
                    help=f"fraction of a generation's tokens that were OUTPUT (default {DEFAULT_GEN_OUTPUT_FRAC})")
    ap.add_argument("--consume-frac", type=float, default=DEFAULT_CONSUME_FRAC,
                    help=f"consumption cost as fraction of avoided regeneration (default {DEFAULT_CONSUME_FRAC})")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)

    # resolve rates: --model preset, then explicit flags, then Opus 4.8 defaults
    in_rate, out_rate = DEFAULT_IN_RATE, DEFAULT_OUT_RATE
    if args.model:
        in_rate, out_rate = MODEL_RATES[args.model]
    if args.in_rate is not None:
        in_rate = args.in_rate
    if args.out_rate is not None:
        out_rate = args.out_rate
    args.in_rate, args.out_rate = in_rate, out_rate

    path = args.events or os.path.join(dg_home(), "events.jsonl")
    if not os.path.exists(path):
        print(f"error: event log not found: {path}", file=sys.stderr)
        return 2
    events = load_events(path)
    if not events:
        print(f"error: no events in {path}", file=sys.stderr)
        return 2

    rep = build_report(collect(events), args)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(render_text(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
