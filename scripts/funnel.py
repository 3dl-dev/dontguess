#!/usr/bin/env python3
"""Measure the dontguess exchange conversion funnel from the operator event log.

Usage:
    python3 scripts/funnel.py [--since 'YYYY-MM-DD HH:MM'] [--home ~/.dontguess]

Written 2026-07-27 to make the "did the economics changes actually work?" question
re-runnable instead of re-derived by hand each time.

Deliberate choices, do not "simplify" these away:
  * Events are DEDUPED BY EVENT ID. The store double-appends relay-origin events
    (one copy per configured relay), which inflates naive put counts ~6%.
    See dontguess-8f5.
  * Heartbeat/probe/smoke traffic is filtered out of the demand numbers. Leaving
    it in roughly doubles the apparent buy count and makes the hit rate meaningless.
  * "assign completions" reads as 0 because no completion event kind is emitted;
    treat a nonzero here as the signal that compression labor finally moved.
"""
import argparse
import base64
import collections
import datetime
import json
import os
import re
import sys

NOISE = re.compile(
    r"operator-heartbeat|probe|smoke|canary|SURFACE-BRIDGE|live[- ]push|"
    r"isolation test|warm-test|debug-reader|journal-trace|watch-fold|"
    r"unique-17|17\d{8}|reverse a linked list|^x$|deploy smoke",
    re.I,
)

# Deploy markers, so a run can be attributed to the binary that served it.
MARKERS = [
    ("2026-07-27 17:19", "v0.9.0 two-unit pricing"),
    ("2026-07-27 18:47", "v0.9.1 credit rail"),
]


def load(home):
    path = os.path.join(home, "events.jsonl")
    seen = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            seen.setdefault(e["id"], e)  # dedup by event id
    ev = sorted(seen.values(), key=lambda x: x["timestamp"])
    for e in ev:
        try:
            e["p"] = json.loads(base64.b64decode(e["payload"]))
        except Exception:
            e["p"] = {}
    return ev


def has(e, tag):
    return tag in e.get("tags", [])


def report(ev, label):
    puts = [e for e in ev if has(e, "exchange:put") and e["p"]]
    real_puts = [p for p in puts if not NOISE.search(p["p"].get("description", ""))]
    buys = [e for e in ev if has(e, "exchange:buy") and e["p"]]
    real_buys = [b for b in buys if not NOISE.search(b["p"].get("task", ""))]

    accepts = [e for e in ev if has(e, "exchange:phase:buyer-accept")]
    rejects = [e for e in ev if has(e, "exchange:phase:buyer-accept-reject")]
    delivers = [e for e in ev if has(e, "exchange:phase:deliver")]
    assigns = [e for e in ev if has(e, "exchange:assign")]

    loans = collections.Counter()
    for e in ev:
        for t in ("scrip-loan-mint", "scrip-loan-repay", "scrip-loan-vig-accrue"):
            if has(e, "dontguess:" + t):
                loans[t] += 1

    conv = 100.0 * len(delivers) / len(accepts) if accepts else 0.0
    reject_reasons = collections.Counter(
        e["p"].get("reason", "?") for e in rejects if isinstance(e["p"], dict)
    )

    print(f"\n=== {label} ===")
    print(f"  events (deduped)      {len(ev)}")
    print(f"  puts   real/raw       {len(real_puts)}/{len(puts)}")
    print(f"  buys   real/raw       {len(real_buys)}/{len(buys)}")
    print(f"  buyer-accept          {len(accepts)}")
    print(f"  buyer-accept-reject   {len(rejects)}   {dict(reject_reasons) or ''}")
    print(f"  deliver               {len(delivers)}")
    print(f"  ACCEPT->DELIVER       {conv:.0f}%        <- headline conversion")
    print(f"  compression assigns   {len(assigns)} issued")
    print(f"  LOANS mint/repay/vig  {loans['scrip-loan-mint']}/"
          f"{loans['scrip-loan-repay']}/{loans['scrip-loan-vig-accrue']}"
          f"   <- credit rail engaged?")

    # Delivered token value: what buyers actually avoided re-deriving.
    cost = {}
    for p in puts:
        cost[p["id"]] = p["p"].get("token_cost", 0)
    for e in ev:
        if has(e, "exchange:match") and e["p"]:
            for r in e["p"].get("results", []):
                cost.setdefault(r["entry_id"], r.get("token_cost_original", 0))
    saved = sum(cost.get(e["p"].get("entry_id"), 0) for e in delivers
                if isinstance(e["p"], dict))
    stock = sum(cost.get(p["id"], 0) for p in real_puts)
    util = 100.0 * saved / stock if stock else 0.0
    print(f"  delivered token value {saved:,} of {stock:,} in stock ({util:.1f}% utilization)")

    # Price realism: are we still quoting production cost for a copy?
    ratios = []
    for e in ev:
        if has(e, "exchange:match") and e["p"]:
            for r in e["p"].get("results", []):
                tc, pr = r.get("token_cost_original", 0), r.get("price", 0)
                if tc > 0:
                    ratios.append(100.0 * pr / tc)
    if ratios:
        ratios.sort()
        print(f"  price as % of token_cost  median {ratios[len(ratios)//2]:.0f}%"
              f"  (84% = pre-v0.9.0, ~21% = two-unit pricing)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", default=os.path.expanduser("~/.dontguess"))
    ap.add_argument("--since", default=None, help="'YYYY-MM-DD HH:MM'")
    args = ap.parse_args()

    ev = load(args.home)
    if not ev:
        print("no events found", file=sys.stderr)
        return 1

    report(ev, "ALL TIME")
    for marker, name in MARKERS:
        cut = datetime.datetime.strptime(marker, "%Y-%m-%d %H:%M").timestamp() * 1e9
        seg = [e for e in ev if e["timestamp"] >= cut]
        if seg:
            report(seg, f"SINCE {marker} ({name})")
    if args.since:
        cut = datetime.datetime.strptime(args.since, "%Y-%m-%d %H:%M").timestamp() * 1e9
        report([e for e in ev if e["timestamp"] >= cut], f"SINCE {args.since}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
