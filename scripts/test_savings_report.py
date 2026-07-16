#!/usr/bin/env python3
"""Tests for savings-report.py — valuation math and buyer attribution.

Run: python3 scripts/test_savings_report.py   (no external deps; exits non-zero on failure)
"""
import base64
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("savings_report", os.path.join(HERE, "savings-report.py"))
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

_failures = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _failures.append(name)


def approx(a, b, tol=1e-6):
    return abs(a - b) <= tol


def ev(eid, sender, tag, payload_obj, antecedents=None, ts=1_000_000_000_000_000_000):
    return {
        "id": eid, "sender": sender * 8 if len(sender) < 12 else sender,
        "tags": [tag],
        "payload": base64.b64encode(json.dumps(payload_obj).encode()).decode(),
        "antecedents": antecedents or [], "timestamp": ts,
    }


def test_value_reuse_math():
    # 10,000 avoided tokens, 30% output, 5% consumption, Opus rates.
    nt, nf, bd = sr.value_reuse(10_000, 0.30, 0.05, 5.0, 25.0)
    # avoided output = 3000 @ $25/MTok = 0.075 ; avoided input = 7000 @ $5 = 0.035
    # consume input = 500 @ $5 = 0.0025 (subtracted)
    check("net_tokens = 10000 - 500 consume = 9500", nt == 9500)
    check("net_fiat = 0.075 + 0.035 - 0.0025 = 0.1075", approx(nf, 0.1075))
    check("output valued 5x input (breakdown carries split)",
          approx(bd["avoided_output_tokens"], 3000) and approx(bd["avoided_input_tokens"], 7000))


def test_output_input_valuation_differs():
    # Same token count, different output fraction => different fiat. This is the whole point:
    # tokens are NOT fungible in dollars.
    _, f_lo, _ = sr.value_reuse(100_000, 0.10, 0.0, 5.0, 25.0)
    _, f_hi, _ = sr.value_reuse(100_000, 0.90, 0.0, 5.0, 25.0)
    check("output-heavy work is worth more fiat than input-heavy at equal tokens", f_hi > f_lo * 2)


def test_buyer_attribution_via_antecedent():
    # match sender is the OPERATOR; real buyer must be read from the antecedent buy event.
    op = "0" * 64
    buyer = "b" * 64
    seller = "s" * 64
    events = [
        ev("buy1", buyer, "exchange:buy", {"task": "do X", "budget": 5000}),
        ev("put1", seller, "exchange:put",
           {"token_cost": "40000", "content_type": "exchange:content-type:code", "description": "X recipe"}),
        ev("match1", op, "exchange:match",
           {"search_meta": {"total_candidates": 12},
            "results": [{"entry_id": "e1", "seller_key": seller,
                         "token_cost_original": 40000, "price": 3000,
                         "similarity": 0.5, "description": "X recipe"}]},
           antecedents=["buy1"]),
    ]
    r = sr.collect(events)
    reuse = r["reuses"][0]
    check("buyer resolved to buy sender, not match sender", reuse["buyer"] == buyer[:12])
    check("reuse flagged cross_agent (seller != buyer)", reuse["cross_agent"] is True)
    check("operator not mistaken for buyer", reuse["buyer"] != op[:12])


def test_self_reuse_not_counted():
    # If the buyer IS the seller (self smoke test), it must not count as realized reuse.
    who = "w" * 64
    op = "0" * 64
    events = [
        ev("buy1", who, "exchange:buy", {"task": "self", "budget": 1}),
        ev("match1", op, "exchange:match",
           {"search_meta": {"total_candidates": 1},
            "results": [{"entry_id": "e1", "seller_key": who,
                         "token_cost_original": 8000, "price": 1, "similarity": 0.9, "description": "self"}]},
           antecedents=["buy1"]),
    ]
    r = sr.collect(events)

    class A:  # minimal args
        in_rate, out_rate = 5.0, 25.0
        gen_output_frac, consume_frac = 0.30, 0.05
    rep = sr.build_report(r, A)
    check("self/trivial reuse excluded from realized headline",
          rep["realized_savings"]["reuse_events"] == 0)


def test_synthetic_buys_excluded():
    check("heartbeat detected as synthetic", sr._synthetic("operator-heartbeat keepalive 20260714"))
    check("real task not synthetic", not sr._synthetic("implement continual-learning harness"))


if __name__ == "__main__":
    print("test_savings_report:")
    test_value_reuse_math()
    test_output_input_valuation_differs()
    test_buyer_attribution_via_antecedent()
    test_self_reuse_not_counted()
    test_synthetic_buys_excluded()
    if _failures:
        print(f"\n{len(_failures)} FAILED: {_failures}")
        sys.exit(1)
    print("\nall passed")
