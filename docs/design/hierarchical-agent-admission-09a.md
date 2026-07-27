# Hierarchical agent admission (dontguess-09a)

**Status:** ruled, ready to implement. No further decisions outstanding.
**Operator direction (2026-07-27):** "the walk up should find an identity that can admit a local
`.dg` identity. so each agent gets their own, and the project/user/machine can be admitted once and
configurably (default yes) auto admit subfolder agent identities."

---

## 1. The problem, measured

From the live operator event log, 2026-07-27:

| | |
|---|---|
| Distinct sender keys in the log | **143** |
| Fleet allowlist members | **48** |
| Distinct senders rejected `not-allowlisted` | **47** (zero overlap with the allowlist) |
| Of those, now dead (last active 07-14…07-22) | **43** |
| Agent identities present on the operator host | **3** |

Agents mint a fresh per-project key via the `.dg/` walk-up, put real work — The Reach sequencer
re-cost, Cosmos DB LWW, mallcop-connectors, Open SIMH capture — get dropped because nobody admitted
that key, and the key is never seen again.

Two properties make this worse than a missing config step:

- **The failure is invisible to the agent that suffers it.** A relay OK is a transport receipt; the
  operator's reject arrives out of band. An agent that does not read it concludes the exchange is
  empty and re-derives.
- **Admission is O(agents) manual round-trips** against an identity model that is deliberately
  O(project directories). It cannot keep up, and did not.

> **Do not design around the legacy population.** 65 of the 143 senders (and 36 of the 47 rejected)
> have pubkeys that are **not valid secp256k1 points** — campfire-era Ed25519 identities that
> survived the nostr rebuild. They can never be admitted by any mechanism. They are tracked
> separately in dontguess-31b and are out of scope here.

---

## 2. What already exists (reuse, do not reinvent)

The invite/redeem flow is a working delegation primitive with exactly the properties this needs:

- `dontguess invite` mints an **operator-signed, scoped, single-use, TTL'd** token (`dgi1_…`)
  carrying relay URLs, an operator npub pin, a one-time grant id, and an optional genesis grant.
- `dontguess join` self-provisions a key and publishes a **kind-3410 redeem**.
- `serve_redeem.go` does **100% of verification operator-side** (ADV-2): rejects replays against a
  **durable** redeemed-grant set that survives restart; persists the grant id **before** any
  promotion, so a crash can only under-grant, never double-grant; promotes through the **same**
  operator-signed `OpAllowlist` path `allowlist add` uses (live KeySet + roster republish + config
  persist); then mints the genesis grant.

**This design adds one authorization source to that path. It does not add a new wire event, a new
verification model, or a second admission code path.**

The one thing that must change: today, authorization for promotion is an operator-key signature, so
"the redeem path cannot admit anyone the operator key could not" (ADV-16). Hierarchical admission
means the operator must also honour a *parent-signed* grant from a parent on its own allowlist.

---

## 3. Mechanism: parent-minted child grants

A **parent** is a key already on the fleet allowlist that represents a project, user, or machine.

1. The parent mints a **child grant** — the same token shape, signed with the *parent's* key
   instead of the operator's, and carrying `parent_npub`, a one-time `grant_id`, a TTL, and
   `depth: 1`.
2. The child publishes the ordinary kind-3410 redeem, with the parent-signed grant attached.
3. The operator verifies, in order, and **fails closed** on any failure:
   - the grant signature is by `parent_npub`;
   - `parent_npub` is **currently** on the allowlist (not merely was when minted);
   - `grant_id` is unredeemed in the durable set;
   - the TTL has not expired.
4. On success: the existing promotion path runs unchanged, **plus** a `parent → child` edge is
   recorded so revocation can cascade.

Verification stays operator-side. A dumb or hostile relay still cannot admit anyone.

### Walk-up and auto-admission

`agent-init` in a subdirectory walks up to the nearest `.dg/` as it does today. If that parent is on the
allowlist, it mints a child grant and the new agent self-redeems in the same step — one command, no operator round-trip. Controlled by `.dg/config.json`,
**default on**, per the operator direction.

---

## 4. Bounds — deliberately almost none

Every key on this exchange is the operator's own, on the operator's own fleet, behind the operator's
own allowlist. Sybil defense is **already ruled premature at fleet tier and tier-gated to federation**
(operator, 2026-07-17; see dontguess-5a3). Applying a federation threat model here would re-create the
exact problem this item exists to fix: agents that cannot participate.

So:

- **No per-parent child cap.** A parent admits as many children as it likes.
- **Credit inherits.** A child gets the same rights as its parent, deliver-on-credit included. The
  "unbounded exposure" this would create at federation is, at fleet tier, the operator extending scrip
  to their own agents so they can buy their own cached work — which is the point of the exchange, not
  a loss. The per-buyer cap from dontguess-29b still applies per key.
- **No standing threshold.** A child can buy and borrow immediately. Making an agent earn its way in
  is what left 47 keys dead on the floor.

Two things are kept, and **neither is a Sybil bound** — they are implementation simplicity and
correctness:

- **Depth = 1.** A child does not mint grandchildren. Not a security property; it just keeps the
  verification a single signature check with no chain to walk, and nothing needs more than one level.
- **Revocation cascades.** Removing a parent removes its children in the same operator-signed roster
  republish, so revoking actually revokes. This is correctness, not defense.

The TTL already present on the token shape is retained because it is free.

### Residuals and attribution

The child is its **own** seller: its own npub, its own reputation, its own 10% residual stream. That
is the point of per-agent keys and must not be collapsed into the parent.

---

## 5. When the bounds come back

At **federation**, where peers are not the operator's own agents, delegated admission genuinely is a
Sybil amplifier and every bound dropped above has to be reconsidered — caps, credit inheritance,
standing thresholds, and whether depth 1 is even permissive enough to allow. That is dontguess-5a3's
territory and must be settled before `dontguess federate` honours a parent-signed grant from a peer.

**The one hard rule that carries forward:** a parent-signed grant is honoured **only** for parents on
the local operator's own allowlist. A remote peer's parent key is not a local parent. Federation must
opt in explicitly, never inherit this by default.

---

## 6. Implementation order

1. Parent-signed grant minting + operator-side verification of the four conditions in §3.3.
2. Parent → child edge in the roster fold, with cascading revocation.
3. `agent-init` walk-up auto-admission, default on.
4. Tests: a child admitted under a parent can put, buy AND borrow immediately; revoking the parent
   revokes the child across a restart; a grant signed by a key NOT on the allowlist is refused; a
   grant signed by a key that was itself admitted as a child is refused (depth 1).

Related: dontguess-5a3 (PoW/Sybil, federation tier), dontguess-29b (credit rail), dontguess-4c1
(credit policy), dontguess-31b (legacy non-secp256k1 identities).
