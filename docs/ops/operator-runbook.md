# DontGuess Operator Runbook

**Audience:** whoever runs `dontguess up --relay` (or `--team`/`--fleet`) and owns the resulting
operator identity — a human, or an agent acting as one. This is the canonical operator-facing
companion to the design (`docs/design/onboarding-tiered-scaling-federation.md`, §7/§7.3) and the
confidentiality envelope (`docs/design/content-confidentiality-envelope-541.md`). Where this doc
and the design doc disagree, the design doc wins — file an item, don't silently pick one.

**Read the §8.9 informed-consent block in the root `CLAUDE.md` before you run any of this.** The
short version: your operator key decrypts your entire historical corpus, forever, with no forward
secrecy and no revocation. Rotation (§5 below) protects only future content.

---

## 0. Before you start — what "operator" means here

Team/fleet tier has exactly **one** operator identity (one secp256k1 keypair). It:

- signs every roster/allowlist admission,
- unwraps every buyer's CEK at delivery time (it is the single plaintext-trust point, §541),
- is the one thing that must survive machine loss (§4 export/import) and can be rotated but never
  silently forked (ADV-4 — a second `up --relay` on a machine with no local operator key **refuses
  to mint** rather than create a competing sequencer; see `cmd/dontguess/up.go`).

Solo tier needs none of this — `dontguess up` with no relay runs entirely local, no relay, no
scrip, no operator-network exposure. Skip straight to a fleet only when you actually need
multi-machine sharing.

---

## 1. Relay bootstrap (ONCE — no recurring SSH)

**Team tier works against ANY nostr relay you can reach over websocket — a stock strfry, a public
relay, whatever. The exchange does 100% of admission/trust verification itself
(`selfAdmitOperator` → the live signed-IPC allowlist path, `pkg/exchange` `TrustChecker`); the
relay is a dumb transport.** You do not need to install or configure anything relay-side to run a
fleet.

```
dontguess up --relay ws://your-relay-host:7777
```

This is the entire bootstrap for the common case: it mints (or reuses) the operator identity,
starts `serve`, self-admits the operator's own key into the fleet allowlist + roster over the
signed IPC path `dontguess allowlist add` also uses, and installs the boot service (§3). No relay
SSH, no relay config file, nothing to keep in sync by hand.

### 1.1 Optional: self-hosting a hardened strfry relay (edge hardening, not required)

If you also **own** the relay (rather than using someone else's), you can optionally harden it
with a roster-aware `writePolicy` that pins the operator pubkey as sole write-admission authority
at the relay layer — a second, independent gate in front of the exchange's own trust check
(defense-in-depth, design §2). This is **relay-owner hardening, not a team-tier onboarding
requirement.** If you skip it, team tier still works correctly; you just don't get the extra
relay-side denylist/rate-cap layer.

If you choose to do this:

1. Install strfry (`github.com/hoytech/strfry`) on the relay host you control.
2. Configure its `writePolicy` plugin to pin your operator's pubkey (`dontguess status` prints the
   operator npub/pubkey) as the sole authority for the fleet roster event (`kind 30078`,
   `d`-tag=`fleet`), and to apply your own denylist/rate-cap policy after that check.
3. Start strfry and point `dontguess up --relay` at it. **This step happens once, at relay
   creation.** Every admission after this point (`dontguess allowlist add`, `dontguess invite` /
   `dontguess join`) is a signed nostr event over the wire — there is no SSH or relay-admin
   credential the operator ever needs again.

**The operator holds no relay-admin credentials after bootstrap.** The operator's secp256k1 key
signs application-layer events (roster, puts, settles); it is never used to SSH into or
administer the relay process itself. If your relay needs an operator (server restarts, disk
management, writePolicy edits), that is a **relay-owner** role, which may or may not be the same
person as the **exchange operator** — keep the two credential sets separate. Losing SSH access to
the relay host does not affect the exchange operator's ability to run `dontguess up --relay`
against a *different* relay carrying the same roster history.

---

## 2. Key custody

The operator identity is one secp256k1 private key, `$DG_HOME/nostr-operator.key` (0600,
`mlock`'d against swap where the platform allows it — non-fatal if `CAP_IPC_LOCK`/`RLIMIT_MEMLOCK`
is unavailable). Two custody boundaries, do not conflate them (§541 §3.5/§4.2):

**What 1Password/HSM custody DOES protect:**
- the key file at rest on disk when `serve` is not running,
- the key in transit during `dontguess operator export` / `dontguess operator import` between
  hosts (the private key crosses the boundary only via an in-memory JSON template piped to `op`'s
  stdin, or via `op read`'s stdout captured directly into memory — never a scratch file, never
  shell history, never a log line).

**What it does NOT protect:** the live scalar in `serve`'s process memory while the operator is
running and unwrapping CEKs — that memory is used directly for every NIP-44 ECDH unwrap and
BIP-340 signature. A loaded 1Password-custodied key is exactly as exposed in-process as a plain
0600 file once `serve` has read it. Only a hardware HSM that performs the ECDH operation itself
(key never leaves the device) removes this window. dontguess does not ship HSM support today —
this is a known, accepted gap (dontguess-973 C1), not a documentation error.

### 2.1 Export (multi-host operator only)

```
dontguess operator export --vault <1Password-vault> [--title dontguess-operator]
```

Only needed for the rare genuine multi-host operator (the same operator process, or its failover
twin, running on a second machine). Refuses to overwrite a *different* operator identity already
stored under the same vault/title — it either confirms an identical match (no-op) or fails loud,
never silently forks or overwrites (§6 ADV-4).

### 2.2 Import

```
dontguess operator import --vault <1Password-vault> [--title dontguess-operator]
```

Restores the exported key onto a second host. **This is the correct multi-host path — do NOT run
`up --relay` on a second machine expecting it to "join" the same operator.** A second machine
with no local operator key that runs `up --relay` against a relay carrying an existing operator's
events is refused (ADV-4 probe, `cmd/dontguess/up.go` `probeExistingOperatorEvents`): the fleet
has exactly one operator, and every other machine is either (a) this same operator restored via
`operator import`, or (b) a **member** that runs `dontguess join <invite-token>` (§4), never a
second `up --relay`.

---

## 3. Boot unit + linger

`dontguess up --relay` (and `--team`/`--fleet`) installs a boot service automatically as its last
step — this is not a separate manual task:

- **Linux:** a systemd `--user` unit is written and enabled, and `loginctl enable-linger
  <username>` is run so the unit keeps running across logout, not just while a session is active
  (`pkg/bootservice/bootservice.go`; ADV-6 — without linger, the operator silently stops the
  instant the admin logs out, and every fleet member loses service).
- **macOS:** a launchd plist with `RunAtLoad`+`KeepAlive` is installed (launchd has no separate
  linger concept — the plist itself is the always-on equivalent).

Idempotent: re-running `dontguess up --relay` on a machine that already has the service installed
is a no-op for this step. If the boot-service install path reports a dry-run (missing systemd/
launchd, or insufficient privilege), the CLI output says so explicitly — `up` never silently skips
this and reports success.

**Solo tier does not install a boot service.** Plain `dontguess up` (no relay) starts `serve` in
the background with a pidfile shim (`spawnDetachedServe`) for operator convenience
(`kill $(cat $DG_HOME/dontguess.pid)`) but is not wired into systemd/launchd — that scope is the
`--relay` flow only.

---

## 4. Live admit / revoke

Once a fleet is running, admitting or removing a member never requires a restart or an
out-of-band relay edit:

```
# Operator: mint a one-paste invite for a new member
dontguess invite alice --scrip 50000 --ttl 72h
  invite token: dgi1_<base64 operator-signed blob>

# Alice, on her own machine, one paste:
dontguess join dgi1_<token>
  ✓ verified operator signature, not expired
  ✓ provisioned member identity
  ✓ admitted to fleet allowlist + relay roster
  ✓ genesis grant: 50000 scrip
```

`invite` mints an operator-signed, single-use, TTL'd token; `join` self-provisions the member's
own key (never the operator's), publishes a redeem event the operator's serve loop verifies
(signature valid, not expired, not already redeemed) and promotes into both the fleet allowlist
and the trust check live — sub-second, no operator restart. Direct admit/remove of an existing
npub (skipping the invite flow) is also live:

```
dontguess allowlist add <npub>       # admits a seller/buyer npub immediately
dontguess allowlist remove <npub>    # revokes immediately
dontguess allowlist list             # current fleet allowlist
```

Both paths go through the same signed-IPC admit op (mirrors `dontguess mint`'s auth model) — a
local process on the operator's box cannot forge an admission without the operator key, and
`allowlist remove` de-admits both the exchange's live trust check and republishes the roster event
so any relay-side policy picks it up on its next subscription push.

**Every allowlisted principal — seller or buyer — needs this before their first put/settle
succeeds.** The trust check applies to every settle phase (buyer-accept, complete, dispute,
preview-request), not just sellers.

---

## 5. Key rotation

Rotation protects content put **after** rotation only. It gives **zero retroactive protection**
for content put before a leak — that is a permanent property of the append-only, no-forward-secrecy
design (§541 §4.2), not a bug. State this to whoever asks "does rotating the key fix the leak."

1. **Export the current key first.** `dontguess operator export --vault <vault>` — you need the
   OLD key's decrypt capability to re-wrap existing CEKs in step 3; do this before generating the
   new key.
2. **Mint the new key.** Generate a fresh operator identity (a clean `$DG_HOME`'s key-generation
   path, or `dontguess operator import` a key minted elsewhere into a new home).
3. **Re-point the roster.** Update the fleet roster (`kind 30078`, `d`-tag=`fleet`) — and, if you
   run the optional hardened relay (§1.1), its `writePolicy` pin — to the new pubkey. Until this
   completes, the relay still accepts writes signed by the OLD key; don't delete the old key yet.
4. **Re-wrap the CEK index.** One-time local pass: for every inventory entry's
   `WrappedCEKOperator` wrapped to the old pubkey, unwrap with the OLD (retained, decrypt-only) key
   and re-wrap to the NEW key. This is local state work — the immutable put/wrap events already on
   the relay are untouched (and cannot be, per no-forward-secrecy); only the operator's local
   re-wrap index changes so future settle/deliver unwraps use the new key.
5. **Retire, then destroy, the old key.** Do not delete the old private key material until the
   re-wrap pass finishes and you've spot-checked a sample of entries decrypt correctly under the
   new key. Once verified, securely delete the old key file and revoke it from 1Password/HSM
   storage.

Full threat-model language: `docs/design/onboarding-tiered-scaling-federation.md` §7.3.

---

## 6. Operator export / import — quick reference

See §2 above for the full custody discussion. Command summary:

```
dontguess operator export --vault <1Password-vault> [--title dontguess-operator]
dontguess operator import --vault <1Password-vault> [--title dontguess-operator]
```

Use `export`/`import` only for a genuine second host running the SAME operator identity (failover,
planned migration, or rotation's step 2 restore). Every other second machine is a **member**
(§4 `dontguess join`), never a second `up --relay`.

---

## 7. Quick command index

| Task | Command |
|---|---|
| Solo bootstrap (no relay) | `dontguess up` |
| Fleet bootstrap / promote | `dontguess up --relay ws://host:7777[,ws://host2:7777]` |
| Explicit team tier (fails loud with no relay configured) | `dontguess up --team` |
| Confirm you're the first operator on an unverifiable relay | `dontguess up --relay <url> --new-operator` |
| Invite a member | `dontguess invite <name> [--scrip N] [--ttl D]` |
| Redeem an invite (member) | `dontguess join <dgi1_token>` |
| Admit/revoke an npub directly | `dontguess allowlist add\|remove <npub>` |
| List the fleet allowlist | `dontguess allowlist list` |
| Export operator key to 1Password | `dontguess operator export --vault <vault>` |
| Import operator key from 1Password | `dontguess operator import --vault <vault>` |

Federation (`dontguess federate <peer-beacon>`) is **not covered here** — it is open/undesigned
per `docs/design/onboarding-tiered-scaling-federation.md` §5; do not build operational process
around it yet.
