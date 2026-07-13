#!/usr/bin/env bash
# 01-individual-tier.sh — Individual-tier lifecycle demo (nostr-first).
#
# Proves the complete campfire-free basic lifecycle on the INDIVIDUAL tier
# (DONTGUESS_RELAY_URLS unset): a single operator inits an exchange, starts the
# engine, accepts a put over the local IPC socket, processes a buy, and returns the
# cached content inline — no cf, no campfire, no relay.
#
# This is the nostr-first successor to the retired cf-era demos (test/demo/01-08),
# which drove the exchange through `cf --cf-home <id> put/buy` against a hosted
# campfire that no longer exists. The team-tier / multi-agent wire path is covered
# by the gated in-process round-trip test (cmd/dontguess TestE2E*, design ed2-G).
#
# Pattern: isolated temp DG_HOME, trap cleanup on EXIT, tee transcript.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
OUTPUT_FILE="$OUTPUT_DIR/01-individual-tier.txt"
mkdir -p "$OUTPUT_DIR"

# Tee all output to the transcript file.
exec > >(tee "$OUTPUT_FILE") 2>&1

tee_section() { echo ""; echo "=== SECTION: $1 ==="; }
run() { echo "\$ $*"; "$@"; }

# ---------------------------------------------------------------------------
# Setup — isolated, campfire-free temp environment
# ---------------------------------------------------------------------------

TMP=$(mktemp -d /tmp/dontguess-demo-01-XXXX)
export DG_HOME="$TMP/dg"
mkdir -p "$DG_HOME"
# Individual tier: NO relay URLs. The client routes through the local serve IPC.
unset DONTGUESS_RELAY_URLS CF_HOME AGENT_CF_HOME 2>/dev/null || true

SERVE_PID=""
trap '
    echo ""
    echo "=== SECTION: cleanup ==="
    if [ -n "${SERVE_PID:-}" ] && kill -0 "$SERVE_PID" 2>/dev/null; then
        echo "\$ kill $SERVE_PID"
        kill "$SERVE_PID" 2>/dev/null || true
    fi
    echo "\$ rm -rf $TMP"
    rm -rf "$TMP"
    echo "cleanup complete."
' EXIT

# ---------------------------------------------------------------------------
# Binary — always build from source. A system dontguess-operator may be a stale
# cf-era build without the nostr-first put/buy verbs, so the demo never trusts it.
# ---------------------------------------------------------------------------

PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
echo "# Building dontguess-operator from source..."
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
BINARY="$TMP/dontguess-operator"
go build -o "$BINARY" "$PROJECT_ROOT/cmd/dontguess"
echo "# Built: $BINARY"

# ---------------------------------------------------------------------------
# Section: init — bootstrap the campfire-free exchange (operator key + store)
# ---------------------------------------------------------------------------

tee_section "init"
run "$BINARY" init

# ---------------------------------------------------------------------------
# Section: serve — start the exchange engine in the background
# ---------------------------------------------------------------------------

tee_section "serve"
echo "\$ dontguess serve --poll-interval 300ms &"
DG_HOME="$DG_HOME" nohup "$BINARY" serve --poll-interval 300ms > "$TMP/serve.log" 2>&1 &
SERVE_PID=$!
echo "$SERVE_PID" > "$DG_HOME/dontguess.pid"

echo "# Waiting for the operator IPC socket..."
SOCK="$DG_HOME/ipc/dontguess.sock"
for _ in $(seq 1 40); do
    [ -S "$SOCK" ] && break
    kill -0 "$SERVE_PID" 2>/dev/null || { echo "ERROR: serve died"; cat "$TMP/serve.log"; exit 1; }
    sleep 0.25
done
if [ ! -S "$SOCK" ]; then
    echo "ERROR: operator socket not ready in 10s"; cat "$TMP/serve.log"; exit 1
fi
echo "# Exchange engine running (PID $SERVE_PID), socket: $SOCK"
grep -E "exchange serving|operator:|replayed" "$TMP/serve.log" | head -5 || true

# ---------------------------------------------------------------------------
# Section: put — seller offers cached inference (individual tier, zero relay)
# ---------------------------------------------------------------------------

tee_section "put"
CONTENT='package main

import (
    "encoding/json"
    "net/http"
)

// Handler validates incoming POST JSON requests and returns structured errors.
func Handler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var body map[string]any
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    w.WriteHeader(http.StatusOK)
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "fields": len(body)})
}'
CONTENT_B64=$(printf '%s' "$CONTENT" | base64 -w0)

echo "\$ dontguess put --description ... --content_type exchange:content-type:code --token_cost 2000"
"$BINARY" put \
    --description "Go HTTP handler: validates POST JSON, returns structured errors" \
    --content "$CONTENT_B64" \
    --token_cost 2000 \
    --content_type exchange:content-type:code

# Give the engine a poll tick to index the accepted put.
sleep 1

# ---------------------------------------------------------------------------
# Section: buy — buyer requests cached inference; expect an inline HIT
# ---------------------------------------------------------------------------

tee_section "buy"
echo "\$ dontguess buy --task 'Go HTTP handler that validates incoming POST JSON requests' --budget 5000"
# Capture stdout+stderr: the HIT status line is written to stderr, the matched
# content to stdout — the demo asserts on both.
BUY_OUT=$("$BINARY" buy \
    --task "Go HTTP handler that validates incoming POST JSON requests" \
    --budget 5000 2>&1)
echo "$BUY_OUT"

# ---------------------------------------------------------------------------
# Section: verify — the buy must be an inline HIT carrying the seller's content
# ---------------------------------------------------------------------------

tee_section "verify"
if printf '%s' "$BUY_OUT" | grep -q "HIT"; then
    echo "# PASS: buy returned an inline HIT on the individual tier"
else
    echo "# FAIL: expected an inline HIT, got:"
    echo "$BUY_OUT"
    exit 1
fi

# ---------------------------------------------------------------------------
# Section: summary
# ---------------------------------------------------------------------------

tee_section "summary"
echo "Tier:          individual (DONTGUESS_RELAY_URLS unset, zero relay)"
echo "DG_HOME:       $DG_HOME"
echo "Store:         $DG_HOME/events.jsonl"
echo ""
echo "# Demo complete. Transcript written to: $OUTPUT_FILE"
