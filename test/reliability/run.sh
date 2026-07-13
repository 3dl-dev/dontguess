#!/bin/sh
# test/reliability/run.sh — entry point for the wrapper reliability gate (nostr-first).
#
# The cf-era shell harnesses (wrapper_test.sh, wrapper_parallel.sh,
# e2e_full_pipeline.sh, operator_accept_put.sh, attempt_log_test.sh) were retired
# with the nostr-first cutover (dontguess-ed2 §6 item 9): they required the deleted
# `cf` binary and a live hosted campfire at ~/.cf to verify "reached the exchange".
# Their wrapper-reliability coverage now lives in gated Go tests that drive the REAL
# shipped wrapper (extracted from site/install.sh) against a stub operator:
#
#   TestInstallE2E_*                 (test/install_e2e_test.go)
#     auto-start gating (H6, individual vs team tier), operator dispatch (no cf),
#     individual-tier put/buy reachability end-to-end, attempt-log JSONL.
#   TestInstall_Flock*               (test/install_flock_injection_test.go)
#     flock single-operator auto-start, PID-file write, shell-injection hardening.
#   TestInstaller_NoCfDownload / TestWrapper_*   (test/install_nostr_wrapper_test.go)
#     no cf download, no cf dispatch, serve auto-start byte-gated to individual tier.
#
# These are part of `go test -race ./...` (the CI gate), so this entry point just
# runs them directly under the race detector, cache-busting with -count=1.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Running wrapper reliability tests (nostr-first, Go) ==="
cd "${REPO_ROOT}"
go test -race -count=1 -run 'TestInstall' ./test/

echo "=== All reliability tests passed ==="
