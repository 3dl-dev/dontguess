# test/reliability

Wrapper reliability tests for the `dontguess` installer + wrapper (nostr-first).

The cf-era shell harnesses were retired with the nostr-first cutover
(dontguess-ed2 §6 item 9): they required the deleted `cf` binary and a live hosted
campfire to verify a buy "reached the exchange". Their coverage now lives in gated
Go tests that drive the REAL shipped wrapper (extracted verbatim from
`site/install.sh`) against a stub operator, so drift in the installer fails CI:

| Test | File | Covers |
|------|------|--------|
| `TestInstallE2E_*` | `test/install_e2e_test.go` | H6 auto-start tier gating (individual vs team), operator dispatch (no cf), individual-tier put/buy reachability end-to-end, attempt-log JSONL |
| `TestInstall_Flock*` | `test/install_flock_injection_test.go` | flock single-operator auto-start, PID-file write, shell-injection hardening |
| `TestInstaller_NoCfDownload`, `TestWrapper_*` | `test/install_nostr_wrapper_test.go` | no cf download, no cf dispatch, serve auto-start byte-gated to individual tier |

**Run the reliability gate:** `sh test/reliability/run.sh`
(runs `go test -race -count=1 -run TestInstall ./test/`; these are also part of the
`go test -race ./...` CI gate).
