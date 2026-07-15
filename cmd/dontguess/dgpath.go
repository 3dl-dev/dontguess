package main

import (
	"os"
	"path/filepath"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// resolveDGHome returns the DG_HOME directory: the DG_HOME environment variable
// if set, otherwise $HOME/.dontguess. This is the single canonical implementation —
// operator.go (socketPath) and status.go previously each had their own copy.
//
// dontguess is its own portfolio member: its operator identity
// ($DG_HOME/nostr-operator.key), per-agent identities ($DG_HOME/agents/), and
// operator IPC socket live under dontguess's OWN home — NOT under ~/.cf, which
// is cf/rd's identity home (a nostr-operator.key there would collide with rd's
// portfolio key). The legacy campfire SDK config (CF_HOME / ~/.cf) is a separate,
// campfire-era concern and is unaffected by this default.
//
// Socket path: resolveDGHome() + "/ipc/dontguess.sock" — UNLESS the exchange
// config records a relocated OperatorSocketPath (dontguess-7b2, a long
// DG_HOME pushes the default past the platform's unix socket length limit);
// see resolveOperatorSocketPathFor below, which every CLI socket dialer uses.
func resolveDGHome() string {
	if dg := os.Getenv("DG_HOME"); dg != "" {
		return dg
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".dontguess"
	}
	return filepath.Join(home, ".dontguess")
}

// resolveOperatorSocketPathFor returns the operator IPC socket path CLI
// clients should dial for dgHome (dontguess-7b2, design §4/§9 Gate A/P2). It
// reads the exchange config's OperatorSocketPath — written by serve's
// bindOperatorSocket after a successful bind — and uses it when present,
// since a long DG_HOME may have forced serve to relocate the socket under
// $XDG_RUNTIME_DIR. Falls back to the default DG_HOME-relative path when no
// config exists yet or it carries no recorded socket path (matches prior
// behavior byte-for-byte for a short DG_HOME / pre-serve state).
func resolveOperatorSocketPathFor(dgHome string) string {
	if cfg, err := exchange.LoadConfig(dgHome); err == nil && cfg.OperatorSocketPath != "" {
		return cfg.OperatorSocketPath
	}
	return filepath.Join(dgHome, "ipc", "dontguess.sock")
}
