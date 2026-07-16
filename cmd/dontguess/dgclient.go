package main

// dgclient.go — project-local client resolution (dontguess-884).
//
// A dontguess CLIENT (put/buy/agent-init) never consults an ambient environment
// variable and never "reckons about its identity" per invocation. Instead it
// discovers a project-local `.dg/` directory by walking UP from the current
// working directory (exactly like `.git`). That `.dg/` holds:
//
//   - the agent's signing identity   (.dg/nostr-identity.json — resolved by
//     identity.Resolve, the same file layout agent homes have always used), and
//   - the client config              (.dg/config.json — how to reach the
//     exchange: relay URLs + operator npub, plus a human label).
//
// So `dontguess buy --task ...` run anywhere inside a project tree signs with the
// right identity and reaches the right exchange with no env vars and no flags.
// There is no client DG_HOME/AGENT_CF_HOME. (The OPERATOR daemon keeps its own
// service home — a long-running service, not a per-CLI concern.)

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// dgDirName is the project-local dontguess directory discovered by walk-up.
const dgDirName = ".dg"

// dgConfigFile is the client config within a .dg/ directory.
const dgConfigFile = "config.json"

// clientConfig is .dg/config.json — everything a client needs to reach the
// exchange, so no env var is required. All fields optional.
type clientConfig struct {
	// AgentName is a human label for the identity in this .dg/ (display only;
	// resolution uses the key file, not the name).
	AgentName string `json:"agent_name,omitempty"`
	// RelayURLs is the team-tier relay set. Consulted when neither
	// DONTGUESS_RELAY_URLS nor --relay is set.
	RelayURLs []string `json:"relay_urls,omitempty"`
	// OperatorNpub is the exchange operator's npub (put encrypts to it; buy may
	// pin it). Consulted when --operator-npub is not passed.
	OperatorNpub string `json:"operator_npub,omitempty"`
}

// findDgDir walks up from startDir to the filesystem root, returning the path of
// the nearest .dg directory, or "" if none exists.
func findDgDir(startDir string) string {
	dir := startDir
	for {
		candidate := filepath.Join(dir, dgDirName)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// discoverDgDir walks up from the current working directory for a .dg/ directory.
func discoverDgDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return findDgDir(cwd)
}

// loadClientConfig loads .dg/config.json discovered by walk-up. Returns a zero
// config (all fields empty) when there is no .dg/ or no config file — every
// field is optional, so callers layer their own fallbacks. The second return is
// the discovered .dg/ path ("" if none).
func loadClientConfig() (clientConfig, string) {
	dg := discoverDgDir()
	if dg == "" {
		return clientConfig{}, ""
	}
	var cfg clientConfig
	if data, err := os.ReadFile(filepath.Join(dg, dgConfigFile)); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	return cfg, dg
}

// writeClientConfig writes .dg/config.json (0644 — no secrets; the KEY lives in
// .dg/agents/<name>/ at 0600). Caller owns merging.
func writeClientConfig(dgDir string, cfg clientConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dgDir, dgConfigFile), append(data, '\n'), 0o644)
}

// resolveDefaultAgentDir returns the identity home for the discovered .dg/: the
// --as override under .dg/agents/<name>, else the config's default agent_name,
// else .dg/ itself (single-identity layout).
func resolveDefaultAgentDir(dg, overrideName string) string {
	if name := strings.TrimSpace(overrideName); name != "" {
		return filepath.Join(dg, "agents", name)
	}
	var cfg clientConfig
	if data, err := os.ReadFile(filepath.Join(dg, dgConfigFile)); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	if cfg.AgentName != "" {
		return filepath.Join(dg, "agents", cfg.AgentName)
	}
	return dg
}

// loadAgentSigner resolves the AGENT signing identity WITHOUT any environment
// variable (dontguess-884). Resolution order:
//
//  1. --agent-home <path>  explicit home directory (advanced / tests), or
//  2. --as <name>          a named identity under the discovered .dg/agents/<name>, or
//  3. the discovered .dg/   itself (the project's default identity — the common case).
//
// It is deliberately distinct from the operator key: team-tier put/buy/settle are
// always signed by the agent identity, never the operator's (design §3.1).
func loadAgentSigner(agentName, agentHome string) (identity.Signer, error) {
	// (1) Explicit path override.
	if h := strings.TrimSpace(agentHome); h != "" {
		return resolveSignerAt(h)
	}
	// (2)/(3) Walk-up .dg/.
	dg := discoverDgDir()
	if dg == "" {
		cwd, _ := os.Getwd()
		return nil, fmt.Errorf("no %s/ found from %s upward — run `dontguess agent-init <name> --fleet-member` "+
			"in your project to create one (no env var, no per-command flag)", dgDirName, cwd)
	}
	return resolveSignerAt(resolveDefaultAgentDir(dg, agentName))
}

// resolveOperatorNpub returns the --operator-npub flag value if set, else the
// operator_npub from the walk-up .dg/config.json (dontguess-884), so a client in
// a configured project needs no --operator-npub on every put/buy.
func resolveOperatorNpub(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	cfg, _ := loadClientConfig()
	return strings.TrimSpace(cfg.OperatorNpub)
}

func resolveSignerAt(dir string) (identity.Signer, error) {
	id, err := identity.Resolve(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve agent identity at %s: %w", dir, err)
	}
	return id, nil
}
