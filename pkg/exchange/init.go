// Package exchange implements the DontGuess exchange operator lifecycle.
//
// Nostr-first (docs/design/nostr-first-rebuild-decision.md): an exchange is no
// longer a campfire. `dontguess init` bootstraps the operator's OWN home under
// DG_HOME — a persistent secp256k1 (nostr) operator identity, the local
// append-only event store (pkg/store), and a config file recording the relay
// URLs the operator federates over. There is no campfire creation, beacon,
// naming registration, or convention promotion here.
package exchange

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/campfire-net/dontguess/pkg/identity"
	dgstore "github.com/campfire-net/dontguess/pkg/store"
)

// operatorKeyFile is the on-disk name of the persisted secp256k1 (nostr)
// operator private key within DG_HOME. It mirrors the name used by the serve
// path (cmd/dontguess/serve.go loadOrCreateNostrOperatorIdentity) so `init` and
// `serve` bootstrap the SAME operator identity.
const operatorKeyFile = "nostr-operator.key"

// storeFile is the DG_HOME-relative name of the local append-only event log.
const storeFile = "events.jsonl"

// Config is the local operator config written after init. It is campfire-free:
// it records the operator's nostr identity, the relay URLs the operator serves,
// and the local store path.
type Config struct {
	// OperatorKeyHex is the operator's nostr public key (x-only BIP-340 hex).
	OperatorKeyHex string `json:"operator_key"`
	// OperatorNpub is the NIP-19 bech32 encoding of OperatorKeyHex.
	OperatorNpub string `json:"operator_npub,omitempty"`
	// RelayURLs are the relay websocket URLs the operator federates over
	// (the DONTGUESS_RELAY_URLS the operator will serve).
	RelayURLs []string `json:"relay_urls,omitempty"`
	// StorePath is the absolute path to the local event log.
	StorePath string `json:"store_path"`
	// CreatedAt is the wall-clock nanosecond timestamp of first init.
	CreatedAt int64 `json:"created_at"`
	// TrustLevels configures per-operation trust floors (serve-path concern).
	// Left untouched by init; preserved here for the serve wiring that reads it.
	TrustLevels TrustLevels `json:"trust_levels,omitempty"`
	// MinReputation is the sell-side reputation floor. 0 (default) disables
	// reputation gating.
	MinReputation int `json:"min_reputation,omitempty"`
}

// InitOptions controls the campfire-free Init operation.
type InitOptions struct {
	// DGHome is the operator home directory. If empty, it resolves to the
	// DG_HOME environment variable, then $HOME/.dontguess.
	DGHome string
	// RelayURLs are recorded in the config as the relays the operator serves.
	RelayURLs []string
	// Force rewrites the config even if one already exists. The operator key is
	// NEVER overwritten regardless of Force (identity is load-or-create).
	Force bool
}

// resolveDGHome mirrors cmd/dontguess/dgpath.go: DG_HOME env, then
// $HOME/.dontguess. Kept package-local so pkg/exchange has no dependency on the
// cmd package.
func resolveDGHome(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if dg := os.Getenv("DG_HOME"); dg != "" {
		return dg
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".dontguess"
	}
	return filepath.Join(home, ".dontguess")
}

// ConfigPath returns the path to the exchange operator config file within
// dgHome.
func ConfigPath(dgHome string) string {
	return filepath.Join(dgHome, "dontguess-exchange.json")
}

// LoadConfig reads the exchange config from dgHome.
func LoadConfig(dgHome string) (*Config, error) {
	data, err := os.ReadFile(ConfigPath(dgHome))
	if err != nil {
		return nil, fmt.Errorf("reading exchange config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing exchange config: %w", err)
	}
	return &cfg, nil
}

// Init bootstraps the operator's own DontGuess home campfire-free:
//
//	(a) operator identity — a persistent secp256k1 (nostr) key at
//	    $DG_HOME/nostr-operator.key, minted on first run and REUSED (never
//	    overwritten) thereafter. Written 0600.
//	(b) the local event store — the canonical append-only log at
//	    $DG_HOME/events.jsonl, created if absent.
//	(c) the config file — records the operator pubkey and the relay URLs the
//	    operator will serve.
//
// It is idempotent: re-running Init returns the same operator identity and
// leaves the store intact. If a config already exists and opts.Force is false,
// the existing config's CreatedAt is preserved. Returns the Config written to
// disk.
func Init(opts InitOptions) (*Config, error) {
	dgHome := resolveDGHome(opts.DGHome)
	if err := os.MkdirAll(dgHome, 0700); err != nil {
		return nil, fmt.Errorf("creating DG_HOME %s: %w", dgHome, err)
	}

	// (a) Operator identity — load-or-create, never overwrite.
	id, err := loadOrCreateOperatorIdentity(dgHome)
	if err != nil {
		return nil, fmt.Errorf("operator identity: %w", err)
	}

	// (b) Local event store — Open creates the file if absent (O_CREATE) and is
	// a no-op-open on an existing log. Close immediately: init only ensures it
	// exists; serve opens it for the engine.
	storePath := filepath.Join(dgHome, storeFile)
	st, err := dgstore.Open(storePath)
	if err != nil {
		return nil, fmt.Errorf("opening local store %s: %w", storePath, err)
	}
	if cerr := st.Close(); cerr != nil {
		return nil, fmt.Errorf("closing local store %s: %w", storePath, cerr)
	}

	// (c) Config — preserve CreatedAt across re-init for idempotency unless
	// Force is set (a forced re-init stamps a fresh CreatedAt).
	configPath := ConfigPath(dgHome)
	createdAt := time.Now().UnixNano()
	if !opts.Force {
		if existing, lerr := LoadConfig(dgHome); lerr == nil && existing.CreatedAt != 0 {
			createdAt = existing.CreatedAt
		}
	}

	cfg := &Config{
		OperatorKeyHex: id.PubKeyHex(),
		OperatorNpub:   id.Npub(),
		RelayURLs:      opts.RelayURLs,
		StorePath:      storePath,
		CreatedAt:      createdAt,
	}
	if err := writeConfig(configPath, cfg); err != nil {
		return nil, fmt.Errorf("writing exchange config: %w", err)
	}

	return cfg, nil
}

// loadOrCreateOperatorIdentity returns the persisted secp256k1 (nostr) operator
// identity under dgHome, minting and persisting a fresh one on first run. The
// private key is stored 32-byte hex at 0600 and is NEVER overwritten once
// present (idempotent). This mirrors serve.go's loadOrCreateNostrOperatorIdentity
// so `init` and `serve` converge on the same operator key at
// $DG_HOME/nostr-operator.key.
func loadOrCreateOperatorIdentity(dgHome string) (*identity.Secp256k1Identity, error) {
	keyPath := filepath.Join(dgHome, operatorKeyFile)
	if data, err := os.ReadFile(keyPath); err == nil {
		if privHex := trimNewline(string(data)); privHex != "" {
			id, perr := identity.FromPrivHex(privHex)
			if perr != nil {
				return nil, fmt.Errorf("parsing persisted operator key %s: %w", keyPath, perr)
			}
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading operator key %s: %w", keyPath, err)
	}

	id, err := identity.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating operator identity: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(id.PrivHex()+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("writing operator key %s: %w", keyPath, err)
	}
	return id, nil
}

// trimNewline strips a trailing newline and surrounding whitespace from a
// persisted key file without pulling in the strings package for one call.
func trimNewline(s string) string {
	for len(s) > 0 {
		c := s[len(s)-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	for len(s) > 0 {
		c := s[0]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			s = s[1:]
			continue
		}
		break
	}
	return s
}

// writeConfig serializes cfg to configPath (mode 0600).
func writeConfig(configPath string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(configPath, data, 0600)
}
