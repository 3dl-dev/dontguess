// Package embedscript ships the dense-embedding Python script (all-MiniLM-L6-v2,
// 384-dim ONNX) INSIDE the Go binary via go:embed, so an installed operator can
// always locate it — even though the release ships only the binary and never the
// repo's cmd/embed/main.py (dontguess-6f0: without this the operator silently
// falls back to TF-IDF because defaultEmbedScriptPath can't find the script on
// disk).
//
// embed_minilm.py is a byte-for-byte copy of cmd/embed/main.py (the canonical
// dev-invocation script). TestEmbeddedScriptMatchesCanonical guards against
// drift — edit cmd/embed/main.py and re-copy it here, or the test fails.
package embedscript

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed embed_minilm.py
var scriptBytes []byte

var (
	once       sync.Once
	cachedPath string
	cachedErr  error
)

// Bytes returns the embedded Python script's raw bytes.
func Bytes() []byte { return scriptBytes }

// Path extracts the embedded script to a stable, content-addressed cache path
// and returns it, writing the file only if it is missing or stale. The
// content-addressed name means a binary upgrade that changes the script writes a
// new file rather than reusing an outdated one. Safe to call concurrently and
// repeatedly; the extraction runs at most once per process.
//
// The cache dir is $XDG_CACHE_HOME/dontguess (or ~/.cache/dontguess), falling
// back to $TMPDIR. Returns "" and an error only if no writable location exists.
func Path() (string, error) {
	once.Do(func() {
		sum := sha256.Sum256(scriptBytes)
		name := "embed_minilm." + hex.EncodeToString(sum[:8]) + ".py"

		dir := cacheDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			cachedErr = fmt.Errorf("embedscript: mkdir cache %s: %w", dir, err)
			return
		}
		p := filepath.Join(dir, name)

		// Write only if absent or contents differ (idempotent across restarts).
		if existing, err := os.ReadFile(p); err != nil || !sameBytes(existing, scriptBytes) {
			tmp := p + ".tmp"
			if err := os.WriteFile(tmp, scriptBytes, 0o755); err != nil {
				cachedErr = fmt.Errorf("embedscript: write %s: %w", tmp, err)
				return
			}
			if err := os.Rename(tmp, p); err != nil {
				cachedErr = fmt.Errorf("embedscript: rename %s: %w", p, err)
				return
			}
		}
		cachedPath = p
	})
	return cachedPath, cachedErr
}

func cacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "dontguess")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "dontguess")
	}
	return filepath.Join(os.TempDir(), "dontguess")
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
