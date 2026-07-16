package embedscript

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestEmbeddedScriptMatchesCanonical is the drift guard: the embedded copy MUST
// be byte-for-byte identical to the canonical cmd/embed/main.py. If you edit one,
// re-copy it to the other, or dense embeddings ship stale/divergent.
func TestEmbeddedScriptMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile(filepath.Join("..", "..", "cmd", "embed", "main.py"))
	if err != nil {
		t.Fatalf("read canonical cmd/embed/main.py: %v", err)
	}
	if !bytes.Equal(canonical, Bytes()) {
		t.Fatalf("embedded embed_minilm.py has drifted from cmd/embed/main.py "+
			"(embedded=%d bytes, canonical=%d bytes) — re-copy: cp cmd/embed/main.py pkg/embedscript/embed_minilm.py",
			len(Bytes()), len(canonical))
	}
}

// TestEmbeddedScriptIsNonTrivial guards against an empty/corrupt embed.
func TestEmbeddedScriptIsNonTrivial(t *testing.T) {
	if len(Bytes()) < 1000 {
		t.Fatalf("embedded script suspiciously small: %d bytes", len(Bytes()))
	}
	if !bytes.Contains(Bytes(), []byte("all-MiniLM-L6-v2")) {
		t.Error("embedded script does not reference the expected model")
	}
}

// TestPathExtractsRunnableScript verifies Path() writes a file whose contents
// match the embedded bytes and is idempotent across calls.
func TestPathExtractsRunnableScript(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// Reset the extraction memo so this test drives a fresh extraction.
	once = sync.Once{}
	cachedPath, cachedErr = "", nil

	p, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read extracted %s: %v", p, err)
	}
	if !bytes.Equal(got, Bytes()) {
		t.Error("extracted script contents differ from embedded bytes")
	}
	// Idempotent: second call returns the same path without error.
	p2, err := Path()
	if err != nil || p2 != p {
		t.Errorf("Path not idempotent: p=%q p2=%q err=%v", p, p2, err)
	}
}
