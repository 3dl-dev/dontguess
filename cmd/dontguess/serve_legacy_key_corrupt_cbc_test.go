package main

// serve_legacy_key_corrupt_cbc_test.go — ground-source proof for dontguess-cbc:
// a corrupt/truncated legacy local-operator.key must never panic the climb.
//
// Before the fix, loadLegacyLocalOperatorKey returned the raw trimmed file
// contents with no length check. A pre-P3 home whose local-operator.key was
// truncated to fewer than 16 bytes (disk corruption, partial write, manual
// edit) would sail through loadLegacyLocalOperatorKey unchecked, reach
// applyLegacyOperatorAlias, and panic on legacyOperatorKey[:16] — crashing
// serve startup on the climb (index out of range).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// TestLoadLegacyLocalOperatorKey_CorruptFile_ClearErrorNotPanic writes a 5-char
// (truncated) local-operator.key — well under the 32-hex-char key
// loadOrCreateLocalOperatorKey always produces — and drives the exact read path
// runServeLocal uses on the climb (loadLegacyLocalOperatorKey). It must return a
// clear, actionable error instead of the raw corrupt bytes, so the caller (serve's
// climb) fails loudly at the read site instead of panicking later inside
// applyLegacyOperatorAlias's [:16] slice.
func TestLoadLegacyLocalOperatorKey_CorruptFile_ClearErrorNotPanic(t *testing.T) {
	dgHome := t.TempDir()
	keyPath := filepath.Join(dgHome, "local-operator.key")
	if err := os.WriteFile(keyPath, []byte("ab12x"), 0o600); err != nil {
		t.Fatalf("seed corrupt local-operator.key: %v", err)
	}

	key, err := loadLegacyLocalOperatorKey(dgHome)
	if err == nil {
		t.Fatalf("loadLegacyLocalOperatorKey with a 5-char corrupt key = (%q, nil), want a clear error", key)
	}
	if key != "" {
		t.Fatalf("loadLegacyLocalOperatorKey returned a non-empty key (%q) alongside its error — the caller must not use it", key)
	}
	if !strings.Contains(err.Error(), "truncated or corrupt") {
		t.Fatalf("loadLegacyLocalOperatorKey error = %q, want a clear truncated/corrupt message", err.Error())
	}
	t.Logf("clear error surfaced (not a panic): %v", err)
}

// TestApplyLegacyOperatorAlias_ShortKey_NoPanic exercises the actual production
// slice site directly with a short key (defense in depth: even if some future
// caller bypasses loadLegacyLocalOperatorKey's validation, the [:16] slice inside
// applyLegacyOperatorAlias's log line must not panic).
func TestApplyLegacyOperatorAlias_ShortKey_NoPanic(t *testing.T) {
	st := exchange.NewState()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("applyLegacyOperatorAlias panicked on a short legacy key: %v", r)
		}
	}()

	applyLegacyOperatorAlias(st, "ab12x", "deadbeef0000000000000000000000000000000000000000000000000000", func(string, ...any) {})
}

// TestRunServeLocal_CorruptLegacyKey_ClearErrorNotPanic drives the actual climb
// (runServeLocal) against a dgHome seeded with a truncated legacy key, proving the
// end-to-end path — not just the two helpers in isolation — fails loudly instead of
// panicking.
func TestRunServeLocal_CorruptLegacyKey_ClearErrorNotPanic(t *testing.T) {
	dgHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(dgHome, "local-operator.key"), []byte("ab12x"), 0o600); err != nil {
		t.Fatalf("seed corrupt local-operator.key: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runServeLocal panicked on a corrupt legacy key instead of returning a clear error: %v", r)
		}
	}()

	err := runServeLocal(dgHome)
	if err == nil {
		t.Fatalf("runServeLocal with a corrupt legacy key = nil error, want a clear error")
	}
	if !strings.Contains(err.Error(), "legacy local operator key") {
		t.Fatalf("runServeLocal error = %q, want it to name the legacy local operator key as the cause", err.Error())
	}
}
