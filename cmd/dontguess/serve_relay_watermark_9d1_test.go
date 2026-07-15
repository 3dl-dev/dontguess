package main

// serve_relay_watermark_9d1_test.go — dontguess-9d1 (b60 LOW fold-in): the empty
// climb-watermark sidecar must FAIL LOUD, not fail open.
//
// establishClimbWatermark's empty-file branch previously `return 0, nil`, which
// silently DISABLES the climb egress fence (watermark 0 fences nothing). An empty
// or truncated sidecar + a fresh relay cursor would then re-broadcast the entire
// pre-climb plaintext corpus. writeClimbWatermarkFile always writes at least
// "0\n", so an empty file is never a state we produced — it is corruption, and
// must be treated like the negative / non-numeric cases (loud error), never as 0.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEstablishClimbWatermark_EmptyFile_FailsLoud(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"whitespace-only": "   \n\t ",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "climb-egress.watermark")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("write watermark file: %v", err)
			}
			// ls is never read on the empty-file branch — the guard fires first.
			w, err := establishClimbWatermark(path, nil)
			if err == nil {
				t.Fatalf("establishClimbWatermark returned nil error for an empty sidecar (w=%d) — the fence is silently DISABLED (fail-open regression)", w)
			}
			if w != 0 {
				t.Fatalf("expected watermark 0 alongside the error, got %d", w)
			}
		})
	}
}

// TestEstablishClimbWatermark_ValidZero_StillReadsClean is the control: a
// well-formed "0\n" sidecar (exactly what writeClimbWatermarkFile persists for a
// born-fleet operator) must still read back cleanly as 0 — proving the empty-file
// error above is specifically about emptiness, not any file containing 0.
func TestEstablishClimbWatermark_ValidZero_StillReadsClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "climb-egress.watermark")
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatalf("write watermark file: %v", err)
	}
	w, err := establishClimbWatermark(path, nil)
	if err != nil {
		t.Fatalf("establishClimbWatermark on a valid '0' sidecar returned error: %v", err)
	}
	if w != 0 {
		t.Fatalf("watermark = %d, want 0", w)
	}
}
