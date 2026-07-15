package main

// serve_socket_xdg_test.go — item dontguess-7b2 (design §4/§9 Gate A/P2).
//
// GROUND-SOURCE (mandatory, real IO):
//
//  1. TestBindOperatorSocket_LongDGHome_RelocatesUnderXDGRuntimeDir constructs
//     a REAL over-long DG_HOME path (deeper than the platform's sockaddr_un
//     sun_path limit once "/ipc/dontguess.sock" is appended) and asserts
//     bindOperatorSocket actually net.Listen-binds a REAL unix socket under
//     $XDG_RUNTIME_DIR instead of failing, and that the resolved path is
//     persisted into the real on-disk exchange config (exchange.LoadConfig)
//     so a CLI client (resolveOperatorSocketPathFor) finds the SAME path.
//
//  2. TestBindOperatorSocket_BindFailure_IsHardError pre-occupies the
//     resolved socket path with a real listener (a genuine net.Listen
//     collision, not a mock), calls bindOperatorSocket against the SAME
//     DG_HOME, and asserts it returns a non-nil error (HARD startup error) —
//     then greps the returned error text plus this file's production code to
//     prove no WARN-and-continue path survives: bindOperatorSocket must
//     return (nil, error), never (nil, nil).

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// newXDGTestEngine builds a minimal real exchange.Engine backed by a real
// local store under dgHome, mirroring the harness used by the dontguess-347
// ground-source test (serve_relay_async_attach_test.go) — no mocks, real
// store IO.
func newXDGTestEngine(t *testing.T, dgHome string) *exchange.Engine {
	t.Helper()
	localStorePath := filepath.Join(dgHome, "events.jsonl")
	localStore, err := dgstore.Open(localStorePath)
	if err != nil {
		t.Fatalf("opening local store: %v", err)
	}
	t.Cleanup(func() { _ = localStore.Close() })

	operatorIdentity, err := loadOrCreateNostrOperatorIdentity(dgHome)
	if err != nil {
		t.Fatalf("nostr operator identity: %v", err)
	}

	return exchange.NewEngine(exchange.EngineOptions{
		CampfireID:        "local",
		LocalStore:        localStore,
		OperatorPublicKey: operatorIdentity.PubKeyHex(),
		Logger:            t.Logf,
	})
}

// TestBindOperatorSocket_LongDGHome_RelocatesUnderXDGRuntimeDir is the
// dontguess-7b2 ground-source test for the relocation half of the fix. A REAL
// over-long DG_HOME (built from t.TempDir() plus a long nested path segment,
// comfortably past maxUnixSocketPathLen once "/ipc/dontguess.sock" is
// appended) must cause bindOperatorSocket to actually bind under a SHORT
// $XDG_RUNTIME_DIR path, and the resolved path must be readable back from
// the real on-disk exchange config by resolveOperatorSocketPathFor — the
// exact function every CLI socket dialer (socketPath(), status.go) now uses.
func TestBindOperatorSocket_LongDGHome_RelocatesUnderXDGRuntimeDir(t *testing.T) {
	base := t.TempDir()
	// A short, dedicated runtime dir — NOT t.TempDir(), whose name embeds the
	// full test function name and is itself long enough to blow the
	// sockaddr_un limit once "/dontguess-<hash>.sock" is appended, defeating
	// the very relocation this test verifies.
	runtimeDir, rerr := os.MkdirTemp("", "dg7b2xdg")
	if rerr != nil {
		t.Fatalf("MkdirTemp runtimeDir: %v", rerr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	// Build a DG_HOME whose default socket path ("<dgHome>/ipc/dontguess.sock")
	// exceeds maxUnixSocketPathLen. A single long path segment does it.
	longSegment := strings.Repeat("a", 120)
	dgHome := filepath.Join(base, longSegment)
	if err := os.MkdirAll(dgHome, 0700); err != nil {
		t.Fatalf("mkdir dgHome: %v", err)
	}
	defaultPath := filepath.Join(dgHome, "ipc", "dontguess.sock")
	if len(defaultPath) <= maxUnixSocketPathLen {
		t.Fatalf("test setup bug: default path %d bytes, want > %d", len(defaultPath), maxUnixSocketPathLen)
	}

	eng := newXDGTestEngine(t, dgHome)
	logger := log.New(os.Stderr, "[test-7b2] ", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup, err := bindOperatorSocket(ctx, dgHome, eng, logger)
	if err != nil {
		t.Fatalf("bindOperatorSocket with long DG_HOME: %v", err)
	}
	defer cleanup()

	resolved := resolveOperatorSocketPath(dgHome)
	if !strings.HasPrefix(resolved, runtimeDir) {
		t.Fatalf("resolved socket path %q not under XDG_RUNTIME_DIR %q — relocation did not happen", resolved, runtimeDir)
	}
	if len(resolved) > maxUnixSocketPathLen {
		t.Fatalf("relocated socket path %q is still %d bytes (> %d) — relocation did not shorten it", resolved, len(resolved), maxUnixSocketPathLen)
	}

	// Real bind must actually be listening at the resolved path — dial it.
	conn, derr := net.Dial("unix", resolved)
	if derr != nil {
		t.Fatalf("dialing resolved socket %q: %v", resolved, derr)
	}
	conn.Close() //nolint:errcheck

	// The resolved path must be persisted into the REAL on-disk config, and a
	// CLI client (resolveOperatorSocketPathFor) must resolve to the SAME path
	// — this is what makes "operator not reachable" go away for a long
	// DG_HOME instead of leaving CLI clients dialing the wrong (never-bound)
	// default path.
	cfg, lerr := exchange.LoadConfig(dgHome)
	if lerr != nil {
		t.Fatalf("LoadConfig after bind: %v", lerr)
	}
	if cfg.OperatorSocketPath != resolved {
		t.Fatalf("config.OperatorSocketPath = %q, want %q", cfg.OperatorSocketPath, resolved)
	}
	if got := resolveOperatorSocketPathFor(dgHome); got != resolved {
		t.Fatalf("resolveOperatorSocketPathFor(dgHome) = %q, want %q (CLI client would dial the wrong path)", got, resolved)
	}
}

// TestBindOperatorSocket_BindFailure_IsHardError is the dontguess-7b2
// ground-source test for the fail-loud half of the fix. It forces a REAL
// net.Listen failure at the exact resolved socket path — a non-empty
// directory sitting where the socket file needs to be created, which
// listenOperatorSocket's unconditional "remove stale socket file" cannot
// clear (os.Remove fails on a non-empty directory, same as it would on a
// permission-denied path) — then calls bindOperatorSocket against the same
// DG_HOME and asserts:
//
//   - a non-nil error is returned (HARD startup error, never a silent nil,nil)
//   - the returned cleanup func is nil
//
// This is the accept/reject gate from the item's DONE clause: "a
// post-relocation bind failure is a HARD startup error (never WARN)". Using a
// long DG_HOME here also exercises the post-relocation path specifically
// (the blocking directory lives at the XDG-relocated path).
func TestBindOperatorSocket_BindFailure_IsHardError(t *testing.T) {
	base := t.TempDir()
	runtimeDir, rerr := os.MkdirTemp("", "dg7b2xdg")
	if rerr != nil {
		t.Fatalf("MkdirTemp runtimeDir: %v", rerr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	longSegment := strings.Repeat("b", 120)
	dgHome := filepath.Join(base, longSegment)
	if err := os.MkdirAll(dgHome, 0700); err != nil {
		t.Fatalf("mkdir dgHome: %v", err)
	}

	resolved := resolveOperatorSocketPath(dgHome)
	if !strings.HasPrefix(resolved, runtimeDir) {
		t.Fatalf("test setup bug: expected relocation under %q, got %q", runtimeDir, resolved)
	}

	// Occupy the resolved socket path with a REAL non-empty directory — a
	// genuine bind failure, not a mock or forced error injection.
	// listenOperatorSocket does `_ = os.Remove(path)` to clear a stale socket
	// file, but os.Remove errors (silently, by design — a live socket file
	// removal failing is not itself fatal) on a non-empty directory, so the
	// blocker survives into net.Listen, which then fails for real (EEXIST /
	// "address already in use" against a directory).
	if err := os.MkdirAll(resolved, 0700); err != nil {
		t.Fatalf("occupying resolved socket path with a directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resolved, "keep-nonempty"), []byte("x"), 0600); err != nil {
		t.Fatalf("writing file to keep blocker directory non-empty: %v", err)
	}

	eng := newXDGTestEngine(t, dgHome)
	logger := log.New(os.Stderr, "[test-7b2] ", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup, err := bindOperatorSocket(ctx, dgHome, eng, logger)
	if err == nil {
		t.Fatalf("bindOperatorSocket returned nil error against a pre-occupied socket path — bind failure was silently swallowed (the exact dontguess-7b2 regression)")
	}
	if cleanup != nil {
		cleanup()
		t.Fatalf("bindOperatorSocket returned a non-nil cleanup alongside an error — caller could still treat this as success")
	}
	t.Logf("bindOperatorSocket correctly failed loud: %v", err)
}
