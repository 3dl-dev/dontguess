package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestListenOperatorSocket_RefusesToClobberLiveOperator is the dontguess-884
// guarantee: an unconfigured client's auto-started serve must NEVER clobber a
// running operator. listenOperatorSocket probes the path first; a live socket
// makes it fail closed instead of unlinking the real operator's listener + pidfile
// out from under it.
func TestListenOperatorSocket_RefusesToClobberLiveOperator(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "op.sock")

	// A live operator holds the socket. A bound unix listener accepts connects into
	// its backlog even without an explicit Accept loop, so the liveness probe sees it.
	ln1, err := listenOperatorSocket(path)
	if err != nil {
		t.Fatalf("first (real operator) bind failed: %v", err)
	}
	defer ln1.Close()

	// A second operator on the SAME DG_HOME socket must refuse — not clobber.
	ln2, err := listenOperatorSocket(path)
	if err == nil {
		ln2.Close()
		t.Fatal("second listenOperatorSocket CLOBBERED the live operator instead of failing closed")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected an 'already running' refusal, got: %v", err)
	}

	// The real operator's socket must still be live (not unlinked).
	conn, derr := net.DialTimeout("unix", path, time.Second)
	if derr != nil {
		t.Fatalf("real operator's socket was clobbered — dial failed: %v", derr)
	}
	_ = conn.Close()
}

// TestListenOperatorSocket_RebindsStaleSocket: a crash-leftover socket file with
// no live listener must still be removed and rebound (fail-closed only applies to
// a LIVE owner, never a stale path).
func TestListenOperatorSocket_RebindsStaleSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "op.sock")

	// Leftover file at the socket path, nothing listening (simulates a crash).
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed stale socket file: %v", err)
	}
	ln, err := listenOperatorSocket(path)
	if err != nil {
		t.Fatalf("stale socket should be reclaimed and rebound, got: %v", err)
	}
	_ = ln.Close()
}
