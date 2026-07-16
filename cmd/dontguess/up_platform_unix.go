//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// up_platform_unix.go — Unix implementations of the platform-specific process
// and advisory-lock primitives spawnDetachedServe / lockWithTimeout need. The
// Windows equivalents live in up_platform_windows.go. Splitting these out keeps
// up.go portable so the release cross-compile (linux/darwin/windows) builds on
// every target (dontguess-a72 release fix — up.go's raw syscall.Flock/Setsid
// broke the windows/amd64 build once up.go landed post-v0.7.0).

// flockTryExclusive attempts a non-blocking exclusive advisory lock on f.
// Returns (true, nil) if acquired, (false, nil) if another process holds it,
// or (false, err) on any other error.
func flockTryExclusive(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if err == syscall.EWOULDBLOCK {
		return false, nil
	}
	return false, err
}

// flockUnlock releases the advisory lock held on f.
func flockUnlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// setDetachedProcAttr makes cmd start in its own session (setsid) so it
// survives the parent `dontguess up` process exiting.
func setDetachedProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
