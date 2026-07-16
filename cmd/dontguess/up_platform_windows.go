//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// up_platform_windows.go — Windows implementations of the platform-specific
// primitives in up_platform_unix.go. `dontguess up`'s detached-serve flow is a
// Unix-first operational path (systemd --user, unix sockets), but the binary
// must still build and run on windows/amd64 (v0.7.0 shipped a windows asset),
// so these give a faithful equivalent: LockFileEx for the single-writer lock,
// CREATE_NEW_PROCESS_GROUP to detach the spawned serve.

// flockTryExclusive attempts a non-blocking exclusive lock on f via LockFileEx
// with LOCKFILE_FAIL_IMMEDIATELY. A lock held by another process surfaces as
// ERROR_LOCK_VIOLATION, mapped to (false, nil) to mirror the Unix EWOULDBLOCK
// contract.
func flockTryExclusive(f *os.File) (bool, error) {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

// flockUnlock releases the lock held on f.
func flockUnlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}

// setDetachedProcAttr detaches the spawned serve into a new process group so it
// survives the parent exiting (the closest Windows analogue to setsid).
func setDetachedProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
