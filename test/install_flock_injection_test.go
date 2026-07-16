// Package scale_test — install.sh flock subshell shell-injection regression (dontguess-732).
//
// The production wrapper (embedded as a heredoc in site/install.sh) auto-starts
// the operator inside a `flock ... sh -c '...'` subshell. The vulnerable version
// string-interpolated DG_HOME, DG_OP, PID_FILE, and LOG into that single-quoted
// command text by breaking out of the quote:
//
//	nohup env CF_HOME="'"$DG_HOME"'" "'"$DG_OP"'" serve >"'"$LOG"'" 2>&1 &
//
// A DG_HOME or DG_OP value containing a single quote (and shell metacharacters)
// breaks out of the literal and executes injected commands at operator-launch.
//
// These tests prove the fix by exercising the REAL wrapper code path: the wrapper
// bytes are extracted verbatim from site/install.sh (the exact bytes the installer
// writes to ~/.local/bin/dontguess) — no hand-written fixture, no stub of the code
// under test. The tests:
//
//  1. TestInstall_FlockInjection_DGHome / _DGOp — set DG_HOME / DG_OP to a value
//     containing a single quote plus a command-injection canary, drive the wrapper
//     so the flock subshell runs, and assert the canary file was NOT created.
//  2. TestInstall_FlockBenignStillWorks — drive the wrapper with a benign DG_HOME
//     and assert the operator-start path still functions (the operator stub is
//     exec'd with the right CF_HOME and a PID file is written).
package scale_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// extractWrapperFromInstaller reads site/install.sh, finds the
// `cat > ... <<'ENDWRAPPER' ... ENDWRAPPER` heredoc, and returns the exact wrapper
// bytes the installer writes. This guarantees the test exercises the real,
// shipped wrapper code — not a copy that could drift.
func extractWrapperFromInstaller(t *testing.T) string {
	t.Helper()
	// Locate the repo root by walking up until we find site/install.sh.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	var installPath string
	for d := dir; ; {
		cand := filepath.Join(d, "site", "install.sh")
		if _, err := os.Stat(cand); err == nil {
			installPath = cand
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatalf("could not locate site/install.sh walking up from %s", dir)
		}
		d = parent
	}
	data, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("reading %s: %v", installPath, err)
	}
	// Match: cat > "..." <<'ENDWRAPPER'\n  <body>  \nENDWRAPPER
	re := regexp.MustCompile(`(?s)<<'ENDWRAPPER'\n(.*?)\nENDWRAPPER`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatalf("could not find ENDWRAPPER heredoc in %s", installPath)
	}
	body := string(m[1])
	if !strings.Contains(body, "flock") {
		t.Fatalf("extracted wrapper does not contain the flock auto-start block; extraction is wrong")
	}
	return body
}

// installerScene sets up a directory tree that lets the extracted wrapper reach
// the flock auto-start path: a bin dir with a recording operator stub + cf stub,
// and a DG_HOME with a valid exchange config but NO live operator PID (so the
// wrapper tries to start one).
type installerScene struct {
	testDir string
	binDir  string
	wrapper string // path to the extracted wrapper, made executable
	opLog   string // operator stub records its argv + env here
	canary  string // file the injection payload would create
}

func newInstallerScene(t *testing.T) *installerScene {
	t.Helper()
	testDir := t.TempDir()
	binDir := filepath.Join(testDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	opLog := filepath.Join(testDir, "operator.log")
	canary := filepath.Join(testDir, "PWNED_CANARY")

	// Recording operator stub. The wrapper's flock body does:
	//   nohup env DG_HOME=... <DG_OP> serve ...
	// (nostr-first: the serve process is pinned to DG_HOME, not CF_HOME — cf is
	// gone entirely.) This stub records that it was invoked with the right DG_HOME
	// + argv, then exits so the wrapper's start logic completes. (It does NOT stay
	// resident as a "dontguess-operator" process, so the post-start probe path will
	// not falsely pass — but the injection assertion does not depend on the probe.)
	opStub := "#!/bin/sh\n" +
		"{ echo \"OP_INVOKED dg_home=$DG_HOME\"; echo \"argv=$*\"; } >> " + shellQuote(opLog) + "\n" +
		"exit 0\n"
	if err := writeExecFile(t, filepath.Join(binDir, "dontguess-operator"), []byte(opStub)); err != nil {
		t.Fatalf("writing operator stub: %v", err)
	}

	// Extract and install the REAL wrapper.
	wrapperSrc := extractWrapperFromInstaller(t)
	wrapperPath := filepath.Join(binDir, "dontguess")
	if err := writeExecFile(t, wrapperPath, []byte(wrapperSrc)); err != nil {
		t.Fatalf("writing extracted wrapper: %v", err)
	}

	return &installerScene{
		testDir: testDir,
		binDir:  binDir,
		wrapper: wrapperPath,
		opLog:   opLog,
		canary:  canary,
	}
}

// shellQuote single-quotes s for safe embedding in a /bin/sh script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// makeDGHome creates a DG_HOME dir at the given path with a valid exchange config
// and no operator PID, so the wrapper enters the flock auto-start path.
func makeDGHome(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir DG_HOME %q: %v", path, err)
	}
	// Nostr-first config (dontguess-ed2): the wrapper no longer parses an
	// exchange_campfire_id — the individual-tier config check is existence-only,
	// and the operator reads DONTGUESS_RELAY_URLS + the operator key itself. Write
	// the current config shape (operator_key / operator_npub).
	const fakeOpKey = "aabbcc1122334455aabbcc1122334455aabbcc1122334455aabbcc1122334455"
	cfg := fmt.Sprintf(`{"operator_key": %q, "operator_npub": "npub1fake"}`, fakeOpKey)
	if err := os.WriteFile(filepath.Join(path, "dontguess-exchange.json"), []byte(cfg), 0644); err != nil {
		t.Fatalf("writing exchange config: %v", err)
	}
	// No dontguess.pid → pid_is_operator returns false → flock auto-start runs.
}

// runWrapper executes the wrapper with the given env additions and returns combined output.
func (s *installerScene) runWrapper(t *testing.T, dgHome, dgOp string, extraEnv ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(s.wrapper, "buy", "--task", "injection probe", "--budget", "100")
	cmd.Dir = s.testDir // hermetic: never inherit a stray .dg/ from the repo cwd (dontguess-884)
	env := []string{
		"HOME=" + s.testDir,
		"PATH=" + s.binDir + ":" + os.Getenv("PATH"),
		"DG_HOME=" + dgHome,
		// Ensure no inherited CI synthetic-injection noise affects the path.
		"DG_SYNTHETIC=0",
	}
	if dgOp != "" {
		env = append(env, "DG_OP="+dgOp)
	}
	env = append(env, extraEnv...)
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// TestInstall_FlockInjection_DGHome proves a DG_HOME containing a single quote +
// a command-injection payload does NOT execute injected commands when the wrapper
// reaches the flock auto-start subshell.
//
// DG_HOME is used to build PID_FILE/LOG/LOCK and is interpolated into the flock
// body in the vulnerable version (`CF_HOME="'"$DG_HOME"'"`). We point DG_HOME at a
// REAL directory whose name carries the payload, so the config check passes and the
// flock body runs with the malicious value.
func TestInstall_FlockInjection_DGHome(t *testing.T) {
	t.Parallel()
	s := newInstallerScene(t)

	// The directory name itself is the injection payload. In the vulnerable
	// version DG_HOME lands inside double quotes: CF_HOME="<DG_HOME>". A double
	// quote closes that string, `; touch <canary> ;` runs, and a trailing double
	// quote re-balances. (Single quotes would be inert there — the value sits in a
	// double-quoted context — so the payload deliberately uses a double quote.)
	payloadDir := filepath.Join(s.testDir, `dg"; touch `+s.canary+` ; echo "`)
	makeDGHome(t, payloadDir)

	out, _ := s.runWrapper(t, payloadDir, "" /* default DG_OP */)
	t.Logf("wrapper output:\n%s", out)

	if _, err := os.Stat(s.canary); err == nil {
		t.Fatalf("INJECTION EXECUTED: canary %s was created — DG_HOME shell injection succeeded", s.canary)
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error on canary: %v", err)
	}
	t.Logf("DG_HOME injection blocked: canary %s was NOT created", s.canary)
}

// TestInstall_FlockInjection_DGOp proves a DG_OP containing shell metacharacters +
// a command-injection payload does NOT execute injected commands. DG_OP is the
// operator binary path interpolated as `"'"$DG_OP"'"` in the vulnerable flock body.
func TestInstall_FlockInjection_DGOp(t *testing.T) {
	t.Parallel()
	s := newInstallerScene(t)

	dgHome := filepath.Join(s.testDir, "dg_home")
	makeDGHome(t, dgHome)

	// DG_OP payload: in the vulnerable version DG_OP lands inside double quotes
	// ("$DG_OP"), so a double quote breaks out, `; touch <canary> ;` runs, and a
	// trailing double quote re-balances. If injection is blocked, the wrapper
	// instead tries to exec a binary literally named with this payload → fails to
	// start the operator (which is fine; we only assert the canary did not run).
	dgOp := `x"; touch ` + s.canary + ` ; echo "`

	out, _ := s.runWrapper(t, dgHome, dgOp)
	t.Logf("wrapper output:\n%s", out)

	if _, err := os.Stat(s.canary); err == nil {
		t.Fatalf("INJECTION EXECUTED: canary %s was created — DG_OP shell injection succeeded", s.canary)
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error on canary: %v", err)
	}
	t.Logf("DG_OP injection blocked: canary %s was NOT created", s.canary)
}

// TestInstall_FlockBenignStillWorks proves the wrapper's flock auto-start path
// still functions normally with a benign DG_HOME: it execs the operator stub with
// CF_HOME pinned to DG_HOME and writes a PID file. This guards against the fix
// breaking normal operation (e.g. mis-passed env vars).
func TestInstall_FlockBenignStillWorks(t *testing.T) {
	t.Parallel()
	s := newInstallerScene(t)

	dgHome := filepath.Join(s.testDir, "benign_home")
	makeDGHome(t, dgHome)
	dgOp := filepath.Join(s.binDir, "dontguess-operator")

	out, _ := s.runWrapper(t, dgHome, dgOp)
	t.Logf("wrapper output:\n%s", out)

	// 1. The operator stub must have been invoked (proves the flock body ran the
	//    nohup env ... serve line) with DG_HOME pinned (nostr-first: CF_HOME is gone).
	logData, err := os.ReadFile(s.opLog)
	if err != nil {
		t.Fatalf("operator was not invoked (no log %s): %v\nwrapper output:\n%s", s.opLog, err, out)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "OP_INVOKED") {
		t.Fatalf("operator stub not invoked; log:\n%s", logStr)
	}
	if !strings.Contains(logStr, "dg_home="+dgHome) {
		t.Errorf("operator DG_HOME not pinned.\nwant dg_home=%s\ngot log:\n%s", dgHome, logStr)
	}
	if !strings.Contains(logStr, "argv=serve") {
		t.Errorf("operator not invoked with 'serve'; got log:\n%s", logStr)
	}

	// 2. A PID file must have been written into DG_HOME by the flock body.
	pidPath := filepath.Join(dgHome, "dontguess.pid")
	if _, err := os.Stat(pidPath); err != nil {
		t.Errorf("flock body did not write PID file %s: %v", pidPath, err)
	}

	t.Logf("Benign DG_HOME path works: operator started with pinned CF_HOME and PID written")
}

// TestInstall_HealthProbeDeadlineHonored proves the DONTGUESS_HEALTH_PROBE_DEADLINE
// env knob actually controls the wrapper's operator-wait deadline, rather than
// being dead code with a hardcoded timeout.
//
// It exercises the knob DETERMINISTICALLY by holding the wrapper's start-lock
// (${DG_HOME}/dontguess.start.lock) for the whole invocation. That forces the
// wrapper's `flock -n "$LOCK"` to fail on every run, so it takes the lost-flock
// probe branch (site/install.sh ~line 321), whose loop polls for a PID that can
// never appear (nobody can start the operator while we hold the lock) for exactly
// DONTGUESS_HEALTH_PROBE_DEADLINE seconds. The wrapper's wall-clock runtime is
// therefore the probe deadline, and it tracks the knob.
//
// Why not drive the post-start readiness loop (~line 347) directly: that path is
// gated on `_i_started_operator -eq 1`, which flips based on whether the flock
// body found a pre-existing operator PID — a non-deterministic branch. An earlier
// alive-stub version of this test relied on that branch and passed locally but
// FLAKED ON CI (the wrapper took the _i_started_operator=0 branch, skipped the
// readiness loop entirely, exec'd the buy stub and "succeeded"). Holding the lock
// removes that non-determinism: the lost-flock probe path is taken on every run,
// in every environment. Both wait loops read the same ${DONTGUESS_HEALTH_PROBE_DEADLINE:-N}
// knob, so proving it at the probe site proves the knob is wired.
func TestInstall_HealthProbeDeadlineHonored(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, deadlineSecs string) time.Duration {
		t.Helper()
		testDir := t.TempDir()
		binDir := filepath.Join(testDir, "bin")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatalf("mkdir bin: %v", err)
		}

		// Instant-exit operator stub. Because we hold the start-lock, the operator is
		// never actually started, so this stub is only ever invoked for the final buy
		// dispatch, where it must return promptly (no sleep) — the measured runtime is
		// then the probe deadline alone. If the lock-hold ever failed, the wrapper would
		// win the flock, start this stub, watch it exit, hit the dead-PID break and
		// return in ~0.2s, which makes the discrimination assertion below fail LOUDLY
		// rather than hang for a live stub's lifetime.
		opStub := "#!/bin/sh\nexit 0\n"
		if err := writeExecFile(t, filepath.Join(binDir, "dontguess-operator"), []byte(opStub)); err != nil {
			t.Fatalf("writing operator stub: %v", err)
		}

		wrapperSrc := extractWrapperFromInstaller(t)
		wrapperPath := filepath.Join(binDir, "dontguess")
		if err := writeExecFile(t, wrapperPath, []byte(wrapperSrc)); err != nil {
			t.Fatalf("writing extracted wrapper: %v", err)
		}

		dgHome := filepath.Join(testDir, "dg_home")
		makeDGHome(t, dgHome)
		dgOp := filepath.Join(binDir, "dontguess-operator")

		// Hold the wrapper's start-lock so its `flock -n` cannot win. flock(2) (what
		// syscall.Flock takes) is the same advisory lock util-linux `flock` uses, so a
		// held LOCK_EX here deterministically blocks the wrapper's LOCK_NB acquisition.
		lockPath := filepath.Join(dgHome, "dontguess.start.lock")
		lockF, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("open start-lock: %v", err)
		}
		defer lockF.Close()
		if err := syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("acquire start-lock: %v", err)
		}
		defer func() { _ = syscall.Flock(int(lockF.Fd()), syscall.LOCK_UN) }()

		cmd := exec.Command(wrapperPath, "buy", "--task", "deadline probe", "--budget", "100")
		cmd.Dir = testDir // hermetic: never inherit a stray .dg/ from the repo cwd (dontguess-884)
		cmd.Env = []string{
			"HOME=" + testDir,
			"PATH=" + binDir + ":" + os.Getenv("PATH"),
			"DG_HOME=" + dgHome,
			"DG_OP=" + dgOp,
			"DG_SYNTHETIC=0",
			"DONTGUESS_HEALTH_PROBE_DEADLINE=" + deadlineSecs,
		}
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf

		start := time.Now()
		_ = cmd.Run() // exit code is irrelevant; the knob's effect is the time spent in the probe loop
		elapsed := time.Since(start)
		t.Logf("deadline=%s elapsed=%s output:\n%s", deadlineSecs, elapsed, buf.String())
		return elapsed
	}

	elapsed1 := run(t, "1")
	elapsed5 := run(t, "5")

	// Mutation-proof lower bound: with the knob honored, deadline=1 spends ~1s in the
	// probe loop. If the knob were dead code (hardcoded 5s default), this would be ~5s.
	if elapsed1 >= 3*time.Second {
		t.Fatalf("DONTGUESS_HEALTH_PROBE_DEADLINE=1 took %s, expected ~1s (well under 3s) — the deadline knob is not being honored (dead code)", elapsed1)
	}
	// deadline=5 must actually spend ~5s in the probe loop — proves the knob value is
	// read, not a fixed small timeout the knob happens not to affect.
	if elapsed5 < 4*time.Second {
		t.Fatalf("DONTGUESS_HEALTH_PROBE_DEADLINE=5 took %s, expected ~5s — the knob does not control the probe deadline", elapsed5)
	}
	// Discriminating power: the runtime must track the knob across a wide gap.
	if elapsed5-elapsed1 < 3*time.Second {
		t.Fatalf("expected deadline=5 (%s) to exceed deadline=1 (%s) by >=3s — wall-clock runtime must track the knob", elapsed5, elapsed1)
	}
}
