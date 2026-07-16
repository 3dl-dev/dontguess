// Package scale_test — nostr-first install END-TO-END regression (dontguess-ed2
// item ed2-H, design docs/design/nostr-first-client-ed2.md §6 item 9 + §7.6).
//
// This is the behavioral successor to the deleted cf-era test/e2e-install.sh: it
// drives the REAL shipped installer wrapper (extracted verbatim from
// site/install.sh, shared with install_flock_injection_test.go /
// install_nostr_wrapper_test.go) against a stubbed dontguess-operator binary in an
// isolated HOME/DG_HOME/PATH sandbox — no network. Where install_nostr_wrapper_test.go
// asserts the wrapper BYTES (grep-level), this test asserts the wrapper's BEHAVIOR
// when actually executed:
//
//  1. No cf: a poison `cf` binary is placed first on PATH; if the wrapper ever
//     dispatched through cf the poison fires a canary. Every verb must route to the
//     dontguess-operator binary instead (proven by the operator stub's invocation log).
//  2. H6 (design §3.10 / RT-C#2): the flock serve auto-start runs ONLY on the
//     individual tier. With DONTGUESS_RELAY_URLS UNSET the wrapper flock-auto-starts
//     a (stub) serve; with it SET (team tier) the wrapper NEVER auto-starts a local
//     operator — it dispatches the verb straight to the relay-attached binary.
//  3. The individual-tier put/buy path is reachable end-to-end through the wrapper:
//     the auto-started operator answers the dispatched buy and the wrapper streams
//     the operator's response back to the caller.
//
// The operator stub is a compiled Go binary literally named `dontguess-operator`
// so its /proc/<pid>/comm satisfies the wrapper's `pid_is_operator` gate
// (comm prefix "dontguess-oper") — a shell-script stub would report comm "sh" and
// the wrapper's readiness probe would (correctly) reject it.
package scale_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// stubOperatorPath is the path to the compiled dontguess-operator stub, built once
// by TestMain and shared (read-only) across the parallel subtests.
var stubOperatorPath string

// stubOperatorSrc is a minimal dontguess-operator stand-in. It records every
// invocation to $DG_STUB_LOG and, for `serve`, binds the IPC socket the wrapper
// probes for readiness and stays resident so pid_is_operator passes.
const stubOperatorSrc = `package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func logln(s string) {
	p := os.Getenv("DG_STUB_LOG")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, s)
}

func main() {
	verb := ""
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	switch verb {
	case "serve":
		logln(fmt.Sprintf("SERVE_INVOKED dg_home=%s relay=%q", os.Getenv("DG_HOME"), os.Getenv("DONTGUESS_RELAY_URLS")))
		dgHome := os.Getenv("DG_HOME")
		sockDir := filepath.Join(dgHome, "ipc")
		os.MkdirAll(sockDir, 0755)
		sock := filepath.Join(sockDir, "dontguess.sock")
		os.Remove(sock)
		l, err := net.Listen("unix", sock)
		if err != nil {
			logln("SERVE_LISTEN_ERR " + err.Error())
			os.Exit(1)
		}
		defer l.Close()
		// Stay resident: the wrapper's readiness probe checks the pid is still a
		// live operator AND that the socket exists.
		time.Sleep(60 * time.Second)
	default:
		logln(fmt.Sprintf("OP_INVOKED verb=%s args=%v relay=%q dg_home=%s", verb, os.Args[1:], os.Getenv("DONTGUESS_RELAY_URLS"), os.Getenv("DG_HOME")))
		switch verb {
		case "buy":
			fmt.Println("MATCH stub-cached-content")
		case "put":
			fmt.Println("PUT-ACCEPTED entry=stub")
		}
	}
}
`

// TestMain compiles the stub operator once (a real ELF so its comm matches the
// wrapper's pid_is_operator prefix) and runs the suite.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dg-stub-op")
	if err != nil {
		panic("mkdtemp stub op: " + err.Error())
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module dgstubop\n\ngo 1.25\n"), 0644); err != nil {
		panic("write stub go.mod: " + err.Error())
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(stubOperatorSrc), 0644); err != nil {
		panic("write stub main.go: " + err.Error())
	}
	out := filepath.Join(dir, "dontguess-operator")
	build := exec.Command("go", "build", "-o", out, ".")
	build.Dir = dir
	if b, err := build.CombinedOutput(); err != nil {
		panic("build stub operator: " + err.Error() + "\n" + string(b))
	}
	stubOperatorPath = out

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// e2eScene is an isolated install sandbox: a bin dir holding the extracted wrapper,
// the compiled operator stub, and a poison `cf` that fires a canary if ever invoked.
type e2eScene struct {
	testDir  string
	binDir   string
	wrapper  string // extracted wrapper, executable
	opBin    string // path to the operator stub (DG_OP)
	opLog    string // operator stub records verb + env here
	cfCanary string // created iff the wrapper ever dispatched through cf
}

func newE2EScene(t *testing.T) *e2eScene {
	t.Helper()
	testDir := t.TempDir()
	binDir := filepath.Join(testDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	// Operator stub → dontguess-operator (copy the compiled bytes; writeExecFile
	// closes the ETXTBSY race under ForkLock).
	opBin := filepath.Join(binDir, "dontguess-operator")
	stubBytes, err := os.ReadFile(stubOperatorPath)
	if err != nil {
		t.Fatalf("reading stub operator: %v", err)
	}
	if err := writeExecFile(t, opBin, stubBytes); err != nil {
		t.Fatalf("installing operator stub: %v", err)
	}

	// Poison cf: if the wrapper ever routes through cf, this fires the canary.
	cfCanary := filepath.Join(testDir, "CF_INVOKED")
	cfStub := "#!/bin/sh\ntouch " + shellQuote(cfCanary) + "\nexit 0\n"
	if err := writeExecFile(t, filepath.Join(binDir, "cf"), []byte(cfStub)); err != nil {
		t.Fatalf("installing cf poison: %v", err)
	}

	// The REAL shipped wrapper.
	wrapperSrc := extractWrapperFromInstaller(t)
	wrapperPath := filepath.Join(binDir, "dontguess")
	if err := writeExecFile(t, wrapperPath, []byte(wrapperSrc)); err != nil {
		t.Fatalf("installing wrapper: %v", err)
	}

	return &e2eScene{
		testDir:  testDir,
		binDir:   binDir,
		wrapper:  wrapperPath,
		opBin:    opBin,
		opLog:    filepath.Join(testDir, "op.log"),
		cfCanary: cfCanary,
	}
}

// dgHome returns a short DG_HOME path (kept short so the operator's unix socket
// stays under the ~108-byte sun_path limit) and seeds it with an exchange config.
func (s *e2eScene) dgHome(t *testing.T) string {
	t.Helper()
	h := filepath.Join(s.testDir, "h")
	makeDGHome(t, h) // shared helper: writes dontguess-exchange.json, no live pid
	return h
}

// run executes the wrapper with the given DG_HOME + extra env and args, returning
// combined output. It registers a cleanup that kills any operator the wrapper
// auto-started (pid recorded in DG_HOME/dontguess.pid).
func (s *e2eScene) run(t *testing.T, dgHome string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	t.Cleanup(func() { killPidFile(filepath.Join(dgHome, "dontguess.pid")) })

	cmd := exec.Command(s.wrapper, args...)
	// Run from an isolated cwd (never the repo tree). The wrapper's tier detection
	// walks UP from the cwd for a .dg/config.json (dontguess-884); a stray .dg/ in
	// an ancestor (e.g. the dontguess repo's own team-tier .dg/) would otherwise
	// flip an individual-tier case to team and skip the auto-start under test.
	cmd.Dir = s.testDir
	env := []string{
		"HOME=" + s.testDir,
		"PATH=" + s.binDir + ":" + os.Getenv("PATH"),
		"DG_HOME=" + dgHome,
		"DG_OP=" + s.opBin,
		"DG_STUB_LOG=" + s.opLog,
		// Keep args deterministic: no CI synthetic-tag injection.
		"DG_SYNTHETIC=0",
	}
	env = append(env, extraEnv...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *e2eScene) opLogContents(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(s.opLog)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("reading op log: %v", err)
	}
	return string(b)
}

func (s *e2eScene) assertNoCf(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(s.cfCanary); err == nil {
		t.Fatalf("wrapper dispatched through cf — canary %s was created (cf must be fully removed from the hot path)", s.cfCanary)
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error on cf canary: %v", err)
	}
}

// killPidFile best-effort SIGKILLs the pid recorded in a wrapper pid file.
func killPidFile(pidFile string) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// TestInstallE2E_IndividualTier_AutoStartsAndDispatches proves the individual tier
// (DONTGUESS_RELAY_URLS unset): the wrapper flock-auto-starts the operator, then the
// put AND buy verbs reach the operator binary and the buy's response streams back
// through the wrapper — never through cf.
func TestInstallE2E_IndividualTier_AutoStartsAndDispatches(t *testing.T) {
	t.Parallel()
	s := newE2EScene(t)
	dgHome := s.dgHome(t)

	// buy: unset DONTGUESS_RELAY_URLS → individual tier.
	buyOut, err := s.run(t, dgHome, []string{"DONTGUESS_RELAY_URLS="}, "buy", "--task", "reachability probe", "--budget", "100")
	if err != nil {
		t.Fatalf("wrapper buy failed: %v\noutput:\n%s", err, buyOut)
	}
	t.Logf("individual-tier buy output:\n%s", buyOut)

	log := s.opLogContents(t)

	// (H6) The individual tier auto-started serve.
	if !strings.Contains(log, "SERVE_INVOKED") {
		t.Errorf("individual tier did not auto-start serve; op log:\n%s", log)
	}
	if !strings.Contains(log, `relay=""`) {
		t.Errorf("serve was started with a non-empty relay set — individual tier must run relay-free; op log:\n%s", log)
	}
	// The buy reached the operator binary (not cf).
	if !strings.Contains(log, "OP_INVOKED verb=buy") {
		t.Errorf("buy did not reach the dontguess-operator binary; op log:\n%s", log)
	}
	// The operator's response streamed back through the wrapper — path reachable end-to-end.
	if !strings.Contains(buyOut, "MATCH stub-cached-content") {
		t.Errorf("operator buy response did not reach the caller through the wrapper; output:\n%s", buyOut)
	}
	s.assertNoCf(t)

	// Attempt-log feature (folds the retired reliability/attempt_log_test.sh): the
	// wrapper appends a JSONL line to DG_HOME/dontguess-attempts.log on the dispatch
	// path, classifying a clean run as tag "success".
	attemptLog, err := os.ReadFile(filepath.Join(dgHome, "dontguess-attempts.log"))
	if err != nil {
		t.Errorf("wrapper did not write the attempt log %s/dontguess-attempts.log: %v", dgHome, err)
	} else {
		al := string(attemptLog)
		if !strings.Contains(al, `"cmd":"buy"`) {
			t.Errorf("attempt log missing the buy entry; log:\n%s", al)
		}
		if !strings.Contains(al, `"tag":"success"`) {
			t.Errorf("attempt log did not classify the clean buy as success; log:\n%s", al)
		}
	}

	// put: the operator is now running, so this exercises the dispatch path with an
	// already-live operator (no second start).
	putOut, err := s.run(t, dgHome, []string{"DONTGUESS_RELAY_URLS="}, "put",
		"--description", "stub artifact", "--token_cost", "1000",
		"--content_type", "exchange:content-type:code", "--content", "YmFzZTY0")
	if err != nil {
		t.Fatalf("wrapper put failed: %v\noutput:\n%s", err, putOut)
	}
	log = s.opLogContents(t)
	if !strings.Contains(log, "OP_INVOKED verb=put") {
		t.Errorf("put did not reach the dontguess-operator binary; op log:\n%s", log)
	}
	if !strings.Contains(putOut, "PUT-ACCEPTED") {
		t.Errorf("operator put response did not reach the caller through the wrapper; output:\n%s", putOut)
	}
	s.assertNoCf(t)
}

// TestInstallE2E_TeamTier_NoAutoStart proves H6 in the other direction: with
// DONTGUESS_RELAY_URLS SET (team tier) the wrapper dispatches the verb straight to
// the relay-attached binary and NEVER auto-starts a local operator (which would mint
// its own key and become a rogue competing sequencer).
func TestInstallE2E_TeamTier_NoAutoStart(t *testing.T) {
	t.Parallel()
	s := newE2EScene(t)
	dgHome := s.dgHome(t)

	const relay = "wss://relay.example:7777"
	out, err := s.run(t, dgHome, []string{"DONTGUESS_RELAY_URLS=" + relay}, "buy", "--task", "team probe", "--budget", "100")
	if err != nil {
		t.Fatalf("wrapper buy (team tier) failed: %v\noutput:\n%s", err, out)
	}
	t.Logf("team-tier buy output:\n%s", out)

	log := s.opLogContents(t)

	// The buy reached the operator binary, carrying the relay URL (team tier).
	if !strings.Contains(log, "OP_INVOKED verb=buy") {
		t.Errorf("team-tier buy did not reach the dontguess-operator binary; op log:\n%s", log)
	}
	if !strings.Contains(log, `relay="`+relay+`"`) {
		t.Errorf("team-tier buy did not carry DONTGUESS_RELAY_URLS to the binary; op log:\n%s", log)
	}
	// H6: NO local serve was auto-started.
	if strings.Contains(log, "SERVE_INVOKED") {
		t.Fatalf("TEAM-TIER ROGUE SEQUENCER: the wrapper auto-started a local operator with DONTGUESS_RELAY_URLS set; op log:\n%s", log)
	}
	// And no pid file was written (the individual-tier auto-start block was skipped entirely).
	if _, err := os.Stat(filepath.Join(dgHome, "dontguess.pid")); err == nil {
		t.Errorf("team tier wrote a pid file — the individual-tier auto-start block was not skipped")
	}
	s.assertNoCf(t)
}
