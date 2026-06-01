package main

// bucketed_write_test.go — feature test for dontguess-b05 (campfire SDK v0.17 → v0.31.2 port).
//
// PROOF OBJECTIVE: the operator's real SDK write path (protocol.Client.Send,
// which the operator uses via exchange.sendTaggedMessage / view + convention
// publishing) lands messages on disk in the v0.31 BUCKETED layout:
//
//     <transportDir>/<campfireID>/messages/YYYY-MM/DD/<nanos>-<id>.cbor
//
// This is the entire point of the port: v0.17 wrote a FLAT layout
// (messages/<id>.cbor with no date buckets). Once this test passes against
// v0.31.2, the flat-writing v0.17 operator can be retired.
//
// GROUND TRUTH: this asserts real files on a real scratch filesystem campfire
// in a tempdir. No mocked store, no fake transport — exchange.Init creates an
// actual filesystem campfire and the SDK client signs and writes a real
// message through the fs transport.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/campfire-net/campfire/cf-protocol/protocol"
	"github.com/campfire-net/dontguess/pkg/exchange"
)

// bucketDirRE matches a v0.31 month bucket directory name "YYYY-MM".
var bucketMonthRE = regexp.MustCompile(`^\d{4}-\d{2}$`)

// bucketDayRE matches a v0.31 day bucket directory name "DD".
var bucketDayRE = regexp.MustCompile(`^\d{2}$`)

// TestOperatorSDKWrite_BucketedLayout proves the v0.31.2 SDK write path produces
// the bucketed messages/YYYY-MM/DD/<...>.cbor layout on a fresh scratch campfire.
func TestOperatorSDKWrite_BucketedLayout(t *testing.T) {
	configDir := t.TempDir()
	transportDir := t.TempDir()
	convDir := conventionDirForOpTest(t)

	// exchange.Init creates a real filesystem campfire under transportDir and
	// returns the operator client bound to that transport. This is the exact
	// path the operator uses at startup; the convention/view declarations it
	// publishes are written via protocol.Client.Send.
	cfg, client, err := exchange.Init(exchange.InitOptions{
		ConfigDir:         configDir,
		Transport:         protocol.FilesystemTransport{Dir: transportDir},
		BeaconDir:         t.TempDir(),
		ConventionDir:     convDir,
		SkipConfigCascade: true,
	})
	if err != nil {
		t.Fatalf("exchange.Init: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Publish one explicit message through the real SDK write path and capture
	// its ID so we can assert the exact bucketed file exists.
	msg, err := client.Send(protocol.SendRequest{
		CampfireID: cfg.ExchangeCampfireID,
		Payload:    []byte("bucketed-write proof payload"),
		Tags:       []string{"status"},
	})
	if err != nil {
		t.Fatalf("client.Send: %v", err)
	}
	if msg.ID == "" {
		t.Fatal("client.Send returned a message with no ID")
	}

	campfireDir := filepath.Join(transportDir, cfg.ExchangeCampfireID)
	messagesDir := filepath.Join(campfireDir, "messages")

	// 1) No flat *.cbor files directly under messages/ — that would be the old
	//    v0.17 layout and means the port did not take effect.
	flat := flatCBORFiles(t, messagesDir)
	if len(flat) > 0 {
		t.Fatalf("found flat messages/*.cbor files (old v0.17 layout): %v", flat)
	}

	// 2) The message we sent lives at messages/YYYY-MM/DD/<nanos>-<id>.cbor.
	found := findBucketedMessage(t, messagesDir, msg.ID)
	if found == "" {
		t.Fatalf("sent message %s not found in any bucketed dir under %s", msg.ID, messagesDir)
	}

	// 3) Validate the full bucketed shape of the discovered path:
	//    messages / YYYY-MM / DD / <file>.cbor
	rel, err := filepath.Rel(messagesDir, found)
	if err != nil {
		t.Fatalf("filepath.Rel(%s, %s): %v", messagesDir, found, err)
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 {
		t.Fatalf("bucketed path has %d components, want 3 (YYYY-MM/DD/file): %q", len(parts), rel)
	}
	if !bucketMonthRE.MatchString(parts[0]) {
		t.Errorf("month bucket %q does not match YYYY-MM", parts[0])
	}
	if !bucketDayRE.MatchString(parts[1]) {
		t.Errorf("day bucket %q does not match DD", parts[1])
	}
	if !strings.HasSuffix(parts[2], ".cbor") {
		t.Errorf("message file %q does not end in .cbor", parts[2])
	}
	if !strings.Contains(parts[2], msg.ID) {
		t.Errorf("message file %q does not contain message ID %s", parts[2], msg.ID)
	}

	// 4) The file is a real, non-empty file on disk.
	info, err := os.Stat(found)
	if err != nil {
		t.Fatalf("stat bucketed message file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("bucketed message file %s is empty", found)
	}

	t.Logf("v0.31 bucketed write confirmed: %s (%d bytes)", rel, info.Size())
}

// flatCBORFiles returns any *.cbor files found directly in messagesDir (the old
// flat v0.17 layout). An empty slice means no flat files (bucketed layout).
func flatCBORFiles(t *testing.T, messagesDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(messagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", messagesDir, err)
	}
	var flat []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".cbor") {
			flat = append(flat, e.Name())
		}
	}
	return flat
}

// findBucketedMessage walks messagesDir looking for a *.cbor file whose name
// contains msgID, sitting under a YYYY-MM/DD bucket. Returns the absolute path
// or "" if not found.
func findBucketedMessage(t *testing.T, messagesDir, msgID string) string {
	t.Helper()
	var found string
	err := filepath.Walk(messagesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".cbor") && strings.Contains(info.Name(), msgID) {
			found = path
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walking %s: %v", messagesDir, err)
	}
	return found
}
