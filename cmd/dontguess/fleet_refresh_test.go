package main

// Tests for the runtime fleet-allowlist refresh (dontguess-1a2 items a + b):
// serve re-reads campfire membership on an interval and reconciles the KeySet,
// admitting joiners AND revoking (de-allowlisting) leavers — the allowlist is no
// longer a one-shot startup snapshot. The operator key is never revoked.

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/campfire-net/campfire/cf-protocol/protocol"

	"github.com/campfire-net/dontguess/pkg/exchange"
)

// fakeMemberSource returns a canned member list, satisfying fleetMemberSource.
type fakeMemberSource struct {
	members []protocol.MemberRecord
	err     error
}

func (f *fakeMemberSource) Members(string) ([]protocol.MemberRecord, error) {
	return f.members, f.err
}

func recs(keys ...string) []protocol.MemberRecord {
	out := make([]protocol.MemberRecord, 0, len(keys))
	for _, k := range keys {
		out = append(out, protocol.MemberRecord{MemberPubkey: k})
	}
	return out
}

// TestSyncFleetMembership_AddsAndRevokes: reconciling against a new member set
// admits joiners and revokes leavers in a single pass.
func TestSyncFleetMembership_AddsAndRevokes(t *testing.T) {
	const op = "operatorkey"
	fleet := exchange.NewKeySet("keya", "keyb", op)

	// keya leaves, keyc joins, keyb stays, operator stays.
	added, removed := syncFleetMembership(fleet, []string{"keyb", "keyc", op}, op)

	if fleet.Allowed("keya") {
		t.Error("keya should have been revoked (no longer a member)")
	}
	if !fleet.Allowed("keyb") {
		t.Error("keyb should still be admitted")
	}
	if !fleet.Allowed("keyc") {
		t.Error("keyc should have been admitted (new member)")
	}
	if len(added) != 1 || added[0] != "keyc" {
		t.Errorf("added = %v, want [keyc]", added)
	}
	if len(removed) != 1 || removed[0] != "keya" {
		t.Errorf("removed = %v, want [keya]", removed)
	}
}

// TestSyncFleetMembership_NeverRevokesOperator: the operator retains write
// authority even when absent from the campfire membership list.
func TestSyncFleetMembership_NeverRevokesOperator(t *testing.T) {
	const op = "operatorkey"
	fleet := exchange.NewKeySet(op, "member1")

	// Desired set omits the operator entirely.
	_, removed := syncFleetMembership(fleet, []string{"member1"}, op)

	if !fleet.Allowed(op) {
		t.Error("operator key must never be revoked by a membership refresh")
	}
	for _, r := range removed {
		if r == op {
			t.Error("operator key must not appear in the revoked set")
		}
	}
}

// TestRefreshFleetLoop_ReconcilesThenStops: the loop reads the source on its
// tick, reconciles the KeySet, and returns when the context is cancelled.
func TestRefreshFleetLoop_ReconcilesThenStops(t *testing.T) {
	const op = "operatorkey"
	fleet := exchange.NewKeySet("stale-member", op)
	src := &fakeMemberSource{members: recs("fresh-member", op)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.New(log.Writer(), "[test] ", 0)
	done := make(chan struct{})
	go func() {
		refreshFleetLoop(ctx, fleet, src, "campfire-id-abcdef0123456789", op, 5*time.Millisecond, logger)
		close(done)
	}()

	// Wait for the loop to admit the fresh member and revoke the stale one.
	deadline := time.After(2 * time.Second)
	for {
		if fleet.Allowed("fresh-member") && !fleet.Allowed("stale-member") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("loop did not reconcile in time: fresh=%v stale=%v",
				fleet.Allowed("fresh-member"), fleet.Allowed("stale-member"))
		case <-time.After(2 * time.Millisecond):
		}
	}
	if !fleet.Allowed(op) {
		t.Error("operator must remain admitted after refresh")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshFleetLoop did not return after context cancel")
	}
}

// TestRefreshFleetLoop_MembersErrorDoesNotTearDown: a Members() error is logged
// and the loop keeps the previous allowlist snapshot intact.
func TestRefreshFleetLoop_MembersErrorDoesNotTearDown(t *testing.T) {
	const op = "operatorkey"
	fleet := exchange.NewKeySet("member1", op)
	src := &fakeMemberSource{err: context.DeadlineExceeded}

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(log.Writer(), "[test] ", 0)
	done := make(chan struct{})
	go func() {
		refreshFleetLoop(ctx, fleet, src, "campfire-id-abcdef0123456789", op, 2*time.Millisecond, logger)
		close(done)
	}()

	// Let several error ticks elapse.
	time.Sleep(30 * time.Millisecond)
	if !fleet.Allowed("member1") || !fleet.Allowed(op) {
		t.Error("allowlist must be untouched when Members() errors")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshFleetLoop did not return after context cancel")
	}
}
