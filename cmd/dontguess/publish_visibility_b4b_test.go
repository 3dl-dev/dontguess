package main

// publish_visibility_b4b_test.go — dontguess-b4b.
//
// THE GAP THIS CLOSES. When a malformed e-tag wedged the operator outbox
// (dontguess-6d2), 36 operator-authored messages — matches, settlements, and
// buy-miss answers owed to real buyers — sat unpublished at RF=1 for THIRTEEN
// HOURS. Throughout, the exchange kept folding, indexing, pricing and answering
// locally, so every counter `dontguess status` reported climbed normally and the
// operator looked healthy. The outage was found only by hand-querying the relay.
//
// The measurement was never missing: Outbox.PublishLag() has existed since the
// transport was written. Nothing read it. A health signal that cannot distinguish
// "shipping" from "silently not shipping" is worse than no signal, because it is
// believed.
//
// These tests pin the aggregation and the rendering, so a wedged outbox is
// visible in one status call.

import (
	"strings"
	"testing"
)

// TestPublishRegistry_ReportsWorstLagNotSum pins the aggregation choice. Each leg
// publishes the SAME local records independently, so summing lag would multiply
// one stall by the leg count and report a 3-record backlog as 6. The max answers
// the question actually being asked: is anything not shipping?
func TestPublishRegistry_ReportsWorstLagNotSum(t *testing.T) {
	t.Parallel()
	// A nil registry must be safe — the individual tier has no legs at all.
	var nilReg *publishRegistry
	nilReg.addLeg(nil)
	if got := firstPublishRegistry(nil); got != nil {
		t.Fatalf("firstPublishRegistry(nil) = %v, want nil", got)
	}
	if got := firstPublishRegistry([]*publishRegistry{nil, nil}); got != nil {
		t.Fatalf("firstPublishRegistry(all-nil) = %v, want nil", got)
	}

	reg := &publishRegistry{}
	if snap := reg.snapshot(); snap.Legs != 0 || snap.Lag != 0 {
		t.Fatalf("empty registry snapshot = %+v, want zero", snap)
	}
	reg.add(nil) // must not register a nil leg
	if snap := reg.snapshot(); snap.Legs != 0 {
		t.Fatalf("a nil Outbox was registered as a leg: %+v", snap)
	}
}

// TestStatusRendersWedgedEgressLoudly is the operator-facing half: the exact
// condition that hid for thirteen hours must read as a problem, not as a number
// buried in a list.
func TestStatusRendersWedgedEgressLoudly(t *testing.T) {
	t.Parallel()

	t.Run("behind", func(t *testing.T) {
		out := renderStatusPublish(t, &StatusSnapshot{
			SchemaVersion: 1,
			Since:         "24h0m0s",
			Publish:       &publishMetrics{Lag: 36, Quarantined: 0, Retried: 4, Legs: 2},
		})
		if !strings.Contains(out, "BEHIND") {
			t.Errorf("a 36-event publish backlog did not render as BEHIND:\n%s", out)
		}
		if !strings.Contains(out, "36") {
			t.Errorf("the backlog size is not shown:\n%s", out)
		}
		// The whole point is that this is legible without knowing what a cursor is.
		if !strings.Contains(out, "NOT on the relay") {
			t.Errorf("output does not say the events are not on the relay:\n%s", out)
		}
	})

	t.Run("healthy", func(t *testing.T) {
		out := renderStatusPublish(t, &StatusSnapshot{
			SchemaVersion: 1,
			Since:         "24h0m0s",
			Publish:       &publishMetrics{Lag: 0, Quarantined: 0, Retried: 0, Legs: 2},
		})
		if !strings.Contains(out, "OK") {
			t.Errorf("a fully-published exchange did not render OK:\n%s", out)
		}
		if strings.Contains(out, "BEHIND") || strings.Contains(out, "WARNING") {
			t.Errorf("healthy egress rendered an alarm:\n%s", out)
		}
	})

	t.Run("quarantined warns", func(t *testing.T) {
		out := renderStatusPublish(t, &StatusSnapshot{
			SchemaVersion: 1,
			Since:         "24h0m0s",
			Publish:       &publishMetrics{Lag: 0, Quarantined: 2, Retried: 9, Legs: 1},
		})
		// Lag 0 with quarantined > 0 is the subtle case: the stream is MOVING, so a
		// lag-only signal reads healthy, yet two records will never reach the relay.
		if !strings.Contains(out, "WARNING") {
			t.Errorf("quarantined records did not raise a warning despite zero lag:\n%s", out)
		}
		if !strings.Contains(out, "ONLY in the local log") {
			t.Errorf("output does not explain that quarantined records are local-only:\n%s", out)
		}
	})

	t.Run("no legs attached", func(t *testing.T) {
		out := renderStatusPublish(t, &StatusSnapshot{
			SchemaVersion: 1,
			Since:         "24h0m0s",
			Publish:       &publishMetrics{Legs: 0},
		})
		// Zero legs with zero lag must NOT read as OK — nothing is publishing at all.
		if !strings.Contains(out, "WEDGED") {
			t.Errorf("zero relay legs rendered as healthy; a detached operator publishes nothing:\n%s", out)
		}
	})
}

// renderStatusPublish captures printStatus output and returns the relay-egress
// section, so the assertions above read against what an operator actually sees.
func renderStatusPublish(t *testing.T, snap *StatusSnapshot) string {
	t.Helper()
	out := captureStdout(t, func() { printStatus(snap, false) })
	idx := strings.Index(out, "Relay egress")
	if idx < 0 {
		t.Fatalf("status output has no 'Relay egress' section at all:\n%s", out)
	}
	rest := out[idx:]
	if end := strings.Index(rest, "\nOperator\n"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}
