package relay

// outbox_headofline_6d2_test.go — dontguess-6d2.
//
// THE OUTAGE THIS PINS. One operator record carried a campfire-era 16-byte
// antecedent, which the adapter emitted as an undersized NIP-01 "e" tag. The
// relay rejected it: OK=false, "invalid: unexpected size for fixed-size tag: e".
//
// publishWithRetry treated that rejection exactly like a transient transport
// error and retried it forever. But the event is IMMUTABLE — its id is a content
// hash — so no retry could ever succeed. The cursor never advanced past it, and
// every later operator message queued behind it. On the live exchange that meant
// operator egress stopped at 04:30:52 and stayed stopped for thirteen hours:
// matches, settlements and buy-miss answers never reached the relay, buyers saw
// only "ambiguous timeout", and `dontguess status` reported the exchange healthy
// the entire time.
//
// The rule this file enforces: a permanently-rejected record costs exactly
// itself. It must never cost the stream.

import (
	"context"
	"strings"
	"testing"
)

// TestPermanentRejectionDoesNotStrandLaterEvents is the core case: three
// records, the middle one permanently rejected. The third MUST still publish.
func TestPermanentRejectionDoesNotStrandLaterEvents(t *testing.T) {
	t.Parallel()
	pub := newFakePublisher()
	ob, s, _ := newOutboxWithStore(t, pub)

	recs := []string{"aaa", "bbb", "ccc"}
	for _, id := range recs {
		if err := s.Append(localRec(id)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	// Learn the wire id of the middle record, then mark it permanently rejected
	// with the EXACT message the live relay returned.
	all, err := s.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	mid, err := ob.toSignedEvent(all[1])
	if err != nil {
		t.Fatalf("toSignedEvent: %v", err)
	}
	pub.mu.Lock()
	pub.reject[mid.ID] = true
	pub.rejectMsg = map[string]string{mid.ID: "invalid: unexpected size for fixed-size tag: e"}
	pub.mu.Unlock()

	if err := ob.Tick(context.Background()); err != nil {
		t.Fatalf("Tick returned an error instead of quarantining the bad record: %v", err)
	}

	// The cursor must have advanced past ALL THREE — the rejected one is
	// quarantined, not retried forever.
	if got := ob.Cursor(); got != 3 {
		t.Fatalf("cursor = %d, want 3 — a permanently-rejected record stalled the stream; every later operator message is stranded behind it, which is the outage (dontguess-6d2)", got)
	}
	if got := ob.PublishQuarantined(); got != 1 {
		t.Fatalf("PublishQuarantined = %d, want 1 — a quarantined event exists only locally at RF=1 and MUST be countable, or the gap is invisible", got)
	}

	// The third record must actually have reached the relay.
	last, err := ob.toSignedEvent(all[2])
	if err != nil {
		t.Fatalf("toSignedEvent(last): %v", err)
	}
	var sawLast bool
	for _, id := range pub.publishedIDs() {
		if id == last.ID {
			sawLast = true
		}
	}
	if !sawLast {
		t.Fatal("the record AFTER the rejected one never published — head-of-line blocking is still present")
	}
}

// TestTransientRejectionStillRetries pins that the fix is narrow. A transient
// reason must NOT be quarantined, or a relay hiccup would silently drop
// operator events — losing data instead of stalling, a strictly worse trade.
func TestTransientRejectionStillRetries(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"rate-limited: slow down", "error: try again later", "some unrecognised reason"} {
		t.Run(reason, func(t *testing.T) {
			if isPermanentRejection(reason) {
				t.Fatalf("isPermanentRejection(%q) = true, want false — a transient or unknown reason must keep retrying so no operator event is dropped", reason)
			}
		})
	}
	for _, reason := range []string{
		"invalid: unexpected size for fixed-size tag: e",
		"blocked: not on write allowlist",
		"pow: difficulty 28 required",
		"INVALID: Bad Signature",
	} {
		t.Run(reason, func(t *testing.T) {
			if !isPermanentRejection(reason) {
				t.Fatalf("isPermanentRejection(%q) = false, want true — retrying an event the relay calls unfixable wedges the whole stream", reason)
			}
		})
	}
}

// TestDuplicateRejectionCountsAsAcked — a relay that already holds the event is
// reporting success, not failure. Retrying it forever would wedge exactly as a
// permanent rejection does.
func TestDuplicateRejectionCountsAsAcked(t *testing.T) {
	t.Parallel()
	if !isDuplicateRejection("duplicate: already have this event") {
		t.Fatal("a duplicate rejection must be treated as an ACK")
	}
	if isDuplicateRejection("invalid: unexpected size for fixed-size tag: e") {
		t.Fatal("an invalid rejection must not be mistaken for a duplicate")
	}
	if !strings.HasPrefix("duplicate: x", "duplicate:") {
		t.Fatal("sanity")
	}
}
