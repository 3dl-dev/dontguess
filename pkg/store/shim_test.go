package store_test

import (
	"path/filepath"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/store"
)

// openTestStore opens a fresh events.jsonl store in a temp dir.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.StorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func rec(id string, ts int64, tags ...string) store.MessageRecord {
	if tags == nil {
		tags = []string{}
	}
	return store.MessageRecord{
		ID:        id,
		Sender:    "sender-" + id,
		Payload:   []byte(`{"k":"` + id + `"}`),
		Tags:      tags,
		Timestamp: ts,
	}
}

// TestShim_StorePath verifies the conventional log path shape.
func TestShim_StorePath(t *testing.T) {
	t.Parallel()
	got := store.StorePath("/some/dir")
	if want := filepath.Join("/some/dir", "events.jsonl"); got != want {
		t.Errorf("StorePath = %q, want %q", got, want)
	}
}

// TestShim_NowNano verifies NowNano returns a positive, monotone-ish nanos value.
func TestShim_NowNano(t *testing.T) {
	t.Parallel()
	a := store.NowNano()
	b := store.NowNano()
	if a <= 0 || b < a {
		t.Errorf("NowNano not positive/nondecreasing: a=%d b=%d", a, b)
	}
}

// TestShim_AddMessageAndListMessages verifies AddMessage appends and the record
// is observable via ListMessages, matching campfire's add->list round trip.
func TestShim_AddMessageAndListMessages(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	n, err := s.AddMessage(rec("a", 10, "exchange:put"))
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	if n != 1 {
		t.Errorf("AddMessage returned %d, want 1", n)
	}
	got, err := s.ListMessages(0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("ListMessages = %+v, want single record 'a'", got)
	}
}

// TestShim_ListMessages_ReturnsEveryRecordRegardlessOfCampfireID replaces
// TestShim_ListMessages_CampfireFilter, which verified a capability that
// dontguess-ab6 deliberately removed.
//
// The old cfID scoping is gone: campfire is retired, the stored value was
// vestigial ("local" or "" across the whole live log), and this method had zero
// non-test callers, so the filter never ran in production. What still matters —
// and is what this test now guards — is that removing the filter did not make
// ListMessages DROP anything: every record comes back whatever its historical
// CampfireID says, including the mixed values already on disk.
func TestShim_ListMessages_ReturnsEveryRecordRegardlessOfCampfireID(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	for _, r := range []store.MessageRecord{
		rec("a", 10),
		rec("b", 11),
		rec("c", 12), // the shape new records now have
	} {
		if _, err := s.AddMessage(r); err != nil {
			t.Fatalf("AddMessage %s: %v", r.ID, err)
		}
	}

	all, err := s.ListMessages(0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if got := ids(all); got != "a,b,c" {
		t.Errorf("ids = %q, want %q — a record must never be filtered out by its historical CampfireID", got, "a,b,c")
	}
}

// TestShim_ListMessages_SinceIsExclusive verifies the since bound is strictly
// greater-than (timestamp > since), exactly matching campfire's afterTimestamp.
func TestShim_ListMessages_SinceIsExclusive(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	for _, r := range []store.MessageRecord{
		rec("a", 10),
		rec("b", 20),
		rec("c", 30),
	} {
		if _, err := s.AddMessage(r); err != nil {
			t.Fatalf("AddMessage %s: %v", r.ID, err)
		}
	}

	// since == 20 must EXCLUDE the record at exactly 20 and include only 30.
	got, err := s.ListMessages(20)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if g := ids(got); g != "c" {
		t.Errorf("since=20 ids = %q, want %q (exclusive lower bound)", g, "c")
	}

	// since == 0 returns everything (all timestamps > 0).
	all, _ := s.ListMessages(0)
	if g := ids(all); g != "a,b,c" {
		t.Errorf("since=0 ids = %q, want %q", g, "a,b,c")
	}
}

// TestShim_ListMessages_TagOrMatch verifies tag filtering uses OR semantics and
// is case-insensitive, matching campfire.
func TestShim_ListMessages_TagOrMatch(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	for _, r := range []store.MessageRecord{
		rec("a", 10, "exchange:put"),
		rec("b", 11, "exchange:match"),
		rec("c", 12, "exchange:buy", "exchange:match"),
		rec("d", 13, "exchange:settle"),
	} {
		if _, err := s.AddMessage(r); err != nil {
			t.Fatalf("AddMessage %s: %v", r.ID, err)
		}
	}

	// Single tag: only records carrying exchange:match (OR against their tag set).
	match, err := s.ListMessages(0, store.MessageFilter{Tags: []string{"exchange:match"}})
	if err != nil {
		t.Fatalf("ListMessages match: %v", err)
	}
	if g := ids(match); g != "b,c" {
		t.Errorf("tag=match ids = %q, want %q", g, "b,c")
	}

	// Multi-tag OR: put OR settle.
	orRes, _ := s.ListMessages(0, store.MessageFilter{Tags: []string{"exchange:put", "exchange:settle"}})
	if g := ids(orRes); g != "a,d" {
		t.Errorf("tag OR ids = %q, want %q", g, "a,d")
	}

	// Case-insensitive match, matching campfire's LOWER() comparison.
	ci, _ := s.ListMessages(0, store.MessageFilter{Tags: []string{"EXCHANGE:MATCH"}})
	if g := ids(ci); g != "b,c" {
		t.Errorf("case-insensitive tag ids = %q, want %q", g, "b,c")
	}

	// Empty Tags disables tag filtering.
	none, _ := s.ListMessages(0, store.MessageFilter{Tags: nil})
	if g := ids(none); g != "a,b,c,d" {
		t.Errorf("empty-tags ids = %q, want %q", g, "a,b,c,d")
	}
}

// TestShim_ListMessages_OrderStableByTimestamp verifies ascending timestamp
// order, with append order preserved for equal timestamps (stable), matching
// campfire's ORDER BY timestamp over an insertion-ordered table.
func TestShim_ListMessages_OrderStableByTimestamp(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	// Append out of timestamp order, with a tie at ts=10 (x before y).
	for _, r := range []store.MessageRecord{
		rec("late", 30),
		rec("x", 10),
		rec("y", 10),
		rec("mid", 20),
	} {
		if _, err := s.AddMessage(r); err != nil {
			t.Fatalf("AddMessage %s: %v", r.ID, err)
		}
	}
	got, _ := s.ListMessages(0)
	// Ascending timestamp; the ts=10 tie keeps append order x,y.
	if g := ids(got); g != "x,y,mid,late" {
		t.Errorf("order ids = %q, want %q", g, "x,y,mid,late")
	}
}

// TestShim_ListMessages_OnlyFirstFilterApplied verifies that, like campfire,
// only filters[0] is honored when multiple are supplied.
func TestShim_ListMessages_OnlyFirstFilterApplied(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	for _, r := range []store.MessageRecord{
		rec("a", 10, "exchange:put"),
		rec("b", 11, "exchange:match"),
	} {
		if _, err := s.AddMessage(r); err != nil {
			t.Fatalf("AddMessage %s: %v", r.ID, err)
		}
	}
	got, _ := s.ListMessages(0,
		store.MessageFilter{Tags: []string{"exchange:put"}},
		store.MessageFilter{Tags: []string{"exchange:match"}},
	)
	if g := ids(got); g != "a" {
		t.Errorf("only-first-filter ids = %q, want %q", g, "a")
	}
}

// TestShim_GetMessage verifies found and not-found contracts.
func TestShim_GetMessage(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	if _, err := s.AddMessage(rec("a", 10, "exchange:put")); err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	got, err := s.GetMessage("a")
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if got == nil || got.ID != "a" {
		t.Fatalf("GetMessage(\"a\") = %+v, want the record with ID \"a\"", got)
	}

	// Not found: nil record, nil error.
	miss, err := s.GetMessage("does-not-exist")
	if err != nil {
		t.Fatalf("GetMessage(miss) err = %v, want nil", err)
	}
	if miss != nil {
		t.Errorf("GetMessage(miss) = %+v, want nil", miss)
	}
}

// ids joins record IDs with commas for compact order assertions.
func ids(recs []store.MessageRecord) string {
	out := ""
	for i, r := range recs {
		if i > 0 {
			out += ","
		}
		out += r.ID
	}
	return out
}
