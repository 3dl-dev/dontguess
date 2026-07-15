package relay

// intake_cursor.go is the INGEST-side counterpart to outbox.go's durable publish
// cursor (dontguess-61a). A fresh operator's Intake subscribe REQ had no bound on
// `since` at all (Since=0) AND no `kinds` filter, so every start — and every
// periodic resync audit — re-read the relay's ENTIRE history across every kind
// any client had ever published there, not just dontguess's own events (the
// dropped_smuggled flood). This file gives the Intake leg a durable, per-relay
// "how far have we ingested" watermark, mirroring the Outbox's cursorFile
// write-temp+fsync+rename discipline (crash-safe, atomic), so a restart or a
// resync cycle resumes from disk rather than from Since=0.
//
// Unlike the Outbox cursor (which COUNTS published-and-ACKed records, advancing
// by exactly one per publish), the Intake cursor tracks CALENDAR time: the
// highest nostr `created_at` this operator has observed from the relay. It only
// ever climbs (Advance is a no-op for an equal-or-older value), so an
// out-of-order redelivery — the Sequencer's id-dedup already absorbs those —
// can never rewind it.
//
// See docs/design/onboarding-tiered-scaling-federation.md §4 (61a) + §9 Gate A.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// IntakeCursor persists the last-seen relay event `created_at` (NIP-01 seconds)
// this operator has ingested from ONE relay. It bounds the REQ `since` on
// startup and on the periodic resync audit so neither re-reads the relay's full
// history — only the window since this cursor (§4 61a). A fresh operator/fresh
// relay pair (no sidecar yet) reads back Value()==0; the caller is responsible
// for applying a BOUNDED backfill window in that case rather than treating 0 as
// "since the beginning of time" (the documented "pre-bootstrap entries not
// ingested" semantic — see DefaultBackfillWindowSeconds).
type IntakeCursor struct {
	mu   sync.Mutex
	path string
	val  int64
}

// DefaultBackfillWindowSeconds bounds how far back a genuinely fresh operator
// (empty local store AND no persisted Intake cursor for this relay) backfills
// on its very first subscribe, instead of an unbounded Since=0. Entries older
// than this window that predate the operator's first connection to the relay
// are NOT ingested — a deliberate, documented trade-off (§4 61a): a fresh
// operator gets a bounded, recent slice of the exchange's history, not its
// entire past. 7 days is generous for a newly-onboarded operator to catch up on
// recent inventory without re-reading years of accumulated dontguess events.
const DefaultBackfillWindowSeconds = int64(7 * 24 * 3600)

// OpenIntakeCursor reads the existing cursor value (0 if the sidecar does not
// yet exist — a fresh operator/fresh relay pair) and returns an IntakeCursor
// ready to advance. Mirrors openCursor (outbox.go) but stores a calendar-time
// watermark instead of a monotonic publish count.
func OpenIntakeCursor(path string) (*IntakeCursor, error) {
	if path == "" {
		return nil, fmt.Errorf("intake cursor: empty path")
	}
	c := &IntakeCursor{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("intake cursor: read %s: %w", path, err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return c, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("intake cursor: parse %s (value %q): %w", path, s, err)
	}
	if n < 0 {
		return nil, fmt.Errorf("intake cursor: %s has negative value %d", path, n)
	}
	c.val = n
	return c, nil
}

// Value returns the current durable cursor value (0 if never advanced).
func (c *IntakeCursor) Value() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.val
}

// Advance bumps the cursor to seenAt if it is newer than the current value,
// persisting durably (fsync before return). An equal-or-older seenAt is a
// silent no-op — the watermark only ever climbs, so an out-of-order redelivery
// can never rewind it. On a persist failure the in-memory value is NOT
// advanced, so a restart re-reads the pre-advance value from disk rather than
// silently skipping the not-yet-durable window.
func (c *IntakeCursor) Advance(seenAt int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seenAt <= c.val {
		return nil
	}
	if err := c.persistLocked(seenAt); err != nil {
		return err
	}
	c.val = seenAt
	return nil
}

// persistLocked atomically writes n to the sidecar: temp file -> fsync ->
// rename -> best-effort dir fsync. Caller holds c.mu. Identical discipline to
// outbox.go's cursorFile.persistLocked.
func (c *IntakeCursor) persistLocked(n int64) error {
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, ".intakecursor-*.tmp")
	if err != nil {
		return fmt.Errorf("intake cursor: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(strconv.FormatInt(n, 10) + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("intake cursor: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("intake cursor: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("intake cursor: close temp: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("intake cursor: rename %s -> %s: %w", tmpName, c.path, err)
	}
	committed = true
	if dirf, derr := os.Open(dir); derr == nil {
		_ = dirf.Sync()
		_ = dirf.Close()
	}
	return nil
}
