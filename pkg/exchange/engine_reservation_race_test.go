package exchange

// -race regression test for dontguess-471 fix #2: matchToReservation and
// buyerRecentEntries were UNSYNCHRONIZED maps mutated in dispatch handlers. In
// local-relay mode dispatch runs on TWO goroutines concurrently — the poll loop
// (pollLocalStore → dispatch) and the operator/auto-accept path
// (rebuildAndDispatchGapLocal → dispatch). localMu only makes the cursor claims
// atomic; the handler bodies (which write these two maps via reservationFor /
// setReservation / deleteReservation / recordBuyerSettlement) ran outside any
// shared lock. This test drives those exact production accessors from two
// goroutines over overlapping keys; run under `go test -race` it fails on the
// pre-fix unsynchronized maps and passes with resvMu.

import (
	"sync"
	"testing"
)

func TestReservationMaps_ConcurrentDispatch_RaceClean(t *testing.T) {
	eng := NewEngine(EngineOptions{
		OperatorPublicKey: "operator-key",
		Logger:            func(string, ...any) {},
	})

	const (
		iterations = 2000
		keys       = 16
	)
	matchKey := func(i int) string {
		return "match-" + string(rune('a'+i%keys))
	}
	buyerKey := func(i int) string {
		return "buyer-" + string(rune('a'+i%keys))
	}
	entryKey := func(i int) string {
		return "entry-" + string(rune('a'+i%keys))
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Poll-loop role: writes reservations and records settlements.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			eng.setReservation(matchKey(i), "res-"+matchKey(i))
			eng.recordBuyerSettlement(buyerKey(i), entryKey(i))
			_, _ = eng.reservationFor(matchKey(i))
		}
	}()

	// Operator/auto-accept role: reads/deletes reservations and records settlements
	// over the SAME overlapping keys.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = eng.reservationFor(matchKey(i))
			eng.recordBuyerSettlement(buyerKey(i), entryKey(i))
			eng.deleteReservation(matchKey(i))
		}
	}()

	wg.Wait()
}
