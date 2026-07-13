package exchange_test

// Race test for KeySet (dontguess-1a2 item c): Allowed runs from the engine
// poll-loop dispatch goroutine while Add/Remove run from the serve
// membership-refresh goroutine. Without the internal RWMutex these are a data
// race on the members map. Run under `go test -race` to exercise the guard.

import (
	"sync"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

func TestKeySet_ConcurrentAllowedAddRemove_RaceClean(t *testing.T) {
	t.Parallel()
	ks := exchange.NewKeySet("seed-key")

	const workers = 8
	const iters = 500
	keys := []string{"k0", "k1", "k2", "k3", "seed-key"}

	var wg sync.WaitGroup
	wg.Add(workers * 3)

	// Readers: Allowed + Len + Keys concurrently with writers.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = ks.Allowed(keys[i%len(keys)])
				_ = ks.Len()
				_ = ks.Keys()
			}
		}()
	}
	// Adders.
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ks.Add(keys[(i+w)%len(keys)])
			}
		}(w)
	}
	// Removers (runtime de-allowlisting).
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ks.Remove(keys[(i+w)%len(keys)])
			}
		}(w)
	}
	wg.Wait()
	// No assertion on final membership — the point is the -race detector must not
	// fire. A final Allowed call proves the set is still usable.
	_ = ks.Allowed("seed-key")
}
