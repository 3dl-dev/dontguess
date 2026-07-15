package exchange

// state_put_prefetch_a5e_test.go — the ground-source test for dontguess-a5e
// (prefetchPutBlobs / fetchBlobBounded, state_put.go). a5e moved BlobStore.Fetch
// off s.mu (fetch BEFORE the write lock is taken) and added a 30s watchdog
// (blobFetchDeadline) around the fetch so a hung Blossom host cannot wedge the
// fold goroutine even off the lock. Wave 8 shipped this with NO test — every
// existing offload test used MemoryBlobStore, which is instant and never
// exercises either the off-lock discipline or the deadline branch.
//
// Proven here, with a deliberately-SLOW BlobStore (Fetch blocks on a channel,
// nothing about the timing is faked/short-circuited):
//
//	(1) a fetch that is currently IN FLIGHT does not stall a concurrent State
//	    read — proves s.mu is not held across BlobStore.Fetch (the whole point
//	    of prefetchPutBlobs running before s.mu.Lock in Apply/Replay);
//	(2) a fetch that never returns within blobFetchDeadline (30s, the REAL
//	    production constant — not shortened) is abandoned and the put DROPS
//	    fail-closed, identical to the pre-a5e under-lock drop outcome (same
//	    fail-closed contract TestApplyPut_V2Blob_MissingBlob_Dropped proves for
//	    an instant fetch error; this proves it for the timeout branch, which no
//	    existing test reaches).

import (
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/identity"
)

// blockingBlobStore is a BlobStore whose Fetch blocks until the test unblocks
// it (or forever, for the deadline test). It signals entry into Fetch via
// started so a test can deterministically wait for the fetch to be in flight
// before asserting concurrent-access behavior, instead of racing on a sleep.
type blockingBlobStore struct {
	mu          sync.Mutex
	startedOnce sync.Once
	started     chan struct{}
	unblock     chan struct{}
	content     []byte
}

func newBlockingBlobStore() *blockingBlobStore {
	return &blockingBlobStore{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
}

// Put stores content under a single fixed pointer (this test double only ever
// needs to hold one blob at a time — the offloaded ciphertext under test).
func (b *blockingBlobStore) Put(content []byte) (string, error) {
	b.mu.Lock()
	b.content = append([]byte(nil), content...)
	b.mu.Unlock()
	return "blocking-store-pointer", nil
}

func (b *blockingBlobStore) Fetch(pointer string) ([]byte, error) {
	b.startedOnce.Do(func() { close(b.started) })
	<-b.unblock
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.content, nil
}

// (1) A slow, in-flight BlobStore.Fetch must not stall a concurrent State
// read. If prefetchPutBlobs's fetch ran under s.mu (the pre-a5e shape), the
// PendingPuts() call below would block until the fetch completes; it must
// instead return immediately because prefetchPutBlobs runs BEFORE s.mu.Lock.
func TestPrefetchPutBlobs_SlowFetchDoesNotStallConcurrentStateRead(t *testing.T) {
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("seller: %v", err)
	}
	operator, err := identity.Generate()
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	s := teamTierState(t, operator)

	plaintext := []byte("a reusable artifact fetched from a deliberately slow blob host")
	blob := newBlockingBlobStore()
	// buildEncObjectBlob calls blob.Put(ciphertext), which stores the real
	// AEAD-sealed ciphertext bytes into blob.content under a fixed pointer;
	// Fetch (below) blocks, then returns those same bytes.
	enc, _ := buildEncObjectBlob(t, seller, operator.PubKeyHex(), plaintext, blob)
	msg := marshalV2Put(t, seller, "reusable go flock contention test pattern (slow blob)", 4242, enc)
	s.SetBlobStore(blob)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Apply(msg) // blocks inside fetchBlobBounded until blob.unblock closes
	}()

	// Wait until the fetch is actually in flight (deterministic — no sleep-race).
	select {
	case <-blob.started:
	case <-time.After(10 * time.Second):
		close(blob.unblock) // avoid leaking the Apply goroutine before failing
		wg.Wait()
		t.Fatal("blob fetch never started")
	}

	// While the fetch is still blocked, a concurrent State read must complete
	// promptly. This is the direct proof that s.mu is NOT held across the
	// in-flight BlobStore.Fetch (a5e's whole point).
	done := make(chan struct{})
	go func() {
		s.PendingPuts() // takes s.mu.RLock; must not block on the pending fetch
		close(done)
	}()
	select {
	case <-done:
		// good: the concurrent read was not stalled by the in-flight fetch.
	case <-time.After(2 * time.Second):
		close(blob.unblock) // unblock so Apply's goroutine doesn't leak
		wg.Wait()
		t.Fatal("concurrent State read stalled while a BlobStore.Fetch was in flight — s.mu is held across the fetch (a5e regression)")
	}

	// Now let the fetch complete and confirm the put still folds correctly end
	// to end — the off-lock prefetch must deliver the SAME plaintext the
	// under-lock path would have.
	close(blob.unblock)
	wg.Wait()

	entry, ok := s.GetPendingPut(msg.ID)
	if !ok {
		t.Fatal("v2 blob_pointer put with a slow-but-successful fetch did NOT fold")
	}
	if string(entry.Content) != "" {
		t.Fatalf("entry.Content non-nil for an offloaded entry: %q", entry.Content)
	}
	if entry.ContentSize != int64(len(plaintext)) {
		t.Fatalf("entry.ContentSize = %d, want %d (decrypted plaintext size)", entry.ContentSize, len(plaintext))
	}
}

// (2) A fetch that never returns within blobFetchDeadline (30s — the real
// production constant, not shortened for the test) must be abandoned and the
// put dropped FAIL-CLOSED, exactly like the pre-a5e under-lock drop path.
// This deliberately spends real wall-clock time on the actual deadline: any
// shortcut (injecting a fake clock, using an unexported test-only deadline
// override) would stop proving that the SHIPPED 30s constant is what is
// enforced.
func TestFetchBlobBounded_DeadlineExceeded_DropsPutFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 30s deadline test in -short mode")
	}
	seller, err := identity.Generate()
	if err != nil {
		t.Fatalf("seller: %v", err)
	}
	operator, err := identity.Generate()
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	s := teamTierState(t, operator)

	plaintext := []byte("bytes behind a blob host that never answers within the fold deadline")
	blob := newBlockingBlobStore()
	enc, _ := buildEncObjectBlob(t, seller, operator.PubKeyHex(), plaintext, blob)
	msg := marshalV2Put(t, seller, "reusable go flock contention test pattern (hung blob host)", 4242, enc)
	s.SetBlobStore(blob)

	start := time.Now()
	s.Apply(msg) // must return on its own once fetchBlobBounded's 30s watchdog fires
	elapsed := time.Since(start)

	// Never unblock the fetch (simulates a genuinely hung host); release the
	// abandoned goroutine at test end so it doesn't leak past this test.
	t.Cleanup(func() { close(blob.unblock) })

	if elapsed < blobFetchDeadline {
		t.Fatalf("Apply returned after %s, before the %s deadline elapsed — the watchdog did not enforce the real constant", elapsed, blobFetchDeadline)
	}
	if elapsed > blobFetchDeadline+15*time.Second {
		t.Fatalf("Apply took %s — far longer than the %s deadline plus slack; the watchdog is not bounding the fold", elapsed, blobFetchDeadline)
	}

	if _, ok := s.GetPendingPut(msg.ID); ok {
		t.Fatal("v2 blob_pointer put FOLDED after its fetch exceeded blobFetchDeadline — fail-closed broken (un-fetchable content must never fold, identical to the pre-a5e under-lock drop)")
	}
}
