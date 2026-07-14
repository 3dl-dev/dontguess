package exchange_test

// Unit tests for the Blossom client seam (dontguess-7783): pkg/exchange/blossom.go.
//
// Covered:
//   - MemoryBlobStore Put/Fetch round-trips content unchanged.
//   - MemoryBlobStore Put is content-addressed/idempotent: identical content
//     yields the same pointer.
//   - Fetch on an unknown pointer returns ErrBlobNotFound.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

func TestMemoryBlobStore_PutFetchRoundTrip(t *testing.T) {
	t.Parallel()
	store := exchange.NewMemoryBlobStore()

	content := []byte("some large cached inference result payload")
	ptr, err := store.Put(content)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ptr == "" {
		t.Fatal("Put returned empty pointer")
	}

	got, err := store.Fetch(ptr)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("Fetch returned %q, want %q", got, content)
	}
}

func TestMemoryBlobStore_PutIsContentAddressedIdempotent(t *testing.T) {
	t.Parallel()
	store := exchange.NewMemoryBlobStore()

	content := []byte("identical content put twice")
	ptr1, err := store.Put(content)
	if err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	ptr2, err := store.Put(content)
	if err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	if ptr1 != ptr2 {
		t.Fatalf("expected identical content to produce the same pointer, got %q and %q", ptr1, ptr2)
	}
}

func TestMemoryBlobStore_FetchUnknownPointer(t *testing.T) {
	t.Parallel()
	store := exchange.NewMemoryBlobStore()

	_, err := store.Fetch("memblob:doesnotexist")
	if !errors.Is(err, exchange.ErrBlobNotFound) {
		t.Fatalf("Fetch unknown pointer: got err=%v, want ErrBlobNotFound", err)
	}
}
