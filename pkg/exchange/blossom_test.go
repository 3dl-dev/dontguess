package exchange_test

// Unit tests for the Blossom client seam (dontguess-7783): pkg/exchange/blossom.go.
//
// Covered:
//   - MemoryBlobStore Put/Fetch round-trips content unchanged.
//   - MemoryBlobStore Put is content-addressed/idempotent: identical content
//     yields the same pointer.
//   - Fetch on an unknown pointer returns ErrBlobNotFound.
//   - State.FetchAndVerifyBlob succeeds when the fetched bytes match the
//     entry's ContentHash, and fails (tamper detection) when they don't.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// TestFetchAndVerifyBlob_Success verifies that a blob whose content matches
// the entry's recorded ContentHash is returned successfully.
func TestFetchAndVerifyBlob_Success(t *testing.T) {
	t.Parallel()
	st := exchange.NewState()
	blobStore := exchange.NewMemoryBlobStore()
	st.SetBlobStore(blobStore)

	content := []byte("full content that lives only in the blob store")
	ptr, err := blobStore.Put(content)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	sum := sha256.Sum256(content)
	entry := &exchange.InventoryEntry{
		EntryID:     "entry-1",
		ContentHash: "sha256:" + hex.EncodeToString(sum[:]),
		BlobPointer: ptr,
	}

	got, err := st.FetchAndVerifyBlob(entry)
	if err != nil {
		t.Fatalf("FetchAndVerifyBlob: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("FetchAndVerifyBlob returned %q, want %q", got, content)
	}
}

// TestFetchAndVerifyBlob_TamperedBlobFails verifies that if the bytes stored
// under the blob pointer no longer match the entry's ContentHash (simulating
// a tampered or corrupted blob), FetchAndVerifyBlob refuses to return them.
// This is the free content-hash-spoof mitigation the design doc calls for.
func TestFetchAndVerifyBlob_TamperedBlobFails(t *testing.T) {
	t.Parallel()
	st := exchange.NewState()
	blobStore := exchange.NewMemoryBlobStore()
	st.SetBlobStore(blobStore)

	original := []byte("the original, legitimate content")
	ptr, err := blobStore.Put(original)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Simulate tamper/corruption: MemoryBlobStore is content-addressed and has
	// no public overwrite-by-pointer API (by design), so model the tamper at
	// the verification boundary instead — construct an entry whose
	// ContentHash does not match what's actually stored under ptr, exactly as
	// a corrupted/malicious blob host would produce.
	tampered := []byte("this is NOT what the seller originally put!!")
	tamperedSum := sha256.Sum256(tampered)
	mismatchedEntry := &exchange.InventoryEntry{
		EntryID:     "entry-2-mismatch",
		ContentHash: "sha256:" + hex.EncodeToString(tamperedSum[:]),
		BlobPointer: ptr, // pointer still resolves to `original` bytes, not `tampered`
	}

	if _, err := st.FetchAndVerifyBlob(mismatchedEntry); err == nil {
		t.Fatal("FetchAndVerifyBlob succeeded on hash mismatch, want error (tamper detection)")
	}
}

func TestFetchAndVerifyBlob_NoBlobPointer(t *testing.T) {
	t.Parallel()
	st := exchange.NewState()
	st.SetBlobStore(exchange.NewMemoryBlobStore())

	entry := &exchange.InventoryEntry{EntryID: "entry-3", ContentHash: "sha256:abc"}
	if _, err := st.FetchAndVerifyBlob(entry); err == nil {
		t.Fatal("FetchAndVerifyBlob with empty BlobPointer: want error, got nil")
	}
}

func TestFetchAndVerifyBlob_NoBlobStoreConfigured(t *testing.T) {
	t.Parallel()
	st := exchange.NewState() // no SetBlobStore call

	entry := &exchange.InventoryEntry{EntryID: "entry-4", ContentHash: "sha256:abc", BlobPointer: "memblob:xyz"}
	if _, err := st.FetchAndVerifyBlob(entry); err == nil {
		t.Fatal("FetchAndVerifyBlob with no configured store: want error, got nil")
	}
}
