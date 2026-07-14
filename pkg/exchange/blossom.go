package exchange

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// BlobStore is the Blossom client seam (dontguess-7783). It abstracts the
// content-addressed blob storage used for large put content, so the exchange
// state fold never inlines oversize bytes into the replicated message log /
// InventoryEntry.
//
// Implementations MUST be content-addressed: Put must return a pointer that
// deterministically identifies the content (e.g. derived from its sha256), so
// that independent nodes replaying the same put converge on the same blob
// reference rather than diverging on storage-side nondeterminism (protects
// the "anyone replaying the log recomputes byte-identical state" invariant —
// see docs/design/nostr-first-rebuild-decision.md "Determinism of the fold").
//
// A real implementation talks to a Blossom server over HTTP (BUD-01/02). This
// package ships only the seam plus an in-memory test double (MemoryBlobStore);
// wiring a live HTTP client is separately scoped.
type BlobStore interface {
	// Put uploads content and returns a pointer that Fetch can later resolve
	// back to the identical bytes. Implementations should be idempotent for
	// identical content (same bytes in -> same/compatible pointer out).
	Put(content []byte) (pointer string, err error)

	// Fetch resolves a pointer previously returned by Put back to its bytes.
	// Returns an error if the pointer is unknown.
	Fetch(pointer string) (content []byte, err error)
}

// ErrBlobNotFound is returned by BlobStore.Fetch when the pointer is unknown.
var ErrBlobNotFound = errors.New("exchange: blob not found")

// MemoryBlobStore is an in-memory, content-addressed BlobStore. It is the
// default test double for the Blossom seam: deterministic, no network, keyed
// by the sha256 of the content so Put is naturally idempotent.
//
// Production callers should supply a real Blossom HTTP client implementing
// the same BlobStore interface; MemoryBlobStore is not durable and is not
// intended for production use.
type MemoryBlobStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte
}

// NewMemoryBlobStore creates an empty in-memory blob store.
func NewMemoryBlobStore() *MemoryBlobStore {
	return &MemoryBlobStore{blobs: make(map[string][]byte)}
}

// Put stores content keyed by its sha256 hex digest and returns that digest
// (prefixed "memblob:") as the pointer.
func (m *MemoryBlobStore) Put(content []byte) (string, error) {
	sum := sha256.Sum256(content)
	ptr := "memblob:" + hex.EncodeToString(sum[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blobs == nil {
		m.blobs = make(map[string][]byte)
	}
	// Idempotent: identical content always maps to the same pointer/bytes.
	stored := make([]byte, len(content))
	copy(stored, content)
	m.blobs[ptr] = stored
	return ptr, nil
}

// Fetch returns the bytes previously stored under pointer.
func (m *MemoryBlobStore) Fetch(pointer string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	content, ok := m.blobs[pointer]
	if !ok {
		return nil, ErrBlobNotFound
	}
	out := make([]byte, len(content))
	copy(out, content)
	return out, nil
}

// SetBlobStore configures the optional Blossom client seam. Passing nil
// restores legacy behavior (all content inlined regardless of size, subject
// only to MaxContentBytes). Not safe to call concurrently with Apply/Replay.
func (s *State) SetBlobStore(store BlobStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobStore = store
}

// BlobStore returns the currently configured Blossom client seam, or nil.
func (s *State) BlobStore() BlobStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blobStore
}

// sha256Ref returns the canonical "sha256:"+hex(sha256(b)) content-address
// string used throughout the exchange for ContentHash/CiphertextHash values.
func sha256Ref(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
