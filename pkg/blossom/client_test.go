package blossom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// newAddressableBackend is a minimal content-addressed HTTP blob host used to
// exercise the real HTTP round trip (PUT then GET), plus a 404 path.
func newAddressableBackend(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	blobs := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			blobs[key] = b
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			mu.Lock()
			b, ok := blobs[key]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			http.Error(w, "nope", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_PutFetch_RoundTrip(t *testing.T) {
	srv := newAddressableBackend(t)
	c := NewClient(srv.URL)

	content := bytes.Repeat([]byte("dontguess-575-blossom-transport "), 4096) // ~128 KiB
	ptr, err := c.Put(content)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Pointer is the sha256 hex (content address).
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); ptr != want {
		t.Fatalf("pointer = %q, want sha256 hex %q", ptr, want)
	}

	got, err := c.Fetch(ptr)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("fetched %d bytes, want %d — not byte-identical", len(got), len(content))
	}
}

func TestClient_Fetch_UnknownPointer_IsBlobNotFound(t *testing.T) {
	srv := newAddressableBackend(t)
	c := NewClient(srv.URL)

	_, err := c.Fetch("00000000000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeef")
	if err == nil {
		t.Fatalf("Fetch of unknown pointer: want error, got nil")
	}
	if !errors.Is(err, exchange.ErrBlobNotFound) {
		t.Fatalf("Fetch of unknown pointer: want ErrBlobNotFound, got %v", err)
	}
}

func TestClient_Put_Idempotent(t *testing.T) {
	srv := newAddressableBackend(t)
	c := NewClient(srv.URL)
	content := []byte("same bytes -> same pointer")
	p1, err := c.Put(content)
	if err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	p2, err := c.Put(content)
	if err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("Put not idempotent: %q != %q", p1, p2)
	}
}

func TestNormalizePointer(t *testing.T) {
	cases := map[string]string{
		"deadbeef":                       "deadbeef",
		"memblob:deadbeef":               "deadbeef",
		"https://host/path/deadbeef":     "deadbeef",
		"https://host:8080/x/y/deadbeef": "deadbeef",
	}
	for in, want := range cases {
		if got := normalizePointer(in); got != want {
			t.Fatalf("normalizePointer(%q) = %q, want %q", in, got, want)
		}
	}
}
