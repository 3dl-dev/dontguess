package identity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// wsRelay stands up a real websocket server that runs the relay half of the
// NIP-42 handshake (RelayAuthenticate) against a supplied allowlist. It is the
// test fixture that makes "relay round-trip authenticated via NIP-42" a genuine
// over-the-wire exchange rather than an in-process function call — the client
// speaks to it through a real *websocket.Conn.
func wsRelay(t *testing.T, allowlist *Allowlist) (relayURL string, results <-chan relayResult) {
	t.Helper()
	ch := make(chan relayResult, 4)
	upgrader := websocket.Upgrader{}

	var relayURLHolder string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		pk, authErr := RelayAuthenticate(conn, relayURLHolder, allowlist)
		ch <- relayResult{pubkey: pk, err: authErr}
		// Give the client a moment to read the OK before the conn closes.
		time.Sleep(20 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	relayURLHolder = "ws" + strings.TrimPrefix(srv.URL, "http")
	return relayURLHolder, ch
}

type relayResult struct {
	pubkey string
	err    error
}

func dial(t *testing.T, relayURL string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(relayURL, nil)
	if err != nil {
		t.Fatalf("dial relay %s: %v", relayURL, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestNIP42RoundTrip_AllowlistedAccepted drives the full handshake over a real
// websocket: an allowlisted fleet member authenticates and the relay accepts,
// returning the correct authenticated pubkey.
func TestNIP42RoundTrip_AllowlistedAccepted(t *testing.T) {
	t.Parallel()

	member, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	al, err := NewAllowlist(member.Npub())
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}

	relayURL, results := wsRelay(t, al)
	conn := dial(t, relayURL)

	if err := ClientAuthenticate(conn, member, relayURL); err != nil {
		t.Fatalf("ClientAuthenticate (allowlisted member should be accepted): %v", err)
	}

	select {
	case res := <-results:
		if res.err != nil {
			t.Fatalf("relay reported auth error for allowlisted member: %v", res.err)
		}
		if res.pubkey != member.PubKeyHex() {
			t.Fatalf("relay authed pubkey %s, want %s", res.pubkey, member.PubKeyHex())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for relay result")
	}
}

// TestNIP42RoundTrip_StrangerRejected proves the allowlist is enforced at the
// handshake: an identity NOT on the allowlist is refused even though its
// signature is cryptographically valid (NIP-42 auth proves who, allowlist
// decides whether).
func TestNIP42RoundTrip_StrangerRejected(t *testing.T) {
	t.Parallel()

	member, _ := Generate()
	stranger, _ := Generate()
	al, err := NewAllowlist(member.Npub()) // stranger deliberately excluded
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}

	relayURL, results := wsRelay(t, al)
	conn := dial(t, relayURL)

	err = ClientAuthenticate(conn, stranger, relayURL)
	if err == nil {
		t.Fatal("stranger not on the allowlist was accepted (allowlist not enforced at handshake)")
	}
	if !strings.Contains(err.Error(), "reject") {
		t.Fatalf("expected a rejection error, got: %v", err)
	}

	select {
	case res := <-results:
		if res.err == nil {
			t.Fatal("relay accepted a non-allowlisted stranger")
		}
		if res.pubkey != "" {
			t.Fatalf("relay returned a pubkey %q for a rejected stranger", res.pubkey)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for relay result")
	}
}
