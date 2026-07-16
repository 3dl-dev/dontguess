package main

// buy_large_blossom_575_test.go — dontguess-575 GROUND-SOURCE gate.
//
// Proves the CLI (`dontguess buy` RunE) now wires a buyer-side BlobStore so
// >32 KiB encrypted content is fetchable FROM THE CLI (previously library-only:
// only relayclient.Settle with an explicit SettleOptions.BlobStore could fetch
// an offloaded blob — buy.go passed none). The test drives the REAL runBuy
// against the full in-process operator team stack (engine + relay wiring +
// LocalScripStore + AutoDeliverOnBuyerAccept), where the oversize ciphertext is
// offloaded to a REAL HTTP Blossom backend (httptest) and the CLI fetches it
// over HTTP via DONTGUESS_BLOSSOM_URL -> blossom.Client.
//
// What is REAL vs faked: the crypto (secp256k1 sign, NIP-44 CEK wrap,
// ChaCha20-Poly1305 AEAD), the exchange engine + scrip moves, the nostr
// websocket wire (e2eHub), and the Blossom transport (a real net/http round trip
// to an httptest server) are all real. Nothing about the blob fetch is stubbed:
// buy.go constructs its own blossom.Client from the env and the fetch is a
// genuine HTTP GET that must hit the backend or the buy loud-fails.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/blossom"
	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// newBlossomBackend starts a minimal content-addressed HTTP blob host: PUT
// /<addr> stores the body, GET /<addr> returns it (404 if unknown). This is the
// "real Blossom backend" the CLI fetch must hit.
func newBlossomBackend(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	blobs := map[string][]byte{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		if key == "" {
			http.Error(w, "no blob address", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mu.Lock()
			blobs[key] = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet, http.MethodHead:
			mu.Lock()
			b, ok := blobs[key]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(b)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestE2E_575_LargeContent_BuyFromCLI_FetchesFromBlossom is the item's
// ground-source gate: a >32 KiB encrypted entry offloaded to a real HTTP blob
// backend is bought FROM THE CLI and its decrypted plaintext round-trips
// byte-for-byte. A companion subtest proves the ≤32 KiB inline path is unchanged
// (nil buyer BlobStore when DONTGUESS_BLOSSOM_URL is unset).
func TestE2E_575_LargeContent_BuyFromCLI_FetchesFromBlossom(t *testing.T) {
	hushRelayLogs(t)

	dir := t.TempDir()
	ls, err := dgstore.Open(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	operator, _ := identity.Generate()
	seller, sellerHome := newAgentIdentity(t)
	buyer, buyerHome := newAgentIdentity(t)
	_ = sellerHome // the seller put is injected directly (v2 blob offload), not via runPut

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	st := newE2EStack(t, ctx, ls, operator, dir+"/events.jsonl.pubcursor",
		e2eShortPublishInterval, seller.PubKeyHex(), buyer.PubKeyHex())
	t.Cleanup(func() { cancel(); st.stop() })
	hub := newE2EHub(t, st.conn)
	opPubHex := operator.PubKeyHex()

	// ONE real HTTP Blossom backend + client, wired to the operator so applyPut
	// can fetch+verify+gate the offloaded ciphertext. The CLI buyer constructs its
	// OWN client from DONTGUESS_BLOSSOM_URL (below) — proving the CLI wiring, not
	// just a shared in-process object.
	backend := newBlossomBackend(t)
	opBlob := blossom.NewClient(backend.URL)
	st.eng.State().SetBlobStore(opBlob)

	// --- fixtures: a >32 KiB high-entropy plaintext (byte-exact recovery is
	// provable) and a small inline plaintext, with distinct descriptions so each
	// buy matches the intended entry. ---
	largeBlock := []byte("DONTGUESS-575-LARGE-SECRET-" + randHex(t, 24) + "-" + randHex(t, 96) + " ")
	largeSecret := bytes.Repeat(largeBlock, (exchange.BlossomOffloadThreshold/len(largeBlock))+64)
	if len(largeSecret) <= exchange.BlossomOffloadThreshold {
		t.Fatalf("large fixture %d not oversize (threshold %d)", len(largeSecret), exchange.BlossomOffloadThreshold)
	}
	inlineSecret := []byte("DONTGUESS-575-INLINE-SECRET-" + randHex(t, 32))

	const largeDesc = "rust tokio async mutex deadlock avoidance concurrency guide"
	const largeTask = "rust tokio async mutex deadlock concurrency avoidance guide"
	const inlineDesc = "postgres window function ranking sql analytics recipe for dashboards"
	const inlineTask = "sql window function ranking recipe for a postgres analytics dashboard"

	// Large: v2 confidential put with the CIPHERTEXT offloaded to the HTTP backend
	// (buildLargeV2Put uploads via opBlob and emits enc.blob_pointer).
	largePayload, _, _, _, _ := buildLargeV2Put(t, seller, opPubHex, largeDesc,
		"see it now", largeSecret, 60000, opBlob)
	largePutEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil, largePayload)
	st.conn.inject(largePutEv)
	hub.storePut(largePutEv)

	// Inline: v2 confidential put with the ciphertext inline in the 3401 put (the
	// buyer REQ-fetches it over conn — the hub retains it for that fetch).
	inlinePayload, _, _, _ := buildInlineV2Put(t, seller, opPubHex, inlineDesc,
		"buy now use it", inlineSecret, 8000)
	inlinePutEv := signExchangeEvent(t, seller,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil, inlinePayload)
	st.conn.inject(inlinePutEv)
	hub.storePut(inlinePutEv)

	waitFor(t, 15*time.Second, "both v2 puts auto-accept into matchable inventory", func() bool {
		return len(st.eng.State().Inventory()) == 2
	})

	st.mint(t, buyer.PubKeyHex(), wireIDBuyerMint)

	// ── (1) LARGE: buy the offloaded entry FROM THE CLI, fetching over HTTP ──
	t.Run("large_offloaded_content_fetches_from_CLI", func(t *testing.T) {
		t.Setenv("DONTGUESS_BLOSSOM_URL", backend.URL)

		buyCmd := newBuyCmd()
		var out, errb bytes.Buffer
		buyCmd.SetOut(&out)
		buyCmd.SetErr(&errb)
		setBuyFlags(t, buyCmd, map[string]string{
			"agent-home": buyerHome,
			"task":       largeTask,
			"budget":     "1000000",
			"relay":      hub.wsURL(),
			"timeout":    "60s",
		})
		if err := runBuy(buyCmd, nil); err != nil {
			t.Fatalf("runBuy (large, from CLI) returned error: %v\nstderr:\n%s", err, errb.String())
		}
		if !bytes.Equal(out.Bytes(), largeSecret) {
			t.Fatalf("large content mismatch: got %d bytes, want %d bytes (byte-identical required)",
				out.Len(), len(largeSecret))
		}
		if !strings.Contains(errb.String(), "SETTLED") {
			t.Fatalf("stderr did not surface the SETTLED outcome:\n%s", errb.String())
		}
	})

	// ── (2) INLINE: the ≤32 KiB path is unchanged with NO buyer BlobStore ──
	t.Run("inline_content_unchanged_without_blossom", func(t *testing.T) {
		// Explicitly no DONTGUESS_BLOSSOM_URL: newBuyerBlobStore() -> nil, so the
		// inline path must round-trip with no Blossom capability at all.
		if v := strings.TrimSpace(os.Getenv("DONTGUESS_BLOSSOM_URL")); v != "" {
			t.Fatalf("precondition: DONTGUESS_BLOSSOM_URL should be unset for the inline leg, got %q", v)
		}

		buyCmd := newBuyCmd()
		var out, errb bytes.Buffer
		buyCmd.SetOut(&out)
		buyCmd.SetErr(&errb)
		setBuyFlags(t, buyCmd, map[string]string{
			"agent-home": buyerHome,
			"task":       inlineTask,
			"budget":     "1000000",
			"relay":      hub.wsURL(),
			"timeout":    "60s",
		})
		if err := runBuy(buyCmd, nil); err != nil {
			t.Fatalf("runBuy (inline, no blossom) returned error: %v\nstderr:\n%s", err, errb.String())
		}
		if !bytes.Equal(out.Bytes(), inlineSecret) {
			t.Fatalf("inline content mismatch: got %q, want %q", out.String(), string(inlineSecret))
		}
		if !strings.Contains(errb.String(), "SETTLED") {
			t.Fatalf("stderr did not surface the SETTLED outcome:\n%s", errb.String())
		}
	})
}
