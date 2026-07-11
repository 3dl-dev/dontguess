// socket.go is the individual-tier (zero-relay) client transport for
// dontguess (design docs/design/nostr-first-client-ed2.md §3.3, item
// ed2-E): sign(agentKey) is skipped entirely — individual tier is "zero
// identity ceremony" — submit(SocketTransport) talks to the already-running
// `dontguess serve` over its operator unix socket (OpPut/OpBuy,
// cmd/dontguess/ipc.go + individual_ops.go), and await happens SERVER-SIDE
// (the engine's own poll loop resolving the match), not client-side like the
// team-tier RelayTransport's per-phase REQ subscription (§3.2/§3.5).
//
// SocketTransport deliberately does NOT reuse this package's team-tier Put
// (relayclient.go, ed2-A) — that primitive signs with an agent key and
// speaks nostr EVENT/OK/REQ frames over a websocket, none of which exist on
// this tier. It is a separate, self-contained JSON request/response round
// trip over a unix socket. Types are named distinctly
// (SocketPutRequest/SocketPutResult, SocketBuyRequest/SocketBuyResult) so
// they cannot collide with the team-tier buy primitive being built in
// parallel (ed2-B).
//
// Tier detection (design §3.3): DONTGUESS_RELAY_URLS empty => individual =>
// SocketTransport; set => team => RelayTransport. Callers (cmd/dontguess's
// put/buy cobra commands) own that decision — this file has no opinion on
// env vars.
package relayclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// opPutName and opBuyName MUST match cmd/dontguess/ipc.go's OpPut/OpBuy
// constants exactly. Duplicated here (not imported) because pkg/relayclient
// cannot import "main" the other way — main already imports pkg/relayclient
// (see put.go), so the dependency can only run one direction.
const (
	opPutName = "put"
	opBuyName = "buy"
)

// DefaultSocketDialTimeout bounds the initial unix-socket dial — a serve
// that is not running (or not yet listening) must fail loud and fast, never
// hang (design §0/§5, LOUD-EVERYWHERE discipline).
const DefaultSocketDialTimeout = 3 * time.Second

// DefaultSocketPutTimeout bounds an individual-tier OpPut round trip
// (mirrors serve's operatorConnDeadline, 5s, plus slack for AutoAcceptPut
// opMu contention against the auto-accept ticker — cmd/dontguess/serve.go).
const DefaultSocketPutTimeout = 8 * time.Second

// DefaultSocketBuyTimeout bounds an individual-tier OpBuy round trip. It
// MUST exceed the server's opBuyConnDeadline (cmd/dontguess/individual_ops.go,
// 10s) — otherwise the client would give up before the server's own bounded
// await can even report a clean timeout.
const DefaultSocketBuyTimeout = 12 * time.Second

// SocketTransport talks to a running `dontguess serve` over its operator
// unix domain socket (individual tier: DONTGUESS_RELAY_URLS unset). Unlike
// the team-tier RelayTransport, there is no agent signing key, no relay
// dial, and no client-side per-phase subscription — the server folds the
// put/buy, blocks server-side for a match, and returns the answer in one
// request/response round trip.
type SocketTransport struct {
	// Path is the operator unix socket path (cmd/dontguess's socketPath()).
	// Required — this package has no default of its own (no DG_HOME
	// resolution here; that stays cmd/dontguess's job, dgpath.go).
	Path string
}

// NewSocketTransport builds a SocketTransport for the operator socket at
// path.
func NewSocketTransport(path string) *SocketTransport {
	return &SocketTransport{Path: path}
}

// SocketPutRequest is the caller-supplied content of an individual-tier put.
type SocketPutRequest struct {
	Description string
	Content     []byte // raw, already-decoded bytes
	TokenCost   int64
	// ContentType is the FULL exchange content-type tag, e.g.
	// "exchange:content-type:code" (the engine strips the prefix
	// internally), mirroring PutRequest.
	ContentType string
	Domains     []string
}

// SocketPutResult is the outcome of an individual-tier put. Unlike the
// team-tier PutResult there is no relay OK / put-reject distinction — the
// socket round trip either succeeds (durably appended AND promoted into
// matchable inventory, in one server-side call) or fails loud with an error.
type SocketPutResult struct {
	PutID string
}

// SocketBuyRequest is the caller-supplied content of an individual-tier buy.
type SocketBuyRequest struct {
	Task   string
	Budget int64
	// MaxResults <= 0 defaults to 3 server-side.
	MaxResults  int
	ContentType string
	Domains     []string
}

// SocketBuyResult is the outcome of an individual-tier buy.
//
//   - Matched=true, Miss=false: a real hit — Content holds the raw
//     (already-decoded) matched bytes.
//   - Matched=false, Miss=true: a genuine buy-miss — no cache exists yet.
//   - TimedOut=true: the server's bounded await window elapsed with no
//     match/miss observed (should not happen on individual tier absent an
//     engine stall — callers must NEVER report this as "no cache exists",
//     design §5.4's AMBIGUOUS-timeout discipline).
type SocketBuyResult struct {
	BuyID       string
	Matched     bool
	Miss        bool
	TimedOut    bool
	EntryID     string
	ContentType string
	TokenCost   int64
	Content     []byte
}

// socketPutWire is the raw JSON response shape for OpPut (mirrors
// cmd/dontguess's opPutResponse).
type socketPutWire struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	PutID string `json:"put_id,omitempty"`
}

// socketBuyWire is the raw JSON response shape for OpBuy (mirrors
// cmd/dontguess's opBuyResponse).
type socketBuyWire struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	BuyID       string `json:"buy_id,omitempty"`
	Matched     bool   `json:"matched"`
	Miss        bool   `json:"miss,omitempty"`
	TimedOut    bool   `json:"timed_out,omitempty"`
	EntryID     string `json:"entry_id,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	TokenCost   int64  `json:"token_cost,omitempty"`
	Content     string `json:"content,omitempty"`
}

// dial connects to t.Path and sets a deadline covering the whole round trip
// (request write + response read). A serve that is not running fails the
// Dial itself immediately (ECONNREFUSED/ENOENT) — no watchdog goroutine is
// needed the way the team-tier relay dial needs one (unix-domain connect
// never blocks the way a stalled TCP/TLS handshake can).
func (t *SocketTransport) dial(timeout time.Duration) (net.Conn, error) {
	if t.Path == "" {
		return nil, fmt.Errorf("relayclient: socket: empty socket path")
	}
	conn, err := net.DialTimeout("unix", t.Path, DefaultSocketDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("relayclient: socket: dial %s: %w (is `dontguess serve` running?)", t.Path, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close() //nolint:errcheck
		return nil, fmt.Errorf("relayclient: socket: set deadline: %w", err)
	}
	return conn, nil
}

// roundTrip sends req as one JSON object and decodes exactly one JSON
// response object into dst.
func socketRoundTrip(conn net.Conn, req map[string]any, dst any) error {
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	if err := json.NewDecoder(conn).Decode(dst); err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	return nil
}

// Put appends req to the running serve's inventory via OpPut, blocking for
// at most DefaultSocketPutTimeout. It dials the socket fresh for this one
// call (individual-tier IPC is a single request/response round trip, not a
// held connection) and fails loud — never silently — when the socket is
// unreachable: the wrapper's flock auto-start guarantees exactly one serve
// owns the file (design §3.3/§3.10), so an unreachable socket means no serve
// is running, which is the caller's job to report, not paper over.
func (t *SocketTransport) Put(req SocketPutRequest) (*SocketPutResult, error) {
	if req.Description == "" {
		return nil, fmt.Errorf("relayclient: socket put: empty description")
	}
	if len(req.Content) == 0 {
		return nil, fmt.Errorf("relayclient: socket put: empty content")
	}
	if req.TokenCost <= 0 {
		return nil, fmt.Errorf("relayclient: socket put: token_cost must be positive")
	}

	conn, err := t.dial(DefaultSocketPutTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	wireReq := map[string]any{
		"op":           opPutName,
		"description":  req.Description,
		"content":      base64.StdEncoding.EncodeToString(req.Content),
		"token_cost":   req.TokenCost,
		"content_type": req.ContentType,
		"domains":      req.Domains,
	}
	var resp socketPutWire
	if err := socketRoundTrip(conn, wireReq, &resp); err != nil {
		return nil, fmt.Errorf("relayclient: socket put: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("relayclient: socket put: %s", resp.Error)
	}
	return &SocketPutResult{PutID: resp.PutID}, nil
}

// Buy submits req to the running serve via OpBuy, blocking for at most
// DefaultSocketBuyTimeout while the server folds+dispatches the buy and (on
// a hit) resolves the matched content. See SocketBuyResult for how to
// interpret Matched/Miss/TimedOut.
func (t *SocketTransport) Buy(req SocketBuyRequest) (*SocketBuyResult, error) {
	if req.Task == "" {
		return nil, fmt.Errorf("relayclient: socket buy: empty task")
	}

	conn, err := t.dial(DefaultSocketBuyTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	wireReq := map[string]any{
		"op":           opBuyName,
		"task":         req.Task,
		"budget":       req.Budget,
		"max_results":  req.MaxResults,
		"content_type": req.ContentType,
		"domains":      req.Domains,
	}
	var resp socketBuyWire
	if err := socketRoundTrip(conn, wireReq, &resp); err != nil {
		return nil, fmt.Errorf("relayclient: socket buy: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("relayclient: socket buy: %s", resp.Error)
	}

	result := &SocketBuyResult{
		BuyID:       resp.BuyID,
		Matched:     resp.Matched,
		Miss:        resp.Miss,
		TimedOut:    resp.TimedOut,
		EntryID:     resp.EntryID,
		ContentType: resp.ContentType,
		TokenCost:   resp.TokenCost,
	}
	if resp.Content != "" {
		content, derr := base64.StdEncoding.DecodeString(resp.Content)
		if derr != nil {
			return nil, fmt.Errorf("relayclient: socket buy: decode content: %w", derr)
		}
		result.Content = content
	}
	return result, nil
}
