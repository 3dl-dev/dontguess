package main

// IPC op constants for the operator unix domain socket protocol.
// All string literals in serve.go and operator.go must use these constants —
// no bare string literals for op names (dontguess-0b1).
const (
	OpListHeld  = "list-held"
	OpAcceptPut = "accept-put"
	OpRejectPut = "reject-put"
	// OpMetrics returns the running engine's degradation counters
	// (exchange.DegradationCounts) — dispatch trust-gate rejections, counted
	// and alarmed rather than silently dropped (docs/design/relay-transport.md
	// §2.4a D4 + §3, dontguess-388). Consumed by `dontguess status`.
	OpMetrics = "metrics"
	// OpMint is the operator genesis-funding god-button (design §4): mint scrip
	// to an agent so the first team-tier buy does not deadlock on
	// ErrBudgetExceeded. Operator-only (the socket lives in a 0700 dir inside the
	// trust boundary), audit-logged. Consumed by `dontguess mint`.
	OpMint = "mint"
)
