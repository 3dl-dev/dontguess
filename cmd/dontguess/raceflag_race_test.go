//go:build race

package main

// raceEnabled reports whether the test binary was built with the race detector
// (-race). The race detector instruments every memory access (~10x slowdown),
// which inflates wall-clock latency assertions without changing behavioral
// correctness — see TestRelayHotPath_BuyMatchP99_UnderBlockedRelay, which uses a
// race-appropriate ceiling so it proves hot-path isolation without flaking on
// instrumentation overhead (dontguess-7e2).
const raceEnabled = true
