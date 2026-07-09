//go:build !race

package main

// raceEnabled is false when the test binary was built without the race detector.
// See raceflag_race_test.go for why latency assertions branch on this.
const raceEnabled = false
