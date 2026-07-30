package exchange_test

// campfirefry_ab6_test.go — dontguess-ab6.
//
// OPERATOR DIRECTIVE: campfire is done and is never coming back. Campfire-era
// records are not ported, not transcoded, not supported. They are DROPPED.
//
// That decision collapses this from a state-preserving migration into a filter,
// and it removes the blocker (dontguess-7f0): we are no longer trying to prove
// that campfire-era-derived state survives, because it is deliberately not
// surviving. What still MUST be measured is the cost — what leaves with them —
// because dropping a put drops its inventory and dropping a scrip message drops
// the balance it created.
//
// isNostrNative is the fence. A record is kept only if EVERY identifier in it is
// a well-formed nostr value:
//
//	id          — 64-hex (32-byte event id).  16-byte campfire ids fail.
//	sender      — 64-hex AND on the secp256k1 curve. Dead ed25519 keys fail.
//	antecedents — every one 64-hex. This is the class that wedged egress for
//	              thirteen hours in dontguess-6d2.
//
// The same predicate is the permanent INGEST FENCE: what cannot be kept now must
// not be accepted later, or the class returns.

import (
	"bufio"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// secp256k1P is the field prime. A 32-byte x-only pubkey is valid only if x < p
// and x^3+7 is a quadratic residue mod p (i.e. the point is actually on-curve).
var secp256k1P, _ = new(big.Int).SetString(
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isOnCurve reports whether a 64-hex string is a real secp256k1 x-only pubkey.
// Roughly half of all 32-byte values are not, which is why 67 of this exchange's
// historical senders are unadmittable dead ed25519 keys.
func isOnCurve(hexKey string) bool {
	if !isHex64(hexKey) {
		return false
	}
	x, ok := new(big.Int).SetString(hexKey, 16)
	if !ok || x.Cmp(secp256k1P) >= 0 {
		return false
	}
	// y^2 = x^3 + 7 mod p; on-curve iff that value is a quadratic residue,
	// i.e. (x^3+7)^((p-1)/2) == 1 mod p.
	y2 := new(big.Int).Exp(x, big.NewInt(3), secp256k1P)
	y2.Add(y2, big.NewInt(7))
	y2.Mod(y2, secp256k1P)
	exp := new(big.Int).Sub(secp256k1P, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	return new(big.Int).Exp(y2, exp, secp256k1P).Cmp(big.NewInt(1)) == 0
}

// FryReason records WHY a record was dropped, so the operation is auditable
// rather than a silent purge.
type FryReason struct {
	ShortID     int `json:"short_id"`
	ShortSender int `json:"short_sender"`
	OffCurve    int `json:"off_curve_sender"`
	ShortAnte   int `json:"short_antecedent"`
	Unparseable int `json:"unparseable"`
}

// isNostrNative is the keep/drop fence AND the future ingest fence.
func isNostrNative(rec *dgstore.Record, why *FryReason) bool {
	switch {
	case !isHex64(rec.ID):
		why.ShortID++
		return false
	case !isHex64(rec.Sender):
		why.ShortSender++
		return false
	case !isOnCurve(rec.Sender):
		why.OffCurve++
		return false
	}
	for _, a := range rec.Antecedents {
		if !isHex64(a) {
			why.ShortAnte++
			return false
		}
	}
	return true
}

// TestFryCampfireEra_MeasureCost writes a fried copy of a store and reports
// exactly what a fry costs in derived state. Measurement only — it never touches
// the input store.
//
//	DONTGUESS_FRY_IN=<copy of events.jsonl> DONTGUESS_FRY_OUT=<path> \
//	DONTGUESS_CENSUS_OPERATOR=<hex> go test ./pkg/exchange -run TestFryCampfireEra -v
func TestFryCampfireEra_MeasureCost(t *testing.T) {
	in := os.Getenv("DONTGUESS_FRY_IN")
	out := os.Getenv("DONTGUESS_FRY_OUT")
	operatorKey := os.Getenv("DONTGUESS_CENSUS_OPERATOR")
	if in == "" || out == "" {
		t.Skip("DONTGUESS_FRY_IN / DONTGUESS_FRY_OUT unset — measurement-only test")
	}
	if operatorKey == "" {
		t.Fatal("DONTGUESS_CENSUS_OPERATOR must be set")
	}

	src, err := os.Open(in)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(out)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	defer dst.Close()

	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	w := bufio.NewWriter(dst)

	var why FryReason
	total, kept := 0, 0
	for sc.Scan() {
		line := sc.Bytes()
		total++
		var rec dgstore.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			why.Unparseable++
			continue
		}
		if !isNostrNative(&rec, &why) {
			continue
		}
		w.Write(line)     //nolint:errcheck
		w.WriteByte('\n') //nolint:errcheck
		kept++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	dropped := total - kept
	t.Logf("=== FRY ===")
	t.Logf("total records:      %d", total)
	t.Logf("kept (nostr-native):%d", kept)
	t.Logf("DROPPED:            %d  (%.1f%%)", dropped, 100*float64(dropped)/float64(total))
	t.Logf("  16-byte id:       %d", why.ShortID)
	t.Logf("  short sender:     %d", why.ShortSender)
	t.Logf("  off-curve sender: %d", why.OffCurve)
	t.Logf("  short antecedent: %d", why.ShortAnte)
	t.Logf("  unparseable:      %d", why.Unparseable)

	before := takeCensus(t, in, operatorKey)
	after := takeCensus(t, out, operatorKey)

	t.Logf("=== COST IN DERIVED STATE ===")
	t.Logf("                    before -> after")
	t.Logf("inventory entries:  %d -> %d", len(before.Inventory), len(after.Inventory))
	t.Logf("agents w/ balance:  %d -> %d", len(before.Balances), len(after.Balances))
	t.Logf("sum(balances):      %d -> %d", before.SumBalances, after.SumBalances)
	t.Logf("total supply:       %d -> %d", before.TotalSupply, after.TotalSupply)
	t.Logf("total burned:       %d -> %d", before.TotalBurned, after.TotalBurned)
	t.Logf("loan principal:     %d -> %d", before.LoanPrincipal, after.LoanPrincipal)
	t.Logf("pending puts:       %d -> %d", before.PendingPuts, after.PendingPuts)
	t.Logf("CONSERVES:          %v -> %v", before.Conserves, after.Conserves)
	t.Logf("supply-sum delta:   %d -> %d", before.TotalSupply-before.SumBalances, after.TotalSupply-after.SumBalances)

	// Name the entries that would be lost, so the cost is concrete rather than a
	// count. An entry losing its inventory means content a buyer could have bought.
	keptIDs := map[string]struct{}{}
	for _, e := range after.Inventory {
		keptIDs[e.EntryID] = struct{}{}
	}
	lost := 0
	for _, e := range before.Inventory {
		if _, ok := keptIDs[e.EntryID]; !ok {
			if lost < 12 {
				t.Logf("  LOST entry %s seller=%s token_cost=%d size=%d", e.EntryID[:12], e.SellerKey[:12], e.TokenCost, e.ContentSize)
			}
			lost++
		}
	}
	t.Logf("inventory entries LOST: %d", lost)
}

// TestIsNostrNative_FenceRejectsTheKnownPoison pins the predicate against the
// exact values that caused today's two outages, so the ingest fence built on it
// cannot silently stop catching them.
func TestIsNostrNative_FenceRejectsTheKnownPoison(t *testing.T) {
	t.Parallel()
	good := "6c74c7bb0f0acb9ee4820f63b52f4209490eaef6fba7d1d2c34c2622413498f1"
	if !isOnCurve(good) {
		t.Fatal("the live operator key is reported off-curve — the curve check itself is wrong")
	}
	// dontguess-31b: the off-curve sender that bricked the operator boot.
	if isOnCurve("e53a88d79ef658a13d2befffb7312b7256563b5f94f0a240340f6580c68e3686") {
		t.Fatal("the 31b boot-bricking key is reported on-curve")
	}

	cases := []struct {
		name string
		rec  dgstore.Record
		want bool
	}{
		{"nostr-native", dgstore.Record{ID: good, Sender: good}, true},
		{"16-byte id", dgstore.Record{ID: "c50d41055706d5d9054f46f8fec2f5a2", Sender: good}, false},
		{"off-curve sender", dgstore.Record{ID: good, Sender: "e53a88d79ef658a13d2befffb7312b7256563b5f94f0a240340f6580c68e3686"}, false},
		// dontguess-6d2: the short antecedent that wedged egress for 13 hours.
		{"short antecedent", dgstore.Record{ID: good, Sender: good, Antecedents: []string{"c50d41055706d5d9054f46f8fec2f5a2"}}, false},
		{"good antecedent", dgstore.Record{ID: good, Sender: good, Antecedents: []string{good}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var why FryReason
			if got := isNostrNative(&tc.rec, &why); got != tc.want {
				t.Fatalf("isNostrNative(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
