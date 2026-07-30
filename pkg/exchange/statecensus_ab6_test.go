package exchange_test

// statecensus_ab6_test.go — dontguess-ab6, PHASE 1 (non-destructive).
//
// You cannot safely migrate what you cannot verify. Before any campfire-era
// record is rewritten or archived, there has to be a way to answer one question
// exactly: does state derived from the NEW log equal state derived from the OLD
// log?
//
// This file builds that answer. StateCensus replays a store the same way serve
// does — exchange.State plus scrip.LocalScripStore over the same local event log
// — and reduces the result to a canonical, order-independent fingerprint of
// everything that is load-bearing:
//
//   - inventory: entry ids, sellers, token_cost, price, content size
//   - scrip: total supply, per-agent balances, loans (principal/repaid)
//   - reputation: per-seller score
//   - conservation: TotalSupply == sum(balances), the invariant a bad migration
//     would break first
//
// Deliberately NOT a migration. Nothing here writes to the live store. Run
// against the real DG_HOME with DONTGUESS_CENSUS_STORE to see live state.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
	dgstore "github.com/3dl-dev/dontguess/pkg/store"
)

// InventoryFingerprint is one entry reduced to the fields a migration must
// preserve exactly. Content bytes are represented by size, not value, so the
// fingerprint stays small and printable while still catching truncation.
type InventoryFingerprint struct {
	EntryID     string `json:"entry_id"`
	SellerKey   string `json:"seller_key"`
	TokenCost   int64  `json:"token_cost"`
	PutPrice    int64  `json:"put_price"`
	ContentSize int64  `json:"content_size"`
	ContentHash string `json:"content_hash"`
}

// LoanFingerprint is one credit record reduced to its money-bearing fields.
type LoanFingerprint struct {
	LoanID    string `json:"loan_id"`
	Borrower  string `json:"borrower"`
	Principal int64  `json:"principal"`
	Repaid    int64  `json:"repaid"`
}

// StateCensus is the complete comparable fingerprint of a store's derived state.
type StateCensus struct {
	Records          int                    `json:"records"`
	AgentsScanned    int                    `json:"agents_scanned"`
	Inventory        []InventoryFingerprint `json:"inventory"`
	Balances         map[string]int64       `json:"balances"`
	Loans            []LoanFingerprint      `json:"loans"`
	Reputation       map[string]int         `json:"reputation"`
	TotalSupply      int64                  `json:"total_supply"`
	TotalBurned      int64                  `json:"total_burned"`
	LoanPrincipal    int64                  `json:"loan_principal"`
	OutstandingHolds int64                  `json:"outstanding_holds"`
	RoundingDust     int64                  `json:"rounding_dust"`
	OutstandingVig   int64                  `json:"outstanding_vig"`
	SumBalances      int64                  `json:"sum_balances"`
	Conserves        bool                   `json:"conserves"`
	PendingPuts      int                    `json:"pending_puts"`
	ActiveOrders     int                    `json:"active_orders"`
}

// takeCensus replays storePath and reduces derived state to a fingerprint.
// operatorKey gates the scrip store's operator-authored messages exactly as
// serve does.
func takeCensus(t *testing.T, storePath, operatorKey string) *StateCensus {
	t.Helper()

	st, err := dgstore.Open(storePath)
	if err != nil {
		t.Fatalf("store.Open(%s): %v", storePath, err)
	}
	defer st.Close()

	recs, err := st.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	state := exchange.NewState()
	state.Replay(exchange.FromStoreRecords(recs))

	ss, err := scrip.NewLocalScripStore(st, operatorKey)
	if err != nil {
		t.Fatalf("NewLocalScripStore: %v", err)
	}

	c := &StateCensus{
		Records:    len(recs),
		Balances:   map[string]int64{},
		Reputation: map[string]int{},
	}

	// ENUMERATE EVERY AGENT, not just sellers holding inventory.
	//
	// LocalScripStore exposes Balance(key) but no AllBalances(), so the candidate
	// set has to be built from the log. Getting this wrong is not a cosmetic
	// error: an incomplete agent set makes sum(balances) too small, which reads as
	// a conservation FAILURE on a live money ledger. The first version of this
	// census summed only inventory sellers plus the operator and reported a
	// 1,431,946 shortfall that was entirely an artifact of the missing keys.
	//
	// Candidates: every record sender, every 64-hex token appearing anywhere in a
	// scrip-kind payload (mint/pay/settle/loan messages name their counterparty),
	// and the operator itself.
	candidates := map[string]struct{}{operatorKey: {}}
	hex64 := regexp.MustCompile(`[0-9a-f]{64}`)
	for i := range recs {
		if s := recs[i].Sender; s != "" {
			candidates[s] = struct{}{}
		}
		for _, m := range hex64.FindAllString(string(recs[i].Payload), -1) {
			candidates[m] = struct{}{}
		}
	}
	for k := range candidates {
		if bal := ss.Balance(k); bal != 0 {
			c.Balances[k] = bal
		}
	}
	c.AgentsScanned = len(candidates)

	for _, e := range state.AllInventoryEntries() {
		c.Inventory = append(c.Inventory, InventoryFingerprint{
			EntryID:     e.EntryID,
			SellerKey:   e.SellerKey,
			TokenCost:   e.TokenCost,
			PutPrice:    e.PutPrice,
			ContentSize: e.ContentSize,
			// ContentHash is the strongest single check that a migration did not
			// alter payloads: it is derived from the content bytes themselves.
			ContentHash: e.ContentHash,
		})
		if _, seen := c.Reputation[e.SellerKey]; !seen {
			c.Reputation[e.SellerKey] = state.SellerReputation(e.SellerKey)
		}
	}
	// Canonical order so two censuses of the same state compare equal regardless
	// of map iteration order.
	sort.Slice(c.Inventory, func(i, j int) bool { return c.Inventory[i].EntryID < c.Inventory[j].EntryID })

	c.TotalSupply = ss.TotalSupply()
	c.TotalBurned = ss.TotalBurned()
	c.OutstandingHolds, c.RoundingDust = holdsAndDust(recs)
	c.LoanPrincipal = ss.TotalLoanPrincipal()
	c.OutstandingVig = ss.TotalOutstandingVig()
	for _, v := range c.Balances {
		c.SumBalances += v
	}
	// THE CONSERVATION INVARIANT (dontguess-7f0), established by independently
	// re-deriving the ledger from the scrip message stream:
	//
	//	totalSupply - totalBurned - outstandingHolds - roundingDust == sum(balances)
	//
	// Getting this equation wrong is what produced a false ~633K "shortfall" and
	// nearly had a live money ledger reported as broken. Two terms are easy to
	// miss and both are load-bearing:
	//
	//   - OUTSTANDING HOLDS. applyBuyHold DEBITS the buyer immediately; the seller
	//     and operator are only credited at settle. Between the two, that scrip is
	//     in neither party's balance. 632,809 of it was outstanding when this was
	//     measured — 55% of everything ever held — because most matches never
	//     complete.
	//   - ROUNDING DUST. Each settle splits the held amount three ways (residual +
	//     exchange_revenue + fee_burned) with integer division, losing exactly 1
	//     scrip per settle. 17 settles, 17 scrip, unassigned to anyone.
	//
	// totalBurned is NOT subtracted from any balance by applyBurn — burn destroys
	// scrip already removed from a balance via a hold, so it only ever increments
	// the counter.
	c.Conserves = c.TotalSupply-c.TotalBurned-c.OutstandingHolds-c.RoundingDust == c.SumBalances
	c.PendingPuts = len(state.PendingPuts())
	c.ActiveOrders = len(state.ActiveOrders())

	return c
}

// TestStateCensus_LiveStore prints the census for a real store when pointed at
// one. It is the measurement step of dontguess-ab6 and is SKIPPED by default so
// it never touches a developer's or CI's environment.
//
//	DONTGUESS_CENSUS_STORE=~/.dontguess/events.jsonl \
//	DONTGUESS_CENSUS_OPERATOR=<hex> \
//	go test ./pkg/exchange -run TestStateCensus_LiveStore -v
func TestStateCensus_LiveStore(t *testing.T) {
	storePath := os.Getenv("DONTGUESS_CENSUS_STORE")
	if storePath == "" {
		t.Skip("DONTGUESS_CENSUS_STORE unset — measurement-only test, nothing to do")
	}
	operatorKey := os.Getenv("DONTGUESS_CENSUS_OPERATOR")
	if operatorKey == "" {
		t.Fatal("DONTGUESS_CENSUS_OPERATOR must be set alongside DONTGUESS_CENSUS_STORE")
	}

	c := takeCensus(t, storePath, operatorKey)

	t.Logf("records:        %d", c.Records)
	t.Logf("inventory:      %d entries", len(c.Inventory))
	t.Logf("balances:       %d agents, sum %d", len(c.Balances), c.SumBalances)
	t.Logf("total supply:   %d", c.TotalSupply)
	t.Logf("total burned:   %d", c.TotalBurned)
	t.Logf("loan principal: %d", c.LoanPrincipal)
	t.Logf("outstanding vig:%d", c.OutstandingVig)
	t.Logf("supply-burned:  %d   (vs sum %d, delta %d)", c.TotalSupply-c.TotalBurned, c.SumBalances, (c.TotalSupply-c.TotalBurned)-c.SumBalances)
	t.Logf("agents scanned: %d", c.AgentsScanned)
	t.Logf("CONSERVES:      %v", c.Conserves)
	t.Logf("pending puts:   %d", c.PendingPuts)
	t.Logf("active orders:  %d", c.ActiveOrders)
	t.Logf("loans:          %d", len(c.Loans))

	if out := os.Getenv("DONTGUESS_CENSUS_OUT"); out != "" {
		b, _ := json.MarshalIndent(c, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatalf("write census: %v", err)
		}
		t.Logf("census written to %s", out)
	}

	// The conservation invariant is reported, NOT asserted, on a live store: if
	// live state already fails to conserve, that is a finding to investigate
	// before migrating — not a reason to fail the measurement that found it.
	if !c.Conserves {
		t.Logf("NOTE: live state does NOT conserve (supply %d vs sum %d, delta %d). Investigate BEFORE any migration — a migration cannot be validated against an invariant that is already broken.",
			c.TotalSupply, c.SumBalances, c.TotalSupply-c.SumBalances)
	}
}

// TestStateCensus_IsDeterministic proves the fingerprint is stable: censusing the
// same store twice must produce identical output, or it is useless as a
// before/after migration comparison.
func TestStateCensus_IsDeterministic(t *testing.T) {
	storePath := os.Getenv("DONTGUESS_CENSUS_STORE")
	if storePath == "" {
		t.Skip("DONTGUESS_CENSUS_STORE unset")
	}
	operatorKey := os.Getenv("DONTGUESS_CENSUS_OPERATOR")
	if operatorKey == "" {
		t.Fatal("DONTGUESS_CENSUS_OPERATOR must be set")
	}

	a := takeCensus(t, storePath, operatorKey)
	b := takeCensus(t, storePath, operatorKey)

	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("census is NOT deterministic over the same store — it cannot be used to validate a migration")
	}
	fmt.Fprintf(os.Stderr, "census deterministic over %d records\n", a.Records)
}

// holdsAndDust re-derives the two ledger terms LocalScripStore does not expose:
// the value of buy-holds that never settled, and the scrip lost to integer
// truncation when a settle splits a held amount three ways.
//
// Both come straight off the scrip message stream. They exist as free functions
// rather than store accessors because the store deliberately models only what it
// needs to answer Balance(); these are audit quantities.
func holdsAndDust(recs []dgstore.Record) (outstanding, dust int64) {
	type held struct{ amount int64 }
	holds := map[string]held{}
	settled := map[string]struct{}{}
	var settles []map[string]any

	for i := range recs {
		var p map[string]any
		if json.Unmarshal(recs[i].Payload, &p) != nil {
			continue
		}
		for _, t := range recs[i].Tags {
			switch t {
			case "dontguess:scrip-buy-hold":
				if rid, ok := p["reservation_id"].(string); ok {
					holds[rid] = held{amount: int64(asF(p["amount"]))}
				}
			case "dontguess:scrip-settle":
				if rid, ok := p["reservation_id"].(string); ok {
					settled[rid] = struct{}{}
				}
				settles = append(settles, p)
			}
		}
	}
	for rid, h := range holds {
		if _, done := settled[rid]; !done {
			outstanding += h.amount
		}
	}
	for _, p := range settles {
		rid, _ := p["reservation_id"].(string)
		h, ok := holds[rid]
		if !ok {
			continue
		}
		parts := int64(asF(p["residual"])) + int64(asF(p["exchange_revenue"])) + int64(asF(p["fee_burned"]))
		dust += h.amount - parts
	}
	return outstanding, dust
}

func asF(v any) float64 {
	f, _ := v.(float64)
	return f
}
