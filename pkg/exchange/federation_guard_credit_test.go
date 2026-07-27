package exchange_test

// dontguess-29b wave-6 fix, item 1+2: the deliver-on-credit tier gate
// (engine_credit.go's creditTierEligible) was gated on the WRONG flag.
//
// engine_core.go documents BrokeredMatchMode as a matching-ROUTING toggle
// ("handleBuy posts an exchange:assign ... instead of running inline
// semantic matching ... Inline matching is the default ... and always
// coexists: operators may toggle this flag to switch routing without
// affecting either path's state machine") — it says nothing about
// trust/deployment topology. FederationGuardEnabled is the actual
// federation-deployment flag ("REQUIRED in multi-operator/federation
// deployments... Defaults false for single-operator deployments").
//
// The wave-5 implementation gated deliver-on-credit on
// `!e.opts.BrokeredMatchMode`, which is both under- and over-inclusive:
//   - a fleet operator who merely enables brokered ROUTING (BrokeredMatchMode
//     = true, FederationGuardEnabled = false, still single-operator) would
//     have been WRONGLY denied credit — routing mode has nothing to do with
//     the Sybil scope fence this gate exists to enforce.
//   - a genuine federation deployment that never touches BrokeredMatchMode
//     (FederationGuardEnabled = true, BrokeredMatchMode = false) would have
//     WRONGLY been granted credit — exactly the Sybil-shaped hole
//     (dontguess-29b's SYBIL CAVEAT) this gate is supposed to close.
//
// TestCreditTierEligible_GatesOnFederationGuardNotBrokeredMatchMode proves
// the gate keys on the right flag by directly asserting creditTierEligible()
// across all four flag combinations. If the gate is reverted to
// `!BrokeredMatchMode` (or any variant that doesn't check
// FederationGuardEnabled), the "brokered routing only" and "federation guard
// only" cases below flip and this test fails.
//
// TestDeliverOnCredit_FederationGuardEnabledMintsNoCredit proves the same
// thing at the integration level: a federation-configured engine
// (FederationGuardEnabled=true) facing a broke buyer at buyer-accept mints
// NO scrip-loan-mint message and falls through to the pre-29b
// insufficient_scrip reject, exactly as it did before deliver-on-credit
// existed.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/store"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

func TestCreditTierEligible_GatesOnFederationGuardNotBrokeredMatchMode(t *testing.T) {
	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)

	cases := []struct {
		name            string
		scripStore      scrip.SpendingStore
		brokeredMode    bool
		federationGuard bool
		want            bool
	}{
		{
			name:       "individual tier (ScripStore == nil) — never eligible regardless of flags",
			scripStore: nil, brokeredMode: false, federationGuard: false,
			want: false,
		},
		{
			name:       "fleet tier, default flags — eligible",
			scripStore: cs, brokeredMode: false, federationGuard: false,
			want: true,
		},
		{
			name:       "fleet tier with brokered ROUTING enabled but no federation guard — STILL eligible (BrokeredMatchMode is a matching-routing flag, not the federation gate)",
			scripStore: cs, brokeredMode: true, federationGuard: false,
			want: true,
		},
		{
			name:       "FederationGuardEnabled on, BrokeredMatchMode off — NEVER eligible (the actual federation/Sybil scope fence)",
			scripStore: cs, brokeredMode: false, federationGuard: true,
			want: false,
		},
		{
			name:       "FederationGuardEnabled on AND BrokeredMatchMode on — never eligible",
			scripStore: cs, brokeredMode: true, federationGuard: true,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := exchange.NewEngine(exchange.EngineOptions{
				OperatorPublicKey:      h.operator.PublicKeyHex(),
				ScripStore:             tc.scripStore,
				BrokeredMatchMode:      tc.brokeredMode,
				FederationGuardEnabled: tc.federationGuard,
				Logger:                 func(string, ...any) {},
			})
			if got := eng.CreditTierEligibleForTest(); got != tc.want {
				t.Errorf("creditTierEligible() = %v, want %v (ScripStore!=nil=%v BrokeredMatchMode=%v FederationGuardEnabled=%v)",
					got, tc.want, tc.scripStore != nil, tc.brokeredMode, tc.federationGuard)
			}
		})
	}
}

// TestDeliverOnCredit_FederationGuardEnabledMintsNoCredit is the integration
// mutation-guard: a federation-configured engine (FederationGuardEnabled=true)
// never mints a shortfall loan for a broke buyer — it falls through to the
// pre-29b insufficient_scrip reject, exactly as if deliver-on-credit did not
// exist. Break the fix (gate on BrokeredMatchMode instead of
// FederationGuardEnabled, or remove the gate entirely) and this test fails:
// a scrip-loan-mint message would appear and the buyer-accept-reject would
// not.
func TestDeliverOnCredit_FederationGuardEnabledMintsNoCredit(t *testing.T) {
	t.Parallel()

	h := newTestHarness(t)
	cs := newCampfireScripStore(t, h)
	eng := exchange.NewEngine(exchange.EngineOptions{
		CampfireID:             h.cfID,
		LocalStore:             h.st,
		OperatorPublicKey:      h.operator.PublicKeyHex(),
		ScripStore:             cs,
		FederationGuardEnabled: true, // the actual federation/Sybil scope fence
		Logger: func(format string, args ...any) {
			t.Logf("[engine] "+format, args...)
		},
	})

	seedInventoryEntry(t, h, eng, "Federation-tier Rust primer", "code", 12000, 8400)
	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected 1 inventory entry, got %d", len(inv))
	}
	salePrice := eng.ComputePriceForTest(inv[0])

	if bal := cs.Balance(h.buyer.PublicKeyHex()); bal != 0 {
		t.Fatalf("test setup: buyer balance should start at 0, got %d", bal)
	}

	preMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{exchange.TagMatch}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = eng.Start(ctx) }()

	h.sendMessage(h.buyer,
		buyPayload("Explain federation-tier Rust primer", salePrice+5000),
		[]string{exchange.TagBuy},
		nil,
	)

	matchMsg := waitForMatchMessage(t, h, preMsgs, 2*time.Second)
	cancel()

	// buyer-accept — zero balance, FederationGuardEnabled=true. Must reproduce
	// the pre-29b reject: decAndSaveHold fails with ErrBudgetExceeded because
	// ensureCreditForShortfall must be a no-op at this tier.
	payload, _ := json.Marshal(map[string]any{
		"phase":    "buyer-accept",
		"entry_id": inv[0].EntryID,
		"accepted": true,
	})
	buyerAccept := h.sendMessage(h.buyer, payload,
		[]string{
			exchange.TagSettle,
			exchange.TagPhasePrefix + exchange.SettlePhaseStrBuyerAccept,
			exchange.TagVerdictPrefix + "accepted",
		},
		[]string{matchMsg.ID},
	)
	allMsgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(allMsgs))
	baRec, err := h.st.GetMessage(buyerAccept.ID)
	if err != nil {
		t.Fatalf("GetMessage(buyer-accept): %v", err)
	}
	dispErr := eng.DispatchForTest(exchange.FromStoreRecord(baRec))
	if dispErr == nil {
		t.Fatal("expected buyer-accept to FAIL with insufficient scrip at federation tier (FederationGuardEnabled=true) — deliver-on-credit must not engage there")
	}

	// NO scrip-loan-mint message must exist anywhere on the log.
	loanMsgs, _ := h.st.ListMessages(h.cfID, 0, store.MessageFilter{Tags: []string{scrip.TagScripLoanMint}})
	if len(loanMsgs) != 0 {
		t.Errorf("expected 0 scrip-loan-mint messages at federation tier, got %d", len(loanMsgs))
	}

	// The pre-29b buyer-accept-reject (reason=insufficient_scrip) must exist.
	if rejects := buyerAcceptRejectMessages(t, h); len(rejects) != 1 {
		t.Errorf("expected exactly 1 settle(buyer-accept-reject) at federation tier, got %d", len(rejects))
	}

	// Balance must be unchanged (still zero) — nothing was minted.
	if bal := cs.Balance(h.buyer.PublicKeyHex()); bal != 0 {
		t.Errorf("buyer balance after failed federation-tier buyer-accept = %d, want 0 (no credit minted)", bal)
	}
}
