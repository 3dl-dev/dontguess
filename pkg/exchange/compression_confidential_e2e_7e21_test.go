package exchange_test

// compression_confidential_e2e_7e21_test.go is the end-to-end proof for
// dontguess-7e21: COMPRESSION WORKS ON A CONFIDENTIAL EXCHANGE, AND THE WORKER'S
// LOAN IS REPAID FROM IT.
//
// This is the test whose absence let the whole failure survive. Every piece
// below was verified in isolation at some point and reported as working; the
// loop as a whole had never once run. Measured on the live exchange 2026-07-28:
// 44 compression assigns posted over its entire life, the last of them on
// 2026-07-16 — the day the final plaintext put was accepted — and not one ever
// claimed or completed.
//
// The four defects it pins, in the order a worker hits them:
//
//	1. NO WORK EXISTED. All three assign emitters returned nil for a v2
//	   confidential entry (dontguess-3c3), and 100% of accepted inventory is v2.
//	   The job board was structurally empty, so nothing downstream could ever run.
//	2. SUBMITTING LEAKED. BuildAssignResult inlined the compressed PLAINTEXT plus
//	   its sha256 into assign-complete — a public signed relay event. Lifting (1)
//	   without fixing this would have published the work in the clear, which is
//	   why the guard could not simply be removed.
//	3. THE DERIVATIVE WAS EMPTY. createCompressionDerivative read only the hash
//	   and size and never the content, entering every derivative into inventory
//	   AND the match index with no bytes — matchable, undeliverable.
//	4. THE BOUNTY DID NOT REPAY. handleAssignAccept paid via a bare AddBudget and
//	   never withheld against the worker's deliver-on-credit debt, so a borrower
//	   could do the work, be paid, and still owe the full loan.
//
// Everything here is real: real secp256k1 identities, a real §541 v2 envelope
// (real CEK, real ChaCha20-Poly1305, real NIP-44 wrap to the operator), the real
// operator fold, the real RunAutoAcceptAssigns ticker, and a real
// scrip-loan-mint. Only the Embedder is a deterministic stub, so GATE2's cosine
// threshold is exercised at an exact boundary instead of MiniLM's numerics.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
	"github.com/3dl-dev/dontguess/pkg/scrip"
)

// confidentialCompressFixture is a team-tier engine (operator signer armed, so
// encryptedRequired is on and only v2 puts fold) holding one v2 confidential
// entry, with a worker that is allowlisted and carrying a loan.
type confidentialCompressFixture struct {
	h        *testHarness
	eng      *exchange.Engine
	cs       *scrip.LocalScripStore
	operator identity.Signer
	// worker is the entry's SELLER: a HOT compression assign is exclusive to the
	// seller, which authored the plaintext and is therefore the party that can
	// actually do the work. (The WARM tier addresses the buyer instead and shares
	// the same lifted guard, submission path and repayment — see
	// TestWarmCompression_V2EntryGetsAssign.)
	worker   identity.Signer
	stranger identity.Signer
	entryID  string
	origText string
}

const (
	confidentialTokenCost = int64(20000)
	// The hot bounty is HotCompressionBountyPct (300%) of token_cost.
	wantHotBounty = confidentialTokenCost * exchange.HotCompressionBountyPct / 100
)

// foldV2Put publishes a v2 confidential put from signer and accepts it,
// returning the folded entry. The payload is built exactly the way
// relayclient.buildPutMessage builds one.
func foldV2Put(t *testing.T, f *confidentialCompressFixture, seller identity.Signer, desc, plaintext string, tokenCost int64) *exchange.InventoryEntry {
	t.Helper()
	payload, _ := buildV2PutPayload(t, seller, f.operator.PubKeyHex(), desc, []byte(plaintext), tokenCost)
	putMsg := f.h.sendMessage(&testAgent{pubKeyHex: seller.PubKeyHex()}, payload,
		[]string{exchange.TagPut, "exchange:content-type:code", "exchange:domain:go"}, nil)

	// Accept through the REAL production path (AutoAcceptPut), not a hand-folded
	// put-accept: AutoAcceptPut is what fires the HOT compression assign, and that
	// firing is precisely what dontguess-7e21 restores for a v2 entry.
	replayAll(t, f.h, f.eng)
	if err := f.eng.AutoAcceptPut(putMsg.ID, tokenCost*70/100, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}
	replayAll(t, f.h, f.eng)

	entry := f.eng.State().GetInventoryEntry(putMsg.ID)
	if entry == nil {
		t.Fatalf("v2 put %s did not fold into inventory — encryptedRequired dropped it", putMsg.ID[:8])
	}
	if entry.WrappedCEKOperator == "" {
		t.Fatal("folded entry is not v2 (no WrappedCEKOperator) — the fixture is not exercising the confidential path")
	}
	return entry
}

func newConfidentialCompressFixture(t *testing.T) *confidentialCompressFixture {
	t.Helper()
	h := newTestHarness(t)
	operator, seller, stranger := useSecpIdentities(t, h)
	worker := seller // hot assigns are exclusive to the entry's seller

	cs, err := scrip.NewLocalScripStore(h.st, operator.PubKeyHex())
	if err != nil {
		t.Fatalf("NewLocalScripStore: %v", err)
	}
	if err := cs.Replay(); err != nil {
		t.Fatalf("cs.Replay: %v", err)
	}
	ks := exchange.NewKeySet(seller.PubKeyHex(), stranger.PubKeyHex())
	tc, err := exchange.NewTrustChecker(operator.PubKeyHex(), ks)
	if err != nil {
		t.Fatalf("NewTrustChecker: %v", err)
	}

	f := &confidentialCompressFixture{h: h, cs: cs, operator: operator, worker: worker, stranger: stranger}
	f.eng = h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator // arms encryptedRequired: only v2 puts fold
		o.ScripStore = cs
		o.TrustChecker = tc
		o.Embedder = markerEmbedder{}
	})

	f.origText = padTo("VEC_A confidential original ", 400)
	entry := foldV2Put(t, f, seller, "a confidential compressible doc", f.origText, confidentialTokenCost)
	f.entryID = entry.EntryID
	return f
}

// TestConfidentialCompression_FullLoop_WorkExists_SubmissionEncrypted_LoanRepaid
// drives the whole loop end to end on a confidential exchange.
func TestConfidentialCompression_FullLoop_WorkExists_SubmissionEncrypted_LoanRepaid(t *testing.T) {
	t.Parallel()
	f := newConfidentialCompressFixture(t)

	// ── (1) WORK EXISTS. Accepting a v2 put posts a hot compression assign. ──
	// Before dontguess-7e21 this was unconditionally suppressed, which is why the
	// live exchange posted zero assigns for the 12 days after its last plaintext
	// put. The assign goes to the entry's SELLER, which authored the plaintext and
	// can therefore actually do the work. Nothing extra is posted here — the
	// fixture's AutoAcceptPut already fired it, exactly as production does.
	var assignID string
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.TaskType == "compress" && a.EntryID == f.entryID {
			assignID = a.AssignID
			break
		}
	}
	if assignID == "" {
		t.Fatal("no compression assign exists for the v2 entry — the compression labor market has no supply (dontguess-7e21 defect 1)")
	}

	// ── The worker is carrying deliver-on-credit debt. ──
	principal := wantHotBounty * 2
	loanPayload, _ := json.Marshal(scrip.LoanMintPayload{
		Borrower: f.worker.PubKeyHex(), Principal: principal, LoanID: "loan-7e21-e2e",
	})
	loanMsg := f.h.sendMessage(f.h.operator, loanPayload, []string{scrip.TagScripLoanMint}, nil)
	replayAll(t, f.h, f.eng)
	f.cs.ApplyMessage(loanMsg)
	if got := f.outstanding(); got != principal {
		t.Fatalf("outstanding principal = %d, want %d", got, principal)
	}
	balanceBefore := f.cs.Balance(f.worker.PubKeyHex())

	// ── (2) THE WORKER CLAIMS, THEN SUBMITS ENCRYPTED. ──
	workerAgent := &testAgent{pubKeyHex: f.worker.PubKeyHex()}
	f.h.sendMessage(workerAgent, []byte(`{}`), []string{exchange.TagAssignClaim}, []string{assignID})
	replayAll(t, f.h, f.eng)

	claimMsgID := ""
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.AssignID == assignID {
			claimMsgID = a.ClaimMsgID
			break
		}
	}
	if claimMsgID == "" {
		t.Fatalf("claim did not fold for assign %s", assignID)
	}

	// The compressed work travels as an ORDINARY v2 PUT — the same envelope any
	// put uses — and the completion only names it. This is what
	// relayclient.BuildAssignResultForPut + the `assign complete` CLI do.
	compressedText := padTo("VEC_A compressed ", 200) // 50% of 400: GATE1 pass; same marker: GATE2 pass
	derivative := foldV2Put(t, f, f.worker, "a confidential compressible doc", compressedText, 5000)

	completeResult, _ := json.Marshal(map[string]any{"put_event": derivative.EntryID})
	f.h.sendMessage(workerAgent, completeResult, []string{exchange.TagAssignComplete}, []string{claimMsgID})
	replayAll(t, f.h, f.eng)

	// ── (3) THE OPERATOR VALIDATES AND PAYS. ──
	f.eng.RunAutoAcceptAssigns()

	if st := f.assignStatus(assignID); st != exchange.AssignPaid {
		t.Fatalf("assign status = %v, want AssignPaid — the operator refused a correctly encrypted submission", st)
	}

	// ── (4) THE LOAN IS REPAID FROM THE BOUNTY. ──
	wantWithheld := wantHotBounty * 50 / 100 // creditRepaymentWithholdPct
	if got, want := f.outstanding(), principal-wantWithheld; got != want {
		t.Fatalf("outstanding principal after the bounty = %d, want %d — compression did not pay down the debt (dontguess-7e21 defect 4)", got, want)
	}
	if got, want := f.cs.Balance(f.worker.PubKeyHex()), balanceBefore+wantHotBounty-wantWithheld; got < want {
		// >= because the worker is ALSO credited for the derivative put itself.
		t.Fatalf("worker balance = %d, want at least %d (bounty %d less withheld %d)", got, want, wantHotBounty, wantWithheld)
	}

	// ── (5) THE DERIVATIVE IS LINKED AND CARRIES CONTENT. ──
	linked := f.eng.State().GetInventoryEntry(derivative.EntryID)
	if linked == nil {
		t.Fatal("derivative entry vanished from inventory")
	}
	if linked.CompressedFrom != f.entryID {
		t.Fatalf("derivative CompressedFrom = %q, want the original %q — the medium loop will keep re-posting assigns for an entry that already has one", linked.CompressedFrom, f.entryID)
	}
	if len(linked.Content) == 0 {
		t.Fatal("derivative carries no content — matchable and undeliverable (dontguess-7e21 defect 3)")
	}
	if linked.WrappedCEKOperator == "" {
		t.Fatal("derivative is not v2 — a plaintext-shaped entry minted from confidential source")
	}
	if !f.eng.State().HasCompressedVersion(f.entryID) {
		t.Fatal("HasCompressedVersion(original) is false after a paid compression")
	}

	// ── (6) THE CANARY: no plaintext, and no hash of it, on any emission. ──
	assertNoPlaintextOnWire(t, f.h, f.origText, compressedText)
}

// TestConfidentialCompression_InlinePlaintextSubmissionRefused proves the
// operator will not accept the OLD submission shape on a confidential exchange.
// This is the guard that makes lifting the assign suppression safe: the reason
// compression could not simply be re-enabled was that completing one published
// the work in the clear, and this is what stops that.
func TestConfidentialCompression_InlinePlaintextSubmissionRefused(t *testing.T) {
	t.Parallel()
	f := newConfidentialCompressFixture(t)

	assignID := ""
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.TaskType == "compress" && a.EntryID == f.entryID {
			assignID = a.AssignID
			break
		}
	}
	if assignID == "" {
		t.Fatal("no compression assign for the v2 entry")
	}

	workerAgent := &testAgent{pubKeyHex: f.worker.PubKeyHex()}
	f.h.sendMessage(workerAgent, []byte(`{}`), []string{exchange.TagAssignClaim}, []string{assignID})
	replayAll(t, f.h, f.eng)
	claimMsgID := ""
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.AssignID == assignID {
			claimMsgID = a.ClaimMsgID
			break
		}
	}

	// The pre-7e21 shape: compressed plaintext inline, exactly what the old
	// BuildAssignResult produced.
	compressed := []byte(padTo("VEC_A compressed ", 200))
	f.h.sendMessage(workerAgent, compressResult(compressed), []string{exchange.TagAssignComplete}, []string{claimMsgID})
	replayAll(t, f.h, f.eng)

	balanceBefore := f.cs.Balance(f.worker.PubKeyHex())
	f.eng.RunAutoAcceptAssigns()

	if st := f.assignStatus(assignID); st == exchange.AssignPaid {
		t.Fatal("the operator PAID an inline plaintext submission on a confidential exchange — the compressed work was published in the clear and then rewarded for it")
	}
	if got := f.cs.Balance(f.worker.PubKeyHex()); got != balanceBefore {
		t.Fatalf("worker balance moved from %d to %d on a refused submission", balanceBefore, got)
	}
}

// TestConfidentialCompression_ForeignPutCannotBeClaimedAsWork proves a worker
// cannot collect a bounty by pointing at a put it did not author — including the
// ORIGINAL entry itself, which would pass GATE2 against itself trivially.
func TestConfidentialCompression_ForeignPutCannotBeClaimedAsWork(t *testing.T) {
	t.Parallel()
	f := newConfidentialCompressFixture(t)

	assignID := ""
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.TaskType == "compress" && a.EntryID == f.entryID {
			assignID = a.AssignID
			break
		}
	}

	workerAgent := &testAgent{pubKeyHex: f.worker.PubKeyHex()}
	f.h.sendMessage(workerAgent, []byte(`{}`), []string{exchange.TagAssignClaim}, []string{assignID})
	replayAll(t, f.h, f.eng)
	claimMsgID := ""
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.AssignID == assignID {
			claimMsgID = a.ClaimMsgID
			break
		}
	}

	// Point at a put the STRANGER authored — real, valid, correctly compressed
	// work, but not this worker's.
	foreign := foldV2Put(t, f, f.stranger, "a confidential compressible doc", padTo("VEC_A compressed ", 200), 5000)
	completeResult, _ := json.Marshal(map[string]any{"put_event": foreign.EntryID})
	f.h.sendMessage(workerAgent, completeResult, []string{exchange.TagAssignComplete}, []string{claimMsgID})
	replayAll(t, f.h, f.eng)

	balanceBefore := f.cs.Balance(f.worker.PubKeyHex())
	f.eng.RunAutoAcceptAssigns()

	if st := f.assignStatus(assignID); st == exchange.AssignPaid {
		t.Fatal("a worker was PAID for referencing a put it did not author — the bounty can be collected without doing any work")
	}
	if got := f.cs.Balance(f.worker.PubKeyHex()); got != balanceBefore {
		t.Fatalf("worker balance moved from %d to %d on a refused submission", balanceBefore, got)
	}
}

func (f *confidentialCompressFixture) assignStatus(assignID string) exchange.AssignStatus {
	for id, rec := range f.eng.State().AssignByIDForTest() {
		if id == assignID {
			return rec.Status
		}
	}
	return exchange.AssignStatus(-1)
}

func (f *confidentialCompressFixture) outstanding() int64 {
	var total int64
	for _, id := range f.cs.LoansByBorrower(f.worker.PubKeyHex()) {
		loan, ok := f.cs.GetLoan(id)
		if !ok || loan.Status != scrip.LoanActive {
			continue
		}
		total += loan.Principal - loan.Repaid
	}
	return total
}

// assertNoPlaintextOnWire is the confidentiality canary: neither the original nor
// the compressed plaintext, nor the sha256 of either, may appear in ANY message
// in the log. That covers the work order (which must name CiphertextHash, never
// sha256(plaintext)) and the completion (which must reference a put, never inline
// the bytes) in a single sweep — if either regresses, this fails.
func assertNoPlaintextOnWire(t *testing.T, h *testHarness, originalText, compressedText string) {
	t.Helper()
	msgs, err := h.st.ListMessages(h.cfID, 0)
	if err != nil {
		t.Fatalf("listing messages: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("no messages captured — the canary would be vacuous")
	}
	banned := map[string]string{
		originalText:                      "the ORIGINAL plaintext",
		compressedText:                    "the COMPRESSED plaintext",
		sha256Ref([]byte(originalText)):   "sha256(original plaintext) — the §4.4 A1/P1 guess-confirmation oracle",
		sha256Ref([]byte(compressedText)): "sha256(compressed plaintext) — the same oracle over the derivative",
	}
	for _, m := range msgs {
		raw := string(m.Payload)
		for needle, what := range banned {
			if strings.Contains(raw, needle) {
				t.Fatalf("CONFIDENTIALITY LEAK: %s appeared on a public emission (tags=%v)", what, m.Tags)
			}
		}
	}
}

// TestWarmCompression_V2EntryGetsAssign covers the tier the deliver-on-credit
// loop actually runs on: a BUYER that just received and decrypted an entry is
// offered the compression work on it (dontguess-7e21).
//
// This is the half of the loop the operator described — borrow to buy, compress
// what you now hold, clear the loan from the bounty — and sendWarmCompressionAssign
// returned nil for every v2 entry before this fix, so the borrower was told the
// work existed and then offered none. The hot tier's full submission/payment/
// repayment path is proved by the E2E above; what this pins is that the WARM
// emitter is reachable at all for a confidential entry.
func TestWarmCompression_V2EntryGetsAssign(t *testing.T) {
	t.Parallel()
	f := newConfidentialCompressFixture(t)

	buyMsg := f.h.sendMessage(&testAgent{pubKeyHex: f.stranger.PubKeyHex()},
		buyPayload("a confidential compressible doc", 100000),
		[]string{exchange.TagBuy}, nil)
	replayAll(t, f.h, f.eng)
	rec, err := f.h.st.GetMessage(buyMsg.ID)
	if err != nil {
		t.Fatalf("GetMessage(buy): %v", err)
	}
	if err := f.eng.DispatchForTest(exchange.FromStoreRecord(rec)); err != nil {
		t.Fatalf("DispatchForTest(buy): %v", err)
	}
	replayAll(t, f.h, f.eng)

	var warm *exchange.AssignRecord
	for _, a := range f.eng.State().AllActiveAssigns() {
		if a.TaskType == "compress" && a.EntryID == f.entryID && a.ExclusiveSender == f.stranger.PubKeyHex() {
			warm = a
			break
		}
	}
	if warm == nil {
		t.Fatal("no WARM compression assign was offered to the buyer of a v2 entry — the borrow-compress-repay loop has no work in it (dontguess-7e21)")
	}
	// And the order it carries leaks nothing: same canary as the E2E, over every
	// emission including this warm assign's payload.
	assertNoPlaintextOnWire(t, f.h, f.origText, padTo("VEC_A compressed ", 200))
}
