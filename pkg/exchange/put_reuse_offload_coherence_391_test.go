package exchange_test

// put_reuse_offload_coherence_391_test.go — the done-gate for dontguess-391.
//
// THE FRAUD THIS CLOSES: the §4 high-reuse Gate 6 (semantic coherence,
// dontguess-5f5) fails OPEN for Blossom-OFFLOADED entries. An offloaded entry
// (>32 KiB, its ciphertext in a Blossom blob) keeps NOTHING inline —
// entry.Content is nil (content-confidentiality-envelope-541 §4.1). The pre-391
// IsHighReuseArtifact re-ran descriptionContentCoherent(nouns, entry.Content) at
// pricing/settle time; on nil content that gate returns TRUE (fail-open), so a
// keyword-stuffed junk >32 KiB put whose DESCRIPTION clears the structural gates
// 1-5 earned the high-reuse accept-price premium (85% vs 70%, engine_pricing.go
// consuming IsHighReuseArtifact) AND the 5x residual (engine_settle.go consuming
// IsHighReuseArtifact) with ZERO semantic verification of the bytes actually sold.
//
// THE FIX (dontguess-391): the operator DOES hold the decrypted plaintext at
// put-accept for the offloaded path too — decryptV2Put fetches+decrypts the blob
// to gate it. applyPut now computes the Gate-6 coherence verdict THERE, on that
// plaintext, and stores it on the entry (InventoryEntry.HighReuseCoherent).
// IsHighReuseArtifact consults the stored verdict for offloaded entries (Content
// nil) instead of re-reading the nil Content; inline entries keep the live
// computation, byte-for-byte unchanged.
//
// DONE conditions proven here, all over REAL secp256k1 + REAL nip44 + REAL
// ChaCha20-Poly1305 + a REAL content-addressed MemoryBlobStore (nothing mocked):
//
//	(a) TestOffloadCoherence_391_IncoherentJunk_NotHighReuse — an OFFLOADED
//	    (>32 KiB) v2 entry with a high-reuse-keyword description but INCOHERENT
//	    (banana-bread/lorem) content is NOT classified high-reuse. The exact
//	    fraud: no premium, no 5x residual. THIS IS THE CASE THAT FAILED PRE-391.
//	(b) TestOffloadCoherence_391_CoherentContent_IsHighReuse — an OFFLOADED entry
//	    whose content genuinely names the description's domain nouns IS classified
//	    high-reuse (the gate does not over-block genuine offloaded artifacts).
//	(c) TestOffloadCoherence_391_InlineUnchanged — an INLINE entry's classification
//	    is UNCHANGED vs pre-391 for both coherent and incoherent content (the
//	    inline live-computation path is untouched).
//	(d) TestOffloadCoherence_391_ReplayStable — a fresh engine that REBUILDS state
//	    from the message log (re-fetch + re-decrypt the blob + re-fold) recomputes
//	    the flag identically, so classification survives Replay for BOTH the fraud
//	    and the genuine offloaded entry.

import (
	"strings"
	"testing"
	"time"

	"github.com/3dl-dev/dontguess/pkg/exchange"
	"github.com/3dl-dev/dontguess/pkg/identity"
)

// highReuseOffloadDesc is a description that clears the FIVE structural §4 gates
// (content_type=code, length floor, primary keyword + adjacent co-signal, context-
// noun floor) — proven by put_reuse_coherence_test.go's genuine flock case. What
// distinguishes fraud from genuine is ONLY whether the content is coherent with it,
// which is precisely what Gate 6 checks and what the offload path used to skip.
const highReuseOffloadDesc = "flock contention test pattern for Go with race detector"

// coherentFlockBlock genuinely names the description's domain nouns (flock,
// contention, race, detector, lock, goroutine). Repeated to exceed the 32 KiB
// offload threshold; the first coherenceContentSampleBytes (8 KiB) — all of which
// is this block — is what Gate 6 samples.
const coherentFlockBlock = `package flocktest
// flock contention test pattern for Go: two goroutines race for one advisory
// flock (file lock). Run under the race detector to surface the contention window.
// The lock is an advisory flock; the goroutine that loses the race blocks until
// the holder releases the flock. This is the canonical flock contention pattern.
func TestFlockContention() { acquireFlock(); go raceForFlock(); releaseFlock() }
`

// incoherentJunkBlock shares NO domain nouns with highReuseOffloadDesc — it is the
// "keyword-stuff the description, sell unrelated bytes" fraud. Repeated past 32 KiB.
const incoherentJunkBlock = `The quick brown fox jumps over the lazy dog. ` +
	`Lorem ipsum dolor sit amet, consectetur adipiscing elit. ` +
	`A recipe for banana bread: flour, sugar, eggs, and ripe bananas. ` +
	`The weather today is mild with scattered clouds over the harbor. `

// bytesAtLeast repeats block until the result exceeds the offload threshold, so
// the put takes the Blossom offload path (entry.Content == nil).
func bytesAtLeast(block string, min int) []byte {
	reps := (min / len(block)) + 2
	return []byte(strings.Repeat(block, reps))
}

// foldOffloadedEntry publishes a v2 OFFLOADED put with the given description and
// plaintext, folds+accepts it, and returns the resulting inventory entry plus the
// shared blob store (so a Replay test can reuse it). It asserts the entry actually
// took the offload path (BlobPointer set, Content nil) — otherwise the test would
// silently prove nothing about the offload gate.
func foldOffloadedEntry(t *testing.T, desc string, plaintext []byte) (entry *exchange.InventoryEntry, operator identity.Signer, shared *exchange.MemoryBlobStore, allMsgs []exchange.Message) {
	t.Helper()
	if len(plaintext) <= exchange.BlossomOffloadThreshold {
		t.Fatalf("test setup: plaintext %d must exceed BlossomOffloadThreshold %d", len(plaintext), exchange.BlossomOffloadThreshold)
	}
	h := newTestHarness(t)
	var seller identity.Signer
	operator, seller, _ = useSecpIdentities(t, h)

	shared = exchange.NewMemoryBlobStore()
	eng := h.newEngineWithOpts(func(o *exchange.EngineOptions) {
		o.OperatorPublicKey = operator.PubKeyHex()
		o.OperatorSigner = operator
	})
	eng.State().SetBlobStore(shared)

	putPayload, _, pointer, _, _ := buildV2BlobPutPayload(
		t, seller, operator.PubKeyHex(), desc, plaintext, 60000, shared)

	putMsg := h.sendMessage(h.seller, putPayload,
		[]string{exchange.TagPut, "exchange:content-type:code"}, nil)
	msgs, _ := h.st.ListMessages(h.cfID, 0)
	eng.State().Replay(exchange.FromStoreRecords(msgs))
	if err := eng.AutoAcceptPut(putMsg.ID, 2100, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("AutoAcceptPut: %v", err)
	}

	inv := eng.State().Inventory()
	if len(inv) != 1 {
		t.Fatalf("expected exactly one folded entry, got %d — offloaded put did not fold (fail-closed drop?)", len(inv))
	}
	entry = inv[0]
	// Prove the offload path was actually taken — the whole point of the item.
	if entry.BlobPointer != pointer {
		t.Fatalf("entry.BlobPointer = %q, want offload pointer %q", entry.BlobPointer, pointer)
	}
	if entry.Content != nil {
		t.Fatalf("entry.Content is non-nil (%d bytes) — an OFFLOADED entry must keep bytes in the blob only; Gate 6 fail-open only bites when Content is nil", len(entry.Content))
	}
	stored, _ := h.st.ListMessages(h.cfID, 0)
	return entry, operator, shared, exchange.FromStoreRecords(stored)
}

// TestOffloadCoherence_391_IncoherentJunk_NotHighReuse is THE fraud case: an
// offloaded entry whose description clears the structural gates but whose >32 KiB
// content is semantically unrelated MUST NOT be classified high-reuse. Pre-391
// this returned TRUE (nil Content → coherence fails open), extracting the premium
// and 5x residual with no verification.
func TestOffloadCoherence_391_IncoherentJunk_NotHighReuse(t *testing.T) {
	t.Parallel()
	plaintext := bytesAtLeast(incoherentJunkBlock, exchange.BlossomOffloadThreshold+8*1024)
	entry, _, _, _ := foldOffloadedEntry(t, highReuseOffloadDesc, plaintext)

	if exchange.IsHighReuseArtifactForTest(entry) {
		t.Fatalf("IsHighReuseArtifact(offloaded junk) = true, want false: a >32 KiB put whose "+
			"description keyword-stuffs %q but whose content is unrelated must NOT earn the "+
			"high-reuse premium (engine_pricing.go) or 5x residual (engine_settle.go) — this is "+
			"the exact fraud dontguess-391 closes", highReuseOffloadDesc)
	}
	// The stored fold-time verdict is the mechanism: it must record incoherent.
	if entry.HighReuseCoherent {
		t.Fatalf("entry.HighReuseCoherent = true for incoherent offloaded content — the fold-time " +
			"Gate-6 computation on the decrypted plaintext failed to catch the mismatch")
	}
}

// TestOffloadCoherence_391_CoherentContent_IsHighReuse proves the gate does not
// over-block: an offloaded entry whose content genuinely names the description's
// domain nouns IS high-reuse.
func TestOffloadCoherence_391_CoherentContent_IsHighReuse(t *testing.T) {
	t.Parallel()
	plaintext := bytesAtLeast(coherentFlockBlock, exchange.BlossomOffloadThreshold+8*1024)
	entry, _, _, _ := foldOffloadedEntry(t, highReuseOffloadDesc, plaintext)

	if !exchange.IsHighReuseArtifactForTest(entry) {
		t.Fatalf("IsHighReuseArtifact(offloaded genuine) = false, want true: content genuinely " +
			"names the description's domain nouns, so a genuine >32 KiB reusable artifact must " +
			"still earn the high-reuse premium/residual")
	}
	if !entry.HighReuseCoherent {
		t.Fatalf("entry.HighReuseCoherent = false for coherent offloaded content — fold-time " +
			"Gate-6 wrongly rejected a genuine artifact")
	}
}

// TestOffloadCoherence_391_InlineUnchanged is the regression guard: the INLINE path
// (entry.Content present, BlobPointer empty) is untouched by dontguess-391 — Gate 6
// is still computed LIVE from entry.Content, yielding the same result as pre-391 for
// both coherent and incoherent content.
func TestOffloadCoherence_391_InlineUnchanged(t *testing.T) {
	t.Parallel()

	// Incoherent inline → false (unchanged: live coherence over present Content).
	incoherent := &exchange.InventoryEntry{
		EntryID:     "inline-incoherent",
		Description: highReuseOffloadDesc,
		ContentType: "code",
		Content:     []byte(incoherentJunkBlock),
		// BlobPointer deliberately empty — inline path.
	}
	if exchange.IsHighReuseArtifactForTest(incoherent) {
		t.Fatalf("IsHighReuseArtifact(inline incoherent) = true, want false: the inline live " +
			"coherence computation must be UNCHANGED by dontguess-391")
	}

	// Coherent inline → true (unchanged).
	coherent := &exchange.InventoryEntry{
		EntryID:     "inline-coherent",
		Description: highReuseOffloadDesc,
		ContentType: "code",
		Content:     []byte(coherentFlockBlock),
	}
	if !exchange.IsHighReuseArtifactForTest(coherent) {
		t.Fatalf("IsHighReuseArtifact(inline coherent) = false, want true: the inline live " +
			"coherence computation must be UNCHANGED by dontguess-391")
	}
}

// TestOffloadCoherence_391_ReplayStable proves the stored verdict survives a full
// state rebuild: a FRESH engine that Replays the message log re-fetches the blob,
// re-decrypts it, re-folds the entry, and recomputes HighReuseCoherent identically —
// so classification is Replay-stable for both the fraud and the genuine entry.
func TestOffloadCoherence_391_ReplayStable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		block    string
		wantHigh bool
	}{
		{"incoherent_stays_not_highreuse", incoherentJunkBlock, false},
		{"coherent_stays_highreuse", coherentFlockBlock, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plaintext := bytesAtLeast(tc.block, exchange.BlossomOffloadThreshold+8*1024)
			liveEntry, operatorSigner, shared, allMsgs := foldOffloadedEntry(t, highReuseOffloadDesc, plaintext)

			// Live classification (baseline for the Replay comparison).
			liveClass := exchange.IsHighReuseArtifactForTest(liveEntry)
			if liveClass != tc.wantHigh {
				t.Fatalf("live IsHighReuseArtifact = %v, want %v", liveClass, tc.wantHigh)
			}

			// Rebuild from scratch: a FRESH operator-keyed engine over the SAME
			// blob store, Replaying the SAME log. It must re-decrypt the blob and
			// recompute the flag — not carry it over from the first engine's memory.
			h2 := newTestHarness(t)
			eng2 := h2.newEngineWithOpts(func(o *exchange.EngineOptions) {
				o.OperatorPublicKey = operatorSigner.PubKeyHex()
				o.OperatorSigner = operatorSigner
			})
			eng2.State().SetBlobStore(shared)
			eng2.State().Replay(allMsgs)

			inv := eng2.State().Inventory()
			if len(inv) != 1 {
				t.Fatalf("rebuild: expected one entry, got %d — offloaded entry did not re-fold on Replay", len(inv))
			}
			rebuilt := inv[0]
			if rebuilt.Content != nil {
				t.Fatalf("rebuild: entry.Content non-nil (%d bytes) — offload not preserved across Replay", len(rebuilt.Content))
			}
			if got := exchange.IsHighReuseArtifactForTest(rebuilt); got != tc.wantHigh {
				t.Fatalf("rebuild: IsHighReuseArtifact = %v, want %v (== live %v) — flag not Replay-stable", got, tc.wantHigh, liveClass)
			}
			if rebuilt.HighReuseCoherent != liveEntry.HighReuseCoherent {
				t.Fatalf("rebuild: HighReuseCoherent = %v, live = %v — verdict recomputed differently on Replay", rebuilt.HighReuseCoherent, liveEntry.HighReuseCoherent)
			}
		})
	}
}
