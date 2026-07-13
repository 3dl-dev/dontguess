package exchange_test

// put_reuse_coherence_test.go — tests for dontguess-5f5: semantic coherence gate
// (Gate 6) on §4 high-reuse-artifact classification.
//
// The five STRUCTURAL gates (content_type, length floor, primary keyword, co-signal
// adjacency, content-bearing context floor) count content-bearing tokens but cannot tell
// whether those tokens MEAN anything relative to the bytes actually sold. A crafted
// description with exactly minHighReuseContextWords (=2) plausible ≥4-char nouns plus the
// trigger phrase clears every structural gate:
//
//	"widget gadget test pattern go"  — 'widget'/'gadget' are 2 content-bearing nouns,
//	                                    'test pattern' + adjacent 'go' is the trigger.
//
// even though the padding nouns are unrelated to the content — extracting the 85% accept
// price + 20% residual §4 reserves for genuine reusable artifacts.
//
// Gate 6 embeds the description's content-bearing CONTEXT nouns (the ones outside the
// trigger cluster) and the put's content, and rejects the entry when they are disconnected.
//
// DONE conditions verified here:
//   - A crafted 2-noun-padding description whose nouns are semantically unrelated to the
//     actual content is REJECTED from high-reuse status (TestCoherenceGate_RejectsDisconnectedPadding).
//   - The same structural stuff, but with content that genuinely mentions the claimed
//     nouns, PASSES — proving the gate keys on coherence, not on the description alone
//     (TestCoherenceGate_AcceptsGenuineContent).
//   - The trigger-stuffing bypass (repeat "test pattern go" in the content) is still
//     rejected, because the gate embeds only the CONTEXT nouns, not the trigger cluster
//     (TestCoherenceGate_RejectsTriggerStuffedContent).
//   - Content-less entries (structural unit-test fixtures) still pass — the gate fails
//     open when there is nothing to compare (TestCoherenceGate_ContentlessStillPasses).
//
// The existing genuine terse positives in put_reuse_class_test.go are content-less and
// therefore continue to pass through Gate 6 on the structural gates alone.

import (
	"testing"

	"github.com/3dl-dev/dontguess/pkg/exchange"
)

// unrelatedContent is prose that shares NO domain nouns with the crafted attack
// descriptions below — the "semantically unrelated actual content" of the spec.
const unrelatedContent = `The quick brown fox jumps over the lazy dog. ` +
	`Lorem ipsum dolor sit amet, consectetur adipiscing elit. ` +
	`A recipe for banana bread: flour, sugar, eggs, and ripe bananas.`

// TestCoherenceGate_RejectsDisconnectedPadding is the core dontguess-5f5 case: a
// description that passes ALL FIVE structural gates via exactly two plausible ≥4-char
// padding nouns, but whose nouns are disconnected from the put's actual content, MUST
// NOT classify as high-reuse.
func TestCoherenceGate_RejectsDisconnectedPadding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		description string
		contentType string
	}{
		{
			name:        "widget_gadget_test_pattern_go",
			description: "widget gadget test pattern go",
			contentType: "code",
		},
		{
			name:        "abcd_efgh_test_pattern_go",
			description: "abcd efgh test pattern go",
			contentType: "code",
		},
		{
			name:        "sprocket_flange_schema_correctness_checklist",
			description: "sprocket flange schema correctness checklist",
			contentType: "analysis",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry := &exchange.InventoryEntry{
				EntryID:     "attack-" + tc.name,
				Description: tc.description,
				ContentType: tc.contentType,
				Content:     []byte(unrelatedContent),
			}
			// Structural gates alone would pass (2 content-bearing padding nouns + trigger).
			if exchange.IsHighReuseArtifactForTest(entry) {
				t.Errorf("IsHighReuseArtifact(%q) = true, want false: padding nouns are "+
					"semantically unrelated to the content — Gate 6 must reject",
					tc.description)
			}
		})
	}
}

// TestCoherenceGate_AcceptsGenuineContent proves Gate 6 keys on description↔content
// coherence, not on the description alone: the SAME structural shape passes when the
// content genuinely names the claimed nouns.
func TestCoherenceGate_AcceptsGenuineContent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		description string
		contentType string
		content     string
	}{
		{
			name:        "flock_contention_with_matching_go_code",
			description: "flock contention test pattern for Go with race detector",
			contentType: "code",
			content: `package flocktest
// Exercises flock contention: two goroutines race for one advisory lock.
// Run under the race detector to surface the contention window.
func TestFlockContention(t *testing.T) { acquireFlock(); defer releaseFlock() }`,
		},
		{
			name:        "schema_checklist_with_matching_content",
			description: "legion.tools v1.2 schema correctness checklist",
			contentType: "analysis",
			content: `# legion.tools v1.2 schema correctness checklist
- validate every field against the declared schema
- verify correctness of each enum value
- confirm required fields are present`,
		},
		{
			name:        "migration_recipe_with_matching_content",
			description: "cf migrate-store --cf-home symlink bridge migration recipe",
			contentType: "analysis",
			content: `Run cf migrate-store to create a symlink bridge for the old cf-home path.
This migration recipe preserves the store while pointing cf-home at the new location.`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry := &exchange.InventoryEntry{
				EntryID:     "genuine-" + tc.name,
				Description: tc.description,
				ContentType: tc.contentType,
				Content:     []byte(tc.content),
			}
			if !exchange.IsHighReuseArtifactForTest(entry) {
				t.Errorf("IsHighReuseArtifact(%q) = false, want true: content genuinely "+
					"names the claimed nouns — Gate 6 must accept", tc.description)
			}
		})
	}
}

// TestCoherenceGate_RejectsTriggerStuffedContent verifies the trigger-stuffing bypass is
// closed: repeating the trigger words ("test pattern go") in the content does NOT rescue a
// disconnected padding-noun description, because Gate 6 embeds only the CONTEXT nouns.
func TestCoherenceGate_RejectsTriggerStuffedContent(t *testing.T) {
	t.Parallel()

	// Content is saturated with the trigger cluster but never mentions widget/gadget.
	triggerStuffed := `test pattern go. test pattern go. golang test pattern. ` +
		`a test pattern implemented in go. test pattern go test pattern go.`

	entry := &exchange.InventoryEntry{
		EntryID:     "trigger-stuffed",
		Description: "widget gadget test pattern go",
		ContentType: "code",
		Content:     []byte(triggerStuffed),
	}
	if exchange.IsHighReuseArtifactForTest(entry) {
		t.Errorf("IsHighReuseArtifact = true, want false: trigger words in content must "+
			"not rescue disconnected padding nouns — Gate 6 embeds only context nouns")
	}
}

// TestCoherenceGate_ContentlessStillPasses is the regression guard: content-less entries
// (the structural unit-test fixtures) must still classify as high-reuse — Gate 6 fails
// open when there is nothing to compare against.
func TestCoherenceGate_ContentlessStillPasses(t *testing.T) {
	t.Parallel()

	entry := &exchange.InventoryEntry{
		EntryID:     "contentless-genuine",
		Description: "legion.tools v1.2 schema correctness checklist",
		ContentType: "code",
		// Content deliberately nil — no bytes to compare.
	}
	if !exchange.IsHighReuseArtifactForTest(entry) {
		t.Errorf("IsHighReuseArtifact(content-less genuine) = false, want true: Gate 6 " +
			"must fail open when there is no content to compare")
	}
}
