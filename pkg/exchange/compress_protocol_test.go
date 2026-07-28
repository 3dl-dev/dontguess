package exchange

import (
	"strings"
	"testing"
)

func TestCompressionProtocol_ContainsRequiredSections(t *testing.T) {
	t.Parallel()

	proto := compressionProtocol(&InventoryEntry{
		EntryID:     "entry-123",
		ContentHash: "sha256:abc",
		ContentType: "code",
		Description: "a compressible doc",
	}, 5000)

	required := []string{
		"COMPRESSION WORK ORDER",
		"Entry: entry-123",
		"Content hash: sha256:abc",
		"Description: a compressible doc",
		"Content type: code",
		"Bounty: 5000 scrip",
		"RETRIEVAL",
		"ACCEPTANCE CRITERIA",
		"Size reduction",
		"Semantic similarity",
		"SUBMISSION",
		"dontguess assign claim",
		"dontguess assign complete",
		"--description",
		"--token-cost",
	}

	for _, s := range required {
		if !strings.Contains(proto, s) {
			t.Errorf("protocol missing required section: %q", s)
		}
	}
}

func TestCompressionProtocol_ContentTypeStrategies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		contentType string
		mustContain string // a phrase unique to this strategy
	}{
		{"code", "function/method signatures"},
		{"analysis", "conclusion"},
		{"summary", "distinct claim"},
		{"plan", "action item"},
		{"data", "Schema/structure"},
		{"review", "finding"},
		{"other", "GENERAL"},
		{"", "GENERAL"}, // unknown defaults to general
	}

	for _, tc := range cases {
		t.Run(tc.contentType, func(t *testing.T) {
			t.Parallel()
			proto := compressionProtocol(&InventoryEntry{EntryID: "e-1", ContentHash: "sha256:x", ContentType: tc.contentType}, 100)
			if !strings.Contains(proto, tc.mustContain) {
				t.Errorf("content_type=%q: protocol missing strategy marker %q", tc.contentType, tc.mustContain)
			}
		})
	}
}

func TestCompressionProtocol_CalibrationRule(t *testing.T) {
	t.Parallel()

	// Every content type strategy must include a calibration rule.
	for _, ct := range []string{"code", "analysis", "summary", "plan", "data", "review", "other"} {
		proto := compressionProtocol(&InventoryEntry{EntryID: "e-1", ContentHash: "sha256:x", ContentType: ct}, 100)
		if !strings.Contains(proto, "Calibration:") {
			t.Errorf("content_type=%q: missing calibration rule", ct)
		}
	}
}

// TestCompressionProtocol_V2NamesCiphertextHashNotPlaintext is the confidentiality
// guard on the work order itself (dontguess-7e21). An exchange:assign is a PUBLIC
// event, so for a v2 confidential entry the order must name the already-public
// CiphertextHash and must NEVER carry ContentHash = sha256(plaintext) — the §4.4
// A1/P1 guess-confirmation oracle dontguess-3c3 removed.
//
// This is what makes lifting 3c3's hot/warm suppression safe: the assign is
// posted again, without the hash that made posting it unsafe.
func TestCompressionProtocol_V2NamesCiphertextHashNotPlaintext(t *testing.T) {
	t.Parallel()

	const plaintextHash = "sha256:deadbeefplaintexthashmustnotappear"
	proto := compressionProtocol(&InventoryEntry{
		EntryID:            "entry-v2",
		ContentHash:        plaintextHash,
		CiphertextHash:     "sha256:cafecafeciphertexthash",
		WrappedCEKOperator: "nip44-wrapped-cek",
		ContentType:        "code",
		Description:        "a confidential doc",
	}, 5000)

	if strings.Contains(proto, plaintextHash) {
		t.Fatalf("LEAK: the work order for a v2 entry carried sha256(plaintext) %q — an exchange:assign is public, so this reopens the §4.4 A1/P1 oracle:\n%s", plaintextHash, proto)
	}
	if !strings.Contains(proto, "Ciphertext hash: sha256:cafecafeciphertexthash") {
		t.Fatalf("v2 work order must name the already-public ciphertext hash, got:\n%s", proto)
	}
	if strings.Contains(proto, "Content hash:") {
		t.Fatalf("v2 work order must not use the plaintext 'Content hash' label at all, got:\n%s", proto)
	}
}
