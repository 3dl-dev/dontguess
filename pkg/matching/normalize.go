// Package matching — buyer query normalization (dontguess-af7).
//
// NormalizeQuery preprocesses a buyer task description before it is embedded
// and matched against the inventory. The goal is vocabulary alignment: buyers
// write informal queries using synonyms and gerunds, while sellers write
// technical inventory descriptions using precise nouns and domain terms.
// TF-IDF matching requires term overlap, so bridging this vocabulary gap
// improves hit rate without replacing the embedder.
//
// Design constraints (from the item spec):
//   - Generic: rules apply to any technical software exchange, not just this
//     corpus. No inventory-specific or entry-specific terms are injected.
//   - Non-destructive: original terms are preserved; expansions are added.
//   - Conservative: only expand when a high-confidence generic relationship
//     exists. Prefer false-miss (no expansion) over false-positive (wrong expansion).
//   - Floor-safe: normalization MUST NOT increase false positives on the
//     ed0 nonsense fixture (0.16 relevance floor still gates junk entries).
//
// Testing: see normalize_test.go for vocabulary-gap A/B comparisons.
package matching

import (
	"strings"
)

// NormalizeQuery preprocesses a buyer task description to align its vocabulary
// with typical inventory description vocabulary. Returns an expanded version
// of the input text: original tokens are preserved, and related technical terms
// are appended as additional context for the TF-IDF embedder.
//
// The expansion uses a generic synonym table — soft-engineering vocabulary that
// maps informal/colloquial phrasing to the more precise technical terms sellers
// use when writing inventory descriptions. No inventory-specific or entry-specific
// terms are injected; the same table applies to any software engineering exchange.
//
// Callers: Index.Search() calls NormalizeQuery before Rank() so all
// buy-path queries benefit automatically. Callers that need to pre-normalize
// before adding to a campfire buy message may call it directly.
func NormalizeQuery(text string) string {
	if text == "" {
		return text
	}

	// Tokenize to find expansion candidates.
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return text
	}

	var expansions []string
	for _, tok := range tokens {
		if extra, ok := queryExpansions[tok]; ok {
			expansions = append(expansions, extra...)
		}
	}

	if len(expansions) == 0 {
		return text
	}

	// Append expanded terms to the original text.
	// This preserves the original tokens' TF-IDF weights and only adds
	// signal — never replaces existing signal.
	return text + " " + strings.Join(expansions, " ")
}

// queryExpansions maps buyer vocabulary tokens to related technical terms that
// are more likely to appear in inventory descriptions.
//
// Rules for entries in this table:
//  1. The key must be a genuine informal/colloquial synonym for the values.
//  2. The values must be widely-recognized technical equivalents, NOT terms
//     specific to any single library, project, or inventory entry.
//  3. When in doubt, omit: a false-miss is preferable to a false-positive.
//  4. All values must survive the ed0 nonsense-fixture test (must not push
//     junk entries above the 0.16 relevance floor for nonsense queries).
//
// Coverage domains: concurrency/testing, configuration, migration/relocation,
// schema/validation, CI/pipeline, auth/security.
var queryExpansions = map[string][]string{
	// --- Concurrency and testing vocabulary ---
	// "flaky" = informal for intermittently failing tests caused by races.
	// "flock" is NOT added — that would be corpus-specific (file-lock library name).
	// "race" and "contention" are the generic technical causes of flaky tests.
	"flaky": {"intermittent", "race", "contention"},

	// "intermittent" = tests that sometimes pass, sometimes fail.
	// Generic technical cause: race conditions.
	"intermittent": {"flaky", "race"},

	// "unreliable" = broader synonym for flaky/intermittent behavior.
	"unreliable": {"intermittent", "flaky"},

	// "concurrent" / "concurrency" = many goroutines / threads running together.
	// "goroutine" is Go-specific but generic within Go codebases.
	"concurrent":   {"goroutine", "race"},
	"concurrency":  {"goroutine", "race", "mutex"},
	"parallel":     {"concurrent", "goroutine"},

	// "locking" / "lock" = synchronization mechanism; "mutex" is the canonical name.
	"locking": {"lock", "mutex", "contention"},
	"lock":    {"mutex", "locking"},

	// --- Configuration and setup vocabulary ---
	// "disable" / "turn off" = bypassing a feature.
	"disable": {"bypass", "skip"},
	"turn":    {"disable"},
	"bypass":  {"disable", "skip"},

	// "setup" / "configure" = initialization / configuration.
	"setup":     {"init", "configuration"},
	"configure": {"setup", "configuration"},

	// --- Migration and relocation vocabulary ---
	// "move" / "moving" = relocating data or config; technical equivalent is "migrate".
	"move":     {"migrate", "migration"},
	"moving":   {"migrate", "migration"},
	"relocate": {"migrate", "move"},
	"transfer": {"migrate"},

	// "migrate" = the canonical technical term.
	"migrate":   {"move", "migration"},
	"migration": {"migrate", "move"},

	// --- Schema and validation vocabulary ---
	// "checker" = informal for "checklist" or "validator".
	"checker":   {"checklist", "validation"},
	"validate":  {"validation", "check"},
	"check":     {"validate", "validation"},
	"rules": {"constraints", "validation"},

	// --- CI and pipeline vocabulary ---
	// "only run" triggers phrasing = the technical mechanism is "filter" or "path".
	"trigger": {"filter"},
	"filter":  {"path", "trigger"},

	// --- Auth and security vocabulary ---
	// "authorization" / "auth" — both forms used in codebases.
	"authorization": {"auth"},
	"auth":          {"authorization"},

	// "revoke" = cancel/withdraw access; used in authorization contexts.
	"revoke": {"authorization", "supersede"},

	// "gap" = missing feature/guard; in security contexts means an exposure.
	// "exposure" → "gap" is a generic security vocabulary mapping.
	"exposure": {"gap"},
}
