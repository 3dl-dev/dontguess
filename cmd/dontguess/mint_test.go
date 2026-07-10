package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestAssertAdvertiseEqualsSign covers the ed5 hard-prerequisite (design §5):
// a config/signer key mismatch is a startup hard error; a match or an absent
// config (empty advertised key) is not.
func TestAssertAdvertiseEqualsSign(t *testing.T) {
	const signer = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	t.Run("match_ok", func(t *testing.T) {
		if err := assertAdvertiseEqualsSign(signer, signer); err != nil {
			t.Fatalf("matching keys must pass, got %v", err)
		}
	})

	t.Run("empty_config_ok", func(t *testing.T) {
		// No persisted config yet — created on first init with the signer's key.
		if err := assertAdvertiseEqualsSign("", signer); err != nil {
			t.Fatalf("empty advertised key must pass, got %v", err)
		}
	})

	t.Run("mismatch_hard_error", func(t *testing.T) {
		other := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		err := assertAdvertiseEqualsSign(other, signer)
		if err == nil {
			t.Fatal("a key mismatch must be a hard error, got nil")
		}
		if !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), signer) {
			t.Errorf("error should name both keys, got %v", err)
		}
	})
}

// TestRunMint_RejectsInvalidInput proves validation happens before any socket
// dial — a malformed recipient or non-positive amount mints nothing.
func TestRunMint_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name      string
		recipient string
		amount    string
	}{
		{"malformed_recipient", "not-a-pubkey", "1000"},
		{"empty_recipient", "", "1000"},
		{"non_numeric_amount", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "lots"},
		{"zero_amount", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0"},
		{"negative_amount", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "-5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runMint(tc.recipient, tc.amount, &out)
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil (out=%q)", tc.name, out.String())
			}
			if out.Len() != 0 {
				t.Errorf("nothing should be written on a validation failure, got %q", out.String())
			}
		})
	}
}
