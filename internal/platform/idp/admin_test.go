// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package idp

import "testing"

// TestUsernameForEmail pins the normalization every human-user create path
// must share (ADR-0093 decision 1): lower-cased and trimmed, so two people
// typing the same address with different case or stray whitespace collide
// on the same install-unique username instead of minting two accounts.
func TestUsernameForEmail(t *testing.T) {
	cases := []struct {
		name  string
		email string
		want  string
	}{
		{"already normalized", "alice@example.com", "alice@example.com"},
		{"upper case", "Alice@Example.COM", "alice@example.com"},
		{"surrounding whitespace", " alice@example.com ", "alice@example.com"},
		{"mixed case and whitespace", " Alice@Example.COM ", "alice@example.com"},
		{"tab and newline", "\talice@example.com\n", "alice@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UsernameForEmail(tc.email); got != tc.want {
				t.Errorf("UsernameForEmail(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}
}
