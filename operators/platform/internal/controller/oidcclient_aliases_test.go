// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"testing"
)

// TestWriteOIDCAliases_AlwaysOverwrites pins the fix from
// zeroroot-ai/platform-operator#22.
//
// Before the fix: writeOIDCAliases used a "write only if missing"
// pattern, so on any rotation the lowercase `client_secret` was
// updated but the uppercase `ZITADEL_CLIENT_SECRET` alias kept the
// previous rotation's value. Consumers that read the uppercase shape
// (chart-mounted dashboard env, in particular) hit
// `invalid_client / invalid secret` against Zitadel.
//
// After the fix: every call to writeOIDCAliases overwrites both alias
// keys with the current truth — a writeSecret call is by definition
// "this is what Zitadel says now," and stale values must not leak
// through.
func TestWriteOIDCAliases_AlwaysOverwrites(t *testing.T) {
	cases := []struct {
		name       string
		initial    map[string][]byte
		clientID   string
		secret     string
		wantID     string
		wantSecret string
	}{
		{
			name:       "empty map gets both aliases written",
			initial:    map[string][]byte{},
			clientID:   "CID-A",
			secret:     "SECRET-A",
			wantID:     "CID-A",
			wantSecret: "SECRET-A",
		},
		{
			name: "stale aliases get overwritten on every call (REGRESSION GUARD)",
			initial: map[string][]byte{
				"ZITADEL_CLIENT_ID":     []byte("CID-OLD"),
				"ZITADEL_CLIENT_SECRET": []byte("SECRET-OLD"),
			},
			clientID:   "CID-NEW",
			secret:     "SECRET-NEW",
			wantID:     "CID-NEW",
			wantSecret: "SECRET-NEW",
		},
		{
			name: "lowercase keys are preserved (writeOIDCAliases only touches the uppercase aliases)",
			initial: map[string][]byte{
				"client_id":     []byte("CID-LOWERCASE"),
				"client_secret": []byte("SECRET-LOWERCASE"),
			},
			clientID:   "CID-NEW",
			secret:     "SECRET-NEW",
			wantID:     "CID-NEW",
			wantSecret: "SECRET-NEW",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeOIDCAliases(tc.initial, tc.clientID, tc.secret)
			if got := string(tc.initial["ZITADEL_CLIENT_ID"]); got != tc.wantID {
				t.Errorf("ZITADEL_CLIENT_ID = %q, want %q", got, tc.wantID)
			}
			if got := string(tc.initial["ZITADEL_CLIENT_SECRET"]); got != tc.wantSecret {
				t.Errorf("ZITADEL_CLIENT_SECRET = %q, want %q", got, tc.wantSecret)
			}
		})
	}
}
