// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenant

import "testing"

// TestSlugifyEmail_MatchesDashboard pins the founding-member name derivation
// byte-for-byte to the dashboard's slugify (app/actions/signup.ts). All three
// creators — dashboard, pending-provisioning reconcile, self-hosted first-admin
// — must agree on this name or a founding member races into two CRs.
func TestSlugifyEmail_MatchesDashboard(t *testing.T) {
	cases := map[string]string{
		"anthony@zeroroot.ai":         "anthony-zeroroot-ai",
		"first-last@sub.example.test": "first-last-sub-example-test",
		"OWNER@Acme.test":             "owner-acme-test",
		"a..b@c":                      "a-b-c",
		"--lead@trail--":              "lead-trail",
	}
	for in, want := range cases {
		if got := SlugifyEmail(in); got != want {
			t.Errorf("SlugifyEmail(%q) = %q, want %q", in, got, want)
		}
	}
	if got := FoundingMemberName("anthony@zeroroot.ai"); got != "anthony-zeroroot-ai-owner" {
		t.Errorf("FoundingMemberName: got %q", got)
	}
}
