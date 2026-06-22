package api

// Spec: non-plugin-secret-isolation Requirement 4 — the renewal path
// recovers the recipient class from the CG-JWT subject so the Mint
// deny check honors the original mint's classification. This test
// pins the parser so a future refactor of the subject shape that
// would silently revert renewals to RecipientClass="" (and therefore
// fail-closed for any secret-resolution renewal) cannot regress
// undetected.

import "testing"

func TestRecipientClassFromSubject(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"component:plugin:my-plugin", "plugin"},
		{"component:tool:my-tool", "tool"},
		{"component:agent:my-agent", "agent"},
		// Bad shapes fall back to "" so the Mint deny check fires
		// closed for any secret-resolution renewal carrying them.
		{"", ""},
		{"agent-1", ""},
		{"component:", ""},
		{"component:plugin", ""},
		{"plugin:my-plugin", ""},
		{":plugin:my-plugin", ""},
	}
	for _, tc := range cases {
		got := recipientClassFromSubject(tc.subject)
		if got != tc.want {
			t.Errorf("recipientClassFromSubject(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
}
