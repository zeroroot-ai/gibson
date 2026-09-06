// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_wiring_test.go — the construction seams and link builders behind the
// signup handlers. The handler tests all wire an explicit clock and app URL
// through the harness (newSignupHarness), which never exercises the fallback
// branches below: no injected clock, no configured product-surface origin.
// Both fallbacks are reachable in production on a misconfigured or partially
// wired daemon, so they get their own direct tests here.

import (
	"testing"
	"time"
)

// TestSignupNow_FallsBackToTheRealClockWhenUnset — a daemon that never had a
// test clock injected must still tell time.
func TestSignupNow_FallsBackToTheRealClockWhenUnset(t *testing.T) {
	s := &DaemonServer{}
	before := time.Now().UTC()
	got := s.signupNow()
	after := time.Now().UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("signupNow() = %v, want between %v and %v", got, before, after)
	}
}

// TestSignupLinks_EmptyBaseIsVisibleRatherThanSilent — WithAppURL is required
// on the self-serve profile, so an empty base is only reachable in tests. The
// links still have a defined shape: signupContinueURL degrades to a relative
// link (a broken link is diagnosable; a silently tokenless email is not) and
// the two notice links degrade to empty (no host to point at).
func TestSignupLinks_EmptyBaseIsVisibleRatherThanSilent(t *testing.T) {
	s := &DaemonServer{} // no WithAppURL call

	const wantContinue = SignupVerifyPath + "?token=tok123"
	if got := s.signupContinueURL("tok123"); got != wantContinue {
		t.Errorf("signupContinueURL with no app URL = %q, want %q", got, wantContinue)
	}
	if got := s.signupSignInURL(); got != "" {
		t.Errorf("signupSignInURL with no app URL = %q, want empty", got)
	}
	if got := s.signupPasswordResetURL(); got != "" {
		t.Errorf("signupPasswordResetURL with no app URL = %q, want empty", got)
	}
}

// TestSignupLinks_ConfiguredBaseBuildsAbsoluteLinks is the counterpart: once
// WithAppURL is wired, every link is an absolute URL under that origin.
func TestSignupLinks_ConfiguredBaseBuildsAbsoluteLinks(t *testing.T) {
	s := (&DaemonServer{}).WithAppURL("https://app.example.test/")

	if got, want := s.signupContinueURL("tok123"), "https://app.example.test"+SignupVerifyPath+"?token=tok123"; got != want {
		t.Errorf("signupContinueURL = %q, want %q", got, want)
	}
	if got, want := s.signupSignInURL(), "https://app.example.test/login"; got != want {
		t.Errorf("signupSignInURL = %q, want %q", got, want)
	}
	if got, want := s.signupPasswordResetURL(), "https://app.example.test/login?prompt=reset"; got != want {
		t.Errorf("signupPasswordResetURL = %q, want %q", got, want)
	}
}
