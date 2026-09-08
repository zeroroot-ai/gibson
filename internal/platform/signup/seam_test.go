// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package signup_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/signup"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestSignupSeam_KnobAbsent_AdminOnly proves that when SIGNUP_SELF_SERVE is
// unset, the signup seam resolves to PolicyAdminOnly (self-hosted fail-safe).
func TestSignupSeam_KnobAbsent_AdminOnly(t *testing.T) {
	t.Setenv(signup.ConfigKnob, "")

	policy, wired, err := signup.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if policy != signup.PolicyAdminOnly {
		t.Errorf("policy = %q, want %q", policy, signup.PolicyAdminOnly)
	}
	if wired {
		t.Errorf("wired = true, want false when knob is absent")
	}
}

// TestSignupSeam_KnobSet_SelfServe proves that when SIGNUP_SELF_SERVE is set
// to any non-empty value, the seam resolves to PolicySelfServe (SaaS profile).
func TestSignupSeam_KnobSet_SelfServe(t *testing.T) {
	t.Setenv(signup.ConfigKnob, "true")

	policy, wired, err := signup.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if policy != signup.PolicySelfServe {
		t.Errorf("policy = %q, want %q", policy, signup.PolicySelfServe)
	}
	if !wired {
		t.Errorf("wired = false, want true when knob is set")
	}
}

// TestSignupSeam_KnobSetArbitraryValue_SelfServe proves that any non-empty
// value other than "approval" activates PolicySelfServe — the open rung is
// what a knob that says nothing else means.
func TestSignupSeam_KnobSetArbitraryValue_SelfServe(t *testing.T) {
	t.Setenv(signup.ConfigKnob, "saas-active")

	policy, wired, err := signup.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if policy != signup.PolicySelfServe {
		t.Errorf("policy = %q, want %q", policy, signup.PolicySelfServe)
	}
	if !wired {
		t.Errorf("wired = false, want true for arbitrary non-empty value")
	}
}

// TestSignupSeam_KnobWhitespaceOnly_AdminOnly proves that a whitespace-only
// value is treated as absent (matches the pkg/seam contract).
func TestSignupSeam_KnobWhitespaceOnly_AdminOnly(t *testing.T) {
	t.Setenv(signup.ConfigKnob, "   ")

	policy, wired, err := signup.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if policy != signup.PolicyAdminOnly {
		t.Errorf("policy = %q, want %q (whitespace treated as absent)", policy, signup.PolicyAdminOnly)
	}
	if wired {
		t.Errorf("wired = true, want false for whitespace-only knob")
	}
}

// TestSignupSeam_KnobApproval_ApprovalRung pins the middle rung of ADR-0006:
// the knob's VALUE selects it, so one knob describes all three rungs and no
// combination of settings can describe a state that is not a rung.
func TestSignupSeam_KnobApproval_ApprovalRung(t *testing.T) {
	t.Setenv(signup.ConfigKnob, signup.KnobValueApproval)

	policy, wired, err := signup.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if policy != signup.PolicyApproval {
		t.Errorf("policy = %q, want %q", policy, signup.PolicyApproval)
	}
	if !wired {
		t.Errorf("wired = false, want true when the knob is set")
	}
}

// The value is compared after trimming and without regard to case, so a chart
// that writes "Approval" or " approval " selects the rung the operator meant
// rather than silently opening public signup.
func TestSignupSeam_KnobApproval_IsTrimmedAndCaseInsensitive(t *testing.T) {
	for _, value := range []string{"Approval", "  approval  ", "APPROVAL"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(signup.ConfigKnob, value)

			policy, _, err := signup.Resolve(context.Background(), discardLogger())
			if err != nil {
				t.Fatalf("Resolve: unexpected error: %v", err)
			}
			if policy != signup.PolicyApproval {
				t.Errorf("policy = %q, want %q", policy, signup.PolicyApproval)
			}
		})
	}
}
