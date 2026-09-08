// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package signup declares the self-serve signup seam for the gibson platform's
// self-hosted vs SaaS deployment-profile model (deploy ADR-0006).
//
// # Seam shape
//
// The signup seam is a policy toggle, not a provider seam: there is no remote
// network endpoint to dial. Enabling the knob means "the SaaS overlay is
// present and the self-serve card-first signup surface is active"; leaving it
// unset means "self-hosted fail-safe — admin-provision only, no public signup".
//
// The seam resolves a [Policy] value. The three values are the three
// registration rungs of ADR-0006, which match what a GitLab self-managed
// operator already knows:
//
//   - [PolicyAdminOnly] — the CLOSED rung, and the fail-safe when the knob is
//     absent. Tenants are provisioned by a platform admin via
//     AdminTenantService.AdminProvisionTenant. Every SignupService RPC returns
//     codes.PermissionDenied.
//
//   - [PolicyApproval] — the APPROVAL rung. Anyone may register, nobody is
//     active until an administrator approves them. Registration needs NO mail
//     transport: a self-hosted instance sits behind the customer's perimeter,
//     where the operator already controls who can reach it, so the human in
//     the approval path is the proof that email verification is on a public
//     surface. Verification RPCs stay refused on this rung.
//
//   - [PolicySelfServe] — the OPEN rung (SaaS profile). The full card-first
//     flow: prove the mailbox, then provision. Unchanged.
//
// # Knob
//
// The config knob is SIGNUP_SELF_SERVE, and its VALUE selects the rung:
//
//	unset or empty  → PolicyAdminOnly   (closed)
//	"approval"      → PolicyApproval    (approval)
//	anything else   → PolicySelfServe   (open)
//
// One knob rather than two, because the rungs are exclusive: a deployment is
// on exactly one of them, and two booleans could describe a state that is not
// a rung. The value is compared case-insensitively after trimming.
//
// # Registration
//
// The seam is registered in the default pkg/seam registry so it appears in
// the startup seam-state log alongside the entitlements seam and any future
// seams.
package signup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/pkg/seam"
)

// Policy describes which tenant-creation path is active for this deployment.
type Policy string

const (
	// PolicySelfServe is the OPEN rung: the self-serve card-first signup path
	// is active (SaaS profile). SignupService.Signup is served normally.
	PolicySelfServe Policy = "self-serve"

	// PolicyApproval is the APPROVAL rung: anyone may register, an
	// administrator approves each account before it becomes usable, and no
	// mail transport is required. SignupService.Register is served; the three
	// verification RPCs are refused, because there is nothing to verify by
	// mail on this rung.
	PolicyApproval Policy = "approval"

	// PolicyAdminOnly is the CLOSED rung, and the self-hosted fail-safe:
	// tenants are provisioned by a platform admin via
	// AdminTenantService.AdminProvisionTenant. Every SignupService RPC returns
	// codes.PermissionDenied.
	PolicyAdminOnly Policy = "admin-only"
)

// KnobValueApproval is the SIGNUP_SELF_SERVE value that selects the approval
// rung. Every other non-empty value selects the open rung.
const KnobValueApproval = "approval"

// ConfigKnob is the environment variable that activates self-serve signup.
// Any non-empty value enables PolicySelfServe; absent means PolicyAdminOnly.
const ConfigKnob = "SIGNUP_SELF_SERVE"

// signupSeam is the package-level seam instance.
var signupSeam = seam.New(seam.Spec[Policy]{
	Name:       "signup",
	ConfigKnob: ConfigKnob,
	FailSafe:   func() (Policy, error) { return PolicyAdminOnly, nil },
	// Remote reads the knob VALUE as the rung selector rather than as an
	// address: "approval" is the approval rung, anything else non-empty is the
	// open rung. Knob absence is handled by FailSafe above.
	Remote: func(value string) (Policy, error) {
		if strings.EqualFold(strings.TrimSpace(value), KnobValueApproval) {
			return PolicyApproval, nil
		}
		return PolicySelfServe, nil
	},
})

func init() {
	// Register in the process-wide seam registry so LogStartupState includes
	// the signup seam alongside entitlements and any future seams.
	seam.Register("signup", ConfigKnob, "saas/signup-svc")
}

// Resolve returns the signup policy for this deployment by reading the
// SIGNUP_SELF_SERVE config knob. It emits observable degradation signals via
// pkg/seam when the knob is absent (self-hosted profile, expected) or when a
// misconfiguration is detected.
//
// wired is true when the knob was set, whichever rung its value selected.
func Resolve(ctx context.Context, logger *slog.Logger) (Policy, bool, error) {
	res, err := signupSeam.Resolve(ctx, logger)
	if err != nil {
		return PolicyAdminOnly, false, fmt.Errorf("signup seam resolve: %w", err)
	}
	return res.Impl, res.Wired, nil
}
