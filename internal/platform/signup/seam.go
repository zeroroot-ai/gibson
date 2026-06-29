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
// The seam resolves a [Policy] value:
//
//   - [PolicyAdminOnly] (fail-safe, knob absent): tenants are provisioned by a
//     platform admin via AdminTenantService.AdminProvisionTenant. The
//     SignupService.Signup RPC returns codes.PermissionDenied when called.
//
//   - [PolicySelfServe] (wired, knob set): the full card-first self-serve
//     signup flow is active (SaaS profile). SignupService.Signup is served
//     normally.
//
// # Knob
//
// The config knob is SIGNUP_SELF_SERVE. Any non-empty value activates
// PolicySelfServe. The value itself is ignored (it is not an endpoint).
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

	"github.com/zeroroot-ai/gibson/pkg/seam"
)

// Policy describes which tenant-creation path is active for this deployment.
type Policy string

const (
	// PolicySelfServe means the self-serve card-first signup path is active
	// (SaaS profile). SignupService.Signup is served normally.
	PolicySelfServe Policy = "self-serve"

	// PolicyAdminOnly means the self-hosted fail-safe is active: tenants are
	// provisioned by a platform admin via AdminTenantService.AdminProvisionTenant.
	// SignupService.Signup returns codes.PermissionDenied when called.
	PolicyAdminOnly Policy = "admin-only"
)

// ConfigKnob is the environment variable that activates self-serve signup.
// Any non-empty value enables PolicySelfServe; absent means PolicyAdminOnly.
const ConfigKnob = "SIGNUP_SELF_SERVE"

// signupSeam is the package-level seam instance.
var signupSeam = seam.New(seam.Spec[Policy]{
	Name:       "signup",
	ConfigKnob: ConfigKnob,
	FailSafe:   func() (Policy, error) { return PolicyAdminOnly, nil },
	// Remote ignores the endpoint value: any non-empty knob means SaaS is
	// active and self-serve is enabled. The "endpoint" is just the knob
	// presence signal, not an address.
	Remote: func(_ string) (Policy, error) { return PolicySelfServe, nil },
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
// wired is true when PolicySelfServe was resolved (knob was set).
func Resolve(ctx context.Context, logger *slog.Logger) (Policy, bool, error) {
	res, err := signupSeam.Resolve(ctx, logger)
	if err != nil {
		return PolicyAdminOnly, false, fmt.Errorf("signup seam resolve: %w", err)
	}
	return res.Impl, res.Wired, nil
}
