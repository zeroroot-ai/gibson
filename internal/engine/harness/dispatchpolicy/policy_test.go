package dispatchpolicy

import (
	"testing"

	capabilitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

func TestParseShape(t *testing.T) {
	cases := map[string]DeploymentShape{
		"customer-isolation": ShapeCustomerIsolation,
		"setec-only":         ShapeSetecOnly,
		"":                   ShapeSetecOnly, // fail-closed
		"nonsense":           ShapeSetecOnly, // fail-closed
		"SETEC-ONLY":         ShapeSetecOnly, // case-sensitive; loader lower-cases first
	}
	for raw, want := range cases {
		if got := ParseShape(raw); got != want {
			t.Errorf("ParseShape(%q) = %d; want %d", raw, got, want)
		}
	}
}

// TestZeroValueIsSetecOnly pins the fail-closed property: an unwired harness
// (zero-value DeploymentShape) must be the strict shape.
func TestZeroValueIsSetecOnly(t *testing.T) {
	var s DeploymentShape
	if s != ShapeSetecOnly {
		t.Fatalf("zero-value DeploymentShape = %d; want ShapeSetecOnly", s)
	}
}

func TestDecide(t *testing.T) {
	const (
		untrusted   = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
		trusted     = componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
		unspecified = componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED
	)
	cases := []struct {
		name       string
		trust      componentpb.ContentTrust
		hasSandbox bool
		shape      DeploymentShape
		want       Decision
	}{
		// The load-bearing rule: untrusted + hosted + no sandbox ⇒ Deny.
		{"untrusted/no-sandbox/saas", untrusted, false, ShapeSetecOnly, Deny},
		// Untrusted with a sandbox always goes to setec.
		{"untrusted/sandbox/saas", untrusted, true, ShapeSetecOnly, RequireSetec},
		{"untrusted/sandbox/onprem", untrusted, true, ShapeCustomerIsolation, RequireSetec},
		// Under customer-isolation the customer owns isolation: untrusted with
		// no sandbox is allowed in-process.
		{"untrusted/no-sandbox/onprem", untrusted, false, ShapeCustomerIsolation, AllowInProcess},
		// Trusted always takes its existing path.
		{"trusted/no-sandbox/saas", trusted, false, ShapeSetecOnly, AllowInProcess},
		{"trusted/sandbox/saas", trusted, true, ShapeSetecOnly, RequireSetec},
		// Unspecified is treated as trusted for backward-compat.
		{"unspecified/no-sandbox/saas", unspecified, false, ShapeSetecOnly, AllowInProcess},
		{"unspecified/sandbox/saas", unspecified, true, ShapeSetecOnly, RequireSetec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.trust, tc.hasSandbox, tc.shape); got != tc.want {
				t.Errorf("Decide(%v, sandbox=%v, shape=%d) = %d; want %d",
					tc.trust, tc.hasSandbox, tc.shape, got, tc.want)
			}
		})
	}
}

// TestIsolationAllowed is the (deployment-shape × isolation-mode) matrix from
// ADR-0010 / gibson#998: under setec-only only HOSTED_SANDBOX (and UNSPECIFIED,
// treated as HOSTED_SANDBOX) is permitted; under customer-isolation every mode
// is permitted.
func TestIsolationAllowed(t *testing.T) {
	all := []capabilitypb.IsolationMode{
		capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED,
		capabilitypb.IsolationMode_ISOLATION_MODE_HOSTED_SANDBOX,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_CLUSTER_ATTESTED,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_SELF_SANDBOX,
		capabilitypb.IsolationMode_ISOLATION_MODE_ON_PREM_SANDBOX_ENDPOINT,
	}

	// setec-only: only UNSPECIFIED + HOSTED_SANDBOX allowed.
	setecOnlyAllowed := map[capabilitypb.IsolationMode]bool{
		capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED:               true,
		capabilitypb.IsolationMode_ISOLATION_MODE_HOSTED_SANDBOX:            true,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_CLUSTER_ATTESTED: false,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_SELF_SANDBOX:     false,
		capabilitypb.IsolationMode_ISOLATION_MODE_ON_PREM_SANDBOX_ENDPOINT:  false,
	}
	for _, iso := range all {
		if got, want := IsolationAllowed(iso, ShapeSetecOnly), setecOnlyAllowed[iso]; got != want {
			t.Errorf("IsolationAllowed(%v, ShapeSetecOnly) = %v; want %v", iso, got, want)
		}
		// customer-isolation: every mode allowed (customer owns the boundary).
		if !IsolationAllowed(iso, ShapeCustomerIsolation) {
			t.Errorf("IsolationAllowed(%v, ShapeCustomerIsolation) = false; want true", iso)
		}
	}
}
