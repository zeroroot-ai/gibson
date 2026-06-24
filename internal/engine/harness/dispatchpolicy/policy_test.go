package dispatchpolicy

import (
	"testing"

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
		name        string
		trust       componentpb.ContentTrust
		hasSandbox  bool
		shape       DeploymentShape
		want        Decision
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
