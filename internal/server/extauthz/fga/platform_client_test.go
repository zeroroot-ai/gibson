package fga

import (
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/authz"
)

// TestClassifyOutcome verifies the OTel attribute mapping covers each
// platform-clients sentinel error + the allow/deny path. Low-cardinality
// labels are critical for the histogram and counter: any new error
// shape must be classified here, not leaked as a unique string.
func TestClassifyOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		resp authz.CheckResponse
		err  error
		want string
	}{
		{"allow", authz.CheckResponse{Allowed: true}, nil, "allow"},
		{"deny", authz.CheckResponse{Allowed: false}, nil, "deny"},
		{"timeout", authz.CheckResponse{}, authz.ErrFGATimeout, "timeout"},
		{"unavailable", authz.CheckResponse{}, authz.ErrFGAUnavailable, "unavailable"},
		{"invalid", authz.CheckResponse{}, authz.ErrInvalidArgument, "invalid"},
		{"wrapped-timeout", authz.CheckResponse{}, errors.Join(authz.ErrFGATimeout, errors.New("ctx deadline")), "timeout"},
		{"unknown-error", authz.CheckResponse{}, errors.New("something else"), "error"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyOutcome(tc.resp, tc.err)
			if got != tc.want {
				t.Fatalf("classifyOutcome(%v, %v) = %q, want %q", tc.resp, tc.err, got, tc.want)
			}
		})
	}
}

// TestNewPlatformFGAClient_RequiresFields — bad opts must NOT silently
// succeed; the underlying platform-clients validator must propagate.
func TestNewPlatformFGAClient_RequiresFields(t *testing.T) {
	t.Parallel()
	_, err := NewPlatformFGAClient(authz.FGAClientOptions{})
	if err == nil {
		t.Fatal("expected error for empty options, got nil")
	}
}

// TestReadinessProbe_NilClient — defensive: probe with nil client must
// not panic and must return an error suitable for /readyz JSON.
func TestReadinessProbe_NilClient(t *testing.T) {
	t.Parallel()
	p := NewReadinessProbe(nil, "")
	if p.Name() != "fga" {
		t.Fatalf("expected default name %q, got %q", "fga", p.Name())
	}
	if err := p.Check(nil); err == nil { //nolint:staticcheck // testing nil ctx + nil client path
		t.Fatal("expected error for nil client, got nil")
	}
}
