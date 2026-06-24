package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// gateFakeRegistry is a minimal ComponentRegistry that returns one configured
// tenant-scoped instance from Discover and nothing from the system lookup
// (i.e. no SANDBOXED entry), so CallToolProto reaches the dispatch-policy gate
// on the in-process / direct-gRPC path.
type gateFakeRegistry struct {
	tenantInstances []component.ComponentInfo
}

func (r *gateFakeRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return r.tenantInstances, nil
}
func (r *gateFakeRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *gateFakeRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *gateFakeRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *gateFakeRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *gateFakeRegistry) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *gateFakeRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *gateFakeRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func newGateHarness(t *testing.T, trust componentpb.ContentTrust, shape dispatchpolicy.DeploymentShape) *DefaultAgentHarness {
	t.Helper()
	return &DefaultAgentHarness{
		logger: slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer: noop.NewTracerProvider().Tracer("test"),
		componentRegistry: &gateFakeRegistry{
			tenantInstances: []component.ComponentInfo{{
				Kind:         "tool",
				Name:         "httpx",
				InstanceID:   "i1",
				ContentTrust: trust,
				// A direct gRPC endpoint would be the bypass path; the gate must
				// fire before it is selected. registryAdapter is nil so the
				// allowed path simply falls through to "tool not found".
				Metadata: map[string]string{"grpc_endpoint": "localhost:1"},
			}},
		},
		deploymentShape: shape,
	}
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

func callGate(t *testing.T, h *DefaultAgentHarness) error {
	t.Helper()
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	return h.CallToolProto(ctx, "httpx", wrapperspb.String("in"), &wrapperspb.StringValue{})
}

func gibsonCode(t *testing.T, err error) types.ErrorCode {
	t.Helper()
	var ge *types.GibsonError
	if errors.As(err, &ge) {
		return ge.Code
	}
	return ""
}

// TestDispatchGate_UntrustedSetecOnly_Denied is the load-bearing case: an
// untrusted tool with no sandboxed dispatch is denied before any bypass path
// is selected.
func TestDispatchGate_UntrustedSetecOnly_Denied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	err := callGate(t, h)
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}

// TestDispatchGate_UntrustedCustomerIsolation_NotDenied: on-prem, the customer
// owns isolation, so the gate does not deny — it falls through (and fails later
// for an unrelated reason, but NOT with the policy-deny code).
func TestDispatchGate_UntrustedCustomerIsolation_NotDenied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeCustomerIsolation)
	err := callGate(t, h)
	if code := gibsonCode(t, err); code == types.SANDBOX_POLICY_DENIED {
		t.Fatal("customer-isolation must not policy-deny untrusted execution")
	}
}

// TestDispatchGate_TrustedSetecOnly_NotDenied: a trusted tool takes its
// existing in-process path even under setec-only.
func TestDispatchGate_TrustedSetecOnly_NotDenied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	err := callGate(t, h)
	if code := gibsonCode(t, err); code == types.SANDBOX_POLICY_DENIED {
		t.Fatal("trusted tool must not be policy-denied")
	}
}

// TestDispatchGateStream_UntrustedSetecOnly_Denied: the streaming path
// (CallToolProtoStream → resolveToolForStreaming) is gated too — an untrusted
// tool dispatched over its own gRPC connection is denied under setec-only
// before the stream is opened (gibson#995).
func TestDispatchGateStream_UntrustedSetecOnly_Denied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	err := h.CallToolProtoStream(ctx, "httpx", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}

// TestDispatchGateStream_TrustedSetecOnly_NotDenied: a trusted streaming tool
// is not policy-denied (it proceeds and fails later for an unrelated reason).
func TestDispatchGateStream_TrustedSetecOnly_NotDenied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	err := h.CallToolProtoStream(ctx, "httpx", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
	if code := gibsonCode(t, err); code == types.SANDBOX_POLICY_DENIED {
		t.Fatal("trusted streaming tool must not be policy-denied")
	}
}
