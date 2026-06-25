package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/engine/tool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// spyAdapter is a component.ComponentDiscovery whose DiscoverTool records
// whether it was reached. Every other method is inherited from the embedded
// nil interface and panics if invoked — so any unexpected fan-out into the
// in-process discovery surface fails the test loudly rather than silently.
//
// DiscoverTool deliberately returns a sentinel error (rather than a working
// tool) so the test asserts on *reachability*, not on a full in-process
// execution: reaching it at all is the violation we are guarding against for
// untrusted components under setec-only.
type spyAdapter struct {
	component.ComponentDiscovery
	discoverToolCalled bool
}

func (s *spyAdapter) DiscoverTool(_ context.Context, _ string) (tool.Tool, error) {
	s.discoverToolCalled = true
	return nil, errors.New("spy: in-process gRPC path was selected")
}

// newNoFallbackHarness wires a harness on the in-process direct-gRPC path: the
// tenant instance carries a grpc_endpoint and a spyAdapter is installed, so a
// component that clears the dispatch-policy gate WILL reach DiscoverTool. The
// gate must stop an untrusted component before that happens.
func newNoFallbackHarness(t *testing.T, trust componentpb.ContentTrust, shape dispatchpolicy.DeploymentShape) (*DefaultAgentHarness, *spyAdapter) {
	t.Helper()
	spy := &spyAdapter{}
	h := &DefaultAgentHarness{
		logger: slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer: noop.NewTracerProvider().Tracer("test"),
		componentRegistry: &gateFakeRegistry{
			tenantInstances: []component.ComponentInfo{{
				Kind:         "tool",
				Name:         "httpx",
				InstanceID:   "i1",
				ContentTrust: trust,
				Metadata:     map[string]string{"grpc_endpoint": "localhost:1"},
			}},
		},
		registryAdapter: spy,
		deploymentShape: shape,
	}
	return h, spy
}

// TestDispatchGate_UntrustedSetecOnly_NoInProcessFallback is the AC-3 invariant
// (gibson#999): an untrusted tool with no sandboxed dispatch under setec-only is
// denied with the typed SANDBOX_POLICY_DENIED code AND never reaches the
// in-process direct-gRPC path — the spy adapter's DiscoverTool is not called.
func TestDispatchGate_UntrustedSetecOnly_NoInProcessFallback(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	err := h.CallToolProto(ctx, "httpx", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
	if spy.discoverToolCalled {
		t.Fatal("untrusted tool reached the in-process gRPC dispatch path; the gate must deny before any in-process fallback")
	}
}

// TestDispatchGate_TrustedSetecOnly_ReachesInProcess is the control: a trusted
// tool with the identical wiring DOES reach the in-process path (the spy is
// invoked). This proves the no-fallback assertion above is load-bearing — the
// path is genuinely reachable and only the gate stops the untrusted case.
func TestDispatchGate_TrustedSetecOnly_ReachesInProcess(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	// Error is expected (the spy returns one); we only assert the path was taken.
	_ = h.CallToolProto(ctx, "httpx", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if !spy.discoverToolCalled {
		t.Fatal("trusted tool did not reach the in-process gRPC path; control wiring is wrong, the no-fallback test would be vacuous")
	}
}
