// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
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
		// The execute gate runs before the trust gate these tests cover. The
		// tenant has the tool enabled, so the trust gate is what decides.
		componentAuthorizer: &recordingAuthorizer{allow: true},
		componentRegistry: &gateFakeRegistry{
			tenantInstances: []component.ComponentInfo{{
				Kind:         "tool",
				Name:         "acme-registry-tool",
				InstanceID:   "i1",
				ContentTrust: trust,
				// The gate reads where an instance runs, not what it reports.
				// The denied case is an attested instance the catalog does not
				// list. The allowed case is an instance on the tenant's machine.
				Attested: trust == componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
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
	ctx := callerCtx(t, "user-42", "acme")
	return h.CallToolProto(ctx, "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
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

// The tool name here must NOT be a kind:tool catalog manifest. These tests are
// about registry-driven dispatch policy; a manifest tool takes the earlier
// manifest path in CallToolProto (ADR-0117) and never reaches the code under
// test. "httpx" used to be safely fictional until it became a real catalog
// tool in gibson#1640.

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
	ctx := callerCtx(t, "user-42", "acme")
	err := h.CallToolProtoStream(ctx, "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
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
	ctx := callerCtx(t, "user-42", "acme")
	err := h.CallToolProtoStream(ctx, "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
	if code := gibsonCode(t, err); code == types.SANDBOX_POLICY_DENIED {
		t.Fatal("trusted streaming tool must not be policy-denied")
	}
}

// TestDispatchGateDelegate_UntrustedSetecOnly_Denied: sub-agent delegation of
// an untrusted agent is denied under setec-only — there is no sandboxed agent
// dispatch (gibson#996).
func TestDispatchGateDelegate_UntrustedSetecOnly_Denied(t *testing.T) {
	h := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := h.DelegateToAgent(ctx, "scanner", agent.Task{})
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}

// TestResolveAgentStanding feeds the DelegateToAgent gate. An agent whose
// instances all run on the tenant's machine is not denied. An attested
// instance of an agent the catalog does not list is denied under setec-only
// with no sandboxed dispatch. An agent with no instance is a built-in one.
func TestResolveAgentStanding(t *testing.T) {
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	decide := func(h *DefaultAgentHarness, name string) dispatchpolicy.Decision {
		t.Helper()
		placement, trust, err := h.resolveAgentStanding(ctx, name)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		return dispatchpolicy.Decide(placement, trust, false, dispatchpolicy.ShapeSetecOnly)
	}

	outside := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	if decide(outside, "scanner") == dispatchpolicy.Deny {
		t.Fatal("an agent on the tenant's machine would be denied; want allowed")
	}

	cluster := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	if decide(cluster, "scanner") != dispatchpolicy.Deny {
		t.Fatal("an attested agent the catalog does not list would run; want denied")
	}

	none := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	none.componentRegistry = &gateFakeRegistry{}
	if decide(none, "scanner") == dispatchpolicy.Deny {
		t.Fatal("a built-in agent would be denied; want allowed")
	}

	if _, _, err := outside.resolveAgentStanding(context.Background(), "scanner"); err == nil {
		t.Fatal("a request with no tenant must fail, so the delegation is denied")
	}
}

// TestDispatchGate_SelfReportedTrustIsNotAnInput is the failing fixture for
// the rule that placement and the catalog decide where a tool runs. An
// attested instance the catalog does not list reports TRUSTED and is denied.
// An instance on the tenant's machine reports UNTRUSTED and is not denied.
func TestDispatchGate_SelfReportedTrustIsNotAnInput(t *testing.T) {
	cluster := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, dispatchpolicy.ShapeSetecOnly)
	reg := cluster.componentRegistry.(*gateFakeRegistry)
	reg.tenantInstances[0].ContentTrust = componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
	if code := gibsonCode(t, callGate(t, cluster)); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("cluster code that reports TRUSTED: code = %q; want SANDBOX_POLICY_DENIED", code)
	}

	outside := newGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	reg = outside.componentRegistry.(*gateFakeRegistry)
	reg.tenantInstances[0].ContentTrust = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
	if code := gibsonCode(t, callGate(t, outside)); code == types.SANDBOX_POLICY_DENIED {
		t.Fatal("an instance on the tenant's machine that reports UNTRUSTED was policy-denied")
	}
}
