// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/wrapperspb"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// These cover the trust decisions that gate running untrusted code outside a
// sandbox: whether a tool has any sandboxed dispatch at all (CallToolProto),
// and the agent content-trust lookup behind DelegateToAgent. A tool with no
// sandboxed dispatch, and an agent whose trust cannot be established, both
// have to deny rather than fall through to an in-process path.

var errRegistryDown = errors.New("redis: connection refused")

// trustLookupRegistry fails whichever lookup the test is exercising.
type trustLookupRegistry struct {
	failTenant bool // Discover errors (agent content-trust lookup)

	tenantInstances []component.ComponentInfo
}

func (r *trustLookupRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	if r.failTenant {
		return nil, errRegistryDown
	}
	return r.tenantInstances, nil
}

func (r *trustLookupRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func (r *trustLookupRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *trustLookupRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *trustLookupRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *trustLookupRegistry) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *trustLookupRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *trustLookupRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func newLookupHarness(reg component.ComponentRegistry) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:            slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:            noop.NewTracerProvider().Tracer("test"),
		componentRegistry: reg,
		deploymentShape:   dispatchpolicy.ShapeSetecOnly,
	}
}

// The tool name must NOT be a kind:tool catalog manifest, or the manifest path
// denies first and this passes without ever reaching the gate it covers.

// TestCallToolProto_UntrustedWithNoSandboxedDispatch_Denied: a tool with no
// kind:tool manifest has no sandboxed dispatch (ADR-0017). When such a tool is
// UNTRUSTED, every remaining path runs it in-process, so under setec-only the
// call is denied rather than continued — even though a direct gRPC endpoint is
// registered and would otherwise have been selected.
func TestCallToolProto_UntrustedWithNoSandboxedDispatch_Denied(t *testing.T) {
	h := newLookupHarness(&trustLookupRegistry{
		// A tenant instance with a direct gRPC endpoint is exactly what the
		// fall-through would have selected.
		tenantInstances: []component.ComponentInfo{{
			Kind: "tool", Name: "acme-registry-tool", InstanceID: "i1",
			ContentTrust: componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
			Metadata:     map[string]string{"grpc_endpoint": "localhost:1"},
		}},
	})
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	err := h.CallToolProto(ctx, "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}

func TestDelegateToAgent_TrustLookupError_Denied(t *testing.T) {
	h := newLookupHarness(&trustLookupRegistry{failTenant: true})
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := h.DelegateToAgent(ctx, "scanner", agent.Task{})
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}

// TestDelegateToAgent_NoTenant_Denied: without a tenant the registry cannot be
// asked what the agent is, so trust is unknown and delegation denies.
func TestDelegateToAgent_NoTenant_Denied(t *testing.T) {
	h := newLookupHarness(&trustLookupRegistry{})
	_, err := h.DelegateToAgent(context.Background(), "scanner", agent.Task{})
	if err == nil {
		t.Fatal("expected a deny error, got nil")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
}
