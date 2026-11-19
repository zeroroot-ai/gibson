// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_resolve_test.go covers the ResolveModel and ResolveAgent handlers of
// HarnessCallbackService. An agent that runs in the sandbox calls them to learn
// where to send its model calls and its A2A messages.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

const resolveTenant = "test-tenant"

var (
	resolveModelGateway = GatewayInfo{URL: "https://models.example.test/", CAPEM: "MODEL-CA"}
	resolveAgentGateway = GatewayInfo{URL: "https://agents.example.test/", CAPEM: "AGENT-CA"}
)

// resolveHarness is a DefaultAgentHarness over a stub slot manager. The slot
// manager is the one that DefaultAgentHarness.ResolveSlotModel asks.
func resolveHarness(sm *stubSlotManager, pins map[string]*agent.SlotConfig) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		slotManager:       sm,
		nodeSlotOverrides: pins,
		tracer:            noop.NewTracerProvider().Tracer("test"),
		logger:            slog.New(slog.DiscardHandler),
		metrics:           NewNoOpMetricsRecorder(),
		missionCtx: MissionContext{
			ID: types.ID("mission-A"), TenantID: resolveTenant, MissionRunID: "run-1", CurrentAgent: "recon-agent",
		},
	}
}

func resolveService(t *testing.T, h AgentHarness, opts ...CallbackServiceOption) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "mission-A", "recon-agent", h)
	base := make([]CallbackServiceOption, 0, 3+len(opts))
	base = append(base, testEventBus(), WithModelGateway(resolveModelGateway), WithAgentGateway(resolveAgentGateway))
	opts = append(base, opts...)
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, opts...)
}

func resolveContext() *harnesspb.ContextInfo {
	return &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent", MissionRunId: "run-1"}
}

func TestCallbackResolveModel_ReplyHoldsTheModelTheURLTheRouteHeadersAndTheCA(t *testing.T) {
	sm := newStubSlotManager()
	sm.picked = SlotModel{Provider: "claude", Model: "claude-sonnet-4-5", ContextWindow: 200000}
	svc := resolveService(t, resolveHarness(sm, nil))

	resp, err := svc.ResolveModel(testCtxWithTenant(), &harnesspb.ResolveModelRequest{
		Context: resolveContext(), Slot: "primary",
	})
	require.NoError(t, err)

	assert.Equal(t, "claude-sonnet-4-5", resp.GetModel())
	assert.Equal(t, "claude", resp.GetProvider())
	assert.EqualValues(t, 200000, resp.GetContextWindow())
	assert.Equal(t, "https://models.example.test", resp.GetGatewayUrl(), "the URL has no trailing slash")
	assert.Equal(t, "MODEL-CA", resp.GetGatewayCaPem())
	want := map[string]string{}
	for _, h := range modelcall.RouteHeaders(resolveTenant, "claude") {
		want[h.Name] = h.Value
	}
	assert.Equal(t, want, resp.GetRouteHeaders())
}

func TestCallbackResolveModel_TheSlotPinOfTheNodeIsHonored(t *testing.T) {
	sm := newStubSlotManager()
	pin := &agent.SlotConfig{Provider: "p2", Model: "m2"}
	svc := resolveService(t, resolveHarness(sm, map[string]*agent.SlotConfig{"primary": pin}))

	req := &harnesspb.ResolveModelRequest{Context: resolveContext(), Slot: "primary"}
	_, err := svc.ResolveModel(testCtxWithTenant(), req)
	require.NoError(t, err)
	assert.Same(t, pin, sm.lastOverride, "the node pin reaches the slot manager")

	req.Slot = "fast"
	_, err = svc.ResolveModel(testCtxWithTenant(), req)
	require.NoError(t, err)
	assert.Nil(t, sm.lastOverride, "a slot that the node does not pin has no pin")
}

func TestCallbackResolveModel_AnUnknownSlotFails(t *testing.T) {
	sm := newStubSlotManager()
	sm.err = errors.New("no provider for the slot")
	svc := resolveService(t, resolveHarness(sm, nil))

	req := &harnesspb.ResolveModelRequest{Context: resolveContext(), Slot: "no-such-slot"}
	_, err := svc.ResolveModel(testCtxWithTenant(), req)

	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestCallbackResolveModel_APickWithNoModelFails(t *testing.T) {
	sm := newStubSlotManager()
	sm.picked = SlotModel{Provider: "claude"}
	svc := resolveService(t, resolveHarness(sm, nil))

	req := &harnesspb.ResolveModelRequest{Context: resolveContext(), Slot: "primary"}
	_, err := svc.ResolveModel(testCtxWithTenant(), req)

	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestCallbackResolveModel_Refusals(t *testing.T) {
	sm := newStubSlotManager()
	svc := resolveService(t, resolveHarness(sm, nil))
	noGateway := resolveService(t, resolveHarness(sm, nil), WithModelGateway(GatewayInfo{}))

	blank := &harnesspb.ResolveModelRequest{Context: resolveContext(), Slot: "  "}
	_, err := svc.ResolveModel(testCtxWithTenant(), blank)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no slot")

	valid := &harnesspb.ResolveModelRequest{Context: resolveContext(), Slot: "primary"}
	_, err = noGateway.ResolveModel(testCtxWithTenant(), valid)
	assert.Equal(t, codes.Unavailable, status.Code(err), "no gateway")

	_, err = svc.ResolveModel(testCtxWithTenant(), &harnesspb.ResolveModelRequest{
		Context: &harnesspb.ContextInfo{MissionId: "no-such-mission", AgentName: "recon-agent"}, Slot: "primary",
	})
	require.Error(t, err, "a run with no registered harness")
	assert.Zero(t, sm.calls, "no refusal reached the slot manager before the checks")
}

func TestResolveAgent_ReplyHoldsTheRouteTheCAAndTheCardURL(t *testing.T) {
	svc := resolveService(t, resolveHarness(newStubSlotManager(), nil))
	svc.componentRegistry = &gateFakeRegistry{tenantInstances: []component.ComponentInfo{
		{Kind: "agent", Name: "peer-agent", InstanceID: "i1"},
	}}
	bank := "bank-1"

	resp, err := svc.ResolveAgent(testCtxWithTenant(), &harnesspb.ResolveAgentRequest{
		Context: resolveContext(), Name: "peer-agent", BankId: &bank,
	})
	require.NoError(t, err)

	assert.Equal(t, "https://agents.example.test/", resp.GetGatewayUrl())
	assert.Equal(t, "AGENT-CA", resp.GetGatewayCaPem())
	assert.Equal(t, "https://agents.example.test/agents/peer-agent/.well-known/agent-card.json", resp.GetAgentCardUrl())
	want := map[string]string{}
	for _, h := range agentcall.RouteHeaders(resolveTenant, "peer-agent", bank) {
		want[h.Name] = h.Value
	}
	assert.Equal(t, want, resp.GetRouteHeaders())
}

func TestResolveAgent_AnAgentOfTheCatalogNeedsNoRegisteredInstance(t *testing.T) {
	svc := resolveService(t, resolveHarness(newStubSlotManager(), nil))

	resp, err := svc.ResolveAgent(testCtxWithTenant(), &harnesspb.ResolveAgentRequest{
		Context: resolveContext(), Name: "cve-triage",
	})

	require.NoError(t, err)
	assert.Equal(t, "https://agents.example.test/", resp.GetGatewayUrl())
}

func TestResolveAgent_Refusals(t *testing.T) {
	h := resolveHarness(newStubSlotManager(), nil)
	svc := resolveService(t, h)
	svc.componentRegistry = &gateFakeRegistry{}
	noGateway := resolveService(t, h, WithAgentGateway(GatewayInfo{}))
	broken := resolveService(t, h)
	broken.componentRegistry = &gateFakeRegistry{discoverErr: errors.New("registry down")}
	ctx := testCtxWithTenant()

	_, err := svc.ResolveAgent(ctx, &harnesspb.ResolveAgentRequest{Context: resolveContext(), Name: "no-such-agent"})
	assert.Equal(t, codes.NotFound, status.Code(err), "an agent that is not available")

	_, err = svc.ResolveAgent(ctx, &harnesspb.ResolveAgentRequest{Context: resolveContext()})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "no name")

	_, err = noGateway.ResolveAgent(ctx, &harnesspb.ResolveAgentRequest{Context: resolveContext(), Name: "cve-triage"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "no gateway")

	_, err = broken.ResolveAgent(ctx, &harnesspb.ResolveAgentRequest{Context: resolveContext(), Name: "no-such-agent"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a registry that cannot answer")
}

func TestResolveStatusMappers(t *testing.T) {
	model := map[error]codes.Code{
		ErrResolveSlotRequired: codes.InvalidArgument,
		ErrResolveNoGateway:    codes.Unavailable,
		ErrResolveNoModel:      codes.NotFound,
		errors.New("other"):    codes.PermissionDenied,
	}
	for err, want := range model {
		assert.Equal(t, want, status.Code(ResolveModelStatus(fmt.Errorf("wrapped: %w", err))), err.Error())
	}
	agentCodes := map[error]codes.Code{
		ErrResolveAgentNameRequired: codes.InvalidArgument,
		ErrResolveAgentNoGateway:    codes.Unavailable,
		ErrResolveAgentNotFound:     codes.NotFound,
		errors.New("other"):         codes.PermissionDenied,
	}
	for err, want := range agentCodes {
		assert.Equal(t, want, status.Code(ResolveAgentStatus(fmt.Errorf("wrapped: %w", err))), err.Error())
	}
}

// An outside agent of the tenant resolves to the same route as any agent, with
// no registered instance. The record of another tenant does not resolve.
func TestResolveAgent_AnOutsideAgentGetsTheAgentGatewayRoute(t *testing.T) {
	h := resolveHarness(newStubSlotManager(), nil)
	store := &outsideStoreStub{names: map[string]bool{"partner-scout": true}}
	svc := resolveService(t, h, WithOutsideAgentStore(func() outsideagentstore.Store { return store }))
	svc.componentRegistry = &gateFakeRegistry{}

	resp, err := svc.ResolveAgent(testCtxWithTenant(), &harnesspb.ResolveAgentRequest{
		Context: resolveContext(), Name: "partner-scout",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://agents.example.test/", resp.GetGatewayUrl())
	assert.Equal(t, "partner-scout", resp.GetRouteHeaders()["x-gibson-route-agent"])

	_, err = svc.ResolveAgent(testCtxWithTenant(), &harnesspb.ResolveAgentRequest{
		Context: resolveContext(), Name: "other-scout",
	})
	assert.Equal(t, codes.NotFound, status.Code(err))

	store.err = errors.New("db down")
	_, err = svc.ResolveAgent(testCtxWithTenant(), &harnesspb.ResolveAgentRequest{
		Context: resolveContext(), Name: "partner-scout",
	})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a store that cannot answer")
}

type outsideStoreStub struct {
	names map[string]bool
	err   error
}

func (o *outsideStoreStub) Register(context.Context, string, outsideagentstore.Entry) (*outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (o *outsideStoreStub) ListPage(context.Context, string, string, bool, int) ([]outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (o *outsideStoreStub) Get(_ context.Context, _, name string) (*outsideagentstore.Entry, error) {
	if o.err != nil {
		return nil, o.err
	}
	if o.names[name] {
		return &outsideagentstore.Entry{Name: name}, nil
	}
	return nil, outsideagentstore.ErrNotFound
}

func (o *outsideStoreStub) Delete(context.Context, string, string) error {
	return errors.New("not used")
}
