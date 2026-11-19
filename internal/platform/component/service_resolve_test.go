// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_resolve_test.go covers ResolveModel and ResolveAgent on the
// ComponentService. An agent in pull mode calls both to learn where to send its
// model calls and its A2A messages.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeSlotModels is a SlotModelResolver. It records the slot and the pin of the
// last call.
type fakeSlotModels struct {
	picked  ResolvedSlot
	err     error
	tenant  string
	slot    string
	pin     *agent.SlotConfig
	called  int
	bySlots map[string]ResolvedSlot
}

func (f *fakeSlotModels) ResolveSlotModel(
	_ context.Context, tenant, slot string, pin *agent.SlotConfig,
) (ResolvedSlot, error) {
	f.called++
	f.tenant, f.slot, f.pin = tenant, slot, pin
	if f.err != nil {
		return ResolvedSlot{}, f.err
	}
	if p, ok := f.bySlots[slot]; ok {
		return p, nil
	}
	if f.bySlots != nil {
		return ResolvedSlot{}, fmt.Errorf("slot %q: %w", slot, errors.New("no provider for the slot"))
	}
	return f.picked, nil
}

var testModelGateway = GatewayInfo{URL: "https://models.example.test/", CAPEM: "MODEL-CA"}

var testAgentGateway = GatewayInfo{URL: "https://agents.example.test/", CAPEM: "AGENT-CA"}

// resolveEnv is a work-id environment with a fake slot resolver and the two
// gateways wired.
func newResolveEnv(t *testing.T, slots *fakeSlotModels) *workIDEnv {
	t.Helper()
	env := newWorkIDEnv(t)
	env.svc.WithSlotModelResolver(slots).WithGateways(testModelGateway, testAgentGateway)
	return env
}

// enqueueAgentWork puts an agent work item with slot pins on the queue and
// returns the context of the agent that claims it.
func (e *workIDEnv) enqueueAgentWork(
	t *testing.T, tenant, workID string, pins map[string]agent.SlotConfig,
) context.Context {
	t.Helper()
	_, err := e.queue.Enqueue(context.Background(), tenant, "agent", "recon", WorkItem{
		WorkID: workID, WorkType: "execute", SlotPins: pins,
	})
	require.NoError(t, err)
	return e.claimedBy(auth.ContextWithTenantString(context.Background(), tenant), t, workID, "component-1")
}

func TestResolveModel_ReplyHoldsTheModelTheUrlTheRouteHeadersAndTheCA(t *testing.T) {
	slots := &fakeSlotModels{picked: ResolvedSlot{Provider: "claude", Model: "claude-sonnet-4-5", ContextWindow: 200000}}
	env := newResolveEnv(t, slots)
	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)

	resp, err := env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: " primary "})
	require.NoError(t, err)

	assert.Equal(t, "claude-sonnet-4-5", resp.GetModel())
	assert.Equal(t, "claude", resp.GetProvider())
	assert.EqualValues(t, 200000, resp.GetContextWindow())
	assert.Equal(t, "https://models.example.test", resp.GetGatewayUrl(), "the URL has no trailing slash")
	assert.Equal(t, "MODEL-CA", resp.GetGatewayCaPem())
	want := map[string]string{}
	for _, h := range modelcall.RouteHeaders(victimTenant, "claude") {
		want[h.Name] = h.Value
	}
	assert.Equal(t, want, resp.GetRouteHeaders(), "the headers are the route headers of the tenant and the provider")
	assert.Equal(t, "primary", slots.slot, "the slot is trimmed")
	assert.Equal(t, victimTenant, slots.tenant)
	assert.Nil(t, slots.pin, "a call with no work id has no pin")
}

// The reply carries the smaller of the model limit and the token cap of the
// node. A zero is an unknown limit and never wins over a known one.
func TestResolveModel_TheReplyCarriesTheSmallerOutputLimit(t *testing.T) {
	cases := []struct {
		name       string
		modelLimit int32
		nodeCap    int32
		want       int32
	}{
		{"the node cap is smaller", 8192, 1000, 1000},
		{"the model limit is smaller", 800, 1000, 800},
		{"only the node cap is known", 0, 1000, 1000},
		{"only the model limit is known", 8192, 0, 8192},
		{"no limit is known", 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slots := &fakeSlotModels{picked: ResolvedSlot{
				Provider: "claude", Model: "m", MaxOutputTokens: tc.modelLimit,
			}}
			env := newResolveEnv(t, slots)
			_, err := env.queue.Enqueue(context.Background(), victimTenant, "agent", "recon", WorkItem{
				WorkID: "work-cap", WorkType: "execute", MaxTokensPerCall: tc.nodeCap,
			})
			require.NoError(t, err)
			ctx := env.claimedBy(auth.ContextWithTenantString(context.Background(), victimTenant),
				t, "work-cap", "component-1")

			resp, err := env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{
				Slot: "primary", WorkId: "work-cap",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, resp.GetMaxOutputTokens())
		})
	}
}

func TestResolveModel_TheSlotPinOfTheNodeIsHonored(t *testing.T) {
	slots := &fakeSlotModels{picked: ResolvedSlot{Provider: "p2", Model: "m2"}}
	env := newResolveEnv(t, slots)
	pins := map[string]agent.SlotConfig{
		"primary": {Provider: "p2", Model: "m2"},
		"fast":    {Provider: "p3", Model: "m3"},
	}
	ctx := env.enqueueAgentWork(t, victimTenant, "work-pinned", pins)

	_, err := env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{WorkId: "work-pinned", Slot: "primary"})
	require.NoError(t, err)
	require.NotNil(t, slots.pin, "the node pin reaches the slot resolution")
	assert.Equal(t, "p2", slots.pin.Provider)
	assert.Equal(t, "m2", slots.pin.Model)

	_, err = env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{WorkId: "work-pinned", Slot: "reasoning"})
	require.NoError(t, err)
	assert.Nil(t, slots.pin, "a slot that the node does not pin has no pin")
}

func TestResolveModel_ASharedComponentGetsNoPinOfTheTenant(t *testing.T) {
	slots := &fakeSlotModels{picked: ResolvedSlot{Provider: "p", Model: "m"}}
	env := newResolveEnv(t, slots)
	pins := map[string]agent.SlotConfig{"primary": {Provider: "p2", Model: "m2"}}
	_, err := env.queue.Enqueue(context.Background(), victimTenant, "agent", "recon", WorkItem{
		WorkID: "work-shared", WorkType: "execute", SlotPins: pins,
	})
	require.NoError(t, err)
	shared := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	ctx := env.claimedBy(shared, t, "work-shared", "component-1")

	_, err = env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{WorkId: "work-shared", Slot: "primary"})
	require.NoError(t, err)
	assert.Nil(t, slots.pin, "a pin names a provider of the owner tenant, and a shared component resolves in its own set")
}

func TestResolveModel_AnUnknownSlotFails(t *testing.T) {
	slots := &fakeSlotModels{bySlots: map[string]ResolvedSlot{"primary": {Provider: "p", Model: "m"}}}
	env := newResolveEnv(t, slots)
	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)

	_, err := env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: "no-such-slot"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	slots.picked = ResolvedSlot{}
	slots.bySlots = nil
	_, err = env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: "primary"})
	assert.Equal(t, codes.NotFound, status.Code(err), "a pick with no model is a slot with no model")
}

func TestResolveModel_TheModelGateRefusalIsPermissionDenied(t *testing.T) {
	slots := &fakeSlotModels{err: fmt.Errorf("slot: %w", modelgate.ErrDenied)}
	env := newResolveEnv(t, slots)
	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)

	_, err := env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: "primary"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	slots.err = fmt.Errorf("slot: %w", errors.Join(modelgate.ErrDenied, modelgate.ErrUnavailable))
	_, err = env.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: "primary"})
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err), "a gate that could not decide is no refusal")
}

func TestResolveModel_Refusals(t *testing.T) {
	slots := &fakeSlotModels{picked: ResolvedSlot{Provider: "p", Model: "m"}}
	env := newResolveEnv(t, slots)
	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)

	cases := map[string]struct {
		ctx  context.Context
		req  *componentpb.ResolveModelRequest
		want codes.Code
	}{
		"no tenant": {context.Background(), &componentpb.ResolveModelRequest{Slot: "primary"}, codes.Unauthenticated},
		"no slot":   {ctx, &componentpb.ResolveModelRequest{Slot: "  "}, codes.InvalidArgument},
		"unclaimed work": {
			ctx, &componentpb.ResolveModelRequest{Slot: "primary", WorkId: "no-such-work"}, codes.PermissionDenied,
		},
	}
	for name, tc := range cases {
		_, err := env.svc.ResolveModel(tc.ctx, tc.req)
		assert.Equal(t, tc.want, status.Code(err), name)
	}
	assert.Zero(t, slots.called, "no refusal reaches the slot resolution")

	bare := newWorkIDEnv(t)
	_, err := bare.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{Slot: "primary"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a server with no gateway cannot resolve a model")
}

func TestResolveAgent_ReplyHoldsTheRouteTheCAAndTheCardURL(t *testing.T) {
	env := newResolveEnv(t, &fakeSlotModels{})
	env.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "i1"}}
	ctx := env.enqueueAgentWork(t, victimTenant, "work-1", nil)

	bank := "bank-1"
	resp, err := env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{
		WorkId: "work-1", Name: " recon-agent ", BankId: &bank,
	})
	require.NoError(t, err)

	assert.Equal(t, "https://agents.example.test/", resp.GetGatewayUrl())
	assert.Equal(t, "AGENT-CA", resp.GetGatewayCaPem())
	assert.Equal(t, "https://agents.example.test/.well-known/agent-card.json", resp.GetAgentCardUrl())
	want := map[string]string{}
	for _, h := range agentcall.RouteHeaders(victimTenant, "recon-agent", "bank-1") {
		want[h.Name] = h.Value
	}
	assert.Equal(t, want, resp.GetRouteHeaders())
}

func TestResolveAgent_AnAgentThatIsNotAvailableFails(t *testing.T) {
	env := newResolveEnv(t, &fakeSlotModels{})
	env.svc.registry = &countingRegistry{}
	ctx := env.enqueueAgentWork(t, victimTenant, "work-1", nil)

	_, err := env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "no-such-agent"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestResolveAgent_Refusals(t *testing.T) {
	env := newResolveEnv(t, &fakeSlotModels{})
	env.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "i1"}}
	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)

	cases := map[string]struct {
		ctx  context.Context
		req  *componentpb.ResolveAgentRequest
		want codes.Code
	}{
		"no tenant": {context.Background(), &componentpb.ResolveAgentRequest{Name: "recon-agent"}, codes.Unauthenticated},
		"no name":   {ctx, &componentpb.ResolveAgentRequest{Name: " "}, codes.InvalidArgument},
		"unclaimed work": {
			ctx, &componentpb.ResolveAgentRequest{Name: "recon-agent", WorkId: "no-such-work"}, codes.PermissionDenied,
		},
	}
	for name, tc := range cases {
		_, err := env.svc.ResolveAgent(tc.ctx, tc.req)
		assert.Equal(t, tc.want, status.Code(err), name)
	}

	bare := newWorkIDEnv(t)
	_, err := bare.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{Name: "recon-agent"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a server with no agent gateway cannot resolve an agent")
}

// memOutsideAgents is an outside agent store with the entries of one tenant.
type memOutsideAgents struct {
	tenant string
	names  map[string]bool
	err    error
}

func (m *memOutsideAgents) Register(context.Context, string, outsideagentstore.Entry) (*outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (m *memOutsideAgents) List(context.Context, string) ([]outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (m *memOutsideAgents) Get(_ context.Context, tenant, name string) (*outsideagentstore.Entry, error) {
	if m.err != nil {
		return nil, m.err
	}
	if tenant == m.tenant && m.names[name] {
		return &outsideagentstore.Entry{Name: name}, nil
	}
	return nil, outsideagentstore.ErrNotFound
}

func (m *memOutsideAgents) Delete(context.Context, string, string) error {
	return errors.New("not used")
}

// An outside agent resolves to the same gateway URL and the same route headers as
// any agent. No registered instance is needed. The record of another tenant does
// not resolve.
func TestResolveAgent_AnOutsideAgentGetsTheAgentGatewayRoute(t *testing.T) {
	env := newResolveEnv(t, &fakeSlotModels{})
	env.svc.registry = &countingRegistry{}
	env.svc.WithOutsideAgents(&memOutsideAgents{tenant: victimTenant, names: map[string]bool{"partner-scout": true}})
	ctx := env.enqueueAgentWork(t, victimTenant, "work-1", nil)

	resp, err := env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "partner-scout"})
	require.NoError(t, err)
	assert.Equal(t, "https://agents.example.test/", resp.GetGatewayUrl())
	want := map[string]string{}
	for _, h := range agentcall.RouteHeaders(victimTenant, "partner-scout", "") {
		want[h.Name] = h.Value
	}
	assert.Equal(t, want, resp.GetRouteHeaders())

	_, err = env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "other-scout"})
	assert.Equal(t, codes.NotFound, status.Code(err), "a name that is not registered")

	env.svc.WithOutsideAgents(&memOutsideAgents{tenant: "another-tenant", names: map[string]bool{"partner-scout": true}})
	_, err = env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "partner-scout"})
	assert.Equal(t, codes.NotFound, status.Code(err), "the record of another tenant")

	env.svc.WithOutsideAgents(&memOutsideAgents{err: errors.New("db down")})
	_, err = env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "partner-scout"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a store that cannot answer")
}

func TestResolveAgent_TheEdgePrefixMatchesTheEndpointAndTheCard(t *testing.T) {
	env := newResolveEnv(t, &fakeSlotModels{})
	env.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "i1"}}
	env.svc.agentGateway.URL = "https://api.localhost.zeroroot.ai:443/gateway/agent"
	ctx := env.enqueueAgentWork(t, victimTenant, "work-1", nil)

	resp, err := env.svc.ResolveAgent(ctx, &componentpb.ResolveAgentRequest{WorkId: "work-1", Name: "recon-agent"})
	require.NoError(t, err)
	assert.Equal(t, "https://api.localhost.zeroroot.ai:443/gateway/agent/", resp.GetGatewayUrl())
	assert.Equal(t, "https://api.localhost.zeroroot.ai:443/gateway/agent/.well-known/agent-card.json", resp.GetAgentCardUrl())
	for _, u := range []string{resp.GetGatewayUrl(), resp.GetAgentCardUrl()} {
		assert.True(t, strings.Contains(u, modelcall.EdgeAgentPrefix), "%s must match the Edge prefix", u)
	}
}
