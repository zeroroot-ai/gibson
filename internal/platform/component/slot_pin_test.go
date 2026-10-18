// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// slotPinEnv is a ComponentService with a real work queue and work-context
// registry over one miniredis, and a tenant with two providers: the default
// one and the one that a mission node pins.
type slotPinEnv struct {
	svc         *ComponentServiceServer
	queue       WorkQueue
	defaultProv *mockLLMProvider
	pinnedProv  *mockLLMProvider
}

func newSlotPinEnv(t *testing.T) *slotPinEnv {
	t.Helper()
	base := newWorkIDEnv(t)

	reply := &llm.CompletionResponse{Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"}}
	defaultProv := &mockLLMProvider{name: "default-p", models: []llm.ModelInfo{{Name: "d-1"}}, completeResp: reply}
	pinnedProv := &mockLLMProvider{
		name:         "fast-p",
		models:       []llm.ModelInfo{{Name: "f-small"}, {Name: "f-large"}},
		completeResp: reply,
	}
	set := newTenantSet("default-p", defaultProv, pinnedProv)
	adapter := NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{adapterTestTenant: set}))

	svc := NewComponentServiceServer(&noopRegistry{}, base.queue, testLogger(), adapter, nil, nil, nil).
		WithWorkContextRegistry(NewRedisWorkContextRegistry(base.state))
	return &slotPinEnv{svc: svc, queue: base.queue, defaultProv: defaultProv, pinnedProv: pinnedProv}
}

// dispatchAgentWork enqueues agent work for tenant with the given work context,
// the way the harness dispatches a mission AGENT node.
func (e *slotPinEnv) dispatchAgentWork(t *testing.T, tenant, workID string, workCtx map[string]string) {
	t.Helper()
	_, err := e.queue.Enqueue(context.Background(), tenant, "agent", "recon", WorkItem{
		WorkID:   workID,
		WorkType: WorkTypeAgentExecute,
		Context:  workCtx,
	})
	require.NoError(t, err)
}

func (e *slotPinEnv) complete(t *testing.T, tenant, workID, slot string) error {
	t.Helper()
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	_, err := e.svc.Complete(ctx, &componentpb.CompleteRequest{
		WorkId:   workID,
		Slot:     slot,
		Messages: []*componentpb.LLMMessage{{Role: "user", Content: "hello"}},
	})
	return err
}

const fastPin = `{"fast":{"provider":"fast-p","model":"f-large","temperature":0,"max_tokens":0}}`

// A node that pins a slot gets the pinned provider and model when its agent
// calls Complete with the work id and that slot (gibson#1203).
func TestComplete_UsesTheSlotPinOfTheDispatchingNode(t *testing.T) {
	env := newSlotPinEnv(t)
	env.dispatchAgentWork(t, adapterTestTenant, "work-pin-1", map[string]string{SlotPinsWorkKey: fastPin})

	require.NoError(t, env.complete(t, adapterTestTenant, "work-pin-1", "fast"))

	assert.Equal(t, 1, env.pinnedProv.calls, "the pinned provider serves the pinned slot")
	assert.Equal(t, "f-large", env.pinnedProv.lastModel, "the pinned model serves the pinned slot")
	assert.Zero(t, env.defaultProv.calls, "the tenant default does not serve a pinned slot")
}

// A slot that the node does not pin keeps the tenant default.
func TestComplete_AnUnpinnedSlotKeepsTheTenantDefault(t *testing.T) {
	env := newSlotPinEnv(t)
	env.dispatchAgentWork(t, adapterTestTenant, "work-pin-2", map[string]string{SlotPinsWorkKey: fastPin})

	require.NoError(t, env.complete(t, adapterTestTenant, "work-pin-2", "primary"))

	assert.Equal(t, 1, env.defaultProv.calls)
	assert.Zero(t, env.pinnedProv.calls)
}

// A work id of another tenant gives no pin: the caller gets its own tenant
// default, never the slot choice of another tenant's node.
func TestComplete_AWorkIDOfAnotherTenantGivesNoPin(t *testing.T) {
	env := newSlotPinEnv(t)
	env.dispatchAgentWork(t, "other-tenant", "work-pin-3", map[string]string{SlotPinsWorkKey: fastPin})

	require.NoError(t, env.complete(t, adapterTestTenant, "work-pin-3", "fast"))

	assert.Equal(t, 1, env.defaultProv.calls)
	assert.Zero(t, env.pinnedProv.calls)
}

// Pins that do not parse refuse the enqueue: the daemon wrote them, so bad
// pins are a defect and must not pass as "no pin".
func TestEnqueue_RefusesSlotPinsThatDoNotParse(t *testing.T) {
	env := newSlotPinEnv(t)
	_, err := env.queue.Enqueue(context.Background(), adapterTestTenant, "agent", "recon", WorkItem{
		WorkID:   "work-pin-4",
		WorkType: WorkTypeAgentExecute,
		Context:  map[string]string{SlotPinsWorkKey: "{not json"},
	})
	require.Error(t, err)
}
