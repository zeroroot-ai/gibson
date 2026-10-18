// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// completeStream is a fake grpc.ServerStreamingServer[CompleteStreamResponse].
type completeStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*componentpb.CompleteStreamResponse
}

func (s *completeStream) Context() context.Context { return s.ctx }
func (s *completeStream) Send(r *componentpb.CompleteStreamResponse) error {
	s.sent = append(s.sent, r)
	return nil
}

// Each completion RPC refuses a work id when the server has no work-context
// registry, before it calls the completer (gibson#1203).
func TestCompletionRPCs_AWorkIDWithNoRegistryIsRefused(t *testing.T) {
	reply := &llm.CompletionResponse{Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"}}
	prov := &mockLLMProvider{name: "default-p", models: []llm.ModelInfo{{Name: "d-1"}}, completeResp: reply, toolCompleteResp: reply}
	base := newWorkIDEnv(t)
	adapter := newTestAdapter(prov)
	svc := NewComponentServiceServer(&noopRegistry{}, base.queue, testLogger(), adapter, nil, nil, nil).
		WithLLMToolCompleter(adapter)
	ctx := auth.ContextWithTenantString(context.Background(), adapterTestTenant)
	msgs := []*componentpb.LLMMessage{{Role: "user", Content: "hello"}}

	calls := map[string]func() error{
		"Complete": func() error {
			_, err := svc.Complete(ctx, &componentpb.CompleteRequest{WorkId: "w", Slot: "fast", Messages: msgs})
			return err
		},
		"CompleteStream": func() error {
			//nolint:contextcheck // a server stream carries its context in the stream
			return svc.CompleteStream(&componentpb.CompleteStreamRequest{WorkId: "w", Slot: "fast", Messages: msgs},
				&completeStream{ctx: ctx})
		},
		"CompleteWithTools": func() error {
			_, err := svc.CompleteWithTools(ctx, &componentpb.CompleteWithToolsRequest{WorkId: "w", Slot: "fast", Messages: msgs})
			return err
		},
		"CompleteStructured": func() error {
			_, err := svc.CompleteStructured(ctx, &componentpb.CompleteStructuredRequest{
				WorkId: "w", Slot: "fast", Messages: msgs, SchemaJson: `{"type":"object"}`})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.FailedPrecondition, status.Code(call()))
		})
	}
	assert.Zero(t, prov.calls, "no completion ran")
}

// CompleteStream applies the node pin too.
func TestCompleteStream_UsesTheSlotPinOfTheDispatchingNode(t *testing.T) {
	env := newSlotPinEnv(t)
	env.pinnedProv.streamChunks = []llm.StreamChunk{{Delta: llm.StreamDelta{Content: "ok"}, FinishReason: llm.FinishReasonStop}}
	env.dispatchAgentWork(t, adapterTestTenant, "work-stream-1", fastPin)

	ctx := auth.ContextWithTenantString(context.Background(), adapterTestTenant)
	stream := &completeStream{ctx: ctx}
	require.NoError(t, env.svc.CompleteStream(&componentpb.CompleteStreamRequest{
		WorkId: "work-stream-1", Slot: "fast", Messages: []*componentpb.LLMMessage{{Role: "user", Content: "hello"}},
	}, stream))
	assert.NotEmpty(t, stream.sent)
	assert.Equal(t, 1, env.pinnedProv.calls, "the pinned provider serves the stream")
	assert.Zero(t, env.defaultProv.calls)
}

// brokenClient returns a Redis client whose server is closed, so every call
// fails.
func brokenClient(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	mr.Close()
	return client
}

// brokenStateClient returns a state client whose server is closed.
func brokenStateClient(t *testing.T) *state.StateClient {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	mr.Close()
	return sc
}

// The binding and its lookup report a store failure, a missing binding and a
// bad document each in their own way.
func TestWorkSlotPins_BindAndLookupPaths(t *testing.T) {
	ctx := context.Background()
	pins := map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}

	t.Run("no pins writes nothing", func(t *testing.T) {
		client := brokenClient(t)
		require.NoError(t, bindWorkSlotPins(ctx, client, WorkItem{WorkID: "w"}))
	})
	t.Run("a store failure fails the bind", func(t *testing.T) {
		client := brokenClient(t)
		require.Error(t, bindWorkSlotPins(ctx, client, WorkItem{WorkID: "w", SlotPins: pins}))
	})
	t.Run("a store failure fails the lookup", func(t *testing.T) {
		client := brokenClient(t)
		_, err := lookupWorkSlotPin(ctx, client, "w", "fast")
		require.Error(t, err)
	})

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	t.Run("no work id or no slot is no pin", func(t *testing.T) {
		pin, err := lookupWorkSlotPin(ctx, client, "", "fast")
		require.NoError(t, err)
		assert.Nil(t, pin)
		pin, err = lookupWorkSlotPin(ctx, client, "w", "")
		require.NoError(t, err)
		assert.Nil(t, pin)
	})
	t.Run("no binding is no pin", func(t *testing.T) {
		pin, err := lookupWorkSlotPin(ctx, client, "w-none", "fast")
		require.NoError(t, err)
		assert.Nil(t, pin)
	})
	t.Run("a bad document fails the lookup", func(t *testing.T) {
		require.NoError(t, mr.Set(workSlotsKey("w-bad"), "{not json"))
		_, err := lookupWorkSlotPin(ctx, client, "w-bad", "fast")
		require.Error(t, err)
	})
	t.Run("a bound pin and an unpinned slot", func(t *testing.T) {
		require.NoError(t, bindWorkSlotPins(ctx, client, WorkItem{WorkID: "w-ok", SlotPins: pins}))
		pin, err := lookupWorkSlotPin(ctx, client, "w-ok", "fast")
		require.NoError(t, err)
		assert.Equal(t, &agent.SlotConfig{Provider: "fast-p", Model: "f-large"}, pin)
		pin, err = lookupWorkSlotPin(ctx, client, "w-ok", "primary")
		require.NoError(t, err)
		assert.Nil(t, pin)
	})
}

// A registry that cannot read the owner refuses the completion: the server
// cannot tell whether the node pinned the slot.
func TestNodeSlotPin_AnOwnerReadFailureRefuses(t *testing.T) {
	sc := brokenStateClient(t)
	base := newWorkIDEnv(t)
	svc := NewComponentServiceServer(&noopRegistry{}, base.queue, testLogger(), nil, nil, nil, nil).
		WithWorkContextRegistry(NewRedisWorkContextRegistry(sc))
	pin, err := svc.nodeSlotPin(context.Background(), adapterTestTenant, "w", "fast")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Nil(t, pin)
}

// failingPinRegistry owns every work item and fails each pin read.
type failingPinRegistry struct{ ownEveryWorkItem }

func (failingPinRegistry) WorkSlotPin(context.Context, string, string) (*agent.SlotConfig, error) {
	return nil, assert.AnError
}

// A failed pin read refuses the completion.
func TestNodeSlotPin_APinReadFailureRefuses(t *testing.T) {
	base := newWorkIDEnv(t)
	svc := NewComponentServiceServer(&noopRegistry{}, base.queue, testLogger(), nil, nil, nil, nil).
		WithWorkContextRegistry(failingPinRegistry{ownEveryWorkItem{tenant: adapterTestTenant}})
	pin, err := svc.nodeSlotPin(context.Background(), adapterTestTenant, "w", "fast")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Nil(t, pin)
}

// ResolveMissionForWork resolves the mission of a work item for its owner
// only.
func TestResolveMissionForWork(t *testing.T) {
	broken := brokenStateClient(t)
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	r := NewMissionContextResolver(sc, testLogger())
	ctx := context.Background()

	writeWorkContext(t, mr, "w-own", "mission-1", "acme")
	mr.HSet(workContextKey("w-nomission"), workContextTenantField, "acme")

	for name, tc := range map[string]struct {
		workID, caller, want string
	}{
		"no work id":      {"", "acme", ""},
		"no work context": {"w-none", "acme", ""},
		"no mission":      {"w-nomission", "acme", ""},
		"the owner":       {"w-own", "acme", "mission-1"},
		"another tenant":  {"w-own", "other", ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := r.ResolveMissionForWork(ctx, tc.workID, tc.caller)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("a store failure is an error", func(t *testing.T) {
		_, err := NewMissionContextResolver(broken, nil).ResolveMissionForWork(ctx, "w", "acme")
		require.Error(t, err)
	})
	t.Run("the shim with no resolver", func(t *testing.T) {
		got, err := resolveMissionContext(ctx, nil, "w-own", "acme")
		require.NoError(t, err)
		assert.Empty(t, got)
		got, err = resolveMissionContext(ctx, r, "w-own", "acme")
		require.NoError(t, err)
		assert.Equal(t, "mission-1", got)
	})
}
