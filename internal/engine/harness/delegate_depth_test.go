// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// discardLogger returns a slog.Logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// chainQueue is a work queue fake that records the delegation context of the
// enqueue call. An agent has no in-process path, so the work queue is where
// a test observes what a delegation hands to the agent.
type chainQueue struct {
	queueFake
	chain  []string
	parent string
}

func (q *chainQueue) Enqueue(ctx context.Context, tenant, kind, name string, item component.WorkItem) (string, error) {
	q.chain, _ = contextkeys.GetCallerChain(ctx)
	q.parent, _ = contextkeys.GetParentAgentRunID(ctx)
	return q.queueFake.Enqueue(ctx, tenant, kind, name, item)
}

// newDelegationHarness builds a harness whose agent "zerocool" is a remote
// component on the work queue. The run id and the depth are those of the
// calling agent.
func newDelegationHarness(t *testing.T, q component.WorkQueue, agentRunID string, depth, maxDepth int) *DefaultAgentHarness {
	t.Helper()
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.missionCtx = MissionContext{
		ID:              types.NewID(),
		Name:            "test-mission",
		CurrentAgent:    "test-agent",
		AgentRunID:      agentRunID,
		DelegationDepth: depth,
	}
	h.maxDelegationDepth = maxDepth
	return h
}

func successQueue(t *testing.T) *chainQueue {
	t.Helper()
	return &chainQueue{queueFake: queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}}
}

// TestDelegateToAgent_CallerChainPropagation verifies that A → B → C
// delegation produces caller_chain = [A_run_id, B_run_id] on the dispatch
// to C.
func TestDelegateToAgent_CallerChainPropagation(t *testing.T) {
	task := agent.NewTask("test", "test task", nil)

	// A delegates to B. The dispatch to B sees caller_chain=["run-a"].
	qB := successQueue(t)
	harnessA := newDelegationHarness(t, qB, "run-a", 0, defaultMaxDelegationDepth)
	_, err := harnessA.DelegateToAgent(callerCtx(t, "user-a", "acme"), "zerocool", task)
	require.NoError(t, err)
	assert.Equal(t, []string{"run-a"}, qB.chain, "chain on B should contain A's run ID")
	assert.Equal(t, "run-a", qB.parent, "B's parent run ID should be A")

	// B (depth=1, run_id="run-b") delegates to C with the A→B chain in its
	// context, as DelegateToAgent sets it.
	ctxWithChain := contextkeys.WithCallerChain(callerCtx(t, "user-b", "acme"), []string{"run-a"})
	ctxWithChain = contextkeys.WithParentAgentRunID(ctxWithChain, "run-a")
	qC := successQueue(t)
	harnessB := newDelegationHarness(t, qC, "run-b", 1, defaultMaxDelegationDepth)
	_, err = harnessB.DelegateToAgent(ctxWithChain, "zerocool", task)
	require.NoError(t, err)
	assert.Equal(t, []string{"run-a", "run-b"}, qC.chain, "chain on C should contain A then B")
	assert.Equal(t, "run-b", qC.parent, "C's parent run ID should be B")
}

// TestDelegateToAgent_DepthCapReturnsError verifies that delegating when the
// current DelegationDepth equals or exceeds maxDelegationDepth returns an error
// whose message contains "delegation_depth_exceeded".
func TestDelegateToAgent_DepthCapReturnsError(t *testing.T) {
	// maxDepth=8, currentDepth=8 → the next hop must be rejected.
	const maxDepth = 8
	q := successQueue(t)
	harnessAtCap := newDelegationHarness(t, q, "run-x", maxDepth, maxDepth)

	_, err := harnessAtCap.DelegateToAgent(callerCtx(t, "user-x", "acme"), "zerocool", agent.NewTask("test", "test task", nil))

	require.Error(t, err, "expected delegation_depth_exceeded error")
	assert.True(t,
		strings.Contains(err.Error(), "delegation_depth_exceeded"),
		"error message should contain delegation_depth_exceeded, got: %s", err.Error(),
	)
	assert.Empty(t, q.gotName, "no work may be enqueued when the depth cap is exceeded")
}

// TestDelegateToAgent_DepthCapDefault verifies that a harness with maxDepth=0
// uses defaultMaxDelegationDepth (8) so that depth=8 is still rejected.
func TestDelegateToAgent_DepthCapDefault(t *testing.T) {
	h := newDelegationHarness(t, successQueue(t), "run-x", defaultMaxDelegationDepth, 0 /* use default */)

	_, err := h.DelegateToAgent(callerCtx(t, "user-x", "acme"), "zerocool", agent.NewTask("test", "test task", nil))

	require.Error(t, err, "expected depth-exceeded error with default cap")
	assert.Contains(t, err.Error(), "delegation_depth_exceeded")
}

// TestDelegateToAgent_DepthBelowCap verifies that delegation at depth < maxDepth
// succeeds, and that the child harness gets the next depth.
func TestDelegateToAgent_DepthBelowCap(t *testing.T) {
	// depth=7, maxDepth=8 → should succeed.
	h := newDelegationHarness(t, successQueue(t), "run-near", 7, 8)
	h.callbackManager = &registrarFake{}
	childDepth := -1
	h.factory = func(_ context.Context, mc MissionContext, _ TargetInfo) (AgentHarness, error) {
		childDepth = mc.DelegationDepth
		return h, nil
	}

	_, err := h.DelegateToAgent(callerCtx(t, "user-x", "acme"), "zerocool", agent.NewTask("test", "test task", nil))

	require.NoError(t, err, "delegation at depth 7 (max=8) should succeed")
	assert.Equal(t, 8, childDepth, "the child harness gets the next delegation depth")
}

// TestDelegateToAgent_DELEGATEDTORelationship verifies that a delegation emits a
// run-provenance fact to the World DelegationSink (parent → child run) rather than
// writing the graph directly — the graph projector is the sole writer (ADR-0107,
// gibson#837).
func TestDelegateToAgent_DELEGATEDTORelationship(t *testing.T) {
	const (
		parentRunID = "run-parent"
		childRunID  = "run-child-42"
	)
	h := newDelegationHarness(t, successQueue(t), parentRunID, 0, 8)
	h.callbackManager = &registrarFake{}

	var captured []DelegationObserved
	h.delegationSink = func(_ context.Context, d DelegationObserved) {
		captured = append(captured, d)
	}
	// The factory gives the child harness its own run id.
	h.factory = func(_ context.Context, mc MissionContext, ti TargetInfo) (AgentHarness, error) {
		mc.AgentRunID = childRunID
		return &DefaultAgentHarness{missionCtx: mc, targetInfo: ti, logger: discardLogger()}, nil
	}

	_, err := h.DelegateToAgent(callerCtx(t, "user-parent", "acme"), "zerocool", agent.NewTask("test", "test task", nil))
	require.NoError(t, err)

	require.Len(t, captured, 1, "expected exactly one delegation observation")
	assert.Equal(t, parentRunID, captured[0].ParentRunID)
	assert.Equal(t, childRunID, captured[0].ChildRunID)
	assert.Equal(t, "zerocool", captured[0].ChildAgent)
}

// TestDelegateToAgent_UnknownAgentIsNotFound proves that an agent with no
// sandbox manifest and no work queue instance gets a typed error. No third
// dispatch path exists.
func TestDelegateToAgent_UnknownAgentIsNotFound(t *testing.T) {
	q := successQueue(t)
	h := newRemoteAgentHarness(t, q, nil)

	_, err := h.DelegateToAgent(callerCtx(t, "user-x", "acme"), "no-such-agent", agent.NewTask("test", "test task", nil))

	require.Error(t, err)
	assert.Equal(t, ErrHarnessAgentNotFound, gibsonCode(t, err))
	assert.Empty(t, q.gotName, "no work may be enqueued for an agent that is not registered")
}

// TestDelegateToAgent_PlatformAgentWithNoLauncherIsDenied proves that an agent
// that the platform starts has the sandbox launch only. With no sandbox
// launcher the delegation gets a typed error, even when a work queue instance
// of the same name exists.
func TestDelegateToAgent_PlatformAgentWithNoLauncherIsDenied(t *testing.T) {
	q := successQueue(t)
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.agentDispatchMode = func(string) (string, bool) { return componentcatalog.DispatchModeSandboxed, true }

	_, err := h.DelegateToAgent(callerCtx(t, "user-x", "acme"), "zerocool", agent.NewTask("test", "test task", nil))

	require.Error(t, err)
	assert.Equal(t, types.SANDBOX_POLICY_DENIED, gibsonCode(t, err))
	assert.Empty(t, q.gotName, "a platform agent must not get work from the work queue")
}

// TestDelegateToAgent_RegisteredAgentWithNoWorkQueueIsNotFound proves that a
// registered agent on a daemon with no work queue gets the typed error. The
// daemon has no other way to reach the agent.
func TestDelegateToAgent_RegisteredAgentWithNoWorkQueueIsNotFound(t *testing.T) {
	h := newRemoteAgentHarness(t, nil, remoteAgentInstances())

	_, err := h.DelegateToAgent(callerCtx(t, "user-x", "acme"), "zerocool", agent.NewTask("test", "test task", nil))

	require.Error(t, err)
	assert.Equal(t, ErrHarnessAgentNotFound, gibsonCode(t, err))
}
