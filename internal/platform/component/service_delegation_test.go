// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_delegation_test.go covers DelegateToAgent (gibson#1186 slice C),
// the hard-cut replacement for the interim FailedPrecondition stub #1201
// shipped. Two concerns get separate coverage:
//
//   - the capability gate (capname.MissionDelegate) — every branch of
//     requireCapability, including the fail-closed nil-checker path, which is
//     exactly the kind of guard that has silently no-op'd before in this
//     codebase (see capability_gate.go's doc comment). A mutation that flips
//     the nil-check, drops the error check, or swaps PermissionDenied for a
//     softer code must turn one of these red.
//   - the dispatch round-trip once the gate passes — real Redis-backed
//     WorkQueue (miniredis) + a stand-in "remote agent" goroutine, mirroring
//     work_id_tenant_test.go's TestCallTool_WaitsOnTheWorkIdTheComponentEchoesBack
//     exactly, because DelegateToAgent uses the identical Enqueue/WaitForResult
//     shape against kind="agent" instead of kind="tool".

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// capCheckCall records one HasCapability invocation for assertions on what
// requireCapability actually asked.
type capCheckCall struct {
	tenant, principal, capability string
}

// mockCapabilityChecker implements CapabilityChecker.
type mockCapabilityChecker struct {
	granted map[string]bool
	// grantID overrides the id ActiveGrantID reports for a granted
	// capability. Left empty, the mock synthesises one — a granted
	// capability must never answer with an empty id, because empty IS the
	// denial.
	grantID string
	err     error
	calls   []capCheckCall
}

func (m *mockCapabilityChecker) ActiveGrantID(_ context.Context, tenant, principal, capability string) (string, error) {
	m.calls = append(m.calls, capCheckCall{tenant: tenant, principal: principal, capability: capability})
	if m.err != nil {
		return "", m.err
	}
	if !m.granted[capability] {
		return "", nil
	}
	if m.grantID != "" {
		return m.grantID, nil
	}
	return "grant-" + capability, nil
}

// countingRegistry wraps noopRegistry to prove Discover was never reached —
// used to pin that a denied capability check short-circuits BEFORE any
// dispatch work happens, not just that it eventually returns an error.
type countingRegistry struct {
	noopRegistry
	discoverCalls int
}

func (r *countingRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	r.discoverCalls++
	return nil, nil
}

// grantedChecker is a one-line convenience for the tests that only care that
// capname.MissionDelegate is granted.
func grantedChecker() *mockCapabilityChecker {
	return &mockCapabilityChecker{granted: map[string]bool{capname.MissionDelegate: true}}
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

func TestDelegateToAgent_MissingTenant(t *testing.T) {
	svc := newParityServer()

	_, err := svc.DelegateToAgent(context.Background(), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDelegateToAgent_MissingAgentName(t *testing.T) {
	svc := newParityServer()

	_, err := svc.DelegateToAgent(tenantCtx(), &componentpb.DelegateToAgentRequest{
		TaskJson: []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDelegateToAgent_MissingTaskJSON(t *testing.T) {
	svc := newParityServer()

	_, err := svc.DelegateToAgent(tenantCtx(), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// Capability gate (capname.MissionDelegate)
// ---------------------------------------------------------------------------

// TestDelegateToAgent_NilCapabilityChecker_FailsClosed pins the single most
// important line in capability_gate.go: an unwired checker must deny, never
// silently allow. This is the exact shape of guard that has previously gone
// dark in this codebase without a test that would catch it (see
// project_gibson_guards_that_cannot_fail).
func TestDelegateToAgent_NilCapabilityChecker_FailsClosed(t *testing.T) {
	reg := &countingRegistry{}
	svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
	// capabilityChecker deliberately left nil.

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Zero(t, reg.discoverCalls, "a request that cannot be authorized must never reach discovery/dispatch")
}

func TestDelegateToAgent_CapabilityNotGranted_Denies(t *testing.T) {
	reg := &countingRegistry{}
	checker := &mockCapabilityChecker{granted: map[string]bool{}} // explicitly empty
	svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithCapabilityChecker(checker)

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Zero(t, reg.discoverCalls, "a denied capability must never reach discovery/dispatch")
}

func TestDelegateToAgent_CapabilityCheckError_DeniesAsInternal(t *testing.T) {
	checker := &mockCapabilityChecker{err: errors.New("postgres: connection refused")}
	svc := newParityServer().WithCapabilityChecker(checker)

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDelegateToAgent_NoIdentityOnContext_Unauthenticated(t *testing.T) {
	svc := newParityServer().WithCapabilityChecker(grantedChecker())

	// tenantCtx() stamps a tenant but no identity — the shape ext-authz would
	// never actually produce, but the handler must not trust an absent
	// Subject either way.
	_, err := svc.DelegateToAgent(tenantCtx(), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestDelegateToAgent_ChecksExactCapabilityAndCaller pins WHAT is checked, not
// just that something is: the wrong capability name or the wrong principal
// would silently authorize a different grant than the one that actually
// covers this call.
func TestDelegateToAgent_ChecksExactCapabilityAndCaller(t *testing.T) {
	checker := &mockCapabilityChecker{granted: map[string]bool{}}
	svc := newParityServer().WithCapabilityChecker(checker)

	_, _ = svc.DelegateToAgent(componentCtx("agent_principal:acct-77"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Len(t, checker.calls, 1)
	assert.Equal(t, "test-tenant", checker.calls[0].tenant)
	assert.Equal(t, "agent_principal:acct-77", checker.calls[0].principal)
	assert.Equal(t, capname.MissionDelegate, checker.calls[0].capability,
		"DelegateToAgent must check mission:delegate, never mission:originate")
}

// ---------------------------------------------------------------------------
// Past the gate: discovery and input parsing
// ---------------------------------------------------------------------------

// erroringRegistry fails every Discover call, for exercising DelegateToAgent's
// discovery-error path (distinct from AgentNotFound's "discovered nothing").
type erroringRegistry struct {
	noopRegistry
	err error
}

func (r *erroringRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return nil, r.err
}

func TestDelegateToAgent_DiscoveryError(t *testing.T) {
	svc := NewComponentServiceServer(
		&erroringRegistry{err: errors.New("redis: connection refused")},
		&noopWorkQueue{}, testLogger(), nil, nil, nil, nil,
	).WithCapabilityChecker(grantedChecker())

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// erroringQueue fails Enqueue, for exercising DelegateToAgent's dispatch-error
// path once the capability gate and discovery both pass.
type erroringQueue struct {
	noopWorkQueue
	err error
}

func (q *erroringQueue) Enqueue(_ context.Context, _, _, _ string, _ WorkItem) (string, error) {
	return "", q.err
}

func TestDelegateToAgent_EnqueueError(t *testing.T) {
	svc := NewComponentServiceServer(
		&dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "inst-agent"}},
		&erroringQueue{err: errors.New("redis: connection refused")},
		testLogger(), nil, nil, nil, nil,
	).WithCapabilityChecker(grantedChecker())

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDelegateToAgent_AgentNotFound(t *testing.T) {
	svc := newParityServer().WithCapabilityChecker(grantedChecker()) // noopRegistry.Discover returns nothing

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "ghost-agent",
		TaskJson:  []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDelegateToAgent_InvalidTaskJSON(t *testing.T) {
	svc := newParityServer().WithCapabilityChecker(grantedChecker())

	_, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  []byte(`not valid json`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// Dispatch round-trip (real Redis-backed WorkQueue)
// ---------------------------------------------------------------------------

// newDelegationEnv wires a ComponentServiceServer with a real miniredis-backed
// WorkQueue and a dispatchRegistry reporting one live "recon-agent" instance,
// exactly the shape work_id_tenant_test.go uses for CallTool's round-trip
// test. granted controls whether capname.MissionDelegate is granted.
func newDelegationEnv(t *testing.T, granted bool) (*ComponentServiceServer, WorkQueue) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	queue := NewRedisWorkQueue(client)
	checker := &mockCapabilityChecker{granted: map[string]bool{capname.MissionDelegate: granted}}
	svc := NewComponentServiceServer(
		&dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "inst-agent"}},
		queue, testLogger(), nil, nil, nil, nil,
	).WithCapabilityChecker(checker)

	return svc, queue
}

// standInAgent claims exactly one work item from queue and replies with
// respond's protojson-encoded WorkResult, exactly as a polling remote agent
// would via PollWork/SubmitResult. It also verifies the payload the handler
// sent is the documented agentpb.ExecuteRequest wire contract, failing the
// channel send if the goal doesn't round-trip — proving the SAME contract
// in-cluster delegation already uses.
func standInAgent(t *testing.T, queue WorkQueue, wantGoal string, respond func(execReq *agentpb.ExecuteRequest) WorkResult) <-chan error {
	t.Helper()
	delivered := make(chan error, 1)
	go func() {
		ctx := context.Background()
		for range 100 {
			item, claimErr := queue.Claim(ctx, "test-tenant", "agent", "recon-agent", "inst-agent", 200*time.Millisecond)
			if claimErr != nil {
				delivered <- claimErr
				return
			}
			if item == nil {
				continue
			}
			if item.WorkType != agentDelegateWorkType {
				delivered <- errors.New("work item did not carry the agent_execute work type")
				return
			}
			var execReq agentpb.ExecuteRequest
			if err := protojson.Unmarshal(item.Payload, &execReq); err != nil {
				delivered <- err
				return
			}
			if execReq.GetTask().GetGoal() != wantGoal {
				delivered <- errors.New("delegated task did not round-trip through agentpb.ExecuteRequest")
				return
			}
			result := respond(&execReq)
			result.WorkID = item.WorkID
			delivered <- queue.DeliverResult(ctx, item.WorkID, result)
			return
		}
		delivered <- errors.New("stand-in agent never claimed a work item")
	}()
	return delivered
}

func TestDelegateToAgent_HappyPath(t *testing.T) {
	svc, queue := newDelegationEnv(t, true)

	delivered := standInAgent(t, queue, "recon 10.0.0.1", func(_ *agentpb.ExecuteRequest) WorkResult {
		execResp := &agentpb.ExecuteResponse{
			Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
		}
		respBytes, err := protojson.Marshal(execResp)
		require.NoError(t, err)
		return WorkResult{Result: respBytes}
	})

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon 10.0.0.1"})
	require.NoError(t, err)

	resp, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  taskJSON,
	})

	require.NoError(t, <-delivered, "the stand-in agent must deliver its result")
	require.NoError(t, err, "DelegateToAgent must observe the result the target agent delivered")
	require.NotNil(t, resp)

	var result agent.Result
	require.NoError(t, json.Unmarshal(resp.ResultJson, &result))
	assert.Equal(t, agent.ResultStatusCompleted, result.Status)
}

// TestDelegateToAgent_TargetReportsBusinessFailure proves a business-level
// failure the target agent reports inside a successful WorkResult (an
// agentpb.ExecuteResponse.Error, not a transport failure) surfaces as a
// FAILED agent.Result in ResultJson, not a gRPC error — the RPC succeeded,
// the delegated task did not, and DelegateToAgentResponse has no dedicated
// error field to carry it any other way.
func TestDelegateToAgent_TargetReportsBusinessFailure(t *testing.T) {
	svc, queue := newDelegationEnv(t, true)

	delivered := standInAgent(t, queue, "recon 10.0.0.1", func(_ *agentpb.ExecuteRequest) WorkResult {
		execResp := &agentpb.ExecuteResponse{
			Error: &commonpb.Error{
				Code:    "AGENT_TIMEOUT",
				Message: "10.0.0.1 did not respond",
			},
		}
		respBytes, err := protojson.Marshal(execResp)
		require.NoError(t, err)
		return WorkResult{Result: respBytes}
	})

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon 10.0.0.1"})
	require.NoError(t, err)

	resp, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  taskJSON,
	})

	require.NoError(t, <-delivered)
	require.NoError(t, err, "a business-level failure must not become a gRPC error")
	require.NotNil(t, resp)

	var result agent.Result
	require.NoError(t, json.Unmarshal(resp.ResultJson, &result))
	assert.Equal(t, agent.ResultStatusFailed, result.Status)
	require.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Message, "10.0.0.1 did not respond")
}

// TestDelegateToAgent_QueueLevelFailure proves a WorkResult.Error (the target
// failed before producing an ExecuteResponse at all — e.g. it could not parse
// the work item) also folds into a FAILED agent.Result rather than crashing on
// a nil protojson unmarshal.
func TestDelegateToAgent_QueueLevelFailure(t *testing.T) {
	svc, queue := newDelegationEnv(t, true)

	delivered := standInAgent(t, queue, "recon 10.0.0.1", func(_ *agentpb.ExecuteRequest) WorkResult {
		return WorkResult{Error: &WorkError{Code: "PARSE_ERROR", Message: "malformed task"}}
	})

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon 10.0.0.1"})
	require.NoError(t, err)

	resp, err := svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  taskJSON,
	})

	require.NoError(t, <-delivered)
	require.NoError(t, err)
	require.NotNil(t, resp)

	var result agent.Result
	require.NoError(t, json.Unmarshal(resp.ResultJson, &result))
	assert.Equal(t, agent.ResultStatusFailed, result.Status)
	require.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Message, "malformed task")
}

// TestDelegateToAgent_TimesOutWhenNoAgentClaimsTheWork proves a target that
// never polls surfaces as DeadlineExceeded rather than hanging the caller
// forever.
func TestDelegateToAgent_TimesOutWhenNoAgentClaimsTheWork(t *testing.T) {
	svc, _ := newDelegationEnv(t, true) // nothing claims the work item

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon 10.0.0.1", Timeout: 50 * time.Millisecond})
	require.NoError(t, err)

	_, err = svc.DelegateToAgent(componentCtx("agent_principal:acct-1"), &componentpb.DelegateToAgentRequest{
		AgentName: "recon-agent",
		TaskJson:  taskJSON,
	})

	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
}
