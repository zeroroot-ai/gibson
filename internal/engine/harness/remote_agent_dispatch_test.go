// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"errors"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/encoding/protojson"
)

// queueFake records what was enqueued and answers with a canned result, so a
// delegation can be checked end to end without Redis.
type queueFake struct {
	gotTenant string
	gotKind   string
	gotName   string
	gotType   string
	gotItem   component.WorkItem

	result    []byte
	resultErr *component.WorkError
	waitErr   error
}

func (q *queueFake) Enqueue(_ context.Context, tenant, kind, name string, item component.WorkItem) (string, error) {
	q.gotTenant, q.gotKind, q.gotName, q.gotType, q.gotItem = tenant, kind, name, item.WorkType, item
	return "1-0", nil
}

func (q *queueFake) Claim(context.Context, string, string, string, string, time.Duration) (*component.WorkItem, error) {
	return nil, nil
}

func (q *queueFake) DeliverResult(context.Context, string, component.WorkResult) error { return nil }

func (q *queueFake) Acknowledge(context.Context, string, string, string, string) error { return nil }

func (q *queueFake) ReclaimAbandoned(context.Context, string, string, string, time.Duration) error {
	return nil
}

func (q *queueFake) WaitForResult(_ context.Context, workID string, _ time.Duration) (*component.WorkResult, error) {
	if q.waitErr != nil {
		return nil, q.waitErr
	}
	return &component.WorkResult{WorkID: workID, Result: q.result, Error: q.resultErr}, nil
}

func newRemoteAgentHarness(t *testing.T, q component.WorkQueue, instances []component.ComponentInfo) *DefaultAgentHarness {
	t.Helper()
	return &DefaultAgentHarness{
		logger:              slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:              noop.NewTracerProvider().Tracer("test"),
		metrics:             &NoOpMetricsRecorder{},
		componentRegistry:   &gateFakeRegistry{tenantInstances: instances},
		workQueue:           q,
		componentAuthorizer: &recordingAuthorizer{allow: true},
	}
}

func remoteAgentInstances() []component.ComponentInfo {
	// No grpc_endpoint: the off-cluster case, reachable only by work queue.
	return []component.ComponentInfo{{Kind: "agent", Name: "zerocool", InstanceID: "i1"}}
}

func executeResponseJSON(t *testing.T, r *agentpb.ExecuteResponse) []byte {
	t.Helper()
	b, err := protojson.Marshal(r)
	if err != nil {
		t.Fatalf("marshal ExecuteResponse: %v", err)
	}
	return b
}

func TestDelegateToAgent_DispatchesToRemoteComponentOverTheWorkQueue(t *testing.T) {
	// The regression this guards: work was enqueued for tools and plugins only,
	// so a component registered as kind=agent polled an empty stream forever
	// (gibson#1197).
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	task := agent.NewTask("probe", "Fetch https://google.com", nil)
	task.Goal = "Fetch https://google.com"
	res, err := h.DelegateToAgent(ctx, "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}

	if q.gotKind != "agent" || q.gotType != "agent_execute" {
		t.Errorf("enqueued kind/work_type = %q/%q, want agent/agent_execute", q.gotKind, q.gotType)
	}
	if q.gotTenant != "zerocool-lab" || q.gotName != "zerocool" {
		t.Errorf("enqueued tenant/name = %q/%q", q.gotTenant, q.gotName)
	}
	if res.TaskID != task.ID {
		t.Errorf("result task id = %v, want %v", res.TaskID, task.ID)
	}
	if res.Status != agent.ResultStatusCompleted {
		t.Errorf("result status = %v, want the remote agent's success", res.Status)
	}

	// The payload must be the same ExecuteRequest an in-cluster gRPC agent gets,
	// so one implementation serves both transports.
	req := &agentpb.ExecuteRequest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(q.gotItem.Payload, req); err != nil {
		t.Fatalf("payload is not an ExecuteRequest: %v", err)
	}
	if got := req.GetTask().GetGoal(); got != "Fetch https://google.com" {
		t.Errorf("dispatched goal = %q, want the task's", got)
	}
}

func TestDelegateToAgent_RemoteErrorFailsTheDelegation(t *testing.T) {
	// A remote agent reporting failure must fail the node with its own reason;
	// swallowing it would leave the mission looking successful.
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Error: &commonpb.Error{Code: "TOOL_MISSING", Message: "no http tool available"},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil {
		t.Fatal("expected an error when the remote agent reports one")
	}
	if !strings.Contains(err.Error(), "no http tool available") {
		t.Errorf("error = %v, want the remote agent's message", err)
	}
}

func TestDelegateToAgent_QueueFailureIsReported(t *testing.T) {
	q := &queueFake{waitErr: errors.New("result wait timed out")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err == nil {
		t.Fatal("expected an error when the work queue never answers")
	}
}

func TestRemoteAgentInstance_LeavesDirectGRPCAgentsToTheAdapter(t *testing.T) {
	// An agent that advertises its own endpoint is dialled directly; queueing it
	// would put a second, slower path in front of a reachable component.
	q := &queueFake{}
	h := newRemoteAgentHarness(t, q, []component.ComponentInfo{{
		Kind: "agent", Name: "zerocool", InstanceID: "i1",
		Metadata: map[string]string{"grpc_endpoint": "zerocool:50052"},
	}})
	if _, found := h.remoteAgentInstance(context.Background(), "zerocool-lab", "zerocool"); found {
		t.Fatal("a gRPC-reachable agent must not be routed over the work queue")
	}
}

func TestRemoteAgentInstance_RequiresATenantAndAQueue(t *testing.T) {
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	if _, found := h.remoteAgentInstance(context.Background(), "", "zerocool"); found {
		t.Error("no tenant must not resolve a remote agent")
	}

	h.workQueue = nil
	if _, found := h.remoteAgentInstance(context.Background(), "zerocool-lab", "zerocool"); found {
		t.Error("no work queue must not resolve a remote agent")
	}
}

func TestRemoteAgentInstance_NoRegisteredComponentFallsThrough(t *testing.T) {
	// Nothing registered is the in-process case: the caller must keep going to
	// the registry-adapter path rather than fail.
	h := newRemoteAgentHarness(t, &queueFake{}, nil)
	if _, found := h.remoteAgentInstance(context.Background(), "zerocool-lab", "local-agent"); found {
		t.Fatal("expected no remote instance")
	}
}

// --- quota bookkeeping -------------------------------------------------------

// quotaSpy counts the concurrent_agents increments and decrements.
type quotaSpy struct {
	inc, dec int
	incErr   error
	decErr   error
}

func (q *quotaSpy) IncrementAgentCount(context.Context) error {
	q.inc++
	return q.incErr
}

func (q *quotaSpy) DecrementAgentCount(context.Context) error {
	q.dec++
	return q.decErr
}

func (q *quotaSpy) IncrementMissionCount(context.Context) error { return nil }
func (q *quotaSpy) DecrementMissionCount(context.Context) error { return nil }

func TestTrackInFlightAgent_CountsTheAgentOnceWhileItRuns(t *testing.T) {
	// A remote agent must count against the tenant's concurrent_agents quota
	// exactly like a local one — the seam is a transport choice, not a loophole.
	spy := &quotaSpy{}
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	h.quotaCounter = spy

	release := h.trackInFlightAgent(context.Background(), "zerocool")
	if spy.inc != 1 {
		t.Fatalf("increments = %d, want 1 on the 0→1 transition", spy.inc)
	}
	if spy.dec != 0 {
		t.Errorf("decremented while the agent is still running")
	}
	release()
	if spy.dec != 1 {
		t.Errorf("decrements = %d, want 1 when the last one finishes", spy.dec)
	}
}

func TestTrackInFlightAgent_OnlyTheEdgesCount(t *testing.T) {
	// Two concurrent delegations to the SAME agent are one occupied slot: the
	// counter moves on 0→1 and 1→0, not on every call, or the quota drifts up
	// and never comes back.
	spy := &quotaSpy{}
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	h.quotaCounter = spy

	releaseA := h.trackInFlightAgent(context.Background(), "zerocool")
	releaseB := h.trackInFlightAgent(context.Background(), "zerocool")
	if spy.inc != 1 {
		t.Errorf("increments = %d, want 1 for two concurrent delegations", spy.inc)
	}

	releaseA()
	if spy.dec != 0 {
		t.Errorf("decremented while one delegation is still in flight")
	}
	releaseB()
	if spy.dec != 1 {
		t.Errorf("decrements = %d, want 1 once the last finishes", spy.dec)
	}
}

func TestTrackInFlightAgent_QuotaErrorsDoNotBlockDelegation(t *testing.T) {
	// The counter is bookkeeping. A Redis blip must not stop an agent running,
	// and must not leave the release path unreachable.
	spy := &quotaSpy{incErr: errors.New("redis down"), decErr: errors.New("redis down")}
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	h.quotaCounter = spy

	release := h.trackInFlightAgent(context.Background(), "zerocool")
	release()
	if spy.inc != 1 || spy.dec != 1 {
		t.Errorf("inc=%d dec=%d, want both attempted despite the errors", spy.inc, spy.dec)
	}
}

func TestTrackInFlightAgent_NoCounterIsANoOp(t *testing.T) {
	// quotaCounter is optional; a nil one must not panic on either edge.
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	h.quotaCounter = nil
	h.trackInFlightAgent(context.Background(), "zerocool")()
}

func TestDelegateToAgent_CountsAgainstTheQuota(t *testing.T) {
	// End to end: the work-queue path takes and releases a slot.
	spy := &quotaSpy{}
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.quotaCounter = spy

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if spy.inc != 1 || spy.dec != 1 {
		t.Errorf("inc=%d dec=%d, want the slot taken and released", spy.inc, spy.dec)
	}
}

func TestDelegateToAgent_MalformedResultIsReported(t *testing.T) {
	// A component answering with something that is not an ExecuteResponse fails
	// the delegation rather than yielding an empty Result that reads as success.
	q := &queueFake{result: []byte(`{"result": "not a message"`)}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err == nil {
		t.Fatal("expected an error for an undecodable result")
	}
}

func TestRemoteAgentInstance_DiscoveryErrorFallsThrough(t *testing.T) {
	// A registry that cannot answer must not fail the delegation outright — the
	// in-process registry adapter is still a valid way to resolve the agent.
	h := newRemoteAgentHarness(t, &queueFake{}, nil)
	h.componentRegistry = &erroringRegistry{}
	if _, found := h.remoteAgentInstance(context.Background(), "acme", "zerocool"); found {
		t.Fatal("a discovery error must not resolve a remote instance")
	}
}

// erroringRegistry fails Discover.
type erroringRegistry struct{ gateFakeRegistry }

func (r *erroringRegistry) Discover(context.Context, string, string, string) ([]component.ComponentInfo, error) {
	return nil, errors.New("registry unavailable")
}

// registrarFake records callback-harness registrations (gibson#1633).
type registrarFake struct {
	registered   []string // "<mission>|<agent>"
	unregistered []string
}

func (r *registrarFake) RegisterHarnessForMission(missionID, agentName string, _ any) string {
	r.registered = append(r.registered, missionID+"|"+agentName)
	return "key-" + agentName
}
func (r *registrarFake) UnregisterHarness(key string) { r.unregistered = append(r.unregistered, key) }

// TestDelegateToAgent_QueueDispatchRegistersTheCallbackHarness: while a
// queue-dispatched agent runs, its harness is registered under
// (mission, agent) so Observe/SubmitFinding from the off-cluster agent resolve;
// it is unregistered when the work item completes.
func TestDelegateToAgent_QueueDispatchRegistersTheCallbackHarness(t *testing.T) {
	reg := &registrarFake{}
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.callbackManager = reg
	h.missionCtx.ID = types.NewID()
	var childAgent string
	h.factory = func(_ context.Context, mc MissionContext, _ TargetInfo) (AgentHarness, error) {
		childAgent = mc.CurrentAgent
		return h, nil
	}
	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	want := h.missionCtx.ID.String() + "|zerocool"
	if len(reg.registered) != 1 || reg.registered[0] != want {
		t.Fatalf("registered = %v, want [%s]", reg.registered, want)
	}
	if childAgent != "zerocool" {
		t.Errorf("child harness CurrentAgent = %q, want zerocool", childAgent)
	}
	if len(reg.unregistered) != 1 || reg.unregistered[0] != "key-zerocool" {
		t.Errorf("unregistered = %v, want [key-zerocool]", reg.unregistered)
	}
}

// TestDelegateToAgent_QueueDispatchWithoutRegistrarStillDispatches: no
// callback manager wired (tests, minimal daemons) is not an error.
func TestDelegateToAgent_QueueDispatchWithoutRegistrarStillDispatches(t *testing.T) {
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	if _, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
}

// TestDelegateToAgent_QueueDispatchChildHarnessFailureIsReported: when the
// child harness for the queue-dispatched agent cannot be built, the delegation
// fails loudly and nothing is enqueued or registered.
func TestDelegateToAgent_QueueDispatchChildHarnessFailureIsReported(t *testing.T) {
	reg := &registrarFake{}
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.callbackManager = reg
	h.missionCtx.ID = types.NewID()
	h.factory = func(context.Context, MissionContext, TargetInfo) (AgentHarness, error) {
		return nil, errors.New("factory down")
	}
	_, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil || !strings.Contains(err.Error(), "child harness") {
		t.Fatalf("err = %v, want a child-harness failure", err)
	}
	if len(reg.registered) != 0 || q.gotName != "" {
		t.Errorf("registered=%v enqueued=%q, want nothing", reg.registered, q.gotName)
	}
}
