// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/gibson/internal/infra/types"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/agentwire"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"go.opentelemetry.io/otel/trace/noop"
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
	return []component.ComponentInfo{{Kind: "agent", Name: "zerocool", InstanceID: "i1"}}
}

// taskResultJSON builds the JSON of the A2A Task that a remote agent returns as
// the result of a work item. A nil env gives a Task with no Gibson extension.
func taskResultJSON(t *testing.T, state a2a.TaskState, env *sdkagent.ResultEnvelope, text string) []byte {
	t.Helper()
	task := &a2a.Task{ID: a2a.NewTaskID(), ContextID: "ctx-1", Status: a2a.TaskStatus{State: state}}
	if text != "" {
		task.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, task, a2a.NewTextPart(text))
	}
	if env != nil {
		task.SetMeta(sdkagent.ExtensionKey, *env)
	}
	b, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal the a2a task: %v", err)
	}
	return b
}

func TestDelegateToAgent_DispatchesToRemoteComponentOverTheWorkQueue(t *testing.T) {
	// The regression this guards: work was enqueued for tools and plugins only,
	// so a component registered as kind=agent polled an empty stream forever
	// (gibson#1197).
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateCompleted, nil, "")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.missionCtx.MissionRunID = "run-7"
	h.missionCtx.AgentRunID = "agent-run-3"

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	task := agent.NewTask("probe", "Fetch https://google.com")
	task.Goal = "Fetch https://google.com"
	res, err := h.DelegateToAgent(ctx, "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}

	if q.gotKind != "agent" || q.gotType != agentwire.WorkType {
		t.Errorf("enqueued kind/work_type = %q/%q, want agent/execute", q.gotKind, q.gotType)
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

	// The payload is one A2A message with the Gibson run context in the
	// extension metadata, so one implementation serves each transport.
	var msg a2a.Message
	if err := json.Unmarshal(q.gotItem.Payload, &msg); err != nil {
		t.Fatalf("payload is not an a2a message: %v", err)
	}
	if got := msg.Parts[0].Text(); got != "Fetch https://google.com" {
		t.Errorf("dispatched goal = %q, want the task's", got)
	}
	if string(msg.TaskID) != task.ID.String() {
		t.Errorf("message task id = %q, want %q", msg.TaskID, task.ID)
	}
	// The run travels in the message, so the agent sends it on its callbacks.
	raw, err := json.Marshal(msg.Metadata[sdkagent.ExtensionKey])
	if err != nil {
		t.Fatalf("encode the extension: %v", err)
	}
	var env sdkagent.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode the extension: %v", err)
	}
	if env.MissionRunID != "run-7" || env.AgentRunID != "agent-run-3" {
		t.Errorf("run ids = %q/%q, want run-7/agent-run-3", env.MissionRunID, env.AgentRunID)
	}
}

func TestDelegateToAgent_RemoteErrorFailsTheDelegation(t *testing.T) {
	// A remote agent reporting failure must fail the node with its own reason;
	// swallowing it would leave the mission looking successful.
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateFailed, &sdkagent.ResultEnvelope{
		Error: &sdkagent.ResultError{Code: "TOOL_MISSING", Message: "no http tool available"},
	}, "no http tool available")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal"))
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
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal")); err == nil {
		t.Fatal("expected an error when the work queue never answers")
	}
}

func TestRemoteAgentInstance_ReportedEndpointSelectsNothing(t *testing.T) {
	// The daemon dials no address that an instance reports. An agent that
	// advertises an endpoint gets its work from the work queue like any other.
	q := &queueFake{}
	h := newRemoteAgentHarness(t, q, []component.ComponentInfo{{
		Kind: "agent", Name: "zerocool", InstanceID: "i1",
		Metadata: map[string]string{"grpc_endpoint": "zerocool:50052"},
	}})
	if _, found := h.remoteAgentInstance(context.Background(), "zerocool-lab", "zerocool"); !found {
		t.Fatal("an agent that reports an endpoint must still take the work queue")
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
	// Nothing registered: the caller reports that the agent was not found.
	h := newRemoteAgentHarness(t, &queueFake{}, nil)
	if _, found := h.remoteAgentInstance(context.Background(), "zerocool-lab", "local-agent"); found {
		t.Fatal("expected no remote instance")
	}
}

func TestDelegateToAgent_MalformedResultIsReported(t *testing.T) {
	// A component answering with something that is not an A2A Task fails
	// the delegation rather than yielding an empty Result that reads as success.
	q := &queueFake{result: []byte(`{"result": "not a message"`)}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal")); err == nil {
		t.Fatal("expected an error for an undecodable result")
	}
}

func TestRemoteAgentInstance_DiscoveryErrorFallsThrough(t *testing.T) {
	// A registry that cannot answer must not fail the delegation outright — the
	// caller then reports that the agent was not found.
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

func (r *registrarFake) RegisterHarnessForMission(missionID, agentName string, _ any) (string, error) {
	r.registered = append(r.registered, missionID+"|"+agentName)
	return "key-" + agentName, nil
}
func (r *registrarFake) UnregisterHarness(key string) { r.unregistered = append(r.unregistered, key) }

// TestDelegateToAgent_QueueDispatchRegistersTheCallbackHarness: while a
// queue-dispatched agent runs, its harness is registered under
// (mission, agent) so Observe/SubmitFinding from the off-cluster agent resolve;
// it is unregistered when the work item completes.
func TestDelegateToAgent_QueueDispatchRegistersTheCallbackHarness(t *testing.T) {
	reg := &registrarFake{}
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateCompleted, nil, "")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.callbackManager = reg
	h.missionCtx.ID = types.NewID()
	var childAgent string
	h.factory = func(_ context.Context, mc MissionContext, _ TargetInfo) (AgentHarness, error) {
		childAgent = mc.CurrentAgent
		return h, nil
	}
	ctx := callerCtx(t, "user-remote", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal")); err != nil {
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
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateCompleted, nil, "")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	if _, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal")); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
}

// TestDelegateToAgent_QueueDispatchChildHarnessFailureIsReported: when the
// child harness for the queue-dispatched agent cannot be built, the delegation
// fails loudly and nothing is enqueued or registered.
func TestDelegateToAgent_QueueDispatchChildHarnessFailureIsReported(t *testing.T) {
	reg := &registrarFake{}
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateCompleted, nil, "")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.callbackManager = reg
	h.missionCtx.ID = types.NewID()
	h.factory = func(context.Context, MissionContext, TargetInfo) (AgentHarness, error) {
		return nil, errors.New("factory down")
	}
	_, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal"))
	if err == nil || !strings.Contains(err.Error(), "child harness") {
		t.Fatalf("err = %v, want a child-harness failure", err)
	}
	if len(reg.registered) != 0 || q.gotName != "" {
		t.Errorf("registered=%v enqueued=%q, want nothing", reg.registered, q.gotName)
	}
}

// A child harness with no mission run is refused by the callback manager. The
// delegation then fails and nothing is enqueued: an agent that runs with no
// registered harness would find no harness for its callbacks (gibson#1217).
func TestDelegateToAgent_QueueDispatchRefusedRegistrationStopsTheWork(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{
		ListenAddress:  "127.0.0.1:0",
		ServiceOptions: []CallbackServiceOption{testEventBus()},
	}, slog.New(slog.DiscardHandler))
	q := &queueFake{result: taskResultJSON(t, a2a.TaskStateCompleted, nil, "")}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())
	h.callbackManager = m
	h.missionCtx.ID = types.NewID() // and no MissionRunID
	h.factory = func(context.Context, MissionContext, TargetInfo) (AgentHarness, error) { return h, nil }

	_, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", agent.NewTask("probe", "goal"))
	var gerr *types.GibsonError
	if !errors.As(err, &gerr) || gerr.Code != ErrHarnessDelegationFailed || !errors.Is(err, ErrHarnessWithoutRun) {
		t.Fatalf("err = %v, want a delegation failure caused by a harness with no run", err)
	}
	if q.gotName != "" {
		t.Errorf("enqueued %q, want nothing", q.gotName)
	}
	if m.registry.Count() != 0 {
		t.Errorf("registry holds %d harnesses, want 0", m.registry.Count())
	}
}
