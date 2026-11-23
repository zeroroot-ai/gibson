// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
)

const pullTenant = "test-tenant"

// eventTypes records the type of each event that the service publishes.
type eventTypes struct {
	mu  sync.Mutex
	got []string
}

func (e *eventTypes) Publish(_ context.Context, event interface{}) error {
	typ := reflect.ValueOf(event).FieldByName("Type").String()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, typ)
	return nil
}

func (e *eventTypes) has(typ string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, g := range e.got {
		if g == typ {
			return true
		}
	}
	return false
}

// pullEnv is a callback service with the harness of one agent node registered,
// as the daemon registers it when it dispatches agent work through the queue.
type pullEnv struct {
	svc      *HarnessCallbackService
	launch   *launchRecorder
	events   *eventTypes
	captured []capturedTool
	mission  string
	loads    *loadSink
}

type pullOpts struct {
	network   *agent.NodeNetwork
	blocked   []string
	status    string
	noSink    bool
	noHarness bool
}

func newPullEnv(t *testing.T, o pullOpts) *pullEnv {
	t.Helper()
	env := &pullEnv{launch: &launchRecorder{}, events: &eventTypes{}, loads: &loadSink{}}
	exec, err := sandboxed.New(sandboxed.Config{Client: env.launch, SandboxClass: "tool"})
	require.NoError(t, err)
	missionID := types.NewID()
	env.mission = missionID.String()
	object, err := authz.AgentSkillObject(pullTenant, "web-recon")
	require.NoError(t, err)
	h := &DefaultAgentHarness{
		logger:  slog.New(slog.DiscardHandler),
		tracer:  noop.NewTracerProvider().Tracer("test"),
		metrics: &NoOpMetricsRecorder{},
		missionCtx: MissionContext{
			ID: missionID, TenantID: pullTenant, MissionRunID: "run-1", CurrentAgent: "test-agent", TaskID: "task-123",
			NodeNetwork: o.network,
		},
		componentAuthorizer: canExecuteAndLoad{mission: env.mission, skill: object},
		skillStore:          func() SkillFileStore { return &fakeSkillFiles{files: webRecon()} },
		missionDenyList:     func(context.Context, string, string) ([]string, error) { return nil, nil },
		skillLoads:          env.loads.sink2(),
		sandboxedExecutor:   exec,
	}
	registry := NewCallbackHarnessRegistry()
	if !o.noHarness {
		mustRegister(t, registry, env.mission, "test-agent", h)
	}
	status := o.status
	if status == "" {
		status = "active"
	}
	opts := []CallbackServiceOption{
		WithEventBus(env.events),
		WithMissionBlockedTools(func(context.Context, string, string) ([]string, error) { return o.blocked, nil }),
		WithAuthzStore(fakeSearchAuthzStore{state: &RunAuthzState{MissionID: env.mission, UserID: "u", TenantID: pullTenant, Status: status}}),
	}
	if !o.noSink {
		opts = append(opts, WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			env.captured = append(env.captured, capturedTool{tenant: tn, call: call})
		}))
	}
	env.svc = NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, opts...)
	return env
}

func (e *pullEnv) call(t *testing.T) (*pullReply, error) {
	t.Helper()
	ctx := callerCtx(t, "user-42", pullTenant)
	resp, err := e.svc.CallPullTool(ctx, pullTenant, e.mission, "run-1", "test-agent", "task-123", SkillScriptTool,
		[]byte(`{"target":"web-recon/scripts/probe.sh"}`))
	if err != nil {
		return nil, err
	}
	return &pullReply{code: resp.GetError().GetCode(), message: resp.GetError().GetMessage(), id: resp.GetToolCallId()}, nil
}

type pullReply struct {
	code    commonpb.ErrorCode
	message string
	id      string
}

// B1. The launch of a pull call carries the network scope of the agent node,
// as the call of an agent in callback mode does: the mode and the allow list.
func TestCallPullTool_TheLaunchCarriesTheNetworkOfTheNode(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{Targets: []string{"198.51.100.7:8443"}}})
	_, err := env.call(t)
	require.NoError(t, err)
	got := env.launch.got
	require.Equal(t, sandboxed.NetworkModeAllowList, got.NetworkMode, "a node with a bound target must not get the class default")
	require.Len(t, got.Egress, 1)
	assert.Equal(t, "198.51.100.7", got.Egress[0].Host)
	assert.Equal(t, uint32(8443), got.Egress[0].Port)
	assert.Len(t, got.Files, 3, "the files of the Agent Skill reach the same launch")

	// A node with no bound target has no egress.
	none := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}})
	_, err = none.call(t)
	require.NoError(t, err)
	assert.Equal(t, sandboxed.NetworkModeNone, none.launch.got.NetworkMode)
	assert.Empty(t, none.launch.got.Egress)

	// Only a node that the author marked research is unrestricted.
	research := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{Research: true}})
	_, err = research.call(t)
	require.NoError(t, err)
	assert.Equal(t, sandboxed.NetworkModeExternalOnly, research.launch.got.NetworkMode)
}

// The scope of the node is never guessed. A node whose harness is not
// registered refuses the call and starts no sandbox.
func TestCallPullTool_RefusesWhenTheNodeCannotBeResolved(t *testing.T) {
	env := newPullEnv(t, pullOpts{noHarness: true})
	_, err := env.call(t)
	require.Error(t, err)
	assert.Empty(t, env.launch.got.Image, "no sandbox started")
}

// B2. The deny list of the mission applies, in both spellings, and a refusal
// starts no sandbox. The refusal is an event, and the call is not recorded as a
// run.
func TestCallPullTool_TheDenyListOfTheMissionApplies(t *testing.T) {
	for _, entry := range []string{"skill-script", "native:skill-script"} {
		env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}, blocked: []string{entry}})
		reply, err := env.call(t)
		require.NoError(t, err)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, reply.code, entry)
		assert.Empty(t, env.launch.got.Image, "%s: a blocked tool started a sandbox", entry)
		assert.Eventually(t, func() bool { return env.events.has("tool.call.blocked") }, time.Second, 10*time.Millisecond, entry)
	}
}

// B2. A run that is no longer active starts no sandbox.
func TestCallPullTool_ARunThatEndedStartsNoSandbox(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}, status: "completed"})
	reply, err := env.call(t)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, reply.code)
	assert.Contains(t, reply.message, "not active")
	assert.Empty(t, env.launch.got.Image)
}

// A server with no flight recorder refuses the call before the launch, as the
// connector path does.
func TestCallPullTool_NoFlightRecorderRefusesBeforeTheLaunch(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}, noSink: true})
	reply, err := env.call(t)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, reply.code)
	assert.Empty(t, env.launch.got.Image)
}

// A run of another tenant, and a call with no agent or no run, are refused.
func TestCallPullTool_RefusesAForeignRunAndAnIncompleteCall(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}})
	ctx := callerCtx(t, "user-42", "other-tenant")
	resp, err := env.svc.CallPullTool(ctx, "other-tenant", env.mission, "run-1", "test-agent", "task-123", SkillScriptTool, []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, resp.GetError().GetCode())
	resp, err = env.svc.CallPullTool(callerCtx(t, "user-42", pullTenant), pullTenant, env.mission, "", "test-agent", "", SkillScriptTool, []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetError().GetCode())
	resp, err = env.svc.CallPullTool(callerCtx(t, "user-42", pullTenant), pullTenant, env.mission, "run-1", "", "", SkillScriptTool, []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetError().GetCode())
	assert.Empty(t, env.launch.got.Image)
}

// The call emits the events of a tool call, and the flight recorder record
// names the tool, the run, the id that the reply carries, and the agent.
func TestCallPullTool_EmitsTheEventsAndRecordsTheAgent(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}})
	reply, err := env.call(t) // the launch of the test client fails, so the call fails after the dispatch
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, reply.code)
	assert.Eventually(t, func() bool { return env.events.has("tool.call.started") && env.events.has("tool.call.failed") },
		time.Second, 10*time.Millisecond)
	require.Len(t, env.captured, 1)
	rec := env.captured[0].call
	assert.Equal(t, SkillScriptTool, rec.ToolName)
	assert.Equal(t, "test-agent", rec.Agent, "the record must name the calling agent")
	assert.Equal(t, "run-1", rec.MissionRunID)
	assert.Equal(t, env.mission, rec.MissionID)
	assert.Equal(t, rec.ToolCallID, reply.id, "the reply must carry the id of the record")
	assert.NotEmpty(t, env.loads.got, "the script is a load of the Agent Skill")
}

type errAuthzStore struct{}

func (errAuthzStore) Get(context.Context, string) (*RunAuthzState, error) {
	return nil, assert.AnError
}

// A store that is not wired, and a store that fails, refuse the call before the
// launch.
func TestCallPullTool_RefusesWithoutAReadableRunState(t *testing.T) {
	env := newPullEnv(t, pullOpts{network: &agent.NodeNetwork{}})
	env.svc.authzStore = nil
	reply, err := env.call(t)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, reply.code)

	env.svc.authzStore = errAuthzStore{}
	reply, err = env.call(t)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, reply.code)
	assert.Empty(t, env.launch.got.Image)
}
