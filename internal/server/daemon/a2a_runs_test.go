// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// a2a_runs_test.go drives the A2A run handling of the daemon (gibson#1400) with
// the real a2a-go client against the real handler of the A2A listener, over
// httptest. The listener adds mTLS in front of the handler, and the handler
// reads the caller from the headers that ext-authz sets. The test client sets
// the same headers. The World is a real brain engine with an in-memory
// Timeline. Nothing is faked between the client and the runs.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

const (
	a2aTestTenant  = "acme"
	a2aTestMission = "m1"
	a2aTestRun     = "run-1"
	a2aTestCaller  = "agent:caller"
	a2aTestBank    = "nightly"
)

// a2aCall is the identity that the test client sends. The listener trusts
// these headers, because only the Agent gateway can reach it.
type a2aCall struct {
	tenant, subject, mission, task, agent, bank string
}

// headerTransport sets the trusted caller headers on each request.
type headerTransport struct {
	call a2aCall
	next http.RoundTripper
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	set := func(k, v string) {
		if v != "" {
			r.Header.Set(k, v)
		}
	}
	set("x-gibson-tenant", h.call.tenant)
	set("x-gibson-subject", h.call.subject)
	set("x-gibson-mission", h.call.mission)
	set("x-gibson-task", h.call.task)
	set("x-gibson-route-agent", h.call.agent)
	set("x-gibson-route-bank", h.call.bank)
	resp, err := h.next.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}
	return resp, nil
}

// a2aEnv is a World, a brain executor with one live mission, the runs and the
// handler on an httptest server.
type a2aEnv struct {
	t    *testing.T
	reg  *brain.Registry
	exec *brainExecutor
	jobs *fakeJobStore
	srv  *httptest.Server
}

type a2aNoCards struct{}

func (a2aNoCards) Card(context.Context, string, string) (*a2a.AgentCard, error) {
	return nil, a2aserver.ErrNoCard
}

func newA2AEnv(t *testing.T) *a2aEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	exec := newBrainExecutor(nil, slog.New(slog.DiscardHandler))
	exec.register(a2aTestMission, &missionBinding{runID: a2aTestRun, tenant: a2aTestTenant})
	jobs := newFakeJobStore()
	runs := newA2ARuns(reg, exec, func() (job.Store, error) { return jobs, nil })
	srv := httptest.NewServer(a2aserver.NewHandler(runs, a2aNoCards{}))
	t.Cleanup(srv.Close)
	env := &a2aEnv{t: t, reg: reg, exec: exec, jobs: jobs, srv: srv}

	eng := reg.For(a2aTestTenant)
	eng.Submit(brain.MissionProjected{ID: a2aTestMission, RunID: a2aTestRun, TenantID: a2aTestTenant})
	eng.Tick()
	require.NotEmpty(t, eng.Missions(), "the mission is in the World")
	return env
}

// client returns an a2a-go client that sends the given call identity.
func (e *a2aEnv) client(c a2aCall) *a2aclient.Client {
	e.t.Helper()
	httpClient := &http.Client{Transport: headerTransport{call: c, next: http.DefaultTransport}}
	cl, err := a2aclient.NewFromEndpoints(context.Background(),
		[]*a2a.AgentInterface{a2a.NewAgentInterface(e.srv.URL, a2a.TransportProtocolJSONRPC)},
		a2aclient.WithJSONRPCTransport(httpClient))
	require.NoError(e.t, err)
	e.t.Cleanup(func() { _ = cl.Destroy() })
	return cl
}

// caller is the identity of an agent inside the test mission.
func a2aTestCall(task, agent, bank string) a2aCall {
	return a2aCall{
		tenant: a2aTestTenant, subject: a2aTestCaller, mission: a2aTestMission,
		task: task, agent: agent, bank: bank,
	}
}

// send sends one text message and returns the Task of the reply.
func send(t *testing.T, cl *a2aclient.Client, taskID a2a.TaskID, text string) (*a2a.Task, error) {
	t.Helper()
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(text))
	msg.TaskID = taskID
	res, err := cl.SendMessage(context.Background(), &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		return nil, err //nolint:wrapcheck // the test asserts the client error as it is
	}
	task, ok := res.(*a2a.Task)
	require.True(t, ok, "the reply is a Task, got %T", res)
	return task, nil
}

// fold applies the events that the runs submitted.
func (e *a2aEnv) fold() { e.reg.For(a2aTestTenant).Tick() }

// workOf returns the work item of the mission with the given id.
func (e *a2aEnv) workOf(id string) (brain.WorkSnapshot, bool) {
	return a2aserver.WorkOf(e.reg.For(a2aTestTenant).Work(), a2aTestMission, id)
}

func TestA2ARuns_StartCreatesAnAgentRunAndGetTaskReadsIt(t *testing.T) {
	env := newA2AEnv(t)
	cl := env.client(a2aTestCall("node-task", "scout", ""))

	task, err := send(t, cl, "", "scan the host")
	require.NoError(t, err)
	assert.Equal(t, a2a.TaskStateSubmitted, task.Status.State)
	assert.Equal(t, a2aTestMission, task.ContextID, "the context of a run is the mission")

	// The World has not folded the event yet. The pending entry answers.
	got, err := cl.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.Equal(t, task.ID, got.ID)
	assert.Equal(t, a2a.TaskStateSubmitted, got.Status.State)

	// After the fold, the work item holds the target, the input and the parent.
	env.fold()
	wi, found := env.workOf(string(task.ID))
	require.True(t, found, "the run is a work item of the mission")
	assert.Equal(t, "agent", wi.Kind)
	assert.Equal(t, "scout", wi.Target)
	assert.Equal(t, "scan the host", wi.Input)
	assert.Equal(t, "node-task", wi.ParentID, "the World links the run to the task of the caller")
	assert.Equal(t, a2aTestRun, wi.RunID)

	got, err = cl.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.Equal(t, brain.TaskStateFromWork(wi.State), got.Status.State)
}

func TestA2ARuns_CancelStopsARunOnce(t *testing.T) {
	env := newA2AEnv(t)
	cl := env.client(a2aTestCall("node-task", "scout", ""))
	task, err := send(t, cl, "", "scan the host")
	require.NoError(t, err)

	canceled, err := cl.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.Equal(t, a2a.TaskStateCanceled, canceled.Status.State)

	env.fold()
	wi, found := env.workOf(string(task.ID))
	require.True(t, found)
	assert.Equal(t, brain.WorkCanceled, wi.State, "the World records the state canceled")

	got, err := cl.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.Equal(t, a2a.TaskStateCanceled, got.Status.State)

	// A run in a final state cannot be canceled again.
	_, err = cl.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
	require.Error(t, err)
	assert.True(t, errors.Is(err, a2a.ErrTaskNotCancelable), "got %v", err)
}

// CancelTask stops the dispatch of a run that is running. The dispatch tracks
// the item under its work id, and the work id is the id of the Task.
func TestA2ARuns_CancelStopsTheDispatchOfARunningItem(t *testing.T) {
	env := newA2AEnv(t)
	cl := env.client(a2aTestCall("node-task", "scout", ""))
	task, err := send(t, cl, "", "scan the host")
	require.NoError(t, err)

	running, release := env.exec.trackWork(context.Background(), brain.DispatchRequest{
		WorkID: string(task.ID), MissionID: a2aTestMission, ParentID: "node-task",
	})
	defer release()
	require.NoError(t, running.Err())

	_, err = cl.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.Error(t, running.Err(), "the context of the dispatch ended")
}

func TestA2ARuns_TheDepthLimitRefusesTheNextRun(t *testing.T) {
	env := newA2AEnv(t)
	eng := env.reg.For(a2aTestTenant)

	// A chain of runs. Each run names the task of the one before it as its
	// parent, so the chain is as long as the limit.
	limit := harness.MaxDelegationDepth()
	parent := "node-task"
	var ids []string
	for i := range limit {
		id := "chain-" + string(rune('a'+i))
		ids = append(ids, id)
		eng.Submit(brain.WorkDispatched{
			ID: id, MissionID: a2aTestMission, RunID: a2aTestRun, ItemKind: "agent", Target: "scout", ParentID: parent,
		})
		parent = a2aserver.TaskIDOf(id)
	}
	env.fold()

	// The caller at the end of the chain is at the limit. Its message is refused.
	deep := env.client(a2aTestCall(a2aserver.TaskIDOf(ids[len(ids)-1]), "scout", ""))
	_, err := send(t, deep, "", "one more")
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrUnauthorized)
	assert.Contains(t, err.Error(), "delegation_depth_exceeded")

	// The caller one step up is below the limit. Its message is accepted.
	below := env.client(a2aTestCall(a2aserver.TaskIDOf(ids[len(ids)-2]), "scout", ""))
	task, err := send(t, below, "", "still fine")
	require.NoError(t, err)
	assert.Equal(t, a2a.TaskStateSubmitted, task.Status.State)
}

func TestA2ARuns_ABankMessageOpensAJobWorkItem(t *testing.T) {
	env := newA2AEnv(t)
	cl := env.client(a2aTestCall("node-task", "scout", a2aTestBank))

	task, err := send(t, cl, "", "run the nightly review")
	require.NoError(t, err)

	env.fold()
	wi, found := env.workOf(string(task.ID))
	require.True(t, found)
	assert.Equal(t, workKindBank, wi.Kind)
	assert.Equal(t, a2aTestBank, wi.Target)
	assert.Contains(t, wi.Input, "run the nightly review")
	assert.Contains(t, wi.Input, a2aTestCaller, "the input names the sender, who becomes the opener of the job")
}

func TestA2ARuns_ABankMessageThatNamesAJobSendsTheNextTurn(t *testing.T) {
	env := newA2AEnv(t)
	opened, err := env.jobs.Open(context.Background(), a2aTestTenant, job.OpenInput{
		BankID: a2aTestBank, Spec: &jobpb.JobSpec{Goal: "review"},
		OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: a2aTestCaller},
	})
	require.NoError(t, err)
	cl := env.client(a2aTestCall("node-task", "scout", a2aTestBank))

	task, err := send(t, cl, a2a.TaskID(opened.ID), "and the second file")
	require.NoError(t, err)

	env.fold()
	wi, found := env.workOf(string(task.ID))
	require.True(t, found)
	assert.Equal(t, workKindJobTurn, wi.Kind)
	assert.Equal(t, opened.ID, wi.Target, "the target is the job")
}

func TestA2ARuns_ACallerContinuesOnlyAJobItOpened(t *testing.T) {
	env := newA2AEnv(t)
	other, err := env.jobs.Open(context.Background(), a2aTestTenant, job.OpenInput{
		BankID: a2aTestBank, Spec: &jobpb.JobSpec{Goal: "review"},
		OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: "agent:someone-else"},
	})
	require.NoError(t, err)
	elsewhere, err := env.jobs.Open(context.Background(), a2aTestTenant, job.OpenInput{
		BankID: "another-bank", Spec: &jobpb.JobSpec{Goal: "review"},
		OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: a2aTestCaller},
	})
	require.NoError(t, err)
	cl := env.client(a2aTestCall("node-task", "scout", a2aTestBank))

	for name, id := range map[string]string{
		"a job that another caller opened": other.ID,
		"a job of another bank":            elsewhere.ID,
		"a job that does not exist":        "job-missing",
	} {
		_, err := send(t, cl, a2a.TaskID(id), "next")
		require.Error(t, err, name)
		assert.ErrorIs(t, err, a2a.ErrTaskNotFound, name)
	}
}

func TestA2ARuns_AMessageToAnAgentCannotContinueATask(t *testing.T) {
	env := newA2AEnv(t)
	cl := env.client(a2aTestCall("node-task", "scout", ""))

	_, err := send(t, cl, "some-task", "next")
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrInvalidParams)
}

func TestA2ARuns_ARunOfAnotherMissionIsNotFound(t *testing.T) {
	env := newA2AEnv(t)
	owner := env.client(a2aTestCall("node-task", "scout", ""))
	task, err := send(t, owner, "", "scan the host")
	require.NoError(t, err)
	env.fold()

	// The same tenant, another mission. The caller learns nothing about the run.
	other := a2aTestCall("node-task", "scout", "")
	other.mission = "m2"
	stranger := env.client(other)

	_, err = stranger.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrTaskNotFound)

	_, err = stranger.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrTaskNotFound)

	// The owner is not affected by the attempt.
	got, err := owner.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
	require.NoError(t, err)
	assert.False(t, got.Status.State.Terminal())
}

func TestA2ARuns_ARunOfAnotherTenantIsNotFound(t *testing.T) {
	env := newA2AEnv(t)
	owner := env.client(a2aTestCall("node-task", "scout", ""))
	task, err := send(t, owner, "", "scan the host")
	require.NoError(t, err)

	// The tenant of the caller comes from the headers. The same mission id and
	// the same task id in another tenant find nothing, before and after the fold.
	other := a2aTestCall("node-task", "scout", "")
	other.tenant = "evil"
	stranger := env.client(other)
	for _, folded := range []bool{false, true} {
		if folded {
			env.fold()
			env.reg.For("evil").Tick()
		}
		_, err = stranger.GetTask(context.Background(), &a2a.GetTaskRequest{ID: task.ID})
		require.Error(t, err)
		assert.ErrorIs(t, err, a2a.ErrTaskNotFound, "folded=%v", folded)

		_, err = stranger.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
		require.Error(t, err)
		assert.ErrorIs(t, err, a2a.ErrTaskNotFound, "folded=%v", folded)
	}

	// A message from the other tenant cannot start a run in the mission of the
	// first one: that mission is not known in its World.
	_, err = send(t, stranger, "", "hello")
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrUnauthorized)
}

func TestA2ARuns_AMissionThatIsNotRunningRefusesAMessage(t *testing.T) {
	env := newA2AEnv(t)
	env.exec.unregister(a2aTestMission, mustBinding(t, env.exec))
	cl := env.client(a2aTestCall("node-task", "scout", ""))

	_, err := send(t, cl, "", "scan the host")
	require.Error(t, err)
	assert.ErrorIs(t, err, a2a.ErrUnauthorized)
}

// mustBinding returns the binding of the test mission.
func mustBinding(t *testing.T, exec *brainExecutor) *missionBinding {
	t.Helper()
	bind, ok := exec.get(a2aTestMission)
	require.True(t, ok)
	return bind
}
