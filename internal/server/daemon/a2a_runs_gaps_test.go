// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
)

// brokenWorldRuns is a runs value over a registry whose store always fails, so
// the World of each tenant is not available.
func brokenWorldRuns(t *testing.T) *a2aRuns {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, func(context.Context, string) (brain.TimelineStore, error) {
		return nil, errors.New("the timeline store is down")
	})
	return newA2ARuns(reg, newBrainExecutor(nil, nil), func() (job.Store, error) { return newFakeJobStore(), nil })
}

func a2aTestCaller1() a2aserver.Caller {
	return a2aserver.Caller{Tenant: a2aTestTenant, Subject: a2aTestCaller, Mission: a2aTestMission, Task: "node-task"}
}

func TestA2ARuns_ATenantWithNoWorldIsRefusedAndNotFound(t *testing.T) {
	runs := brokenWorldRuns(t)
	ctx := context.Background()
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))

	_, err := runs.Start(ctx, a2aserver.StartRequest{
		Caller: a2aTestCaller1(), Route: a2aserver.Route{Agent: "scout"}, Message: msg,
	})
	require.ErrorIs(t, err, a2aserver.ErrRefused)

	_, err = runs.Task(ctx, a2aTestCaller1(), "t1")
	require.ErrorIs(t, err, a2aserver.ErrNotFound)

	_, err = runs.Cancel(ctx, a2aTestCaller1(), "t1")
	require.ErrorIs(t, err, a2aserver.ErrNotFound)
}

func TestA2ARuns_AMissionThatIsNotInTheWorldIsRefused(t *testing.T) {
	env := newA2AEnv(t)
	runs := newA2ARuns(env.reg, env.exec, func() (job.Store, error) { return env.jobs, nil })
	caller := a2aTestCaller1()
	caller.Mission = "ghost"
	env.exec.register("ghost", &missionBinding{runID: "run-g", tenant: a2aTestTenant})

	_, err := runs.Start(context.Background(), a2aserver.StartRequest{
		Caller: caller, Route: a2aserver.Route{Agent: "scout"},
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi")),
	})
	require.ErrorIs(t, err, a2aserver.ErrRefused)
	assert.Contains(t, err.Error(), "the mission is not")
}

// A mission that is done runs no more work. A new message is refused, and a run
// that it started cannot be canceled, since the cancel needs a running mission.
func TestA2ARuns_AMissionThatIsDoneTakesNoNewWorkAndNoCancel(t *testing.T) {
	env := newA2AEnv(t)
	runs := newA2ARuns(env.reg, env.exec, func() (job.Store, error) { return env.jobs, nil })
	ctx := context.Background()
	caller := a2aTestCaller1()
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("scan"))

	task, err := runs.Start(ctx, a2aserver.StartRequest{Caller: caller, Route: a2aserver.Route{Agent: "scout"}, Message: msg})
	require.NoError(t, err)
	env.fold()

	eng := env.reg.For(a2aTestTenant)
	eng.Submit(brain.MissionDone{ID: a2aTestMission, RunID: a2aTestRun, Outcome: brain.MissionCompleted})
	eng.Tick()

	_, err = runs.Start(ctx, a2aserver.StartRequest{Caller: caller, Route: a2aserver.Route{Agent: "scout"}, Message: msg})
	require.ErrorIs(t, err, a2aserver.ErrRefused)
	assert.Contains(t, err.Error(), "the mission is not running")

	_, err = runs.Cancel(ctx, caller, task.ID)
	require.ErrorIs(t, err, a2aserver.ErrRefused)
}

func TestA2ARuns_ABankTurnNeedsTheJobStore(t *testing.T) {
	env := newA2AEnv(t)
	storeErr := errors.New("the data pool is not up")
	runs := newA2ARuns(env.reg, env.exec, func() (job.Store, error) { return nil, storeErr })
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("next"))
	msg.TaskID = "job-a"

	_, _, _, err := runs.target(context.Background(), a2aTestCaller1(), a2aserver.Route{Agent: "a", Bank: "b"}, msg)
	require.ErrorIs(t, err, storeErr)
	assert.Contains(t, err.Error(), "job store")
}

func TestA2ARuns_APendingEntryThatExpiredIsDroppedAndNotServed(t *testing.T) {
	runs := newA2ARuns(brain.NewRegistry(context.Background(), braintest.StoreFactory()), newBrainExecutor(nil, nil),
		func() (job.Store, error) { return newFakeJobStore(), nil })
	caller := a2aTestCaller1()
	old := a2aPending{tenant: caller.Tenant, mission: caller.Mission, target: "scout", at: time.Now().Add(-2 * a2aPendingTTL)}
	runs.pending["old"] = old
	assert.False(t, runs.isPending("old", caller), "an entry past its time is not pending")

	runs.remember("new", a2aPending{tenant: caller.Tenant, mission: caller.Mission, target: "scout", at: time.Now()})
	_, stillThere := runs.pending["old"]
	assert.False(t, stillThere, "remember drops the entries past their time")
	assert.True(t, runs.isPending("new", caller))
	other := caller
	other.Tenant = "other"
	assert.False(t, runs.isPending("new", other), "another tenant never reads the entry")
}
