// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

func TestA2ATaskID_AMissionNodeGetsAFreshIDAndA2AWorkGetsAStableOne(t *testing.T) {
	first := a2aTaskID(brain.DispatchRequest{WorkID: "w1"})
	second := a2aTaskID(brain.DispatchRequest{WorkID: "w1"})
	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second, "a mission node keeps a fresh id for each dispatch")

	req := brain.DispatchRequest{WorkID: "w1", ParentID: "parent"}
	assert.Equal(t, a2aTaskID(req), a2aTaskID(req))
	assert.EqualValues(t, a2aserver.TaskIDOf("w1"), a2aTaskID(req))
}

func TestBrainExecutor_TrackWorkCancelsOnlyA2AWork(t *testing.T) {
	b := newBrainExecutor(nil, nil)

	// A mission node has no parent. Its context is the parent context.
	parent := context.Background()
	ctx, release := b.trackWork(parent, brain.DispatchRequest{WorkID: "node"})
	assert.Equal(t, parent, ctx)
	release()
	assert.False(t, b.CancelWork("node"), "a mission node is not canceled by work id")

	ctx, release = b.trackWork(parent, brain.DispatchRequest{WorkID: "w1", ParentID: "p"})
	require.NoError(t, ctx.Err())
	assert.True(t, b.CancelWork("w1"), "the running item is found")
	assert.ErrorIs(t, ctx.Err(), context.Canceled)

	release()
	assert.False(t, b.CancelWork("w1"), "a released item is gone")
	assert.False(t, b.CancelWork("unknown"))
}

// faultJobStore fails the calls that its fields name and leaves the rest to the
// in-memory store.
type faultJobStore struct {
	*fakeJobStore
	eventsErr, sendErr, getErr error
}

func (f faultJobStore) Events(ctx context.Context, tenant, id string, since int64, limit int32) ([]*job.Event, error) {
	if f.eventsErr != nil {
		return nil, f.eventsErr
	}
	return f.fakeJobStore.Events(ctx, tenant, id, since, limit)
}

func (f faultJobStore) Send(ctx context.Context, tenant string, in job.SendInput) (*job.Input, error) {
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return f.fakeJobStore.Send(ctx, tenant, in)
}

func (f faultJobStore) Get(ctx context.Context, tenant, id string) (*job.Job, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.fakeJobStore.Get(ctx, tenant, id)
}

func bankExecutor(store func() (job.Store, error)) *brainExecutor {
	b := newBrainExecutor(nil, nil)
	b.jobs = store
	return b
}

func turnRequest(kind, target string, in bankTurnInput) brain.DispatchRequest {
	raw, _ := json.Marshal(in)
	return brain.DispatchRequest{WorkID: "w1", ParentID: "p", Kind: kind, Target: target, Input: string(raw)}
}

func TestDispatchBankTurn_OpensAJobAndReportsItsOutcome(t *testing.T) {
	store := newFakeJobStore()
	// The member ends its turn at once, and it left one deliverable.
	store.onOpen = func(j *job.Job) {
		j.State = job.StateWaiting
		j.MemberID = "member-1"
		j.Deliverables = []*jobpb.Deliverable{{Ref: "mr-7", Url: "https://git.example/mr/7"}}
		store.appendEvent(j.ID, job.EventState, job.StateWaiting, "", 0)
	}
	b := bankExecutor(func() (job.Store, error) { return store, nil })
	bind := &missionBinding{tenant: "acme"}

	out, err := b.dispatchBankTurn(context.Background(), bind,
		turnRequest(workKindBank, "nightly", bankTurnInput{Goal: "fix the CVE", Sender: "agent:caller"}))
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "job-a", got["job_id"])
	assert.Equal(t, "member-1", got["member_id"])
	assert.Equal(t, "waiting", got["state"])
	refs, ok := got["deliverables"].([]any)
	require.True(t, ok)
	require.Len(t, refs, 1)
	assert.Equal(t, "mr-7", refs[0].(map[string]any)["ref"])
	assert.Equal(t, "agent:caller", store.jobs["job-a"].OpenedBy.ID, "the job records the sender as its opener")
	assert.Equal(t, "nightly", store.jobs["job-a"].BankID)
}

func TestDispatchBankTurn_ATurnWaitsForTheEndOfItsOwnTurnOnly(t *testing.T) {
	store := newFakeJobStore()
	opened, err := store.Open(context.Background(), "acme", job.OpenInput{
		BankID: "nightly", Spec: &jobpb.JobSpec{Goal: "g"}, OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: "s"},
	})
	require.NoError(t, err)
	// An earlier turn already ended.
	store.appendEvent(opened.ID, job.EventState, job.StateWaiting, "", 0)
	// The member closes the job after this turn.
	store.onSend = func(id string) {
		store.jobs[id].State = job.StateClosed
		store.jobs[id].Verdict = job.VerdictAccomplished
		store.appendEvent(id, job.EventClosed, job.StateClosed, job.VerdictAccomplished, 1)
	}
	b := bankExecutor(func() (job.Store, error) { return store, nil })

	out, err := b.dispatchBankTurn(context.Background(), &missionBinding{tenant: "acme"},
		turnRequest(workKindJobTurn, opened.ID, bankTurnInput{Goal: "next", Sender: "s"}))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "closed", got["state"], "the end of the earlier turn did not end the wait")
	require.Len(t, store.inputs[opened.ID], 1)
	assert.Equal(t, "next", store.inputs[opened.ID][0].Message)
}

func TestDispatchBankTurn_ATurnThatDoesNotEndStopsAtItsBound(t *testing.T) {
	store := newFakeJobStore()
	opened, err := store.Open(context.Background(), "acme", job.OpenInput{
		BankID: "nightly", Spec: &jobpb.JobSpec{Goal: "g"}, OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: "s"},
	})
	require.NoError(t, err)
	b := bankExecutor(func() (job.Store, error) { return store, nil })
	req := turnRequest(workKindJobTurn, opened.ID, bankTurnInput{Goal: "next", Sender: "s"})
	req.Timeout = 20 * time.Millisecond

	_, err = b.dispatchBankTurn(context.Background(), &missionBinding{tenant: "acme"}, req)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "wait for the turn of job")
}

func TestDispatchBankTurn_Refusals(t *testing.T) {
	store := newFakeJobStore()
	opened, err := store.Open(context.Background(), "acme", job.OpenInput{
		BankID: "nightly", Spec: &jobpb.JobSpec{Goal: "g"}, OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: "s"},
	})
	require.NoError(t, err)
	good := bankTurnInput{Goal: "go", Sender: "s"}
	boom := errors.New("boom")
	live := func() (job.Store, error) { return store, nil }

	tests := []struct {
		name    string
		jobs    func() (job.Store, error)
		req     brain.DispatchRequest
		wantErr string
	}{
		{"no job store", nil, turnRequest(workKindBank, "b", good), "serves no jobs"},
		{"the store is down", func() (job.Store, error) { return nil, boom }, turnRequest(workKindBank, "b", good), "job store"},
		{"the input is not JSON", live, brain.DispatchRequest{Kind: workKindBank, Input: "{"}, "read the input of the turn"},
		{"no message", live, turnRequest(workKindBank, "b", bankTurnInput{Sender: "s"}), "needs a message and a sender"},
		{"no sender", live, turnRequest(workKindBank, "b", bankTurnInput{Goal: "go"}), "needs a message and a sender"},
		{"an unknown kind", live, turnRequest("weird", "b", good), `unknown turn kind "weird"`},
		{"the bank cannot open a job", func() (job.Store, error) {
			failing := newFakeJobStore()
			failing.openErr = boom
			return failing, nil
		}, turnRequest(workKindBank, "b", good), "open a job on bank b"},
		{"the events cannot be read", func() (job.Store, error) {
			return faultJobStore{fakeJobStore: store, eventsErr: boom}, nil
		}, turnRequest(workKindJobTurn, opened.ID, good), "read the events of job"},
		{"the turn cannot be sent", func() (job.Store, error) {
			return faultJobStore{fakeJobStore: store, sendErr: boom}, nil
		}, turnRequest(workKindJobTurn, opened.ID, good), "send a turn to job"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bankExecutor(tt.jobs)
			_, err := b.dispatchBankTurn(context.Background(), &missionBinding{tenant: "acme"}, tt.req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestDispatchBankTurn_AJobThatCannotBeReadAfterTheTurnFails(t *testing.T) {
	store := newFakeJobStore()
	store.onOpen = func(j *job.Job) { store.appendEvent(j.ID, job.EventState, job.StateWaiting, "", 0) }
	boom := errors.New("boom")
	b := bankExecutor(func() (job.Store, error) { return faultJobStore{fakeJobStore: store, getErr: boom}, nil })
	_, err := b.dispatchBankTurn(context.Background(), &missionBinding{tenant: "acme"},
		turnRequest(workKindBank, "nightly", bankTurnInput{Goal: "go", Sender: "s"}))
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "read job")
}
