// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// a2aPendingTTL is how long a started run may be missing from the World. The
// World folds the dispatch event on its next tick, so a run is missing for a
// moment only.
const a2aPendingTTL = time.Minute

// a2aRuns runs the agent work that A2A messages start (gibson#1400). The run is
// a work item of the mission of the caller, and the World holds it with the
// link to its parent. The dispatch is the one that a mission node uses, so the
// dispatch gate and the enablement gate of DelegateToAgent apply to it too. The
// child grant is minted there from the mission of the caller. It has the scope
// of the grant of any task of the mission, so it is never wider than the grant
// of the caller.
type a2aRuns struct {
	registry *brain.Registry
	exec     *brainExecutor
	// jobs is where the jobs of a bank live. It is read for each call because
	// the data pool starts after the daemon builds this value.
	jobs func() (job.Store, error)

	mu      sync.Mutex
	pending map[string]a2aPending
}

// a2aPending is a run that the daemon submitted and the World has not folded.
type a2aPending struct {
	tenant, mission, target string
	at                      time.Time
}

var _ a2aserver.Runs = (*a2aRuns)(nil)

func newA2ARuns(reg *brain.Registry, exec *brainExecutor, jobs func() (job.Store, error)) *a2aRuns {
	return &a2aRuns{registry: reg, exec: exec, jobs: jobs, pending: map[string]a2aPending{}}
}

// Start creates the work item of one A2A message.
func (r *a2aRuns) Start(ctx context.Context, req a2aserver.StartRequest) (*a2a.Task, error) {
	c := req.Caller
	eng, ok := api.TenantEngine(r.registry, c.Tenant)
	if !ok {
		return nil, fmt.Errorf("%w: the World of the tenant is not available", a2aserver.ErrRefused)
	}
	runID, err := missionRunOf(eng, c.Mission)
	if err != nil {
		return nil, err
	}
	// The dispatch needs the binding of the mission. A mission with none is not
	// running on this daemon, and the dispatch would drop the item.
	if _, live := r.exec.get(c.Mission); !live {
		return nil, fmt.Errorf("%w: the mission is not running", a2aserver.ErrRefused)
	}
	work := eng.Work()
	if depth := a2aserver.Depth(work, c.Mission, c.Task); depth >= harness.MaxDelegationDepth() {
		return nil, fmt.Errorf("%w: delegation_depth_exceeded: chain length %d, limit %d",
			a2aserver.ErrRefused, depth, harness.MaxDelegationDepth())
	}

	kind, target, input, err := r.target(ctx, c, req.Route, req.Message)
	if err != nil {
		return nil, err
	}
	workID := uuid.NewString()
	r.remember(workID, a2aPending{tenant: c.Tenant, mission: c.Mission, target: target, at: time.Now()})
	eng.Submit(brain.WorkDispatched{
		ID: workID, MissionID: c.Mission, RunID: runID, ItemKind: kind, Target: target, Input: input,
		ParentID: c.Task,
	})
	return a2aserver.TaskFromWork(workID, c.Mission, brain.WorkSnapshot{ID: workID, State: brain.WorkPending}), nil
}

// target decides the kind, the target and the input of the work item. An agent
// route gives agent work. A bank route gives a job on the bank, or the next turn
// of the job that the message names. The caller may continue only a job that
// it opened.
func (r *a2aRuns) target(
	ctx context.Context, c a2aserver.Caller, rt a2aserver.Route, msg *a2a.Message,
) (kind, target, input string, err error) {
	goal := a2aserver.TextOf(msg)
	if rt.Bank == "" {
		if msg.TaskID != "" {
			return "", "", "", fmt.Errorf("%w: a message to an agent cannot continue a task", a2a.ErrInvalidParams)
		}
		return "agent", rt.Agent, goal, nil
	}
	in, err := json.Marshal(bankTurnInput{Goal: goal, Sender: c.Subject})
	if err != nil {
		return "", "", "", fmt.Errorf("encode the turn: %w", err)
	}
	if msg.TaskID == "" {
		return workKindBank, rt.Bank, string(in), nil
	}
	store, err := r.jobs()
	if err != nil {
		return "", "", "", fmt.Errorf("job store: %w", err)
	}
	j, err := store.Get(ctx, c.Tenant, string(msg.TaskID))
	// A job of another bank, or a job that the caller did not open, is not
	// found. The caller learns nothing about it.
	if err != nil || j.BankID != rt.Bank || j.OpenedBy.ID != c.Subject {
		return "", "", "", a2aserver.ErrNotFound
	}
	return workKindJobTurn, j.ID, string(in), nil
}

// Task returns the Task of a run of the caller.
func (r *a2aRuns) Task(_ context.Context, c a2aserver.Caller, id a2a.TaskID) (*a2a.Task, error) {
	eng, ok := api.TenantEngine(r.registry, c.Tenant)
	if !ok {
		return nil, a2aserver.ErrNotFound
	}
	if wi, found := a2aserver.WorkOf(eng.Work(), c.Mission, string(id)); found {
		r.forget(string(id))
		return a2aserver.TaskFromWork(string(id), c.Mission, wi), nil
	}
	if r.isPending(string(id), c) {
		return a2aserver.TaskFromWork(string(id), c.Mission, brain.WorkSnapshot{ID: string(id), State: brain.WorkPending}), nil
	}
	return nil, a2aserver.ErrNotFound
}

// Cancel cancels a run of the caller. It stops the dispatch and records the
// state canceled on the work item. A run in a final state cannot be canceled.
func (r *a2aRuns) Cancel(ctx context.Context, c a2aserver.Caller, id a2a.TaskID) (*a2a.Task, error) {
	t, err := r.Task(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if t.Status.State.Terminal() {
		return nil, a2aserver.ErrNotCancelable
	}
	eng, ok := api.TenantEngine(r.registry, c.Tenant)
	if !ok {
		return nil, a2aserver.ErrNotFound
	}
	runID, err := missionRunOf(eng, c.Mission)
	if err != nil {
		return nil, err
	}
	r.exec.CancelWork(string(id))
	eng.Submit(brain.WorkCompleted{
		ID: string(id), RunID: runID, State: brain.WorkCanceled, Err: "canceled by " + c.Subject,
	})
	canceled := brain.WorkSnapshot{ID: string(id), State: brain.WorkCanceled, Err: "canceled by " + c.Subject}
	return a2aserver.TaskFromWork(string(id), c.Mission, canceled), nil
}

func (r *a2aRuns) remember(id string, p a2aPending) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.pending {
		if time.Since(v.at) > a2aPendingTTL {
			delete(r.pending, k)
		}
	}
	r.pending[id] = p
}

func (r *a2aRuns) forget(id string) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (r *a2aRuns) isPending(id string, c a2aserver.Caller) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[id]
	return ok && p.tenant == c.Tenant && p.mission == c.Mission && time.Since(p.at) <= a2aPendingTTL
}

// missionRunOf returns the run of the active mission. A mission that is not
// active in the World of the tenant is not found for the caller.
func missionRunOf(eng *brain.Engine, missionID string) (string, error) {
	for _, m := range eng.Missions() {
		if m.ID == missionID {
			if !m.Status.IsActive() {
				return "", fmt.Errorf("%w: the mission is not running", a2aserver.ErrRefused)
			}
			return m.RunID, nil
		}
	}
	return "", fmt.Errorf("%w: the mission is not known", a2aserver.ErrRefused)
}
