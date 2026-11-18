// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package helpers: outside_components.go serves a component of the test as an
// outside component of the daemon.
//
// An exit test of the Agent Skills, the finding evidence and the AAIF alignment
// epics needs an agent that it controls. The test registers the agent with
// ComponentService, polls its work like any outside agent, and holds each work
// item open. While the work item is open, the mission runs. The test then calls
// the daemon with the work id and the task grant of the item, as the agent would.
// When the test is done with the item, it releases the item. The mission then
// ends.
//
// The same file serves an outside tool. The tool answers each work item with
// the function that the test gives it.
package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/require"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// ComponentWork is one work item that the daemon gave to an outside component.
type ComponentWork struct {
	WorkID    string
	WorkType  string
	Payload   []byte
	Context   map[string]string
	TaskGrant string
	// MissionID is the mission of the work item. The daemon puts it in the work
	// context. It is empty for a work item that no mission started.
	MissionID string
}

func workOf(r *componentpb.PollWorkResponse) ComponentWork {
	return ComponentWork{
		WorkID: r.GetWorkId(), WorkType: r.GetWorkType(), Payload: r.GetPayload(),
		Context: r.GetContext(), TaskGrant: r.GetTaskGrant(), MissionID: r.GetContext()["mission_id"],
	}
}

// heartbeatLoop keeps a registration alive until ctx ends.
func heartbeatLoop(ctx context.Context, comp componentpb.ComponentServiceClient, instanceID string) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_, _ = comp.Heartbeat(ctx, &componentpb.HeartbeatRequest{InstanceId: instanceID, HealthStatus: "healthy"})
		}
	}
}

// pollLoop polls work until ctx ends and calls handle for each work item. A
// poll error is logged and retried after one second.
func pollLoop(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, instanceID string,
	handle func(ComponentWork),
) {
	for ctx.Err() == nil {
		resp, err := comp.PollWork(ctx, &componentpb.PollWorkRequest{InstanceId: instanceID, TimeoutMs: 5000})
		if err != nil {
			if ctx.Err() == nil {
				t.Logf("outside component %s: PollWork: %v", instanceID, err)
				time.Sleep(time.Second)
			}
			continue
		}
		if resp.GetWorkId() == "" {
			continue
		}
		handle(workOf(resp))
	}
}

// completedTask returns the A2A Task of a finished run. The daemon reads it as
// the result of an agent work item.
func completedTask(workID string) ([]byte, error) {
	task := &a2a.Task{
		ID: a2a.NewTaskID(), ContextID: workID,
		Status: a2a.TaskStatus{State: a2a.TaskStateCompleted},
	}
	out, err := json.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("marshal the A2A task of work %s: %w", workID, err)
	}
	return out, nil
}

// HeldWork is a work item of a HeldAgent that is open. The mission of the item
// runs until the test calls Complete or Fail.
type HeldWork struct {
	ComponentWork
	done chan heldResult
}

type heldResult struct {
	code, message string
}

// Complete ends the work item with a completed A2A Task.
func (w *HeldWork) Complete() { w.done <- heldResult{} }

// Fail ends the work item with an error.
func (w *HeldWork) Fail(code, message string) { w.done <- heldResult{code: code, message: message} }

// HeldAgent is an outside agent that holds each work item open until the test
// releases it.
type HeldAgent struct {
	// Name is the name of the agent in the catalog.
	Name       string
	instanceID string
	works      chan *HeldWork
}

// StartHeldAgent registers an outside agent, enables it in the catalog of the
// tenant of ctx, and starts its heartbeat and its poll loop. The loops end with
// the test.
func StartHeldAgent(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient,
	membership tenantv1.MembershipServiceClient, name string,
) *HeldAgent {
	t.Helper()
	reg, err := comp.RegisterComponent(ctx, &componentpb.RegisterComponentRequest{
		Kind: "agent", Name: name, Version: "1.0.0",
	})
	require.NoError(t, err, "RegisterComponent(agent %s)", name)
	_, err = membership.SetCatalogEnabled(ctx, &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "agent/" + name, Enabled: true,
	})
	require.NoError(t, err, "SetCatalogEnabled(agent/%s)", name)

	a := &HeldAgent{Name: name, instanceID: reg.GetInstanceId(), works: make(chan *HeldWork, 16)}
	loopCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(loopCtx, comp, a.instanceID) }()
	go func() {
		defer wg.Done()
		pollLoop(loopCtx, t, comp, a.instanceID, func(w ComponentWork) {
			held := &HeldWork{ComponentWork: w, done: make(chan heldResult, 1)}
			a.works <- held
			var res heldResult
			select {
			case res = <-held.done:
			case <-loopCtx.Done():
				return
			}
			submit := &componentpb.SubmitResultRequest{WorkId: w.WorkID}
			if res.code != "" {
				submit.Error = &componentpb.ComponentError{Code: res.code, Message: res.message}
			} else {
				task, terr := completedTask(w.WorkID)
				if terr != nil {
					t.Errorf("held agent %s: %v", name, terr)
					return
				}
				submit.Result = task
			}
			if _, serr := comp.SubmitResult(loopCtx, submit); serr != nil && loopCtx.Err() == nil {
				t.Logf("held agent %s: SubmitResult(%s): %v", name, w.WorkID, serr)
			}
		})
	}()
	// The loops log through t, so they end before the test does.
	t.Cleanup(func() { stop(); wg.Wait() })
	return a
}

// Next waits for the next work item of the agent. It fails the test when no
// item arrives within timeout.
func (a *HeldAgent) Next(t *testing.T, timeout time.Duration) *HeldWork {
	t.Helper()
	select {
	case w := <-a.works:
		return w
	case <-time.After(timeout):
		t.Fatalf("the agent %s got no work item within %s: the mission never dispatched it", a.Name, timeout)
		return nil
	}
}

// ServeTool registers an outside tool and answers each work item with handle.
// An error of handle becomes the error of the work item. The loops end with the
// test.
func ServeTool(
	ctx context.Context, t *testing.T, comp componentpb.ComponentServiceClient, name string,
	handle func(payload []byte) ([]byte, error),
) {
	t.Helper()
	reg, err := comp.RegisterComponent(ctx, &componentpb.RegisterComponentRequest{
		Kind: "tool", Name: name, Version: "1.0.0",
	})
	require.NoError(t, err, "RegisterComponent(tool %s)", name)
	instanceID := reg.GetInstanceId()
	loopCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); heartbeatLoop(loopCtx, comp, instanceID) }()
	go func() {
		defer wg.Done()
		pollLoop(loopCtx, t, comp, instanceID, func(w ComponentWork) {
			submit := &componentpb.SubmitResultRequest{WorkId: w.WorkID}
			out, herr := handle(w.Payload)
			if herr != nil {
				submit.Error = &componentpb.ComponentError{Code: "TOOL_FAILED", Message: herr.Error()}
			} else {
				submit.Result = out
			}
			if _, serr := comp.SubmitResult(loopCtx, submit); serr != nil && loopCtx.Err() == nil {
				t.Logf("tool %s: SubmitResult(%s): %v", name, w.WorkID, serr)
			}
		})
	}()
	t.Cleanup(func() { stop(); wg.Wait() })
}

// CreateAgentMission creates a mission definition with one AGENT node that the
// named agent serves, and returns its id. constraints can be nil.
func CreateAgentMission(
	ctx context.Context, t *testing.T, daemon daemonpb.DaemonServiceClient,
	name, agent string, constraints *missionpb.MissionConstraints,
) string {
	t.Helper()
	def := &missionpb.MissionDefinition{
		Name:        name,
		Description: "exit test of the AAIF epics",
		Nodes: map[string]*missionpb.MissionNode{
			"agent": {
				Id: "agent", Name: "Agent", Description: "An outside agent that the test holds open",
				Type: missionpb.NodeType_NODE_TYPE_AGENT,
				Config: &missionpb.MissionNode_AgentConfig{
					AgentConfig: &missionpb.AgentNodeConfig{AgentName: agent},
				},
			},
		},
		EntryPoints: []string{"agent"},
	}
	if constraints != nil {
		def.Constraints = constraints
	}
	resp, err := daemon.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{Definition: def})
	require.NoError(t, err, "CreateMissionDefinition(%s)", name)
	require.NotEmpty(t, resp.GetMissionDefinitionId(), "CreateMissionDefinition(%s) gave no id", name)
	return resp.GetMissionDefinitionId()
}

// MissionRun is a mission that runs in the background.
type MissionRun struct {
	done     chan struct{}
	Terminal MissionEvent
	Events   []MissionEvent
	Err      error
}

// StartMission runs the mission definition against the target and watches its
// events in the background.
func StartMission(
	ctx context.Context, t *testing.T, daemon daemonpb.DaemonServiceClient, defID, targetID string,
) *MissionRun {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	events, err := Subscribe(runCtx, daemon, defID, targetID)
	if err != nil {
		cancel()
		require.NoError(t, err, "RunMission")
	}
	m := &MissionRun{done: make(chan struct{})}
	go func() {
		defer close(m.done)
		defer cancel()
		m.Terminal, m.Events, m.Err = WaitForTerminal(runCtx, events, 14*time.Minute)
	}()
	t.Cleanup(cancel)
	return m
}

// Wait waits for the mission to reach a terminal state and returns the terminal
// event. It fails the test when the mission does not end within timeout.
func (m *MissionRun) Wait(t *testing.T, timeout time.Duration) MissionEvent {
	t.Helper()
	select {
	case <-m.done:
	case <-time.After(timeout):
		t.Fatalf("the mission did not reach a terminal state within %s", timeout)
	}
	require.NoError(t, m.Err, "the mission must reach a terminal state")
	for _, ev := range m.Events {
		t.Logf("mission event: %s", ev)
	}
	return m.Terminal
}

// Eventually calls check every second until it returns true. It fails the test
// with the last message when timeout passes. A check returns a message that says
// what it still waits for.
func Eventually(t *testing.T, timeout time.Duration, what string, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ok, msg := check()
		if ok {
			return
		}
		last = msg
		if time.Now().After(deadline) {
			t.Fatalf("after %s: %s. Last state: %s", timeout, what, last)
		}
		time.Sleep(time.Second)
	}
}
