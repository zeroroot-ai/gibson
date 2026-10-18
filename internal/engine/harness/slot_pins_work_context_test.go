// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// WorkSlotPins keeps each pinned slot and drops a nil entry.
func TestWorkSlotPins_KeepsThePinnedSlots(t *testing.T) {
	pins := WorkSlotPins(map[string]*agent.SlotConfig{
		"fast":    {Provider: "fast-p", Model: "f-large"},
		"ignored": nil,
	})
	assert.Equal(t, map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}, pins)
}

// A node with no pins gives nil, so the work item carries nothing.
func TestWorkSlotPins_NoPinsIsNil(t *testing.T) {
	for _, overrides := range []map[string]*agent.SlotConfig{nil, {}, {"fast": nil}} {
		assert.Nil(t, WorkSlotPins(overrides))
	}
}

// The agent work item that the queue path enqueues carries the slot pins of
// the task (gibson#1203).
func TestDelegateToAgent_PutsTheNodeSlotPinsOnTheWorkItem(t *testing.T) {
	q := &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
	h := newRemoteAgentHarness(t, q, remoteAgentInstances())

	task := agent.NewTask("probe", "goal")
	task.SlotOverrides = map[string]*agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}
	_, err := h.DelegateToAgent(callerCtx(t, "user-remote", "zerocool-lab"), "zerocool", task)
	require.NoError(t, err)

	assert.Equal(t, map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}, q.gotItem.SlotPins)
}
