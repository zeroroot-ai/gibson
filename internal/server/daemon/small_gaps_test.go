// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

func TestProjectBrainEvent_WorkCompletedStates(t *testing.T) {
	tests := []struct {
		name      string
		event     brain.WorkCompleted
		missionID string
		wantNil   bool
		wantType  string
		wantErr   string
	}{
		{"a node that waits for input ends nothing", brain.WorkCompleted{ID: "n1", State: brain.WorkInputRequired}, "m1", true, "", ""},
		{"a canceled node fails with the reason", brain.WorkCompleted{ID: "n1", State: brain.WorkCanceled, Err: "stop"}, "m1", false,
			"node.failed", "stop"},
		{"a canceled node with no reason says canceled", brain.WorkCompleted{ID: "n1", State: brain.WorkCanceled}, "m1", false,
			"node.failed", "canceled"},
		{"a failed node", brain.WorkCompleted{ID: "n1", Err: "boom"}, "m1", false, "node.failed", "boom"},
		{"a good node", brain.WorkCompleted{ID: "n1"}, "m1", false, "node.completed", ""},
		{"no mission to attribute", brain.WorkCompleted{ID: "n1"}, "", true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectBrainEvent(tt.event, tt.missionID)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.NotNil(t, got.MissionEvent)
			assert.Equal(t, tt.wantType, got.MissionEvent.EventType)
			assert.Equal(t, "n1", got.MissionEvent.NodeID)
			assert.Equal(t, tt.wantErr, got.MissionEvent.Error)
		})
	}
}

func TestPinMissionSkills_ABadSkillNameFailsTheStart(t *testing.T) {
	ids, err := pinMissionSkills(context.Background(), nil, "acme", "m1", defWithTools("skill:Bad_Name"))
	require.Error(t, err)
	assert.Nil(t, ids)
	assert.Contains(t, err.Error(), "mission dependency")
}

func TestResolveSlotModel_AFailureToLoadTheTenantProvidersIsReported(t *testing.T) {
	boom := errors.New("provider store is down")
	r := &componentSlotModels{forTenant: func(context.Context, string) (harness.SlotManager, error) { return nil, boom }}
	_, err := r.ResolveSlotModel(context.Background(), "acme", "default", nil)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), `resolve providers for tenant "acme"`)

	floor := &slotModelResolver{forTenant: func(context.Context, string) (harness.SlotManager, error) { return nil, boom }}
	_, _, err = floor.ResolveAgentModel(context.Background(), "acme", "", 8000)
	require.ErrorIs(t, err, boom)
}
