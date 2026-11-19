// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

// An event of a mission that the World does not hold changes no gate.
func TestMissionGate_AnEventOfAnUnknownMissionWritesNothing(t *testing.T) {
	g := &gateRecorder{}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)

	tap.apply(brain.MissionStarted{ID: "ghost", RunID: "r1"})

	tap.mu.Lock()
	defer tap.mu.Unlock()
	assert.Empty(t, tap.states, "the tap holds no state for a mission that is not in the World")
	assert.Zero(t, g.count())
}

// A work item that waits for the gate stops when its context ends.
func TestMissionGate_AwaitOpenStopsWithTheContext(t *testing.T) {
	g := &gateRecorder{block: make(chan struct{}), started: make(chan struct{}, 1)}
	t.Cleanup(func() { close(g.block) })
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := newGateTap(eng, g)
	eng.Submit(brain.MissionCreated{ID: "m1", Name: "run"})
	eng.Submit(brain.MissionStarted{ID: "m1", RunID: "r1"})
	eng.Tick()
	<-g.started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := tap.AwaitOpen(ctx, "m1")
	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "wait for the gate of mission m1")
}

func TestInstallMissionGate_UsesTheDefaultLoggerWhenNoneIsGiven(t *testing.T) {
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	tap := InstallMissionGate("acme", eng, &gateRecorder{}, nil)
	require.NotNil(t, tap)
	assert.NotNil(t, tap.logger)
	assert.Equal(t, "acme", tap.tenant)
}

func TestMissionGateOf_ReturnsTheTapOrAClosedNoOp(t *testing.T) {
	d := &daemonImpl{}
	assert.Equal(t, noMissionGate{}, d.missionGateOf("acme"), "a tenant with no gate")

	d.missionGates.Store("odd", "not a tap")
	assert.Equal(t, noMissionGate{}, d.missionGateOf("odd"), "a value that is not a tap")

	tap := &missionGateTap{tenant: "acme"}
	d.missionGates.Store("acme", tap)
	assert.Same(t, tap, d.missionGateOf("acme"))
}
