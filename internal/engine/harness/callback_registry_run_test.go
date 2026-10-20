// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// runHarness is a harness of one run of a mission.
type runHarness struct {
	tenantAwareMockHarness
	runID  string
	taskID string
}

func (h *runHarness) Mission() MissionContext {
	return MissionContext{TenantID: h.tenantID, MissionRunID: h.runID, TaskID: h.taskID}
}

func newRunHarness(runID string) *runHarness {
	return &runHarness{tenantAwareMockHarness: tenantAwareMockHarness{tenantID: "test-tenant"}, runID: runID}
}

// Run 1 and run 2 of a mission delegate to the agent of the same name. The end
// of the agent of run 1 removes the registration of run 1 and no other
// (gibson#1217).
func TestCallbackHarnessRegistry_UnregisterRemovesOnlyItsOwnRegistration(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	run1, run2 := newRunHarness("run-1"), newRunHarness("run-2")

	key1 := mustRegister(t, registry, "m1", "recon", run1)
	key2 := mustRegister(t, registry, "m1", "recon", run2)
	require.NotEqual(t, key1, key2)

	got, err := registry.Lookup("m1", "recon", "run-2", "")
	require.NoError(t, err)
	assert.Same(t, run2, got)

	registry.Unregister(key1) // the deferred cleanup of run 1
	got, err = registry.Lookup("m1", "recon", "run-2", "")
	require.NoError(t, err)
	assert.Same(t, run2, got, "the cleanup of run 1 removed the harness of run 2")
	assert.Equal(t, 1, registry.Count())

	registry.Unregister(key2)
	_, err = registry.Lookup("m1", "recon", "run-2", "")
	require.Error(t, err)
	assert.Equal(t, 0, registry.Count())
}

// When run 2 ends its agent first, run 1 keeps its own registration.
func TestCallbackHarnessRegistry_EarlierRegistrationSurvivesTheLaterOne(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	run1, run2 := newRunHarness("run-1"), newRunHarness("run-2")
	key1 := mustRegister(t, registry, "m1", "recon", run1)
	key2 := mustRegister(t, registry, "m1", "recon", run2)

	registry.Unregister(key2)
	got, err := registry.Lookup("m1", "recon", "run-1", "")
	require.NoError(t, err)
	assert.Same(t, run1, got)
	registry.Unregister(key1)
	assert.Equal(t, 0, registry.Count())
}

// A callback of run 1 that finds the harness of run 2 under the same mission and
// agent name is refused, so its evidence cannot take the run of run 2.
func TestGetHarness_RefusesACallbackOfAnotherRun(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-2"))
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())

	_, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{
		MissionId: "m1", AgentName: "recon", MissionRunId: "run-1",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// The callback of run 2 still resolves.
	for _, run := range []string{"run-2"} {
		got, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{
			MissionId: "m1", AgentName: "recon", MissionRunId: run,
		})
		require.NoError(t, err, "run %q", run)
		assert.NotNil(t, got)
	}
}

// The manager's cleanup removes the registration. It used to call a legacy map
// that nothing filled, so the registry kept every harness it was given.
func TestCallbackManager_UnregisterHarnessRemovesTheRegistration(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{
		ListenAddress:  "127.0.0.1:0",
		ServiceOptions: []CallbackServiceOption{testEventBus()},
	}, slog.New(slog.DiscardHandler))

	key, err := m.RegisterHarnessForMission("m1", "recon", newRunHarness("run-1"))
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Equal(t, 1, m.registry.Count())

	m.UnregisterHarness(key)
	assert.Equal(t, 0, m.registry.Count())
}

// A callback with no run ID cannot be tied to a run when two runs hold a
// registration of the agent.
func TestCallbackHarnessRegistry_EmptyRunWithTwoRunsIsRefused(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-1"))
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-2"))

	_, err := registry.Lookup("m1", "recon", "", "")
	require.ErrorIs(t, err, ErrCallbackRunMismatch)
}

// A callback with no run ID is refused even when the registrations are of one
// run (gibson#1235). The mission ID is the same for every run of a record.
func TestCallbackHarnessRegistry_EmptyRunIsRefusedWithOneRun(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-1"))

	_, err := registry.Lookup("m1", "recon", "", "")
	require.ErrorIs(t, err, ErrCallbackRunMismatch)
}

// A callback that names its run gets the registration of that run, even when a
// newer run has registered the same agent.
func TestCallbackHarnessRegistry_NamedRunPicksItsOwnRegistration(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	run1, run2 := newRunHarness("run-1"), newRunHarness("run-2")
	mustRegister(t, registry, "m1", "recon", run1)
	mustRegister(t, registry, "m1", "recon", run2)

	got, err := registry.Lookup("m1", "recon", "run-1", "")
	require.NoError(t, err)
	assert.Same(t, run1, got)
	got, err = registry.Lookup("m1", "recon", "run-2", "")
	require.NoError(t, err)
	assert.Same(t, run2, got)

	_, err = registry.Lookup("m1", "recon", "run-3", "")
	require.ErrorIs(t, err, ErrCallbackRunMismatch)
}

// A callback that names no run is refused with InvalidArgument (gibson#1235).
func TestGetHarness_RefusesACallbackWithNoRun(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-1"))
	mustRegister(t, registry, "m1", "recon", newRunHarness("run-2"))
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())

	_, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{MissionId: "m1", AgentName: "recon"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// mustRegister registers a harness and fails the test when the registry refuses it.
func mustRegister(t *testing.T, registry *CallbackHarnessRegistry, missionID, agentName string, h AgentHarness) string {
	t.Helper()
	key, err := registry.Register(missionID, agentName, h)
	require.NoError(t, err)
	return key
}

// A harness with no mission run is refused. A registration without a run would
// serve a callback of any run, and a lookup could not tell the runs apart
// (gibson#1217).
func TestCallbackHarnessRegistry_RegisterRefusesAHarnessWithoutARun(t *testing.T) {
	registry := NewCallbackHarnessRegistry()

	key, err := registry.Register("m1", "recon", newRunHarness(""))
	require.ErrorIs(t, err, ErrHarnessWithoutRun)
	assert.Empty(t, key)
	assert.Equal(t, 0, registry.Count())
}

// A for_each fan-out runs two instances of one agent in one run. Each callback
// gets the harness of its own instance, and a callback of a task that none registered is refused
// (gibson#1229).
func TestCallbackHarnessRegistry_FanOutInstancesKeepTheirOwnHarness(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	a, b := newRunHarness("run-1"), newRunHarness("run-1")
	a.taskID, b.taskID = "task-a", "task-b"
	mustRegister(t, registry, "m1", "recon", a)
	mustRegister(t, registry, "m1", "recon", b)

	got, err := registry.Lookup("m1", "recon", "run-1", "task-a")
	require.NoError(t, err)
	assert.Same(t, a, got, "the callback of task a got the newest harness")
	got, err = registry.Lookup("m1", "recon", "run-1", "task-b")
	require.NoError(t, err)
	assert.Same(t, b, got)

	// A callback with no task cannot be told from its sibling. It is refused
	// and does not get the newest harness (gibson#1235).
	_, err = registry.Lookup("m1", "recon", "run-1", "")
	require.ErrorIs(t, err, ErrCallbackTaskMismatch)
	_, err = registry.Lookup("m1", "recon", "run-1", "task-c")
	require.ErrorIs(t, err, ErrCallbackTaskMismatch)
}

// A callback that names a task no harness holds gets the harness that serves
// every task, if the agent has one.
func TestCallbackHarnessRegistry_UnknownTaskGetsTheNoTaskHarness(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	a, shared := newRunHarness("run-1"), newRunHarness("run-1")
	a.taskID = "task-a"
	mustRegister(t, registry, "m1", "recon", shared)
	mustRegister(t, registry, "m1", "recon", a)

	got, err := registry.Lookup("m1", "recon", "run-1", "task-z")
	require.NoError(t, err)
	assert.Same(t, shared, got)
}

// A callback that names a task no harness serves is refused with
// FailedPrecondition, and the task of a registered instance still resolves
// (gibson#1229).
func TestGetHarness_RefusesACallbackOfAnotherTask(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	a := newRunHarness("run-1")
	a.taskID = "task-a"
	mustRegister(t, registry, "m1", "recon", a)
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())

	_, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{
		MissionId: "m1", AgentName: "recon", MissionRunId: "run-1", TaskId: "task-z",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	got, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{
		MissionId: "m1", AgentName: "recon", MissionRunId: "run-1", TaskId: "task-a",
	})
	require.NoError(t, err)
	assert.Same(t, a, got)
}

// A callback with no task is served when the run holds one registration of the
// agent.
func TestCallbackHarnessRegistry_NoTaskWithOneRegistrationWorks(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	only := newRunHarness("run-1")
	mustRegister(t, registry, "m1", "recon", only)

	got, err := registry.Lookup("m1", "recon", "run-1", "")
	require.NoError(t, err)
	assert.Same(t, only, got)
}
