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
	runID string
}

func (h *runHarness) Mission() MissionContext {
	return MissionContext{TenantID: h.tenantID, MissionRunID: h.runID}
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

	key1 := registry.Register("m1", "recon", run1)
	key2 := registry.Register("m1", "recon", run2)
	require.NotEqual(t, key1, key2)

	got, err := registry.Lookup("m1", "recon", "run-2")
	require.NoError(t, err)
	assert.Same(t, run2, got)

	registry.Unregister(key1) // the deferred cleanup of run 1
	got, err = registry.Lookup("m1", "recon", "")
	require.NoError(t, err)
	assert.Same(t, run2, got, "the cleanup of run 1 removed the harness of run 2")
	assert.Equal(t, 1, registry.Count())

	registry.Unregister(key2)
	_, err = registry.Lookup("m1", "recon", "")
	require.Error(t, err)
	assert.Equal(t, 0, registry.Count())
}

// When run 2 ends its agent first, run 1 keeps its own registration.
func TestCallbackHarnessRegistry_EarlierRegistrationSurvivesTheLaterOne(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	run1, run2 := newRunHarness("run-1"), newRunHarness("run-2")
	key1 := registry.Register("m1", "recon", run1)
	key2 := registry.Register("m1", "recon", run2)

	registry.Unregister(key2)
	got, err := registry.Lookup("m1", "recon", "")
	require.NoError(t, err)
	assert.Same(t, run1, got)
	registry.Unregister(key1)
	assert.Equal(t, 0, registry.Count())
}

// A callback of run 1 that finds the harness of run 2 under the same mission and
// agent name is refused, so its evidence cannot take the run of run 2.
func TestGetHarness_RefusesACallbackOfAnotherRun(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	registry.Register("m1", "recon", newRunHarness("run-2"))
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())

	_, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{
		MissionId: "m1", AgentName: "recon", MissionRunId: "run-1",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// The callback of run 2, and one that names no run while only run 2 is
	// registered, still resolve.
	for _, run := range []string{"run-2", ""} {
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

	key := m.RegisterHarnessForMission("m1", "recon", newRunHarness("run-1"))
	require.NotEmpty(t, key)
	require.Equal(t, 1, m.registry.Count())

	m.UnregisterHarness(key)
	assert.Equal(t, 0, m.registry.Count())
}

// A callback with no run ID cannot be tied to a run when two runs hold a
// registration of the agent. The newest registration would be the wrong
// harness for a late callback of the older run.
func TestCallbackHarnessRegistry_EmptyRunWithTwoRunsIsRefused(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	registry.Register("m1", "recon", newRunHarness("run-1"))
	registry.Register("m1", "recon", newRunHarness("run-2"))

	_, err := registry.Lookup("m1", "recon", "")
	require.ErrorIs(t, err, ErrCallbackRunMismatch)
}

// A callback with no run ID still works when the registrations are of one run.
func TestCallbackHarnessRegistry_EmptyRunWithOneRunWorks(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	first, second := newRunHarness("run-1"), newRunHarness("run-1")
	registry.Register("m1", "recon", first)
	registry.Register("m1", "recon", second)

	got, err := registry.Lookup("m1", "recon", "")
	require.NoError(t, err)
	assert.Same(t, second, got, "one run: the newest registration serves")
}

// A callback that names its run gets the registration of that run, even when a
// newer run has registered the same agent.
func TestCallbackHarnessRegistry_NamedRunPicksItsOwnRegistration(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	run1, run2 := newRunHarness("run-1"), newRunHarness("run-2")
	registry.Register("m1", "recon", run1)
	registry.Register("m1", "recon", run2)

	got, err := registry.Lookup("m1", "recon", "run-1")
	require.NoError(t, err)
	assert.Same(t, run1, got)
	got, err = registry.Lookup("m1", "recon", "run-2")
	require.NoError(t, err)
	assert.Same(t, run2, got)

	_, err = registry.Lookup("m1", "recon", "run-3")
	require.ErrorIs(t, err, ErrCallbackRunMismatch)
}

// A late callback of run 1 that names no run is refused while run 1 and run 2
// both hold a registration. Most agents send no run ID, so the harness of run 2
// must not serve it.
func TestGetHarness_RefusesAnEmptyRunCallbackWhenTwoRunsAreRegistered(t *testing.T) {
	registry := NewCallbackHarnessRegistry()
	registry.Register("m1", "recon", newRunHarness("run-1"))
	registry.Register("m1", "recon", newRunHarness("run-2"))
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())

	_, err := service.getHarness(testCtxWithTenant(), &harnesspb.ContextInfo{MissionId: "m1", AgentName: "recon"})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}
