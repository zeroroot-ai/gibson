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

	got, err := registry.Lookup("m1", "recon")
	require.NoError(t, err)
	assert.Same(t, run2, got, "the current registration is the last one")

	registry.Unregister(key1) // the deferred cleanup of run 1
	got, err = registry.Lookup("m1", "recon")
	require.NoError(t, err)
	assert.Same(t, run2, got, "the cleanup of run 1 removed the harness of run 2")
	assert.Equal(t, 1, registry.Count())

	registry.Unregister(key2)
	_, err = registry.Lookup("m1", "recon")
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
	got, err := registry.Lookup("m1", "recon")
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

	// The callback of run 2, and one that names no run, still resolve.
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
