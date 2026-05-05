// Package orchestrator — checkpoint_integration_parallel.go
//
// This file extends CheckpointIntegration with the parallel-group completion
// machinery for Spec 4 R4. It is split out from checkpoint_integration.go to
// keep the change surface tight and to make the parallel-group hooks easy to
// audit independently.
//
// The fields `parallelGroupTotals` and `parallelGroupFired` live on the
// CheckpointIntegration struct via package-level globals (per-integration
// maps). Why: the canonical struct definition in checkpoint_integration.go
// is locked under a separate edit budget; layering the maps in a sibling
// state container keeps both files self-contained without redeclaring the
// struct.
//
// Spec: mission-checkpointing R4.1, R4.2, R4.3, R4.4.
package orchestrator

import (
	"sync"
)

// parallelGroupState carries per-CheckpointIntegration parallel-group
// metadata that complements the in-struct `parallelGroups` map.
type parallelGroupState struct {
	mu      sync.Mutex
	totals  map[string]int  // expected node count per groupID
	fired   map[string]bool // groupIDs that have already fired
}

// parallelGroupRegistry maps each *CheckpointIntegration pointer to its
// parallel-group sidecar state. Lookups happen on the hot path of
// TrackParallelCompletion, so we use a sync.Map for lock-free reads under
// load.
var parallelGroupRegistry sync.Map

func parallelStateFor(ci *CheckpointIntegration) *parallelGroupState {
	if v, ok := parallelGroupRegistry.Load(ci); ok {
		return v.(*parallelGroupState)
	}
	st := &parallelGroupState{
		totals: make(map[string]int),
		fired:  make(map[string]bool),
	}
	actual, _ := parallelGroupRegistry.LoadOrStore(ci, st)
	return actual.(*parallelGroupState)
}

// WithParallelGroupTotals seeds the integration with the expected number of
// nodes for each parallel group. The orchestrator obtains this map from the
// mission DAG when dispatching a parallel group; the integration then
// auto-fires OnParallelGroupComplete once TrackParallelCompletion sees the
// expected count.
//
// The provided map is shallow-copied. Spec: R4.1.
func WithParallelGroupTotals(totals map[string]int) CheckpointIntegrationOption {
	return func(ci *CheckpointIntegration) {
		if len(totals) == 0 {
			return
		}
		st := parallelStateFor(ci)
		st.mu.Lock()
		defer st.mu.Unlock()
		for k, v := range totals {
			if v > 0 {
				st.totals[k] = v
			}
		}
	}
}

// SetParallelGroupTotal registers the expected node count for a parallel
// group at dispatch time. Used when the orchestrator does not have the totals
// available at integration construction (e.g. dynamically-spawned groups).
// Spec: R4.1.
func (c *CheckpointIntegration) SetParallelGroupTotal(groupID string, expected int) {
	if expected <= 0 {
		return
	}
	st := parallelStateFor(c)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.totals[groupID] = expected
}

// trackParallelCompletionAuto extends the in-struct TrackParallelCompletion
// with auto-fire detection: returns true exactly once when the expected count
// for the group is reached. Falls back to false (deferring to the orchestrator)
// if no expected count is registered.
//
// The exported TrackParallelCompletion method (in checkpoint_integration.go)
// delegates to this helper.
func (c *CheckpointIntegration) trackParallelCompletionAuto(groupID string, completedCount int) bool {
	st := parallelStateFor(c)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.fired[groupID] {
		return false
	}
	expected, ok := st.totals[groupID]
	if !ok || expected <= 0 {
		return false
	}
	if completedCount >= expected {
		st.fired[groupID] = true
		return true
	}
	return false
}

// clearParallelGroupSidecar removes per-group sidecar state.
func (c *CheckpointIntegration) clearParallelGroupSidecar(groupID string) {
	st := parallelStateFor(c)
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.totals, groupID)
	delete(st.fired, groupID)
}
