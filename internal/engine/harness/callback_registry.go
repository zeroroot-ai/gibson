// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"errors"
	"fmt"
	"sync"
)

// CallbackHarnessRegistry maintains a thread-safe registry of active harnesses
// keyed by mission ID and agent name. This enables external agents (running as
// separate gRPC services) to make harness operations through the callback server.
//
// The registry tracks harnesses during agent execution so that callback operations
// can be routed to the correct harness instance. Each external agent execution
// registers its harness before execution and unregisters after completion.
//
// Key Format: "missionID:agentName"
//
// Thread Safety:
//   - All operations use sync.RWMutex for concurrent access
//   - Multiple readers can access simultaneously
//   - Writers block all other access
//
// Usage:
//
//	registry := NewCallbackHarnessRegistry()
//
//	// Register before agent execution
//	key, err := registry.Register(missionID, agentName, harness)
//	defer registry.Unregister(key)
//
//	// External agent makes callback
//	harness, err := registry.Lookup(missionID, agentName, runID, taskID)
//	if err != nil {
//	    return errors.New("harness not found")
//	}
type CallbackHarnessRegistry struct {
	// mu protects the harnesses map
	mu sync.RWMutex

	// harnesses maps a registration key to its harness. The key is unique
	// for each registration, so a registration that ended removes itself and
	// no other (gibson#1217).
	harnesses map[string]AgentHarness

	// byAgent lists, for each "missionID:agentName", the registration keys
	// in the order they were made. The last one is the current registration.
	// Run 2 of a mission registers an agent of the same name while an agent
	// of run 1 may still hold its entry.
	byAgent map[string][]string

	// agentOf maps a registration key to its "missionID:agentName".
	agentOf map[string]string

	// seq makes each registration key unique.
	seq uint64
}

// NewCallbackHarnessRegistry creates a new empty harness registry.
//
// Returns:
//   - *CallbackHarnessRegistry: A new registry instance ready for use
//
// Example:
//
//	registry := NewCallbackHarnessRegistry()
//	key, err := registry.Register("mission-123", "recon-agent", harness)
func NewCallbackHarnessRegistry() *CallbackHarnessRegistry {
	return &CallbackHarnessRegistry{
		harnesses: make(map[string]AgentHarness),
		byAgent:   make(map[string][]string),
		agentOf:   make(map[string]string),
	}
}

// Register adds a harness to the registry and returns the registration key.
//
// The harness is stored under a key composed of missionID and agentName,
// allowing the same agent to run concurrently in different missions without
// conflicts.
//
// Parameters:
//   - missionID: Unique identifier for the mission
//   - agentName: Name of the agent being executed
//   - harness: The harness instance that will handle callbacks
//
// Returns:
//   - string: The registration key. It is unique for each registration.
//
// This method is thread-safe and can be called concurrently from multiple
// goroutines. A harness with no mission run is refused with ErrHarnessWithoutRun.
// A second registration of the same mission and agent becomes the
// current one for Lookup. Unregister removes only the registration of its key,
// so the end of an agent of run 1 leaves the agent of run 2 in place.
//
// Example:
//
//	key, err := registry.Register("mission-123", "recon-agent", harness)
//	defer registry.Unregister(key)
//	// Execute external agent...
func (r *CallbackHarnessRegistry) Register(missionID, agentName string, harness AgentHarness) (string, error) {
	if harness.Mission().MissionRunID == "" {
		return "", fmt.Errorf("%w: mission %s, agent %s", ErrHarnessWithoutRun, missionID, agentName)
	}
	agent := makeRegistryKey(missionID, agentName)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.seq++
	key := fmt.Sprintf("%s#%d", agent, r.seq)
	r.harnesses[key] = harness
	r.byAgent[agent] = append(r.byAgent[agent], key)
	r.agentOf[key] = agent
	return key, nil
}

// Lookup retrieves a harness by mission ID, agent name, run ID and task ID.
//
// This method is called by the callback server when an external agent makes
// a harness operation request. The callback includes the mission ID and agent
// name, which are used to locate the correct harness instance.
//
// Parameters:
//   - missionID: The mission ID provided by the external agent
//   - agentName: The agent name provided by the external agent
//   - runID: The mission run the callback names. It may be empty.
//   - taskID: The task the callback names. It picks one instance of a fan-out.
//
// Returns:
//   - AgentHarness: The registered harness instance
//   - error: Non-nil if no harness is found. ErrCallbackRunMismatch means the
//     callback cannot be tied to one run (gibson#1217).
//
// This method is thread-safe and can be called concurrently with Register
// and Unregister operations. It uses a read lock to allow multiple concurrent
// lookups without blocking.
//
// Example:
//
//	harness, err := registry.Lookup("mission-123", "recon-agent", "run-1", "task-1")
//	if err != nil {
//	    return status.Error(codes.NotFound, "harness not found")
//	}
//	return harness.Complete(ctx, slot, messages)
func (r *CallbackHarnessRegistry) Lookup(missionID, agentName, runID, taskID string) (AgentHarness, error) {
	agent := makeRegistryKey(missionID, agentName)

	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := r.byAgent[agent]
	if len(keys) == 0 {
		return nil, fmt.Errorf("no harness registered for mission %s, agent %s", missionID, agentName)
	}

	if runID != "" {
		var inRun []string
		for _, k := range keys {
			if r.harnesses[k].Mission().MissionRunID == runID {
				inRun = append(inRun, k)
			}
		}
		if len(inRun) == 0 {
			return nil, fmt.Errorf("%w: run %s of mission %s, agent %s", ErrCallbackRunMismatch, runID, missionID, agentName)
		}
		keys = inRun
		// A grant names its mission run in the claim task_id, so a callback of an
		// agent that fills its context from the grant sends the run as the task.
		// The run is not a task of the fan-out, so the callback names none.
		if taskID == runID {
			taskID = ""
		}
	} else {
		runs := map[string]struct{}{}
		for _, k := range keys {
			runs[r.harnesses[k].Mission().MissionRunID] = struct{}{}
		}
		if len(runs) > 1 {
			return nil, fmt.Errorf("%w: a callback with no run matches %d runs of mission %s, agent %s",
				ErrCallbackRunMismatch, len(runs), missionID, agentName)
		}
	}
	return r.selectTask(keys, taskID, missionID, agentName)
}

// selectTask picks one registration of a run by task. A for_each fan-out runs
// several instances of one agent in one run, and each registers its own child
// harness (gibson#1229). A callback that names a task gets the harness of that
// task. A callback with no task gets the newest harness of the run.
func (r *CallbackHarnessRegistry) selectTask(keys []string, taskID, missionID, agentName string) (AgentHarness, error) {
	if taskID != "" {
		for i := len(keys) - 1; i >= 0; i-- {
			if r.harnesses[keys[i]].Mission().TaskID == taskID {
				return r.harnesses[keys[i]], nil
			}
		}
	}
	// A harness with no task serves every task of its agent.
	for i := len(keys) - 1; i >= 0; i-- {
		if r.harnesses[keys[i]].Mission().TaskID == "" {
			return r.harnesses[keys[i]], nil
		}
	}
	if taskID == "" {
		// An agent that sends no task cannot be told from its siblings. It
		// gets the newest harness of the run, as before.
		return r.harnesses[keys[len(keys)-1]], nil
	}
	return nil, fmt.Errorf("%w: task %q of mission %s, agent %s matches none of %d registrations",
		ErrCallbackTaskMismatch, taskID, missionID, agentName, len(keys))
}

// Unregister removes a harness from the registry.
//
// This should be called when an agent execution completes (whether successful
// or failed) to prevent memory leaks. It's typically called in a defer block
// immediately after Register.
//
// Parameters:
//   - key: The registration key returned by Register()
//
// If the key doesn't exist in the registry, this is a no-op (no error is
// returned). This makes it safe to call in defer blocks even if registration
// never happened.
//
// This method is thread-safe and can be called concurrently with other
// registry operations.
//
// Example:
//
//	key, err := registry.Register(missionID, agentName, harness)
//	defer registry.Unregister(key)
//	// Agent execution happens here...
func (r *CallbackHarnessRegistry) Unregister(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	agent, ok := r.agentOf[key]
	if !ok {
		return
	}
	delete(r.harnesses, key)
	delete(r.agentOf, key)
	keys := r.byAgent[agent]
	for i, k := range keys {
		if k == key {
			keys = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	if len(keys) == 0 {
		delete(r.byAgent, agent)
		return
	}
	r.byAgent[agent] = keys
}

// Count returns the number of currently registered harnesses.
//
// This is primarily useful for testing and monitoring to ensure harnesses
// are being properly registered and unregistered.
//
// Returns:
//   - int: The number of active harness registrations
//
// This method is thread-safe.
//
// Example:
//
//	count := registry.Count()
//	if count > 0 {
//	    logger.Info("active harnesses", "count", count)
//	}
func (r *CallbackHarnessRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.harnesses)
}

// Clear removes all harnesses from the registry.
//
// This is primarily useful for testing to reset state between test cases.
// In production, harnesses should be unregistered individually using
// Unregister() when agent execution completes.
//
// This method is thread-safe.
//
// Example:
//
//	// In test teardown
//	registry.Clear()
func (r *CallbackHarnessRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.harnesses = make(map[string]AgentHarness)
	r.byAgent = make(map[string][]string)
	r.agentOf = make(map[string]string)
}

// makeRegistryKey creates a registry key from mission ID and agent name.
//
// The key format is "missionID:agentName" which allows the same agent to
// run concurrently in different missions without conflicts.
//
// Parameters:
//   - missionID: The mission identifier
//   - agentName: The agent name
//
// Returns:
//   - string: The formatted registry key
func makeRegistryKey(missionID, agentName string) string {
	return fmt.Sprintf("%s:%s", missionID, agentName)
}

// ErrCallbackRunMismatch reports a callback that cannot be tied to a run of its
// mission: it names a run that has no registration, or it names no run while
// the registrations span more than one.
var ErrCallbackRunMismatch = errors.New("callback does not match one run of the mission")

// ErrCallbackTaskMismatch is the error of a callback whose task matches no
// registration of its agent in the run.
var ErrCallbackTaskMismatch = errors.New("callback does not match one task of the agent")

// ErrHarnessWithoutRun reports a registration of a harness that has no mission
// run. Every registration belongs to one run, so a lookup can tell the runs of
// a mission apart (gibson#1217).
var ErrHarnessWithoutRun = errors.New("harness has no mission run")
