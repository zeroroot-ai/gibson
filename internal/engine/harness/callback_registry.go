package harness

import (
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
//	key := registry.Register(missionID, agentName, harness)
//	defer registry.Unregister(key)
//
//	// External agent makes callback
//	harness, err := registry.Lookup(missionID, agentName)
//	if err != nil {
//	    return errors.New("harness not found")
//	}
type CallbackHarnessRegistry struct {
	// mu protects the harnesses map
	mu sync.RWMutex

	// harnesses maps "missionID:agentName" keys to harness instances
	harnesses map[string]AgentHarness
}

// NewCallbackHarnessRegistry creates a new empty harness registry.
//
// Returns:
//   - *CallbackHarnessRegistry: A new registry instance ready for use
//
// Example:
//
//	registry := NewCallbackHarnessRegistry()
//	key := registry.Register("mission-123", "recon-agent", harness)
func NewCallbackHarnessRegistry() *CallbackHarnessRegistry {
	return &CallbackHarnessRegistry{
		harnesses: make(map[string]AgentHarness),
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
//   - string: The registration key in the format "missionID:agentName"
//
// This method is thread-safe and can be called concurrently from multiple
// goroutines. If a harness is already registered for the same key, it will
// be overwritten (this typically indicates a programming error).
//
// Example:
//
//	key := registry.Register("mission-123", "recon-agent", harness)
//	defer registry.Unregister(key)
//	// Execute external agent...
func (r *CallbackHarnessRegistry) Register(missionID, agentName string, harness AgentHarness) string {
	key := makeRegistryKey(missionID, agentName)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.harnesses[key] = harness
	return key
}

// Lookup retrieves a harness by mission ID and agent name.
//
// This method is called by the callback server when an external agent makes
// a harness operation request. The callback includes the mission ID and agent
// name, which are used to locate the correct harness instance.
//
// Parameters:
//   - missionID: The mission ID provided by the external agent
//   - agentName: The agent name provided by the external agent
//
// Returns:
//   - AgentHarness: The registered harness instance
//   - error: Non-nil if no harness is found for the given key
//
// This method is thread-safe and can be called concurrently with Register
// and Unregister operations. It uses a read lock to allow multiple concurrent
// lookups without blocking.
//
// Example:
//
//	harness, err := registry.Lookup("mission-123", "recon-agent")
//	if err != nil {
//	    return status.Error(codes.NotFound, "harness not found")
//	}
//	return harness.Complete(ctx, slot, messages)
func (r *CallbackHarnessRegistry) Lookup(missionID, agentName string) (AgentHarness, error) {
	key := makeRegistryKey(missionID, agentName)

	r.mu.RLock()
	defer r.mu.RUnlock()

	harness, ok := r.harnesses[key]
	if !ok {
		return nil, fmt.Errorf("no harness registered for mission %s, agent %s", missionID, agentName)
	}

	return harness, nil
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
//	key := registry.Register(missionID, agentName, harness)
//	defer registry.Unregister(key)
//	// Agent execution happens here...
func (r *CallbackHarnessRegistry) Unregister(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.harnesses, key)
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
