// Package component provides load balancing capabilities for component discovery.
//
// This file implements simple load balancing strategies without external dependencies.
// The load balancer wraps a ComponentRegistry and provides intelligent instance selection.
package component

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
)

// LoadBalanceStrategy defines load balancing algorithms.
type LoadBalanceStrategy string

const (
	// StrategyRoundRobin distributes requests evenly across instances in rotation.
	StrategyRoundRobin LoadBalanceStrategy = "round_robin"

	// StrategyRandom selects instances randomly with uniform distribution.
	StrategyRandom LoadBalanceStrategy = "random"

	// StrategyLeastConnection selects the instance with fewest active connections.
	StrategyLeastConnection LoadBalanceStrategy = "least_connection"
)

// LoadBalancer provides load-balanced component discovery.
//
// It wraps a ComponentRegistry and adds instance selection strategies for distributing
// requests across multiple instances of the same component. This enables horizontal
// scaling and fault tolerance.
//
// Example usage:
//
//	reg := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
//	lb := component.NewLoadBalancer(reg, component.StrategyRoundRobin)
//
//	// Select an instance for each request
//	for i := 0; i < 10; i++ {
//	    info, _ := lb.Select(ctx, "acme", "agent", "k8skiller")
//	    // Connect to info.Metadata["grpc_endpoint"]
//	}
//
// Thread-safe: All methods can be called concurrently.
type LoadBalancer struct {
	registry ComponentRegistry
	strategy LoadBalanceStrategy

	// State for round-robin strategy (per tenant:kind:name key)
	rrMutex    sync.RWMutex
	rrCounters map[string]*uint64

	// State for least-connection strategy (future use)
	connMutex  sync.RWMutex
	connCounts map[string]int // endpoint -> connection count
}

// NewLoadBalancer creates a load balancer wrapping a ComponentRegistry.
//
// The strategy parameter determines how instances are selected:
//   - StrategyRoundRobin: Cycles through instances sequentially
//   - StrategyRandom: Selects instances randomly
//   - StrategyLeastConnection: Selects instance with fewest connections (future)
//
// The load balancer does not take ownership of the registry. The caller is
// responsible for managing the registry lifecycle.
func NewLoadBalancer(reg ComponentRegistry, strategy LoadBalanceStrategy) *LoadBalancer {
	return &LoadBalancer{
		registry:   reg,
		strategy:   strategy,
		rrCounters: make(map[string]*uint64),
		connCounts: make(map[string]int),
	}
}

// Select returns a single component instance based on the configured strategy.
//
// If multiple instances are registered, the strategy determines which one is returned:
//   - RoundRobin: Returns the next instance in sequence
//   - Random: Returns a random instance
//   - LeastConnection: Returns instance with fewest connections (currently same as RoundRobin)
//
// If no instances are registered, returns an error.
// If only one instance exists, it is always returned regardless of strategy.
func (lb *LoadBalancer) Select(ctx context.Context, tenant, kind, name string) (*ComponentInfo, error) {
	instances, err := lb.registry.Discover(ctx, tenant, kind, name)
	if err != nil {
		return nil, fmt.Errorf("discover failed: %w", err)
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no instances of %s:%s available for tenant %s", kind, name, tenant)
	}

	// Single instance — no load balancing needed.
	if len(instances) == 1 {
		return &instances[0], nil
	}

	// Apply strategy.
	var selected *ComponentInfo
	switch lb.strategy {
	case StrategyRoundRobin:
		selected = lb.selectRoundRobin(tenant, kind, name, instances)
	case StrategyRandom:
		selected = lb.selectRandom(instances)
	case StrategyLeastConnection:
		selected = lb.selectLeastConnection(instances)
	default:
		selected = lb.selectRoundRobin(tenant, kind, name, instances)
	}

	return selected, nil
}

// SelectEndpoint returns the gRPC endpoint string from a component's metadata.
//
// The endpoint is stored under the "grpc_endpoint" key in Metadata. Returns an
// error if no instances are found or if the selected instance has no endpoint.
func (lb *LoadBalancer) SelectEndpoint(ctx context.Context, tenant, kind, name string) (string, error) {
	info, err := lb.Select(ctx, tenant, kind, name)
	if err != nil {
		return "", err
	}
	endpoint := info.Metadata["grpc_endpoint"]
	if endpoint == "" {
		return "", fmt.Errorf("component %s/%s/%s has no grpc_endpoint in metadata", tenant, kind, name)
	}
	return endpoint, nil
}

// selectRoundRobin implements round-robin selection.
func (lb *LoadBalancer) selectRoundRobin(tenant, kind, name string, instances []ComponentInfo) *ComponentInfo {
	key := fmt.Sprintf("%s:%s:%s", tenant, kind, name)

	lb.rrMutex.Lock()
	counter, exists := lb.rrCounters[key]
	if !exists {
		var zero uint64
		counter = &zero
		lb.rrCounters[key] = counter
	}
	lb.rrMutex.Unlock()

	count := atomic.AddUint64(counter, 1)
	index := (count - 1) % uint64(len(instances))
	return &instances[index]
}

// selectRandom implements random selection.
func (lb *LoadBalancer) selectRandom(instances []ComponentInfo) *ComponentInfo {
	index := rand.Intn(len(instances))
	return &instances[index]
}

// selectLeastConnection implements least-connection selection.
func (lb *LoadBalancer) selectLeastConnection(instances []ComponentInfo) *ComponentInfo {
	lb.connMutex.RLock()
	defer lb.connMutex.RUnlock()

	var selected *ComponentInfo
	minConnections := -1

	for i := range instances {
		endpoint := instances[i].Metadata["grpc_endpoint"]
		count := lb.connCounts[endpoint]

		if minConnections == -1 || count < minConnections {
			minConnections = count
			selected = &instances[i]
		}
	}

	return selected
}

// IncrementConnections increments the connection count for an endpoint.
// This should be called when a new connection is established.
func (lb *LoadBalancer) IncrementConnections(endpoint string) {
	lb.connMutex.Lock()
	defer lb.connMutex.Unlock()
	lb.connCounts[endpoint]++
}

// DecrementConnections decrements the connection count for an endpoint.
// This should be called when a connection is closed.
func (lb *LoadBalancer) DecrementConnections(endpoint string) {
	lb.connMutex.Lock()
	defer lb.connMutex.Unlock()

	if count, exists := lb.connCounts[endpoint]; exists && count > 0 {
		lb.connCounts[endpoint]--
	}
}

// Strategy returns the current load balancing strategy.
func (lb *LoadBalancer) Strategy() LoadBalanceStrategy {
	return lb.strategy
}

// SetStrategy changes the load balancing strategy at runtime.
//
// Note: Changing strategies resets internal state (e.g., round-robin counters).
func (lb *LoadBalancer) SetStrategy(strategy LoadBalanceStrategy) {
	lb.strategy = strategy

	lb.rrMutex.Lock()
	lb.rrCounters = make(map[string]*uint64)
	lb.rrMutex.Unlock()
}
