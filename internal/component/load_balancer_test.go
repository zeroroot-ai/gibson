package component

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockComponentRegistry is a simple in-memory ComponentRegistry for testing.
type mockComponentRegistry struct {
	components map[string][]ComponentInfo
}

func newMockComponentRegistry() *mockComponentRegistry {
	return &mockComponentRegistry{
		components: make(map[string][]ComponentInfo),
	}
}

func (m *mockComponentRegistry) Register(_ context.Context, tenant, kind, name string, info ComponentInfo) (string, error) {
	key := tenant + ":" + kind + ":" + name
	info.InstanceID = "instance-" + info.Name + "-auto"
	m.components[key] = append(m.components[key], info)
	return info.InstanceID, nil
}

func (m *mockComponentRegistry) Deregister(_ context.Context, tenant, kind, name, instanceID string) error {
	key := tenant + ":" + kind + ":" + name
	instances := m.components[key]
	filtered := make([]ComponentInfo, 0, len(instances))
	for _, inst := range instances {
		if inst.InstanceID != instanceID {
			filtered = append(filtered, inst)
		}
	}
	m.components[key] = filtered
	return nil
}

func (m *mockComponentRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error {
	return nil
}

func (m *mockComponentRegistry) Discover(_ context.Context, tenant, kind, name string) ([]ComponentInfo, error) {
	key := tenant + ":" + kind + ":" + name
	instances := m.components[key]
	if instances == nil {
		return []ComponentInfo{}, nil
	}
	return instances, nil
}

func (m *mockComponentRegistry) DiscoverAll(_ context.Context, tenant, kind string) ([]ComponentInfo, error) {
	var all []ComponentInfo
	prefix := tenant + ":" + kind + ":"
	for key, instances := range m.components {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			all = append(all, instances...)
		}
	}
	return all, nil
}

func (m *mockComponentRegistry) ListTenantComponents(_ context.Context, tenant string) ([]ComponentInfo, error) {
	var all []ComponentInfo
	prefix := tenant + ":"
	for key, instances := range m.components {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			all = append(all, instances...)
		}
	}
	return all, nil
}

func (m *mockComponentRegistry) DiscoverTenantOnly(_ context.Context, tenant, kind, name string) ([]ComponentInfo, error) {
	key := tenant + ":" + kind + ":" + name
	instances := m.components[key]
	if instances == nil {
		return []ComponentInfo{}, nil
	}
	return instances, nil
}

func (m *mockComponentRegistry) DiscoverSystemOnly(_ context.Context, kind, name string) ([]ComponentInfo, error) {
	return m.DiscoverTenantOnly(context.Background(), systemTenant, kind, name)
}

// addInstance is a helper to add a ComponentInfo directly to the mock.
func (m *mockComponentRegistry) addInstance(tenant, kind, name, instanceID, endpoint string) {
	key := tenant + ":" + kind + ":" + name
	m.components[key] = append(m.components[key], ComponentInfo{
		Kind:          kind,
		Name:          name,
		Version:       "1.0.0",
		InstanceID:    instanceID,
		TenantID:      tenant,
		Metadata:      map[string]string{"grpc_endpoint": endpoint},
		StartedAt:     time.Now(),
		LastHeartbeat: time.Now(),
	})
}

func TestLoadBalancer_SingleInstance(t *testing.T) {
	reg := newMockComponentRegistry()
	reg.addInstance("acme", "agent", "davinci", "instance-1", "localhost:50051")

	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		selected, err := lb.Select(ctx, "acme", "agent", "davinci")
		require.NoError(t, err)
		assert.Equal(t, "instance-1", selected.InstanceID)
		assert.Equal(t, "localhost:50051", selected.Metadata["grpc_endpoint"])
	}
}

func TestLoadBalancer_RoundRobin(t *testing.T) {
	reg := newMockComponentRegistry()
	reg.addInstance("acme", "agent", "k8skiller", "instance-1", "localhost:50051")
	reg.addInstance("acme", "agent", "k8skiller", "instance-2", "localhost:50052")
	reg.addInstance("acme", "agent", "k8skiller", "instance-3", "localhost:50053")

	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	selectedIDs := make([]string, 6)
	for i := 0; i < 6; i++ {
		selected, err := lb.Select(ctx, "acme", "agent", "k8skiller")
		require.NoError(t, err)
		selectedIDs[i] = selected.InstanceID
	}

	assert.Equal(t, "instance-1", selectedIDs[0])
	assert.Equal(t, "instance-2", selectedIDs[1])
	assert.Equal(t, "instance-3", selectedIDs[2])
	assert.Equal(t, "instance-1", selectedIDs[3])
	assert.Equal(t, "instance-2", selectedIDs[4])
	assert.Equal(t, "instance-3", selectedIDs[5])
}

func TestLoadBalancer_Random(t *testing.T) {
	reg := newMockComponentRegistry()
	for i := 1; i <= 3; i++ {
		reg.addInstance("acme", "tool", "nmap",
			"instance-"+string(rune('0'+i)),
			"localhost:5005"+string(rune('0'+i)))
	}

	lb := NewLoadBalancer(reg, StrategyRandom)
	ctx := context.Background()

	counts := make(map[string]int)
	for i := 0; i < 100; i++ {
		selected, err := lb.Select(ctx, "acme", "tool", "nmap")
		require.NoError(t, err)
		counts[selected.InstanceID]++
	}

	assert.Equal(t, 3, len(counts), "All instances should be selected")
	for id, count := range counts {
		assert.GreaterOrEqual(t, count, 10, "Instance %s should be selected multiple times", id)
	}
}

func TestLoadBalancer_NoInstances(t *testing.T) {
	reg := newMockComponentRegistry()
	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	_, err := lb.Select(ctx, "acme", "agent", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no instances")
}

func TestLoadBalancer_SelectEndpoint(t *testing.T) {
	reg := newMockComponentRegistry()
	reg.addInstance("acme", "plugin", "cvedb", "instance-1", "localhost:50051")

	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	endpoint, err := lb.SelectEndpoint(ctx, "acme", "plugin", "cvedb")
	require.NoError(t, err)
	assert.Equal(t, "localhost:50051", endpoint)
}

func TestLoadBalancer_StrategyChange(t *testing.T) {
	reg := newMockComponentRegistry()
	for i := 1; i <= 3; i++ {
		reg.addInstance("acme", "agent", "davinci",
			"instance-"+string(rune('0'+i)),
			"localhost:5005"+string(rune('0'+i)))
	}

	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	assert.Equal(t, StrategyRoundRobin, lb.Strategy())

	for i := 0; i < 3; i++ {
		_, err := lb.Select(ctx, "acme", "agent", "davinci")
		require.NoError(t, err)
	}

	lb.SetStrategy(StrategyRandom)
	assert.Equal(t, StrategyRandom, lb.Strategy())

	selected, err := lb.Select(ctx, "acme", "agent", "davinci")
	require.NoError(t, err)
	assert.NotEmpty(t, selected.InstanceID)
}

func TestLoadBalancer_ConcurrentAccess(t *testing.T) {
	reg := newMockComponentRegistry()
	for i := 1; i <= 3; i++ {
		reg.addInstance("acme", "tool", "sqlmap",
			"instance-"+string(rune('0'+i)),
			"localhost:5005"+string(rune('0'+i)))
	}

	lb := NewLoadBalancer(reg, StrategyRoundRobin)
	ctx := context.Background()

	const numGoroutines = 10
	const selectionsPerGoroutine = 20

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines*selectionsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < selectionsPerGoroutine; j++ {
				_, err := lb.Select(ctx, "acme", "tool", "sqlmap")
				if err != nil {
					errors <- err
				}
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "No errors should occur during concurrent access")
}
