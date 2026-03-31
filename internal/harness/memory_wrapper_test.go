package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// mockMemoryManager is a simple mock for testing
type mockMemoryManager struct {
	missionID types.ID
	working   memory.WorkingMemory
}

func (m *mockMemoryManager) Working() memory.WorkingMemory {
	return m.working
}

func (m *mockMemoryManager) Mission() memory.MissionMemory {
	return nil
}

func (m *mockMemoryManager) LongTerm() memory.LongTermMemory {
	return nil
}

func (m *mockMemoryManager) MissionID() types.ID {
	return m.missionID
}

func (m *mockMemoryManager) Close() error {
	return nil
}

func newMockMemoryManager(missionID types.ID) memory.MemoryManager {
	return &mockMemoryManager{
		missionID: missionID,
		working:   memory.NewWorkingMemory(1000),
	}
}

// TestMemoryWrapper verifies that MemoryWrapper is applied to memory managers
func TestMemoryWrapper(t *testing.T) {
	// Create a mock memory manager
	mockMM := newMockMemoryManager(types.NewID())

	// Track whether wrapper was called
	wrapperCalled := false
	var wrappedMM memory.MemoryManager

	// Create config with memory wrapper
	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(nil),
		MemoryManager: mockMM,
		MemoryWrapper: func(mm memory.MemoryManager) memory.MemoryManager {
			wrapperCalled = true
			wrappedMM = memory.NewTracedMemoryManager(mm, trace.NewNoopTracerProvider().Tracer("test"))
			return wrappedMM
		},
	}

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create harness
	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}
	targetInfo := TargetInfo{
		ID:   types.NewID(),
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Verify wrapper was called
	assert.True(t, wrapperCalled, "MemoryWrapper should have been called")
	assert.NotNil(t, wrappedMM, "Wrapper should have returned a wrapped memory manager")

	// Verify the harness uses the wrapped memory manager
	memory := harness.Memory()
	assert.NotNil(t, memory, "Harness should have memory")

	// TracedMemoryManager should be transparent - verify basic operations work
	working := memory.Working()
	working.Set("key", "value")
	val, found := working.Get("key")
	assert.True(t, found, "Key should be found")
	assert.Equal(t, "value", val, "Value should match")
}

// TestMemoryWrapper_NilMemory verifies that wrapper is not called when memory is nil
func TestMemoryWrapper_NilMemory(t *testing.T) {
	wrapperCalled := false

	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(nil),
		MemoryManager: nil, // No memory manager
		MemoryFactory: nil,
		MemoryWrapper: func(mm memory.MemoryManager) memory.MemoryManager {
			wrapperCalled = true
			return mm
		},
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}
	targetInfo := TargetInfo{
		ID:   types.NewID(),
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Wrapper should NOT be called when memory is nil
	assert.False(t, wrapperCalled, "MemoryWrapper should not be called when memory is nil")
}

// TestMemoryWrapper_NilWrapper verifies backward compatibility when wrapper is nil
func TestMemoryWrapper_NilWrapper(t *testing.T) {
	mockMM := newMockMemoryManager(types.NewID())

	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(nil),
		MemoryManager: mockMM,
		MemoryWrapper: nil, // No wrapper
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}
	targetInfo := TargetInfo{
		ID:   types.NewID(),
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Should work without wrapper
	memory := harness.Memory()
	assert.NotNil(t, memory)

	working := memory.Working()
	working.Set("key", "value")
	val, found := working.Get("key")
	assert.True(t, found)
	assert.Equal(t, "value", val)
}

// TestMemoryWrapper_WithFactory verifies wrapper works with MemoryFactory
func TestMemoryWrapper_WithFactory(t *testing.T) {
	wrapperCalled := false
	var wrappedMM memory.MemoryManager

	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(nil),
		MemoryFactory: func(missionID types.ID, tenantID string) (memory.MemoryManager, error) {
			return newMockMemoryManager(missionID), nil
		},
		MemoryWrapper: func(mm memory.MemoryManager) memory.MemoryManager {
			wrapperCalled = true
			wrappedMM = memory.NewTracedMemoryManager(mm, trace.NewNoopTracerProvider().Tracer("test"))
			return wrappedMM
		},
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}
	targetInfo := TargetInfo{
		ID:   types.NewID(),
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Verify wrapper was called
	assert.True(t, wrapperCalled, "MemoryWrapper should have been called with MemoryFactory")
	assert.NotNil(t, wrappedMM, "Wrapper should have returned a wrapped memory manager")

	// Verify basic operations work
	memory := harness.Memory()
	working := memory.Working()
	working.Set("key", "value")
	val, found := working.Get("key")
	assert.True(t, found)
	assert.Equal(t, "value", val)
}
