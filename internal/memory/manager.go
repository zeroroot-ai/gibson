package memory

import (
	"sync"

	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MemoryManager provides unified memory access for a mission with lifecycle management.
// It extends MemoryStore with MissionID() and Close() for resource management.
type MemoryManager interface {
	MemoryStore

	// MissionID returns the mission this manager is scoped to.
	MissionID() types.ID

	// Close releases all resources held by the memory manager.
	// It clears working memory and closes the vector store.
	Close() error
}

// DefaultMemoryManager implements MemoryManager by composing all memory tiers.
type DefaultMemoryManager struct {
	missionID types.ID
	working   WorkingMemory
	mission   MissionMemory
	longTerm  LongTermMemory
	store     vector.VectorStore
	closeMu   sync.Mutex
	closed    bool
}

// NewMemoryManagerWithComponents creates a new MemoryManager with pre-initialized components.
// This is used by the factory when creating Redis-backed memory managers.
//
// Parameters:
//   - missionID: The mission ID to scope this memory manager to
//   - working: Pre-initialized working memory instance
//   - mission: Pre-initialized mission memory instance
//   - longTerm: Pre-initialized long-term memory instance
//   - store: Pre-initialized vector store instance
//
// Returns a MemoryManager ready for use.
func NewMemoryManagerWithComponents(
	missionID types.ID,
	working WorkingMemory,
	mission MissionMemory,
	longTerm LongTermMemory,
	store vector.VectorStore,
) MemoryManager {
	return &DefaultMemoryManager{
		missionID: missionID,
		working:   working,
		mission:   mission,
		longTerm:  longTerm,
		store:     store,
		closed:    false,
	}
}

// Working returns the working memory instance.
func (m *DefaultMemoryManager) Working() WorkingMemory {
	return m.working
}

// Mission returns the mission memory instance.
func (m *DefaultMemoryManager) Mission() MissionMemory {
	return m.mission
}

// LongTerm returns the long-term memory instance.
func (m *DefaultMemoryManager) LongTerm() LongTermMemory {
	return m.longTerm
}

// MissionID returns the mission ID this manager is scoped to.
func (m *DefaultMemoryManager) MissionID() types.ID {
	return m.missionID
}

// Close releases all resources held by the memory manager.
// This method is idempotent and safe to call multiple times.
func (m *DefaultMemoryManager) Close() error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()

	if m.closed {
		return nil
	}

	// Clear working memory (ephemeral)
	m.working.Clear()

	// Close vector store
	if m.store != nil {
		if err := m.store.Close(); err != nil {
			return NewVectorStoreError("failed to close vector store", err)
		}
	}

	m.closed = true
	return nil
}
