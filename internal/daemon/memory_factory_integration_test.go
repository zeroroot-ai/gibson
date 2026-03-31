package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestMemoryFactoryIntegration tests the full integration of MemoryManagerFactory
// with the daemon infrastructure.
func TestMemoryFactoryIntegration(t *testing.T) {
	t.Run("factory creates functional memory managers", func(t *testing.T) {
		sc := setupTestStateClient(t)

		factory, err := NewMemoryManagerFactory(sc, nil)
		require.NoError(t, err)

		ctx := context.Background()
		missionID := types.NewID()

		// Create memory manager
		mgr, err := factory.CreateForMission(ctx, missionID, "")
		require.NoError(t, err)
		require.NotNil(t, mgr)
		defer mgr.Close()

		// Verify mission ID
		assert.Equal(t, missionID, mgr.MissionID())

		// Test working memory
		err = mgr.Working().Set("integration-test", "success")
		assert.NoError(t, err)
		val, exists := mgr.Working().Get("integration-test")
		assert.True(t, exists)
		assert.Equal(t, "success", val)

		// Test all memory tiers are accessible
		assert.NotNil(t, mgr.Working())
		assert.NotNil(t, mgr.Mission())
		assert.NotNil(t, mgr.LongTerm())
	})

	t.Run("multiple missions have isolated memory", func(t *testing.T) {
		sc := setupTestStateClient(t)

		factory, err := NewMemoryManagerFactory(sc, nil)
		require.NoError(t, err)

		ctx := context.Background()

		// Create two missions
		missionID1 := types.NewID()
		missionID2 := types.NewID()

		mgr1, err := factory.CreateForMission(ctx, missionID1, "")
		require.NoError(t, err)
		defer mgr1.Close()

		mgr2, err := factory.CreateForMission(ctx, missionID2, "")
		require.NoError(t, err)
		defer mgr2.Close()

		// Set data in both managers
		err = mgr1.Working().Set("mission-data", "mission-1-value")
		assert.NoError(t, err)
		err = mgr2.Working().Set("mission-data", "mission-2-value")
		assert.NoError(t, err)

		// Verify isolation
		val1, exists1 := mgr1.Working().Get("mission-data")
		val2, exists2 := mgr2.Working().Get("mission-data")

		assert.True(t, exists1)
		assert.True(t, exists2)
		assert.Equal(t, "mission-1-value", val1)
		assert.Equal(t, "mission-2-value", val2)
	})
}
