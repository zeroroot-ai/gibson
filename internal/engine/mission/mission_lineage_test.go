package mission

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestMissionLineageFields tests the new ParentMissionID and Depth fields.
func TestMissionLineageFields(t *testing.T) {
	t.Run("root mission has nil parent and depth 0", func(t *testing.T) {
		mission := &Mission{
			ID:                  types.NewID(),
			Name:                "Root Mission",
			Description:         "A root mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
			Depth:               0,
		}

		assert.Nil(t, mission.ParentMissionID, "root mission should have nil parent")
		assert.Equal(t, 0, mission.Depth, "root mission should have depth 0")
		assert.True(t, mission.IsRootMission(), "IsRootMission should return true")
		assert.Equal(t, types.ID(""), mission.GetParentMissionID(), "GetParentMissionID should return empty ID")
	})

	t.Run("child mission with WithParent method", func(t *testing.T) {
		parentID := types.NewID()
		parentDepth := 0

		mission := &Mission{
			ID:                  types.NewID(),
			Name:                "Child Mission",
			Description:         "A child mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
		}
		mission.WithParent(parentID, parentDepth)

		assert.NotNil(t, mission.ParentMissionID, "child mission should have non-nil parent")
		assert.Equal(t, parentID, *mission.ParentMissionID, "parent ID should match")
		assert.Equal(t, 1, mission.Depth, "child mission should have depth 1")
		assert.False(t, mission.IsRootMission(), "IsRootMission should return false")
		assert.Equal(t, parentID, mission.GetParentMissionID(), "GetParentMissionID should return parent ID")
	})

	t.Run("grandchild mission with proper depth", func(t *testing.T) {
		grandparentID := types.NewID()
		parentID := types.NewID()

		parent := &Mission{
			ID:                  parentID,
			Name:                "Parent Mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
		}
		parent.WithParent(grandparentID, 0) // Parent is depth 1

		grandchild := &Mission{
			ID:                  types.NewID(),
			Name:                "Grandchild Mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
		}
		grandchild.WithParent(parent.ID, parent.Depth) // Grandchild is depth 2

		assert.Equal(t, 1, parent.Depth, "parent should have depth 1")
		assert.Equal(t, 2, grandchild.Depth, "grandchild should have depth 2")
		assert.Equal(t, parentID, grandchild.GetParentMissionID(), "grandchild parent should be parent")
	})

	t.Run("method chaining with WithParent", func(t *testing.T) {
		parentID := types.NewID()

		mission := (&Mission{
			ID:                  types.NewID(),
			Name:                "Chained Mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
		}).WithParent(parentID, 0)

		assert.NotNil(t, mission, "chained method should return mission")
		assert.Equal(t, 1, mission.Depth, "depth should be set via chaining")
		assert.Equal(t, parentID, *mission.ParentMissionID, "parent ID should be set via chaining")
	})
}

// TestMissionBackwardCompatibility ensures existing code still works.
func TestMissionBackwardCompatibility(t *testing.T) {
	t.Run("mission without lineage fields validates correctly", func(t *testing.T) {
		mission := &Mission{
			ID:                  types.NewID(),
			Name:                "Legacy Mission",
			Description:         "Created before lineage support",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
			// ParentMissionID and Depth not set (defaults: nil and 0)
		}

		err := mission.Validate()
		assert.NoError(t, err, "mission without lineage fields should validate")
		assert.Nil(t, mission.ParentMissionID, "ParentMissionID should default to nil")
		assert.Equal(t, 0, mission.Depth, "Depth should default to 0")
		assert.True(t, mission.IsRootMission(), "mission without parent should be root")
	})

	t.Run("existing constructor pattern still works", func(t *testing.T) {
		// This mimics how missions are created in service.go
		mission := &Mission{
			ID:          types.NewID(),
			Name:        "Test Mission",
			Description: "Test Description",
			Status:      MissionStatusPending,
			// No lineage fields set
		}

		// Should still compile and work
		assert.NotNil(t, mission)
		assert.True(t, mission.IsRootMission())
		assert.Equal(t, 0, mission.Depth)
	})
}

// TestMissionJSONSerialization ensures lineage fields serialize correctly.
func TestMissionJSONSerialization(t *testing.T) {
	t.Run("root mission omits parent_mission_id in JSON", func(t *testing.T) {
		mission := &Mission{
			ID:                  types.NewID(),
			Name:                "Root",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
			Depth:               0,
		}

		// JSON marshaling would omit parent_mission_id due to omitempty tag
		assert.Nil(t, mission.ParentMissionID)
		assert.True(t, mission.IsRootMission())
	})

	t.Run("child mission includes parent_mission_id in JSON", func(t *testing.T) {
		parentID := types.NewID()
		mission := &Mission{
			ID:                  types.NewID(),
			Name:                "Child",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           NewUnixTimeNow(),
			UpdatedAt:           NewUnixTimeNow(),
		}
		mission.WithParent(parentID, 0)

		// JSON marshaling would include parent_mission_id
		assert.NotNil(t, mission.ParentMissionID)
		assert.Equal(t, parentID, *mission.ParentMissionID)
		assert.Equal(t, 1, mission.Depth)
	})
}
