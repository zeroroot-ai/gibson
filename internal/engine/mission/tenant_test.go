package mission

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestMission_WithTenant verifies the WithTenant method sets the TenantID correctly
func TestMission_WithTenant(t *testing.T) {
	m := &Mission{
		ID:                  types.NewID(),
		Name:                "Test Mission",
		Description:         "Test Description",
		Status:              MissionStatusPending,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		CreatedAt:           NewUnixTimeNow(),
		UpdatedAt:           NewUnixTimeNow(),
	}

	// Set tenant ID
	m = m.WithTenant("tenant-123")

	assert.Equal(t, "tenant-123", m.TenantID, "TenantID should be set")
}

// TestMission_TenantSerialization verifies JSON serialization with TenantID
func TestMission_TenantSerialization(t *testing.T) {
	m := &Mission{
		ID:                  types.NewID(),
		Name:                "Test Mission",
		Description:         "Test Description",
		Status:              MissionStatusPending,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		CreatedAt:           NewUnixTimeNow(),
		UpdatedAt:           NewUnixTimeNow(),
	}
	m = m.WithTenant("tenant-456")

	// Marshal to JSON
	data, err := json.Marshal(m)
	require.NoError(t, err, "Should marshal without error")

	// Unmarshal back
	var m2 Mission
	err = json.Unmarshal(data, &m2)
	require.NoError(t, err, "Should unmarshal without error")

	// Verify TenantID is preserved
	assert.Equal(t, m.TenantID, m2.TenantID, "TenantID should be preserved through serialization")
	assert.Equal(t, "tenant-456", m2.TenantID, "TenantID should match")
}

// TestMission_BackwardCompatibility verifies missions without TenantID can be loaded
func TestMission_BackwardCompatibility(t *testing.T) {
	// Create valid UUIDs for testing
	missionID := types.NewID()
	targetID := types.NewID()
	missionDefinitionID := types.NewID()

	// Simulate old JSON without tenant_id field
	oldJSON := `{
		"id": "` + string(missionID) + `",
		"name": "Old Mission",
		"description": "Old Description",
		"status": "pending",
		"target_id": "` + string(targetID) + `",
		"mission_definition_id": "` + string(missionDefinitionID) + `",
		"progress": 0,
		"findings_count": 0,
		"run_number": 0,
		"depth": 0,
		"created_at": 0,
		"updated_at": 0
	}`

	var m Mission
	err := json.Unmarshal([]byte(oldJSON), &m)
	require.NoError(t, err, "Should unmarshal old JSON without tenant_id")

	// Verify TenantID is empty (zero value)
	assert.Equal(t, "", m.TenantID, "TenantID should be empty for old data")

	// Verify other fields are loaded correctly
	assert.Equal(t, missionID, m.ID)
	assert.Equal(t, "Old Mission", m.Name)
	assert.Equal(t, MissionStatusPending, m.Status)
}

// TestMission_OmitemptyBehavior verifies omitempty tag works correctly
func TestMission_OmitemptyBehavior(t *testing.T) {
	// Mission without TenantID should not include tenant_id in JSON
	m := &Mission{
		ID:                  types.NewID(),
		Name:                "Test Mission",
		Description:         "Test Description",
		Status:              MissionStatusPending,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		CreatedAt:           NewUnixTimeNow(),
		UpdatedAt:           NewUnixTimeNow(),
	}

	data, err := json.Marshal(m)
	require.NoError(t, err)

	// Parse to map to check fields
	var mapData map[string]interface{}
	err = json.Unmarshal(data, &mapData)
	require.NoError(t, err)

	// tenant_id should not be present when empty
	_, hasTenantID := mapData["tenant_id"]
	assert.False(t, hasTenantID, "tenant_id should not be present when empty due to omitempty")

	// Mission with TenantID should include it
	m = m.WithTenant("tenant-789")
	data, err = json.Marshal(m)
	require.NoError(t, err)

	err = json.Unmarshal(data, &mapData)
	require.NoError(t, err)

	tenantID, hasTenantID := mapData["tenant_id"]
	assert.True(t, hasTenantID, "tenant_id should be present when set")
	assert.Equal(t, "tenant-789", tenantID, "tenant_id should have correct value")
}

// TestMission_MethodChaining verifies WithTenant can be chained with other methods
func TestMission_MethodChaining(t *testing.T) {
	parentID := types.NewID()

	m := &Mission{
		ID:                  types.NewID(),
		Name:                "Test Mission",
		Description:         "Test Description",
		Status:              MissionStatusPending,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		CreatedAt:           NewUnixTimeNow(),
		UpdatedAt:           NewUnixTimeNow(),
	}

	// Chain methods
	m = m.WithTenant("tenant-abc").
		WithParent(parentID, 0).
		WithMemoryContinuity(MemoryContinuityShared)

	assert.Equal(t, "tenant-abc", m.TenantID, "TenantID should be set")
	assert.Equal(t, parentID, *m.ParentMissionID, "ParentMissionID should be set")
	assert.Equal(t, MemoryContinuityShared, m.MemoryContinuity, "MemoryContinuity should be set")
	assert.Equal(t, 1, m.Depth, "Depth should be incremented")
}
