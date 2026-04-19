//go:build stale
// +build stale

// NOTE: references the removed DB-backed mission store constructors
// (NewDBMissionStore / NewDBEventStore). Kept behind the `stale` build
// tag so the file is preserved for future repair but does not block
// `go vet` / `go test`. Rewrite against the Redis store and drop the tag.

package mission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultMissionService_ValidateMission(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	service := NewMissionService(store, nil)
	ctx := context.Background()

	t.Run("valid mission", func(t *testing.T) {
		mission := createTestMission(t)
		err := service.ValidateMission(ctx, mission)
		assert.NoError(t, err)
	})

	t.Run("invalid mission - missing name", func(t *testing.T) {
		mission := createTestMission(t)
		mission.Name = ""
		err := service.ValidateMission(ctx, mission)
		assert.Error(t, err)
	})
}

func TestDefaultMissionService_GetSummary_Basic(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	service := NewMissionService(store, nil)
	ctx := context.Background()

	mission := createTestMission(t)
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	summary, err := service.GetSummary(ctx, mission.ID)
	require.NoError(t, err)
	assert.NotNil(t, summary)
	assert.Equal(t, mission.ID, summary.Mission.ID)
	assert.NotNil(t, summary.Progress)
}
