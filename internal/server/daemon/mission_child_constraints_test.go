// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// A child that a mission originates inherits the health hold of its parent. The fix
// loop reads the hold of the child that delivered the merge request, so the hold of
// the fix mission must reach it (gibson#1469).
func TestHarnessCreate_ChildInheritsTheHealthHoldOfItsParent(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	d := testDaemon(rdb, &fakeAuthorizer{})
	a := newMissionHarnessAdapter(d)
	ctx := tenantTestCtx(t)

	parentDef, err := mission.MarshalDefinitionJSON(&missionpb.MissionDefinition{
		Name:        "parent",
		Constraints: &missionpb.MissionConstraints{HealthHold: durationpb.New(2 * time.Minute), RestartLimit: durationpb.New(7 * time.Minute)},
	})
	require.NoError(t, err)
	parent := newTenantMission("parent")
	parent.MissionDefinitionJSON = string(parentDef)
	require.NoError(t, d.newMissionStore(rdb, "acme").Save(ctx, parent))

	// The child definition is built by the agent with no constraints.
	childDef, err := mission.MarshalDefinitionJSON(&missionpb.MissionDefinition{Name: "fix one"})
	require.NoError(t, err)
	info, err := a.CreateMission(ctx, &harness.MissionClientCreateRequest{
		MissionDefinitionJSON: string(childDef), TargetID: types.NewID(), ParentMissionID: &parent.ID,
	})
	require.NoError(t, err)

	rec, err := d.newMissionStore(rdb, "acme").Get(ctx, info.ID)
	require.NoError(t, err)
	hold, err := fixHoldOf(rec)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, hold, "the fix loop reads the hold of the parent")

	// A child cannot shorten the hold. A longer hold of the child wins.
	own, err := mission.MarshalDefinitionJSON(&missionpb.MissionDefinition{
		Name: "fix two", Constraints: &missionpb.MissionConstraints{HealthHold: durationpb.New(10 * time.Second)},
	})
	require.NoError(t, err)
	info, err = a.CreateMission(ctx, &harness.MissionClientCreateRequest{
		MissionDefinitionJSON: string(own), TargetID: types.NewID(), ParentMissionID: &parent.ID,
	})
	require.NoError(t, err)
	rec, err = d.newMissionStore(rdb, "acme").Get(ctx, info.ID)
	require.NoError(t, err)
	hold, err = fixHoldOf(rec)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, hold, "a shorter hold of the child loses")

	// A parent that is not in the store stops the origination.
	missing := types.NewID()
	_, err = a.CreateMission(ctx, &harness.MissionClientCreateRequest{
		MissionDefinitionJSON: string(childDef), TargetID: types.NewID(), ParentMissionID: &missing,
	})
	require.Error(t, err)
}
