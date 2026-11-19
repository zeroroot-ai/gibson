// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The run template carries the target set, the creator and the suffixed name of
// the request. The first target is the primary one.
func TestNewRunTemplate_CarriesTheTargetSetTheCreatorAndTheSuffixedName(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id: "def-1", Name: "recon", Description: "d", Nodes: map[string]*missionpb.MissionNode{"a": {Id: "a"}},
	}
	primary, extra := types.NewID(), types.NewID()
	creator := principal.Principal{Kind: principal.Component, ID: "agent_principal:9"}
	req := api.RunMissionData{
		MissionDefinitionID: "def-1", NameSuffix: " (a2a 1234)", CreatedBy: creator,
		Variables: map[string]string{"a2a_task_input": "scan"}, MemoryContinuity: "keep",
	}

	got := newRunTemplate(auth.MustNewTenantID("acme"), def, `{"id":"def-1"}`, req, primary, []types.ID{extra}, "https://t")

	assert.Equal(t, "recon (a2a 1234)", got.Name)
	assert.Equal(t, "acme", got.TenantID)
	assert.Equal(t, creator, got.CreatedBy)
	assert.Equal(t, []types.ID{primary, extra}, got.TargetSet())
	assert.Equal(t, "keep", got.MemoryContinuity)
	assert.Equal(t, 1, got.Metrics.TotalNodes)
	assert.Equal(t, map[string]string{"a2a_task_input": "scan"}, got.Metadata["variables"])
	assert.Equal(t, "https://t", got.Metadata["target_ref"])
}

func TestNewRunTemplate_WithNoSuffixKeepsTheDefinitionNameAndAddsNoMetadata(t *testing.T) {
	def := &missionpb.MissionDefinition{Id: "def-1", Name: "recon"}
	got := newRunTemplate(auth.MustNewTenantID("acme"), def, "{}", api.RunMissionData{}, types.NewID(), nil, "")

	assert.Equal(t, "recon", got.Name)
	assert.True(t, got.CreatedBy.IsZero())
	assert.Len(t, got.TargetSet(), 1)
	assert.Empty(t, got.Metadata)
}

// Each target of the request gets the ownership check of the primary one. A
// target of another tenant is not found, and no mission starts.
func TestRun_RefusesATargetSetWithATargetOfAnotherTenant(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tenant := auth.MustNewTenantID("acme")
	ctx := auth.WithTenant(context.Background(), tenant)
	require.NoError(t, mission.NewConnBoundMissionStore(rdb).CreateDefinition(ctx,
		&missionpb.MissionDefinition{Id: "def-1", Name: "recon"}))

	own := &types.Target{ID: types.NewID(), TenantID: "acme", Name: "own"}
	foreign := &types.Target{ID: types.NewID(), TenantID: "victim-co", Name: "foreign"}
	mm := helperMM()
	mm.pool = &mockPool{conn: &datapool.Conn{Redis: rdb}}
	mm.targetStore = &fakeTargetsByID{byID: map[types.ID]*types.Target{own.ID: own, foreign.ID: foreign}}

	_, err := mm.Run(ctx, api.RunMissionData{
		MissionDefinitionID: "recon", TargetIDs: []string{own.ID.String(), foreign.ID.String()},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Empty(t, mm.activeMissions, "no mission started")
}
