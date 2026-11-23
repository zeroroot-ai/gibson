// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	sdkmission "github.com/zeroroot-ai/sdk/mission"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func originate(t *testing.T, req *harnesspb.CreateMissionRequest) (*harnesspb.CreateMissionResponse, *MissionClientCreateRequest) {
	t.Helper()
	client := &recordingMissionClient{}
	svc := newOriginService(t, NewMissionOperatorAdapter(client), originParentMissionID, "zerocool")
	resp, err := svc.CreateMission(originCtx(), req)
	require.NoError(t, err)
	return resp, client.got
}

// An agent that originates the catalog scan marks the mission as a catalog
// launch. The marker comes from the name that the agent gave, so a rescan and the
// ingest of the dependency alerts accept the mission (gibson#1469).
func TestCreateMission_ACatalogLaunchCarriesTheMarker(t *testing.T) {
	req := originRequest()
	req.MissionDefinitionJson = nil
	req.CatalogMission = "scan"
	req.CatalogParams = map[string]string{"imageRef": "registry.example.com/shop@sha256:abc"}
	resp, got := originate(t, req)
	require.Nil(t, resp.GetError(), "the catalog scan must be created: %v", resp.GetError())
	require.NotNil(t, got)
	assert.Equal(t, "scan", got.Metadata[mission.MetadataCatalogMission])
}

// A graph of the caller gets no marker, a forged marker in the payload is removed,
// and a graph named like a checked-in mission is refused.
func TestCreateMission_AGraphOfTheCallerNeverGetsTheMarkerOrACatalogName(t *testing.T) {
	req := originRequest()
	req.Metadata = map[string]*commonpb.TypedValue{
		mission.MetadataCatalogMission: {Kind: &commonpb.TypedValue_StringValue{StringValue: "scan"}},
	}
	resp, got := originate(t, req)
	require.Nil(t, resp.GetError())
	_, forged := got.Metadata[mission.MetadataCatalogMission]
	assert.False(t, forged, "a marker in the payload of a caller is removed")

	named := originRequest()
	named.MissionDefinitionJson = []byte(`{"name":"scan"}`)
	resp, got = originate(t, named)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetError().GetCode(), "a graph named scan is refused")
	assert.Nil(t, got, "no mission is created")

	byName := originRequest()
	byName.Name = "Scan"
	resp, got = originate(t, byName)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.GetError().GetCode(), "the name of the request counts, in any letter case")
	assert.Nil(t, got)
}

// The harness method CreateMission (an interface method that this change cannot prove
// dead) takes the same check as the callback path: a forged marker is removed, the
// caller's map is not changed, and a graph with a catalog name is refused.
func TestDefaultAgentHarnessCreateMission_TakesTheSameGuard(t *testing.T) {
	client := newMockMissionOperator()
	parentID := types.NewID()
	client.records = append(client.records, &MissionRecord{ID: parentID, Status: MissionStatusWorking})
	h := createTestMissionHarness(client, DefaultSpawnLimits())
	h.missionCtx.ID = parentID

	own := map[string]any{mission.MetadataCatalogMission: "scan", "keep": "yes"}
	_, err := h.CreateMission(context.Background(), map[string]any{"name": "my-graph"}, types.NewID().String(),
		&sdkmission.CreateMissionOpts{Name: "mine", Metadata: own})
	require.NoError(t, err)
	_, forged := client.lastCreate.Metadata[mission.MetadataCatalogMission]
	assert.False(t, forged, "a forged marker is removed")
	assert.Equal(t, "yes", client.lastCreate.Metadata["keep"])
	assert.Equal(t, "scan", own[mission.MetadataCatalogMission], "the map of the caller is not changed")

	client.lastCreate = nil
	_, err = h.CreateMission(context.Background(), map[string]any{"name": "scan"}, types.NewID().String(), nil)
	require.Error(t, err, "a graph named scan is refused")
	assert.Nil(t, client.lastCreate, "no mission is created")
	_, err = h.CreateMission(context.Background(), map[string]any{"name": "x"}, types.NewID().String(),
		&sdkmission.CreateMissionOpts{Name: "SCAN"})
	require.Error(t, err, "the name of the options counts, in any letter case")
}

// The marker holds the canonical name that the render returns.
func TestResolveMissionDefinitionJSON_ReturnsTheCanonicalCatalogName(t *testing.T) {
	_, name, err := resolveMissionDefinitionJSON(context.Background(), &harnesspb.CreateMissionRequest{
		CatalogMission: "  scan ", CatalogParams: map[string]string{"imageRef": "r/i@sha256:abc"},
	})
	require.NoError(t, err)
	assert.Equal(t, "scan", name)
	_, name, err = resolveMissionDefinitionJSON(context.Background(), &harnesspb.CreateMissionRequest{MissionDefinitionJson: []byte(`{"name":"x"}`)})
	require.NoError(t, err)
	assert.Empty(t, name, "a graph of the caller has no catalog name")
}
