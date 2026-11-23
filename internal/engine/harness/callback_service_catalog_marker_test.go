// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
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
