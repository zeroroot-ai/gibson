// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type anchorCall struct {
	tenant, missionID string
	params            map[string]string
}

func scanOriginRequest(t *testing.T, name string) (anchors *[]anchorCall, run func() error) {
	t.Helper()
	mgr := &recordingMissionOperator{}
	got := &[]anchorCall{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")
	WithScanAnchorSink(func(_ context.Context, tenant, missionID string, params map[string]string) {
		*got = append(*got, anchorCall{tenant, missionID, params})
	})(svc)
	req := originRequest()
	req.MissionDefinitionJson = nil
	req.CatalogMission = name
	req.CatalogParams = catalogParams(t, name)
	return got, func() error {
		resp, err := svc.CreateMission(originCtx(), req)
		if err != nil {
			return err
		}
		require.Nil(t, resp.GetError(), "the origination must succeed")
		return nil
	}
}

// A scan mission that an agent originates by name hands its parameters to the
// sink, with the tenant of the parent mission and the id of the new mission.
func TestCreateMission_ScanMissionAnchorsItsApplication(t *testing.T) {
	got, run := scanOriginRequest(t, "scan")
	require.NoError(t, run())
	require.Len(t, *got, 1)
	assert.Equal(t, originTenant, (*got)[0].tenant, "the tenant comes from the parent mission")
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", (*got)[0].missionID)
	assert.NotEmpty(t, (*got)[0].params["application"])
	assert.NotEmpty(t, (*got)[0].params["repositoryUrl"])
}

// Another catalog mission has no anchors.
func TestCreateMission_OtherCatalogMissionsWriteNoAnchor(t *testing.T) {
	got, run := scanOriginRequest(t, "fix")
	require.NoError(t, run())
	assert.Empty(t, *got)
}
