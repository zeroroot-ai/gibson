// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// RunCatalogMission refuses before it creates anything: a call with no tenant, a
// mission that does not render, and a target that is not an id.
func TestRunCatalogMission_RefusesBeforeItCreatesAMission(t *testing.T) {
	d := &daemonImpl{}
	good := map[string]string{"repositoryUrl": "https://github.com/acme/shop", "application": "acme/shop", "forgeConnector": "github-fixloop"}

	_, err := d.RunCatalogMission(context.Background(), api.RunCatalogMissionData{Name: "scan", Params: good, TargetID: "t"})
	require.Error(t, err, "a call with no tenant must be refused")

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err = d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: map[string]string{"application": "acme/shop"}, TargetID: "t"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a scan with no branch does not render")

	_, err = d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: good, TargetID: "not-an-id"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a target that is not an id is refused")
}

// A catalog launch creates the record that the person path creates (tenant,
// creator, times), starts the mission, and writes the scan anchors only after the
// start. The caller sees the mission, and a mission that did not start leaves no
// anchor.
func TestRunCatalogMission_SuccessPathStampsTheRecordAndWritesTheAnchorsAfterTheStart(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	ctx, cancel := context.WithCancel(auth.ContextWithTenantString(context.Background(), "acme"))
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	d := testDaemon(rdb, &fakeAuthorizer{})
	d.brainRegistry = reg

	var order []string
	var anchoredFor string
	d.startMission = func(_ context.Context, id string) error { order = append(order, "start:"+id); return nil }
	d.scanAnchors = func(_ context.Context, tenant, missionID string, params map[string]string) {
		order = append(order, "anchors:"+missionID)
		anchoredFor = tenant + "/" + params["application"]
	}
	targetID := types.NewID()
	creator := principal.FromIdentity(auth.Identity{Subject: "user:alice"})
	params := map[string]string{"repositoryUrl": "https://github.com/acme/shop", "application": "acme/shop", "forgeConnector": "github-fixloop"}

	id, err := d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: params, TargetID: targetID.String(), CreatedBy: creator})
	require.NoError(t, err)
	assert.Equal(t, []string{"start:" + id, "anchors:" + id}, order, "the anchors come after the start")
	assert.Equal(t, "acme/acme/shop", anchoredFor)

	// The record carries what ListMissions filters on.
	parsed, err := types.ParseID(id)
	require.NoError(t, err)
	rec, err := d.newMissionStore(rdb, "acme").Get(ctx, parsed)
	require.NoError(t, err)
	assert.Equal(t, "acme", rec.TenantID, "ListMissions filters on the tenant of the record")
	assert.Equal(t, creator, rec.CreatedBy)
	assert.False(t, rec.CreatedAt.Time.IsZero())
	assert.Equal(t, "scan", rec.Name)
	assert.Equal(t, mission.MissionStatusSubmitted, rec.Status)
	assert.Equal(t, targetID, rec.TargetID)
	assert.Equal(t, "scan", rec.Metadata[metadataCatalogMission])

	// The World shows the mission with its creator before it runs.
	require.Eventually(t, func() bool {
		var seen bool
		reg.For("acme").ReadWorld(func(w *brain.World) {
			for _, m := range w.MissionSnapshot() {
				seen = seen || (m.ID == id && m.Name == "scan")
			}
		})
		return seen
	}, 3*time.Second, 10*time.Millisecond, "the caller sees the mission in the World")

	// A mission that does not start leaves no anchor.
	order = nil
	d.startMission = func(context.Context, string) error { return errors.New("no capacity") }
	_, err = d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: params, TargetID: targetID.String(), CreatedBy: creator})
	require.Error(t, err)
	assert.Empty(t, order, "a failed start writes no anchor")
}
