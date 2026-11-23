// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// A definition with the name of a checked-in mission never starts through the
// definition path. The path is the one of RunMission and of the inbound A2A start,
// and a definition stored before the name was reserved may still hold the name
// (gibson#1469).
func TestRun_ADefinitionNamedLikeACatalogMissionIsRefused(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	ctx := tenantTestCtx(t)
	m := &missionManager{pool: &mockPool{conn: &datapool.Conn{Redis: rdb}}, logger: slog.New(slog.DiscardHandler)}

	store, release, err := m.missionStoreFor(ctx, auth.MustNewTenantID("acme"))
	require.NoError(t, err)
	defer release()
	require.NoError(t, store.CreateDefinition(ctx, &missionpb.MissionDefinition{Id: "def-old", Name: "scan"}))

	_, err = m.Run(ctx, api.RunMissionData{MissionDefinitionID: "def-old", TargetIDs: []string{"t"}})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err), "err = %v", err)
}
