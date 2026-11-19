// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func inboundAgentNode(id, agent string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Id:     id,
		Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{AgentName: agent}},
	}
}

type inboundSourceFixture struct {
	source *inboundMissionSource
	ctx    context.Context
	target *types.Target
}

func newInboundSourceFixture(t *testing.T) *inboundSourceFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	tenant := auth.MustNewTenantID("acme")
	ctx := auth.WithTenant(context.Background(), tenant)
	require.NoError(t, mission.NewConnBoundMissionStore(rdb).CreateDefinition(ctx, &missionpb.MissionDefinition{
		Id: "def-1", Name: "recon-def",
		Nodes: map[string]*missionpb.MissionNode{
			"a": inboundAgentNode("a", "recon"),
			"b": inboundAgentNode("b", "scanner"),
			"c": {Id: "c"},
		},
	}))
	target := &types.Target{ID: types.NewID(), TenantID: tenant.String(), Name: "t1"}
	other := &types.Target{ID: types.NewID(), TenantID: "victim-co", Name: "t2"}
	return &inboundSourceFixture{
		source: &inboundMissionSource{
			pool:    &mockPool{conn: &datapool.Conn{Redis: rdb}},
			targets: &fakeTargetsByID{byID: map[types.ID]*types.Target{target.ID: target, other.ID: other}},
		},
		ctx:    ctx,
		target: target,
	}
}

type fakeTargetsByID struct{ byID map[types.ID]*types.Target }

func (f *fakeTargetsByID) Get(_ context.Context, id types.ID) (*types.Target, error) {
	return f.byID[id], nil
}

func TestInboundMissionSource_DefinitionAgents(t *testing.T) {
	f := newInboundSourceFixture(t)

	agents, err := f.source.DefinitionAgents(f.ctx, "recon-def")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"recon", "scanner"}, agents, "only agent nodes name an agent")

	agents, err = f.source.DefinitionAgents(f.ctx, "def-1")
	require.NoError(t, err, "the definition is found by ID too")
	assert.Len(t, agents, 2)

	_, err = f.source.DefinitionAgents(f.ctx, "missing")
	assert.ErrorIs(t, err, api.ErrInboundDefinitionNotFound)

	_, err = f.source.DefinitionAgents(context.Background(), "recon-def")
	assert.ErrorIs(t, err, errNoTenantInContext)

	f.source.pool = &mockPool{err: errors.New("pool down")}
	_, err = f.source.DefinitionAgents(f.ctx, "recon-def")
	assert.ErrorContains(t, err, "pool down")
}

func TestInboundMissionSource_CheckTargets(t *testing.T) {
	f := newInboundSourceFixture(t)
	require.NoError(t, f.source.CheckTargets(f.ctx, []string{f.target.ID.String()}))

	var other types.ID
	for id, tg := range f.source.targets.(*fakeTargetsByID).byID {
		if tg.TenantID == "victim-co" {
			other = id
		}
	}
	for name, id := range map[string]string{
		"a target of another tenant": other.String(),
		"an unknown target":          types.NewID().String(),
		"a name and not a UUID":      "t1",
	} {
		assert.ErrorIs(t, f.source.CheckTargets(f.ctx, []string{id}), api.ErrInboundTargetNotFound, name)
	}
}

func TestRegisterInboundMission_NeedsThePoolTheAuthorizerAndTheTargetStore(t *testing.T) {
	ctx := context.Background()
	keys := pageKeysForTest(t)
	srv := grpc.NewServer()

	d := newMinimalDaemon(nil)
	require.ErrorContains(t, d.registerInboundMission(ctx, srv, keys), "needs the per-tenant data pool")

	d.pool = stubPool{}
	require.ErrorContains(t, d.registerInboundMission(ctx, srv, keys), "needs the authorizer")

	d.authorizer = stubAuthorizer{}
	require.ErrorContains(t, d.registerInboundMission(ctx, srv, keys), "needs the target store")

	d.targetStore = &fakeTargetStoreForMission{}
	require.NoError(t, d.registerInboundMission(ctx, srv, keys))
	assert.NotNil(t, d.inboundMissions)
	assert.Contains(t, srv.GetServiceInfo(), "gibson.tenant.v1.InboundMissionService")
}
