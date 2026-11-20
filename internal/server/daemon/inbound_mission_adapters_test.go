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
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
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

func TestInboundMissionSource_DefinitionPinsTheContent(t *testing.T) {
	f := newInboundSourceFixture(t)

	def, err := f.source.Definition(f.ctx, "recon-def")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"recon", "scanner"}, def.Agents, "only agent nodes name an agent")
	assert.Equal(t, "def-1", def.ID)
	assert.Len(t, def.Hash, 64)

	byID, err := f.source.Definition(f.ctx, "def-1")
	require.NoError(t, err, "the definition is found by ID too")
	assert.Equal(t, def.Hash, byID.Hash)

	_, err = f.source.Definition(f.ctx, "missing")
	require.ErrorIs(t, err, api.ErrInboundDefinitionNotFound)
	_, err = f.source.Definition(context.Background(), "recon-def")
	require.ErrorIs(t, err, errNoTenantInContext)
	f.source.pool = &mockPool{err: errors.New("pool down")}
	_, err = f.source.Definition(f.ctx, "recon-def")
	require.ErrorContains(t, err, "pool down")
}

// A change of the budget, the scope or a node changes the hash of the definition.
func TestInboundMissionSource_DefinitionHashChangesWithTheContent(t *testing.T) {
	f := newInboundSourceFixture(t)
	before, err := f.source.Definition(f.ctx, "recon-def")
	require.NoError(t, err)

	conn, err := f.source.pool.For(f.ctx, auth.MustNewTenantID("acme"))
	require.NoError(t, err)
	store := mission.NewConnBoundMissionStore(conn.Redis)
	def, err := store.GetDefinition(f.ctx, "recon-def")
	require.NoError(t, err)
	def.Constraints = &missionpb.MissionConstraints{MaxTokens: 1 << 30}
	require.NoError(t, store.UpdateDefinition(f.ctx, def))

	after, err := f.source.Definition(f.ctx, "recon-def")
	require.NoError(t, err)
	assert.NotEqual(t, before.Hash, after.Hash)
}

func TestInboundMissionSource_TargetHashes(t *testing.T) {
	f := newInboundSourceFixture(t)
	first, err := f.source.TargetHashes(f.ctx, []string{f.target.ID.String()})
	require.NoError(t, err)
	assert.Len(t, first[f.target.ID.String()], 64)

	// A change of the scope of the target changes the hash. A change of the tags does not.
	f.target.Tags = []string{"x"}
	same, err := f.source.TargetHashes(f.ctx, []string{f.target.ID.String()})
	require.NoError(t, err)
	assert.Equal(t, first, same)
	f.target.URL = "https://elsewhere.example"
	changed, err := f.source.TargetHashes(f.ctx, []string{f.target.ID.String()})
	require.NoError(t, err)
	assert.NotEqual(t, first, changed)

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
		_, err := f.source.TargetHashes(f.ctx, []string{id})
		require.ErrorIs(t, err, api.ErrInboundTargetNotFound, name)
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
	require.ErrorContains(t, d.registerInboundMission(ctx, srv, keys), "needs the capability grant service")

	d.capabilityGrantSvc = &capabilitygrant.CapabilityGrantService{}
	require.NoError(t, d.registerInboundMission(ctx, srv, keys))
	assert.NotNil(t, d.inboundMissions)
	assert.Contains(t, srv.GetServiceInfo(), "gibson.tenant.v1.InboundMissionService")
}

// The hash of a pin must not depend on the bytes of the encoder. The protojson
// encoder may add a space after a comma, and the choice depends on the binary. A
// hash that changed with it would turn every publication stale after an upgrade.
func TestCanonicalJSONHash_IgnoresSpacingAndKeyOrder(t *testing.T) {
	compact, err := canonicalJSONHash([]byte(`{"b":[1,2],"a":{"y":"1","x":true}}`))
	require.NoError(t, err)
	spaced, err := canonicalJSONHash([]byte("{\"a\": {\"x\":true, \"y\":\"1\"},\n \"b\":[1, 2]}"))
	require.NoError(t, err)
	assert.Equal(t, compact, spaced)

	other, err := canonicalJSONHash([]byte(`{"b":[1,3],"a":{"y":"1","x":true}}`))
	require.NoError(t, err)
	assert.NotEqual(t, compact, other, "a change of a value changes the hash")
}

// A golden value fixes the canonical form. A change of the form changes every
// pin, so it must fail this test and be a decision.
func TestDefinitionHash_Golden(t *testing.T) {
	node := inboundAgentNode("n1", "recon")
	// A double with an integral value. protojson writes it as 12.
	node.RetryPolicy = &missionpb.RetryPolicy{MaxRetries: 3, Multiplier: 12.0}
	def := &missionpb.MissionDefinition{
		Id:   "00000000-0000-0000-0000-000000000001",
		Name: "golden",
		// Number fields are part of the pin: an int32, a double of 1e21, and an int64
		// above 2^53 (protojson writes an int64 as a string). Their encoding must not
		// depend on the encoder either.
		Constraints: &missionpb.MissionConstraints{MaxFindings: 100, MaxCost: 1e21, MaxTokens: 9007199254740993},
		Nodes:       map[string]*missionpb.MissionNode{"n1": node},
	}
	got, err := definitionHash(def)
	require.NoError(t, err)
	assert.Equal(t, "9bbb0170d25ae5408f56789968a5486147a935c26d432852c8cb0de53fa08eeb", got)
}

// The same value in other spellings gives one hash: 12, 12.0 and 1.2e1 are one number
// to the canonical form only when the encoder wrote the same text. The pin compares the
// hash of the stored definition with the hash of the definition that a start loaded, and
// both come from MarshalDefinitionJSON of the same message, so the text is the same.
// This test pins what the canonical form does with the spellings of one double.
func TestCanonicalJSONHash_NumberSpellings(t *testing.T) {
	a, err := canonicalJSONHash([]byte(`{"m":12}`))
	require.NoError(t, err)
	b, err := canonicalJSONHash([]byte(`{"m":12.0}`))
	require.NoError(t, err)
	assert.Equal(t, a, b, "12 and 12.0 are one number")
	c, err := canonicalJSONHash([]byte(`{"m":1.2e1}`))
	require.NoError(t, err)
	assert.Equal(t, a, c, "1.2e1 is the same number as 12")
	big1, err := canonicalJSONHash([]byte(`{"m":1e21}`))
	require.NoError(t, err)
	big2, err := canonicalJSONHash([]byte(`{"m":1.0E+21}`))
	require.NoError(t, err)
	assert.Equal(t, big1, big2, "1e21 in two spellings")
	// An int64 is a string in protojson, so it keeps every digit.
	i1, err := canonicalJSONHash([]byte(`{"t":"9007199254740993"}`))
	require.NoError(t, err)
	i2, err := canonicalJSONHash([]byte(`{"t":"9007199254740992"}`))
	require.NoError(t, err)
	assert.NotEqual(t, i1, i2)
}

func TestTargetHash_Golden(t *testing.T) {
	target := &types.Target{
		Name: "t", Type: "http_api", URL: "https://example.test",
		Capabilities: []string{"a", "b"}, Headers: map[string]string{"z": "1", "a": "2"},
	}
	got, err := targetHash(target)
	require.NoError(t, err)
	assert.Equal(t, "043ac3433b605c3b8a2a052bc69824b57b09201b314794ad17d73a9c51750767", got)
}

// A definition fans out when it has a for_each node. A run against more than one
// target needs one, so the source reports it.
func TestInboundMissionSource_DefinitionReportsAForEachNode(t *testing.T) {
	f := newInboundSourceFixture(t)
	plain, err := f.source.Definition(f.ctx, "recon-def")
	require.NoError(t, err)
	assert.False(t, plain.FansOut, "a definition with no for_each node does not fan out")

	conn, err := f.source.pool.For(f.ctx, auth.MustNewTenantID("acme"))
	require.NoError(t, err)
	require.NoError(t, mission.NewConnBoundMissionStore(conn.Redis).CreateDefinition(f.ctx, &missionpb.MissionDefinition{
		Id: "def-fan", Name: "fan-def",
		Nodes: map[string]*missionpb.MissionNode{
			"each": {
				Id: "each", Type: missionpb.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionpb.MissionNode_ForEachConfig{ForEachConfig: &missionpb.ForEachNodeConfig{
					Template: inboundAgentNode("scan", "recon"),
				}},
			},
		},
	}))

	fan, err := f.source.Definition(f.ctx, "fan-def")
	require.NoError(t, err)
	assert.True(t, fan.FansOut)
}
