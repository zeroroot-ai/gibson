// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

var errInboundBoom = errors.New("boom")

type memInboundStore struct {
	entries    map[string]inboundmissionstore.Entry
	publishErr error
	listErr    error
	deleteErr  error
}

func (m *memInboundStore) Publish(
	_ context.Context, _ string, e inboundmissionstore.Entry,
) (*inboundmissionstore.Entry, error) {
	if m.publishErr != nil {
		return nil, m.publishErr
	}
	if old, ok := m.entries[e.Agent]; ok {
		if old.DefinitionID != e.DefinitionID {
			return nil, fmt.Errorf("%w: %s", inboundmissionstore.ErrConflict, e.Agent)
		}
		return &old, nil
	}
	e.CreatedAt = time.Unix(1, 0).UTC()
	m.entries[e.Agent] = e
	return &e, nil
}

func (m *memInboundStore) ListPage(
	_ context.Context, _, after string, hasAfter bool, limit int,
) ([]inboundmissionstore.Entry, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	all := make([]inboundmissionstore.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Agent < all[j].Agent })
	out := []inboundmissionstore.Entry{}
	for _, e := range all {
		if (!hasAfter || e.Agent > after) && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memInboundStore) Get(_ context.Context, _, agent string) (*inboundmissionstore.Entry, error) {
	e, ok := m.entries[agent]
	if !ok {
		return nil, fmt.Errorf("%w: %s", inboundmissionstore.ErrNotFound, agent)
	}
	return &e, nil
}

// The service uses none of the task methods.
func (m *memInboundStore) Reserve(context.Context, string, string, string, func(string) bool, time.Duration) (string, error) {
	return "", errors.New("not used")
}
func (m *memInboundStore) Bind(context.Context, string, string, string) error { return errors.New("not used") }
func (m *memInboundStore) Release(context.Context, string, string) error     { return errors.New("not used") }
func (m *memInboundStore) Owner(context.Context, string, string) (string, error) {
	return "", errors.New("not used")
}

func (m *memInboundStore) Delete(_ context.Context, _, agent string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.entries[agent]; !ok {
		return fmt.Errorf("%w: %s", inboundmissionstore.ErrNotFound, agent)
	}
	delete(m.entries, agent)
	return nil
}

type fakeInboundSource struct {
	defs      map[string]InboundDefinition
	hashes    map[string]string
	defErr    error
	targetErr error
}

func (f *fakeInboundSource) Definition(_ context.Context, id string) (InboundDefinition, error) {
	if f.defErr != nil {
		return InboundDefinition{}, f.defErr
	}
	d, ok := f.defs[id]
	if !ok {
		return InboundDefinition{}, ErrInboundDefinitionNotFound
	}
	return d, nil
}

func (f *fakeInboundSource) TargetHashes(_ context.Context, ids []string) (map[string]string, error) {
	if f.targetErr != nil {
		return nil, f.targetErr
	}
	out := map[string]string{}
	for _, id := range ids {
		h, ok := f.hashes[id]
		if !ok {
			h = "h-" + id
		}
		out[id] = h
	}
	return out, nil
}

// failingInboundFGA fails the calls that the test names.
type failingInboundFGA struct {
	*recordingAuthorizer
	checkErr, writeErr, deleteErr, listErr error
}

func (f *failingInboundFGA) Check(ctx context.Context, user, relation, object string) (bool, error) {
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.recordingAuthorizer.Check(ctx, user, relation, object)
}

func (f *failingInboundFGA) Write(ctx context.Context, t []authz.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.recordingAuthorizer.Write(ctx, t)
}

func (f *failingInboundFGA) Delete(ctx context.Context, t []authz.Tuple) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.recordingAuthorizer.Delete(ctx, t)
}

func (f *failingInboundFGA) ListUsersOfType(ctx context.Context, a, b, c, d string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.recordingAuthorizer.ListUsersOfType(ctx, a, b, c, d)
}

type fakeInboundIdentities struct {
	names []string
	err   error
}

func (f *fakeInboundIdentities) ActiveCapabilityNames(context.Context, string, string) ([]string, error) {
	return f.names, f.err
}

type inboundFixture struct {
	identities *fakeInboundIdentities
	svc        *InboundMissionService
	store      *memInboundStore
	source     *fakeInboundSource
	fga        *failingInboundFGA
	ctx        context.Context
}

const (
	reconObject = "published_mission:acme/recon"
	goodTarget  = "t-1"
)

func newInboundFixture(t *testing.T) *inboundFixture {
	t.Helper()
	f := &inboundFixture{
		store:  &memInboundStore{entries: map[string]inboundmissionstore.Entry{}},
		source: &fakeInboundSource{defs: map[string]InboundDefinition{"def-1": {ID: "def-1", Hash: "hash-1", Agents: []string{"recon", "other"}}}, hashes: map[string]string{}},
		fga:    &failingInboundFGA{recordingAuthorizer: &recordingAuthorizer{fakeAuthorizer: newFakeAuthorizer()}},
	}
	f.identities = &fakeInboundIdentities{names: []string{"mission:originate"}}
	svc, err := NewInboundMissionService(f.store, f.source, f.fga, f.identities, testPageKeys(t))
	require.NoError(t, err)
	f.svc = svc
	f.ctx = auth.WithIdentity(context.Background(),
		auth.Identity{Subject: "admin-1", Tenant: auth.MustNewTenantID("acme")})
	return f
}

func pub(agent, def string, targets ...string) *tenantv1.PublishInboundMissionRequest {
	return &tenantv1.PublishInboundMissionRequest{
		Agent: agent, MissionDefinitionId: def, TargetIds: targets, MaxActiveMissions: 3,
	}
}

func publishedFixture(t *testing.T) *inboundFixture {
	t.Helper()
	f := newInboundFixture(t)
	_, err := f.svc.PublishInboundMission(f.ctx, pub("recon", "def-1", goodTarget, "t-0"))
	require.NoError(t, err)
	return f
}

func TestNewInboundMissionService_NeedsEachArgument(t *testing.T) {
	f := newInboundFixture(t)
	for name, build := range map[string]func() (*InboundMissionService, error){
		"no store": func() (*InboundMissionService, error) {
			return NewInboundMissionService(nil, f.source, f.fga, f.identities, f.svc.pageKeys)
		},
		"no source": func() (*InboundMissionService, error) {
			return NewInboundMissionService(f.store, nil, f.fga, f.identities, f.svc.pageKeys)
		},
		"no fga": func() (*InboundMissionService, error) {
			return NewInboundMissionService(f.store, f.source, nil, f.identities, f.svc.pageKeys)
		},
		"no keys": func() (*InboundMissionService, error) {
			return NewInboundMissionService(f.store, f.source, f.fga, f.identities, nil)
		},
	} {
		svc, err := build()
		assert.Nil(t, svc, name)
		assert.Error(t, err, name)
	}
}

func TestPublishInboundMission_StoresAndWritesTheOwnerTuple(t *testing.T) {
	f := newInboundFixture(t)
	resp, err := f.svc.PublishInboundMission(f.ctx, pub("recon", "def-1", "t-2", goodTarget))
	require.NoError(t, err)
	assert.Equal(t, "recon", resp.GetEntry().GetAgent())
	assert.Equal(t, []string{goodTarget, "t-2"}, resp.GetEntry().GetTargetIds(), "the targets are sorted")
	assert.Equal(t, "admin-1", resp.GetEntry().GetPublishedBy())
	assert.Equal(t, []authz.Tuple{{User: "tenant:acme", Relation: "owner", Object: reconObject}},
		f.fga.writtenTuples())

	again, err := f.svc.PublishInboundMission(f.ctx, pub("recon", "def-1", goodTarget, "t-2"))
	require.NoError(t, err, "the same fields again change nothing")
	assert.Equal(t, resp.GetEntry().GetTargetIds(), again.GetEntry().GetTargetIds())
}

func TestPublishInboundMission_Refusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*inboundFixture)
		ctx   func(*inboundFixture) context.Context
		req   *tenantv1.PublishInboundMissionRequest
		want  codes.Code
	}{
		{"no tenant", nil, func(*inboundFixture) context.Context { return context.Background() },
			pub("recon", "def-1", goodTarget), codes.PermissionDenied},
		{"the agent is not a DNS label", nil, nil, pub("Recon!", "def-1", goodTarget), codes.InvalidArgument},
		{"no target", nil, nil, pub("recon", "def-1"), codes.InvalidArgument},
		{"no limit", nil, nil, &tenantv1.PublishInboundMissionRequest{
			Agent: "recon", MissionDefinitionId: "def-1", TargetIds: []string{goodTarget}}, codes.InvalidArgument},
		{"a limit of zero", nil, nil, &tenantv1.PublishInboundMissionRequest{
			Agent: "recon", MissionDefinitionId: "def-1", TargetIds: []string{goodTarget}, MaxActiveMissions: 0}, codes.InvalidArgument},
		{"too many targets", nil, nil, func() *tenantv1.PublishInboundMissionRequest {
			ids := make([]string, maxInboundTargets+1)
			for i := range ids {
				ids[i] = fmt.Sprintf("t-%d", i)
			}
			return pub("recon", "def-1", ids...)
		}(), codes.InvalidArgument},
		{"a target twice", nil, nil, pub("recon", "def-1", goodTarget, goodTarget), codes.InvalidArgument},
		{"the definition does not exist", nil, nil, pub("recon", "missing", goodTarget), codes.NotFound},
		{"the definition read fails", func(f *inboundFixture) { f.source.defErr = errInboundBoom }, nil,
			pub("recon", "def-1", goodTarget), codes.Internal},
		{"the definition has no ID to pin", func(f *inboundFixture) {
			f.source.defs["def-1"] = InboundDefinition{Hash: "h", Agents: []string{"recon"}}
		}, nil, pub("recon", "def-1", goodTarget), codes.FailedPrecondition},
		{"the definition has no node for the agent", nil, nil, pub("scanner", "def-1", goodTarget),
			codes.InvalidArgument},
		{"the target is not of the tenant", func(f *inboundFixture) { f.source.targetErr = ErrInboundTargetNotFound }, nil,
			pub("recon", "def-1", goodTarget), codes.NotFound},
		{"the target read fails", func(f *inboundFixture) { f.source.targetErr = errInboundBoom }, nil,
			pub("recon", "def-1", goodTarget), codes.Internal},
		{"the store fails", func(f *inboundFixture) { f.store.publishErr = errInboundBoom }, nil,
			pub("recon", "def-1", goodTarget), codes.Internal},
		{"the owner tuple fails", func(f *inboundFixture) { f.fga.writeErr = errInboundBoom }, nil,
			pub("recon", "def-1", goodTarget), codes.Internal},
		{"the agent holds another definition", func(f *inboundFixture) {
			f.source.defs["def-2"] = InboundDefinition{ID: "def-2", Hash: "hash-2", Agents: []string{"recon"}}
			_, _ = f.svc.PublishInboundMission(f.ctx, pub("recon", "def-2", goodTarget))
		}, nil, pub("recon", "def-1", goodTarget), codes.AlreadyExists},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newInboundFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			ctx := f.ctx
			if tt.ctx != nil {
				ctx = tt.ctx(f)
			}
			_, err := f.svc.PublishInboundMission(ctx, tt.req)
			assert.Equal(t, tt.want, code(err))
		})
	}
	// A refusal before the store writes no record and no tuple.
	f := newInboundFixture(t)
	_, _ = f.svc.PublishInboundMission(f.ctx, pub("scanner", "def-1", goodTarget))
	assert.Empty(t, f.store.entries)
	assert.Empty(t, f.fga.writtenTuples())
}

func TestListInboundMissions_PagesByAgent(t *testing.T) {
	f := newInboundFixture(t)
	for _, a := range []string{"c", "a", "b"} {
		f.source.defs["def-"+a] = InboundDefinition{ID: "def-" + a, Hash: "h", Agents: []string{a}}
		_, err := f.svc.PublishInboundMission(f.ctx, pub(a, "def-"+a, goodTarget))
		require.NoError(t, err)
	}
	first, err := f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, first.GetEntries(), 2)
	assert.Equal(t, "a", first.GetEntries()[0].GetAgent())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListInboundMissions(f.ctx,
		&tenantv1.ListInboundMissionsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, second.GetEntries(), 1)
	assert.Equal(t, "c", second.GetEntries()[0].GetAgent())
	assert.Empty(t, second.GetNextPageToken())

	_, err = f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{PageToken: "garbage"})
	assert.Equal(t, codes.InvalidArgument, code(err))
	_, err = f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{PageToken: signedToken(
		t, f.svc.pageKeys, "tenant-inbound-callers", "a", "acme", "recon")})
	assert.Equal(t, codes.InvalidArgument, code(err), "a token of another list is refused")

	f.store.listErr = errInboundBoom
	_, err = f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{})
	assert.Equal(t, codes.Internal, code(err))
	_, err = f.svc.ListInboundMissions(context.Background(), &tenantv1.ListInboundMissionsRequest{})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestUnpublishInboundMission_RemovesTheRecordTheGrantsAndTheOwnerTuple(t *testing.T) {
	f := publishedFixture(t)
	f.fga.withUsers("published_mission", reconObject, "granted_caller", "agent_principal:a1", "agent_principal:a2")

	_, err := f.svc.UnpublishInboundMission(f.ctx, &tenantv1.UnpublishInboundMissionRequest{Agent: "recon"})
	require.NoError(t, err)

	assert.Empty(t, f.store.entries)
	assert.ElementsMatch(t, []authz.Tuple{
		{User: "tenant:acme", Relation: "owner", Object: reconObject},
		{User: "agent_principal:a1", Relation: "granted_caller", Object: reconObject},
		{User: "agent_principal:a2", Relation: "granted_caller", Object: reconObject},
	}, f.fga.deleted)
}

func TestUnpublishInboundMission_Refusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*inboundFixture)
		agent string
		want  codes.Code
	}{
		{"a bad name", nil, "Bad!", codes.InvalidArgument},
		{"not published", nil, "other", codes.NotFound},
		{"the grant list fails", func(f *inboundFixture) { f.fga.listErr = errInboundBoom }, "recon", codes.Internal},
		{"the tuple delete fails", func(f *inboundFixture) { f.fga.deleteErr = errInboundBoom }, "recon", codes.Internal},
		{"the store delete fails", func(f *inboundFixture) { f.store.deleteErr = errInboundBoom }, "recon", codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			_, err := f.svc.UnpublishInboundMission(f.ctx, &tenantv1.UnpublishInboundMissionRequest{Agent: tt.agent})
			assert.Equal(t, tt.want, code(err))
		})
	}
	_, err := newInboundFixture(t).svc.UnpublishInboundMission(context.Background(),
		&tenantv1.UnpublishInboundMissionRequest{Agent: "recon"})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestGrantInboundCaller(t *testing.T) {
	f := publishedFixture(t)
	f.fga.allow("tenant:acme", "belongs_to", "agent_principal:a1")
	_, err := f.svc.GrantInboundCaller(f.ctx, &tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"})
	require.NoError(t, err)
	assert.Contains(t, f.fga.writtenTuples(),
		authz.Tuple{User: "agent_principal:a1", Relation: "granted_caller", Object: reconObject})

	tests := []struct {
		name  string
		setup func(*inboundFixture)
		req   *tenantv1.GrantInboundCallerRequest
		want  codes.Code
	}{
		{"a bad agent", nil, &tenantv1.GrantInboundCallerRequest{Agent: "Bad!", IdentityId: "agent_principal:a1"}, codes.InvalidArgument},
		{"an identity id with no type prefix", nil, &tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "a1"},
			codes.InvalidArgument},
		{"an identity of another tenant", nil, &tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:x9"},
			codes.NotFound},
		{"the tenant check fails", func(f *inboundFixture) { f.fga.checkErr = errInboundBoom },
			&tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"}, codes.Internal},
		{"the agent is not published", nil, &tenantv1.GrantInboundCallerRequest{Agent: "other", IdentityId: "agent_principal:a1"},
			codes.NotFound},
		{"the grant write fails", func(f *inboundFixture) { f.fga.writeErr = errInboundBoom },
			&tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			f.fga.allow("tenant:acme", "belongs_to", "agent_principal:a1")
			if tt.setup != nil {
				tt.setup(f)
			}
			_, err := f.svc.GrantInboundCaller(f.ctx, tt.req)
			assert.Equal(t, tt.want, code(err))
		})
	}
	_, err = f.svc.GrantInboundCaller(context.Background(), &tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestRevokeInboundCaller(t *testing.T) {
	f := publishedFixture(t)
	_, err := f.svc.RevokeInboundCaller(f.ctx, &tenantv1.RevokeInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"})
	require.NoError(t, err)
	assert.Equal(t, []authz.Tuple{{User: "agent_principal:a1", Relation: "granted_caller", Object: reconObject}},
		f.fga.deleted)

	tests := []struct {
		name  string
		setup func(*inboundFixture)
		req   *tenantv1.RevokeInboundCallerRequest
		want  codes.Code
	}{
		{"a bad agent", nil, &tenantv1.RevokeInboundCallerRequest{Agent: "Bad!", IdentityId: "agent_principal:a1"}, codes.InvalidArgument},
		{"a bad identity", nil, &tenantv1.RevokeInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a#1"}, codes.InvalidArgument},
		{"a tool principal", nil, &tenantv1.RevokeInboundCallerRequest{Agent: "recon", IdentityId: "tool_principal:a1"}, codes.InvalidArgument},
		{"the delete fails", func(f *inboundFixture) { f.fga.deleteErr = errInboundBoom },
			&tenantv1.RevokeInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			_, err := f.svc.RevokeInboundCaller(f.ctx, tt.req)
			assert.Equal(t, tt.want, code(err))
		})
	}
	_, err = f.svc.RevokeInboundCaller(context.Background(), &tenantv1.RevokeInboundCallerRequest{Agent: "recon", IdentityId: "agent_principal:a1"})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestListInboundCallers_PagesInMemoryOverAStableSort(t *testing.T) {
	f := publishedFixture(t)
	f.fga.withUsers("published_mission", reconObject, "granted_caller",
		"agent_principal:a3", "agent_principal:a1", "agent_principal:a2")

	first, err := f.svc.ListInboundCallers(f.ctx, &tenantv1.ListInboundCallersRequest{Agent: "recon", PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, []string{"agent_principal:a1", "agent_principal:a2"}, first.GetIdentityIds())
	require.NotEmpty(t, first.GetNextPageToken())

	second, err := f.svc.ListInboundCallers(f.ctx,
		&tenantv1.ListInboundCallersRequest{Agent: "recon", PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	assert.Equal(t, []string{"agent_principal:a3"}, second.GetIdentityIds())
	assert.Empty(t, second.GetNextPageToken())

	tests := []struct {
		name  string
		setup func(*inboundFixture)
		req   *tenantv1.ListInboundCallersRequest
		want  codes.Code
	}{
		{"a bad agent", nil, &tenantv1.ListInboundCallersRequest{Agent: "Bad!"}, codes.InvalidArgument},
		{"a bad token", nil, &tenantv1.ListInboundCallersRequest{Agent: "recon", PageToken: "garbage"},
			codes.InvalidArgument},
		{"not published", nil, &tenantv1.ListInboundCallersRequest{Agent: "other"}, codes.NotFound},
		{"the grant list fails", func(f *inboundFixture) { f.fga.listErr = errInboundBoom },
			&tenantv1.ListInboundCallersRequest{Agent: "recon"}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			_, err := f.svc.ListInboundCallers(f.ctx, tt.req)
			assert.Equal(t, tt.want, code(err))
		})
	}
	_, err = f.svc.ListInboundCallers(context.Background(), &tenantv1.ListInboundCallersRequest{Agent: "recon"})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

// A caller identity has the one ceiling mission:originate, and no other grant and
// no other relation. Any other identity gets FailedPrecondition, and no tuple.
func TestGrantInboundCaller_RefusesAnIdentityThatIsNotACallerIdentity(t *testing.T) {
	const ref = "agent_principal:a1"
	tests := []struct {
		name  string
		setup func(f *inboundFixture)
		want  codes.Code
	}{
		{"a caller identity", func(f *inboundFixture) {}, codes.OK},
		{"an identity that has not enrolled", func(f *inboundFixture) { f.identities.names = nil }, codes.OK},
		{"the same grant again", func(f *inboundFixture) {
			f.fga.stored = []authz.Tuple{{User: ref, Relation: "granted_caller", Object: reconObject}}
		}, codes.OK},
		{"another session bit", func(f *inboundFixture) {
			f.identities.names = []string{"mission:originate", "mission:delegate"}
		}, codes.FailedPrecondition},
		{"a tool grant", func(f *inboundFixture) { f.identities.names = []string{"execute:tool:nmap"} }, codes.FailedPrecondition},
		{"a grant to another definition", func(f *inboundFixture) {
			f.fga.stored = []authz.Tuple{{User: ref, Relation: "granted_caller", Object: "published_mission:acme/other"}}
		}, codes.FailedPrecondition},
		{"a relation on a component", func(f *inboundFixture) {
			f.fga.stored = []authz.Tuple{{User: ref, Relation: "direct_execute", Object: "component:agent/x"}}
		}, codes.FailedPrecondition},
		{"the capability read fails", func(f *inboundFixture) { f.identities.err = errInboundBoom }, codes.Internal},
		{"the tuple read fails", func(f *inboundFixture) { f.fga.readErr = errInboundBoom }, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			f.fga.allow("tenant:acme", "belongs_to", ref)
			tt.setup(f)
			_, err := f.svc.GrantInboundCaller(f.ctx, &tenantv1.GrantInboundCallerRequest{Agent: "recon", IdentityId: ref})
			assert.Equal(t, tt.want, code(err))
			if tt.want != codes.OK {
				assert.NotContains(t, f.fga.writtenTuples(),
					authz.Tuple{User: ref, Relation: "granted_caller", Object: reconObject})
			}
		})
	}
}

// The list shows that a publication is stale, so the admin can publish again.
func TestListInboundMissions_ShowsAStalePublication(t *testing.T) {
	tests := []struct {
		name       string
		change     func(f *inboundFixture)
		wantStale  bool
		wantReason string
	}{
		{"nothing changed", func(*inboundFixture) {}, false, ""},
		{"the definition changed", func(f *inboundFixture) {
			f.source.defs["def-1"] = InboundDefinition{ID: "def-1", Hash: "hash-changed", Agents: []string{"recon"}}
		}, true, "the mission definition changed"},
		{"the definition was deleted", func(f *inboundFixture) { delete(f.source.defs, "def-1") }, true, "was deleted"},
		{"a target changed", func(f *inboundFixture) { f.source.hashes[goodTarget] = "other" }, true, "target changed"},
		{"a target was deleted", func(f *inboundFixture) { f.source.targetErr = ErrInboundTargetNotFound }, true, "target was deleted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := publishedFixture(t)
			tt.change(f)
			resp, err := f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{})
			require.NoError(t, err)
			require.Len(t, resp.GetEntries(), 1)
			assert.Equal(t, tt.wantStale, resp.GetEntries()[0].GetStale())
			assert.Contains(t, resp.GetEntries()[0].GetStaleReason(), tt.wantReason)
		})
	}

	f := publishedFixture(t)
	f.source.defErr = errInboundBoom
	_, err := f.svc.ListInboundMissions(f.ctx, &tenantv1.ListInboundMissionsRequest{})
	assert.Equal(t, codes.Internal, code(err), "a failed read is not a stale publication")
}

func TestPublishInboundMission_PinsTheDefinitionAndEachTarget(t *testing.T) {
	f := newInboundFixture(t)
	_, err := f.svc.PublishInboundMission(f.ctx, pub("recon", "def-1", goodTarget))
	require.NoError(t, err)
	e := f.store.entries["recon"]
	assert.Equal(t, "hash-1", e.DefinitionHash)
	assert.Equal(t, int32(3), e.MaxActive, "the admin sets the limit")
	assert.Equal(t, map[string]string{goodTarget: "h-" + goodTarget}, e.TargetHashes)
}
