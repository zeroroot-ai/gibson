// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// memSkillStore is an in-memory agentskillstore.Store for one tenant.
type memSkillStore struct {
	entries []agentskillstore.Entry
}

func (m *memSkillStore) Publish(
	_ context.Context, _, ref string, p *agentskill.Pulled,
) (*agentskillstore.Entry, error) {
	for i := range m.entries {
		if m.entries[i].Name == p.Manifest.Name {
			m.entries[i].Current = false
		}
	}
	e := agentskillstore.Entry{
		Name: p.Manifest.Name, Digest: p.Digest, Reference: ref,
		Description: p.Manifest.Description, PublishedAt: time.Unix(1, 0), Current: true,
	}
	m.entries = append(m.entries, e)
	return &e, nil
}

func (m *memSkillStore) List(_ context.Context, _, name string, all bool) ([]agentskillstore.Entry, error) {
	var out []agentskillstore.Entry
	for _, e := range m.entries {
		if (name == "" || e.Name == name) && (all || e.Current) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memSkillStore) Get(_ context.Context, _, name, digest string) (*agentskillstore.Entry, error) {
	for _, e := range m.entries {
		if e.Name == name && ((digest == "" && e.Current) || e.Digest == digest) {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", agentskillstore.ErrNotFound, name)
}

func (m *memSkillStore) Resolve(context.Context, string, string, string) (string, error) {
	return "", nil
}

func (m *memSkillStore) Load(ctx context.Context, tenant, name, digest string) (*agentskillstore.Loaded, error) {
	e, err := m.Get(ctx, tenant, name, digest)
	if err != nil {
		return nil, err
	}
	return &agentskillstore.Loaded{
		Entry: *e, Body: "the body", Files: []agentskillstore.FileInfo{{Path: "references/a.md", Size: 3}},
	}, nil
}

func (m *memSkillStore) ReadFile(context.Context, string, string, string, string) ([]byte, error) {
	return nil, nil
}

func (m *memSkillStore) Delete(_ context.Context, _, name string) (int64, error) {
	var kept []agentskillstore.Entry
	var n int64
	for _, e := range m.entries {
		if e.Name == name {
			n++
			continue
		}
		kept = append(kept, e)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: %s", agentskillstore.ErrNotFound, name)
	}
	m.entries = kept
	return n, nil
}

// recordingAuthorizer records the tuples that Delete receives.
type recordingAuthorizer struct {
	*fakeAuthorizer
	deleted []authz.Tuple
}

func (r *recordingAuthorizer) Delete(_ context.Context, t []authz.Tuple) error {
	r.deleted = append(r.deleted, t...)
	return nil
}

func (r *recordingAuthorizer) ListUsersOfType(
	ctx context.Context, objectType, object, relation, userType string,
) ([]string, error) {
	return r.fakeAuthorizer.users[objectType+"|"+object+"|"+relation], nil
}

type fakeSkillSecrets struct {
	values map[string][]byte
	asked  []string
}

func (f *fakeSkillSecrets) Resolve(_ context.Context, name string) ([]byte, error) {
	f.asked = append(f.asked, name)
	v, ok := f.values[name]
	if !ok {
		return nil, fmt.Errorf("secret %q not found", name)
	}
	return v, nil
}

type fakeSharedSkills struct{ entries map[string]SharedAgentSkill }

func (f *fakeSharedSkills) Names() []string {
	var out []string
	for n := range f.entries {
		out = append(out, n)
	}
	return out
}

func (f *fakeSharedSkills) Get(name string) (SharedAgentSkill, bool) {
	e, ok := f.entries[name]
	return e, ok
}

type skillFixture struct {
	svc   *AgentSkillService
	store *memSkillStore
	fga   *recordingAuthorizer
	ctx   context.Context
	pulls []string
	// keychains holds the keychain of each pull.
	keychains []authn.Keychain
	secrets   *fakeSkillSecrets
	shared    *fakeSharedSkills
}

func newSkillFixture(t *testing.T, pullErr error) *skillFixture {
	t.Helper()
	f := &skillFixture{store: &memSkillStore{}, fga: &recordingAuthorizer{fakeAuthorizer: newFakeAuthorizer()}}
	pull := func(_ context.Context, ref, name string, kc authn.Keychain) (*agentskill.Pulled, error) {
		f.pulls = append(f.pulls, ref)
		f.keychains = append(f.keychains, kc)
		if pullErr != nil {
			return nil, pullErr
		}
		return &agentskill.Pulled{
			Manifest: &agentskill.Manifest{Name: name, Description: "d"}, Digest: "sha256:aa",
		}, nil
	}
	f.secrets = &fakeSkillSecrets{values: map[string][]byte{}}
	f.shared = &fakeSharedSkills{}
	svc, err := NewAgentSkillService(f.store, pull, f.fga, f.secrets, f.shared)
	require.NoError(t, err)
	f.svc = svc
	f.ctx = auth.WithIdentity(context.Background(),
		auth.Identity{Subject: "admin-1", Tenant: auth.MustNewTenantID("acme")})
	return f
}

const skillRef = "reg.example/acme/web-recon@sha256:aa"

func code(err error) codes.Code { return status_grpc.Code(err) }

func TestPublishAgentSkill_StoresAndWritesTheOwnerTuple(t *testing.T) {
	f := newSkillFixture(t, nil)
	resp, err := f.svc.PublishAgentSkill(f.ctx, &tenantv1.PublishAgentSkillRequest{Name: "web-recon", Reference: skillRef})
	require.NoError(t, err)
	assert.Equal(t, "sha256:aa", resp.GetEntry().GetDigest())
	assert.True(t, resp.GetEntry().GetCurrent())
	assert.Equal(t, []string{skillRef}, f.pulls)
	assert.Equal(t, []authz.Tuple{{User: "tenant:acme", Relation: "owner", Object: "agent_skill:acme/web-recon"}},
		f.fga.writtenTuples())
}

func TestPublishAgentSkill_Refusals(t *testing.T) {
	req := &tenantv1.PublishAgentSkillRequest{Name: "web-recon", Reference: skillRef}

	f := newSkillFixture(t, nil)
	_, err := f.svc.PublishAgentSkill(context.Background(), req)
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")

	_, err = f.svc.PublishAgentSkill(f.ctx, &tenantv1.PublishAgentSkillRequest{Name: "Bad--Name", Reference: skillRef})
	assert.Equal(t, codes.InvalidArgument, code(err), "a name that breaks the format")
	assert.Empty(t, f.pulls, "no pull for an invalid name")

	f = newSkillFixture(t, fmt.Errorf("%w: no SKILL.md", agentskill.ErrInvalidFolder))
	_, err = f.svc.PublishAgentSkill(f.ctx, req)
	assert.Equal(t, codes.InvalidArgument, code(err), "an invalid folder")
	assert.Empty(t, f.fga.writtenTuples(), "no tuple for a refused publish")
	assert.Empty(t, f.store.entries, "nothing stored for a refused publish")

	f = newSkillFixture(t, fmt.Errorf("%w: file", agentskill.ErrOverLimit))
	_, err = f.svc.PublishAgentSkill(f.ctx, req)
	assert.Equal(t, codes.ResourceExhausted, code(err), "a folder over a limit")
}

func TestListAgentSkills_ReturnsTheCurrentVersionOrEach(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{
		{Name: "a", Digest: "sha256:01"}, {Name: "a", Digest: "sha256:02", Current: true},
	}
	resp, err := f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEntries(), 1)
	assert.Equal(t, "sha256:02", resp.GetEntries()[0].GetDigest())

	resp, err = f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{Name: "a", AllVersions: true})
	require.NoError(t, err)
	assert.Len(t, resp.GetEntries(), 2)

	_, err = f.svc.ListAgentSkills(f.ctx, &tenantv1.ListAgentSkillsRequest{Name: "A--"})
	assert.Equal(t, codes.InvalidArgument, code(err))
}

func TestGetAgentSkill_ReturnsTheBodyAndTheFiles(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:02", Current: true}}
	resp, err := f.svc.GetAgentSkill(f.ctx, &tenantv1.GetAgentSkillRequest{Name: "a"})
	require.NoError(t, err)
	assert.Equal(t, "the body", resp.GetBody())
	require.Len(t, resp.GetFiles(), 1)
	assert.Equal(t, "references/a.md", resp.GetFiles()[0].GetPath())

	_, err = f.svc.GetAgentSkill(f.ctx, &tenantv1.GetAgentSkillRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, code(err))
}

func TestDeleteAgentSkill_RemovesTheGrantsAndTheOwnerTuple(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:02", Current: true}}
	obj := "agent_skill:acme/a"
	f.fga.withUsers("agent_skill", obj, "granted_agent", "agent_principal:x")
	f.fga.withUsers("agent_skill", obj, "granted_mission", "mission:m1")

	resp, err := f.svc.DeleteAgentSkill(f.ctx, &tenantv1.DeleteAgentSkillRequest{Name: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, resp.GetDeletedVersions())
	assert.ElementsMatch(t, []authz.Tuple{
		{User: "tenant:acme", Relation: "owner", Object: obj},
		{User: "agent_principal:x", Relation: "granted_agent", Object: obj},
		{User: "mission:m1", Relation: "granted_mission", Object: obj},
	}, f.fga.deleted)

	_, err = f.svc.DeleteAgentSkill(f.ctx, &tenantv1.DeleteAgentSkillRequest{Name: "a"})
	assert.Equal(t, codes.NotFound, code(err))
}

func TestGrantAgentSkill_WritesAGrantForASubjectOfTheTenant(t *testing.T) {
	f := newSkillFixture(t, nil)
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:02", Current: true}}
	f.fga.allow("tenant:acme", "belongs_to", "agent_principal:x")
	f.fga.allow("tenant:acme", "belongs_to", "mission:m1")

	_, err := f.svc.GrantAgentSkill(f.ctx, &tenantv1.GrantAgentSkillRequest{
		Name: "a", SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT, SubjectId: "x"})
	require.NoError(t, err)
	_, err = f.svc.GrantAgentSkill(f.ctx, &tenantv1.GrantAgentSkillRequest{
		Name: "a", SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION, SubjectId: "m1"})
	require.NoError(t, err)
	assert.Equal(t, []authz.Tuple{
		{User: "agent_principal:x", Relation: "granted_agent", Object: "agent_skill:acme/a"},
		{User: "mission:m1", Relation: "granted_mission", Object: "agent_skill:acme/a"},
	}, f.fga.writtenTuples())

	// A mission of another tenant is refused, and no tuple is written.
	before := len(f.fga.writtenTuples())
	_, err = f.svc.GrantAgentSkill(f.ctx, &tenantv1.GrantAgentSkillRequest{
		Name: "a", SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION, SubjectId: "foreign"})
	assert.Equal(t, codes.NotFound, code(err))
	assert.Len(t, f.fga.writtenTuples(), before)

	_, err = f.svc.GrantAgentSkill(f.ctx, &tenantv1.GrantAgentSkillRequest{Name: "a", SubjectId: "x"})
	assert.Equal(t, codes.InvalidArgument, code(err), "no subject kind")

	_, err = f.svc.GrantAgentSkill(f.ctx, &tenantv1.GrantAgentSkillRequest{
		Name: "none", SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT, SubjectId: "x"})
	assert.Equal(t, codes.NotFound, code(err), "an Agent Skill that does not exist")
}

func TestRevokeAgentSkill_DeletesTheGrantWithoutASubjectCheck(t *testing.T) {
	f := newSkillFixture(t, nil)
	_, err := f.svc.RevokeAgentSkill(f.ctx, &tenantv1.RevokeAgentSkillRequest{
		Name: "a", SubjectKind: tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_MISSION, SubjectId: "gone"})
	require.NoError(t, err)
	assert.Equal(t, []authz.Tuple{
		{User: "mission:gone", Relation: "granted_mission", Object: "agent_skill:acme/a"},
	}, f.fga.deleted)
}

// An anonymous publish reads no secret and passes no credential. A named secret
// is read once, for this call, and its credential reaches the puller only for
// the registry that it names.
func TestPublishAgentSkill_RegistrySecret(t *testing.T) {
	f := newSkillFixture(t, nil)
	_, err := f.svc.PublishAgentSkill(f.ctx, &tenantv1.PublishAgentSkillRequest{Name: "web-recon", Reference: skillRef})
	require.NoError(t, err)
	assert.Empty(t, f.secrets.asked, "no secret name means no secret read")
	reg, nerr := name.NewRegistry("reg.example")
	require.NoError(t, nerr)
	a, rerr := f.keychains[0].Resolve(reg)
	require.NoError(t, rerr)
	assert.Equal(t, authn.Anonymous, a, "no secret name means an anonymous pull")

	f.secrets.values["reg-cred"] = []byte(`{"auths":{"reg.example":{"username":"u","password":"p"}}}`)
	_, err = f.svc.PublishAgentSkill(f.ctx, &tenantv1.PublishAgentSkillRequest{
		Name: "web-recon", Reference: skillRef, RegistrySecret: "reg-cred"})
	require.NoError(t, err)
	assert.Equal(t, []string{"reg-cred"}, f.secrets.asked)
	a, rerr = f.keychains[1].Resolve(reg)
	require.NoError(t, rerr)
	cfg, aerr := a.Authorization()
	require.NoError(t, aerr)
	assert.Equal(t, "u", cfg.Username)

	// A secret that does not exist fails the publish before any pull.
	pulls := len(f.pulls)
	_, err = f.svc.PublishAgentSkill(f.ctx, &tenantv1.PublishAgentSkillRequest{
		Name: "web-recon", Reference: skillRef, RegistrySecret: "missing"})
	assert.Equal(t, codes.FailedPrecondition, code(err))
	assert.Len(t, f.pulls, pulls, "no pull after a failed secret read")
}

func offerShared(f *skillFixture) {
	f.shared.entries = map[string]SharedAgentSkill{"web-recon": {
		Reference: "ops.example/skills/web-recon@sha256:bb",
		Pulled: &agentskill.Pulled{
			Manifest: &agentskill.Manifest{Name: "web-recon", Description: "shared method"}, Digest: "sha256:bb",
		},
	}}
}

func TestListSharedAgentSkills_ShowsWhetherTheTenantHoldsTheDigest(t *testing.T) {
	f := newSkillFixture(t, nil)
	offerShared(f)
	resp, err := f.svc.ListSharedAgentSkills(f.ctx, &tenantv1.ListSharedAgentSkillsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEntries(), 1)
	assert.Equal(t, "sha256:bb", resp.GetEntries()[0].GetDigest())
	assert.False(t, resp.GetEntries()[0].GetEnabled())

	f.store.entries = []agentskillstore.Entry{{Name: "web-recon", Digest: "sha256:bb", Current: true}}
	resp, err = f.svc.ListSharedAgentSkills(f.ctx, &tenantv1.ListSharedAgentSkillsRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetEntries()[0].GetEnabled())

	_, err = f.svc.ListSharedAgentSkills(context.Background(), &tenantv1.ListSharedAgentSkillsRequest{})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

// Enabling copies the content into the tenant and writes the owner tuple. It
// writes no grant, so the tenant admin still grants before a load.
func TestEnableSharedAgentSkill_CopiesTheContentAndGrantsNothing(t *testing.T) {
	f := newSkillFixture(t, nil)
	offerShared(f)
	f.fga.allow("system_tenant:_system", "platform_enabled", "agent_skill:_shared/web-recon")

	resp, err := f.svc.EnableSharedAgentSkill(f.ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "web-recon"})
	require.NoError(t, err)
	assert.Equal(t, "sha256:bb", resp.GetEntry().GetDigest())
	assert.Equal(t, []authz.Tuple{{User: "tenant:acme", Relation: "owner", Object: "agent_skill:acme/web-recon"}},
		f.fga.writtenTuples(), "the owner tuple only, no grant")
	assert.Empty(t, f.pulls, "the daemon does not pull again at enable")
}

func TestEnableSharedAgentSkill_Refusals(t *testing.T) {
	f := newSkillFixture(t, nil)
	offerShared(f)

	// The gate does not offer it: no platform_enabled tuple.
	_, err := f.svc.EnableSharedAgentSkill(f.ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "web-recon"})
	assert.Equal(t, codes.NotFound, code(err), "no platform gate")

	// The gate offers a name that the daemon did not pull.
	f.fga.allow("system_tenant:_system", "platform_enabled", "agent_skill:_shared/ghost")
	_, err = f.svc.EnableSharedAgentSkill(f.ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "ghost"})
	assert.Equal(t, codes.NotFound, code(err), "not pulled")

	_, err = f.svc.EnableSharedAgentSkill(f.ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "Bad--"})
	assert.Equal(t, codes.InvalidArgument, code(err))
	assert.Empty(t, f.store.entries)
	assert.Empty(t, f.fga.writtenTuples())
}
