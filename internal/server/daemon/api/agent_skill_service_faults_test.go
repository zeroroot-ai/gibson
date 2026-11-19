// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

var errSkillBackend = errors.New("the backend is down")

// faultSkillStore fails the calls that its fields name.
type faultSkillStore struct {
	*memSkillStore
	publishErr, listErr, getErr, loadErr, deleteErr error
}

func (f *faultSkillStore) Publish(
	ctx context.Context, tenant, ref, source string, p *agentskill.Pulled,
) (*agentskillstore.Entry, error) {
	if f.publishErr != nil {
		return nil, f.publishErr
	}
	return f.memSkillStore.Publish(ctx, tenant, ref, source, p)
}

func (f *faultSkillStore) List(ctx context.Context, tenant, name string, all bool) ([]agentskillstore.Entry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.memSkillStore.List(ctx, tenant, name, all)
}

func (f *faultSkillStore) Get(ctx context.Context, tenant, name, digest string) (*agentskillstore.Entry, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.memSkillStore.Get(ctx, tenant, name, digest)
}

func (f *faultSkillStore) Load(ctx context.Context, tenant, name, digest string) (*agentskillstore.Loaded, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.memSkillStore.Load(ctx, tenant, name, digest)
}

func (f *faultSkillStore) Delete(ctx context.Context, tenant, name string) (int64, error) {
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return f.memSkillStore.Delete(ctx, tenant, name)
}

// faultSkillFGA fails the calls that its fields name.
type faultSkillFGA struct {
	*recordingAuthorizer
	checkErr, writeErr, deleteErr, listErr error
}

func (f *faultSkillFGA) Check(ctx context.Context, user, relation, object string) (bool, error) {
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.recordingAuthorizer.Check(ctx, user, relation, object)
}

func (f *faultSkillFGA) Write(ctx context.Context, tuples []authz.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.recordingAuthorizer.Write(ctx, tuples)
}

func (f *faultSkillFGA) Delete(ctx context.Context, tuples []authz.Tuple) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.recordingAuthorizer.Delete(ctx, tuples)
}

func (f *faultSkillFGA) ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.recordingAuthorizer.ListUsersOfType(ctx, objectType, object, relation, userType)
}

// faultySkillService is a service whose store and authorizer fail as given. The
// store holds one Agent Skill, "a", that the tenant owns and the operator offers.
func faultySkillService(
	t *testing.T, store func(*faultSkillStore), fga func(*faultSkillFGA),
) (*AgentSkillService, *skillFixture) {
	t.Helper()
	f := newSkillFixture(t, nil)
	offerShared(f)
	f.shared.entries["a"] = f.shared.entries["web-recon"]
	f.store.entries = []agentskillstore.Entry{{Name: "a", Digest: "sha256:02", Current: true}}
	f.fga.allow("system_tenant:_system", "platform_enabled", "agent_skill:_shared/a")
	fs := &faultSkillStore{memSkillStore: f.store}
	ff := &faultSkillFGA{recordingAuthorizer: f.fga}
	if store != nil {
		store(fs)
	}
	if fga != nil {
		fga(ff)
	}
	svc, err := NewAgentSkillService(fs, f.svc.pull, ff, f.secrets, f.shared)
	require.NoError(t, err)
	return svc, f
}

func TestAgentSkillService_BackendFailuresGiveAnInternalError(t *testing.T) {
	agent := tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT
	tests := []struct {
		name  string
		store func(*faultSkillStore)
		fga   func(*faultSkillFGA)
		call  func(s *AgentSkillService, ctx context.Context) error
		want  codes.Code
	}{
		{"publish: the store fails", func(s *faultSkillStore) { s.publishErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.PublishAgentSkill(ctx, &tenantv1.PublishAgentSkillRequest{Name: "a", Reference: skillRef})
				return err
			}, codes.Internal},
		{"publish: the owner tuple cannot be written", nil, func(f *faultSkillFGA) { f.writeErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.PublishAgentSkill(ctx, &tenantv1.PublishAgentSkillRequest{Name: "a", Reference: skillRef})
				return err
			}, codes.Internal},
		{"list: the store fails", func(s *faultSkillStore) { s.listErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.ListAgentSkills(ctx, &tenantv1.ListAgentSkillsRequest{})
				return err
			}, codes.Internal},
		{"grants: the Agent Skill is not in the store", func(s *faultSkillStore) { s.getErr = agentskillstore.ErrNotFound }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.ListAgentSkillGrants(ctx, &tenantv1.ListAgentSkillGrantsRequest{Name: "a"})
				return err
			}, codes.NotFound},
		{"grants: FGA fails", nil, func(f *faultSkillFGA) { f.listErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.ListAgentSkillGrants(ctx, &tenantv1.ListAgentSkillGrantsRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"shared list: the store fails", func(s *faultSkillStore) { s.getErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.ListSharedAgentSkills(ctx, &tenantv1.ListSharedAgentSkillsRequest{})
				return err
			}, codes.Internal},
		{"enable: the platform gate cannot be checked", nil, func(f *faultSkillFGA) { f.checkErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"enable: the store fails", func(s *faultSkillStore) { s.publishErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"enable: the owner tuple cannot be written", nil, func(f *faultSkillFGA) { f.writeErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"get: the current version cannot be read", func(s *faultSkillStore) { s.getErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.GetAgentSkill(ctx, &tenantv1.GetAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"get: the content cannot be loaded", func(s *faultSkillStore) { s.loadErr = agentskillstore.ErrNotFound }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.GetAgentSkill(ctx, &tenantv1.GetAgentSkillRequest{Name: "a", Digest: "sha256:02"})
				return err
			}, codes.NotFound},
		{"delete: FGA cannot list the grants", nil, func(f *faultSkillFGA) { f.listErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.DeleteAgentSkill(ctx, &tenantv1.DeleteAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"delete: FGA cannot delete the tuples", nil, func(f *faultSkillFGA) { f.deleteErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.DeleteAgentSkill(ctx, &tenantv1.DeleteAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"delete: the store fails", func(s *faultSkillStore) { s.deleteErr = errSkillBackend }, nil,
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.DeleteAgentSkill(ctx, &tenantv1.DeleteAgentSkillRequest{Name: "a"})
				return err
			}, codes.Internal},
		{"grant: the subject cannot be checked", nil, func(f *faultSkillFGA) { f.checkErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.GrantAgentSkill(ctx, &tenantv1.GrantAgentSkillRequest{Name: "a", SubjectKind: agent, SubjectId: "x"})
				return err
			}, codes.Internal},
		{"grant: the grant cannot be written", nil, func(f *faultSkillFGA) { f.writeErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				f := s.fga.(*faultSkillFGA)
				f.recordingAuthorizer.allow("tenant:acme", "belongs_to", "agent_principal:x")
				_, err := s.GrantAgentSkill(ctx, &tenantv1.GrantAgentSkillRequest{Name: "a", SubjectKind: agent, SubjectId: "x"})
				return err
			}, codes.Internal},
		{"revoke: the grant cannot be deleted", nil, func(f *faultSkillFGA) { f.deleteErr = errSkillBackend },
			func(s *AgentSkillService, ctx context.Context) error {
				_, err := s.RevokeAgentSkill(ctx, &tenantv1.RevokeAgentSkillRequest{Name: "a", SubjectKind: agent, SubjectId: "x"})
				return err
			}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, f := faultySkillService(t, tt.store, tt.fga)
			err := tt.call(svc, f.ctx)
			require.Error(t, err)
			assert.Equal(t, tt.want, code(err), "error = %v", err)
		})
	}
}

// Each call needs the tenant of the caller and a valid Agent Skill name.
func TestAgentSkillService_RefusesACallWithNoTenantOrABadName(t *testing.T) {
	svc, f := faultySkillService(t, nil, nil)
	anon := context.Background()
	agent := tenantv1.AgentSkillSubjectKind_AGENT_SKILL_SUBJECT_KIND_AGENT
	const bad = "Not A Name"
	calls := map[string]func(ctx context.Context, name string) error{
		"Publish": func(ctx context.Context, name string) error {
			_, err := svc.PublishAgentSkill(ctx, &tenantv1.PublishAgentSkillRequest{Name: name, Reference: skillRef})
			return err
		},
		"List": func(ctx context.Context, name string) error {
			_, err := svc.ListAgentSkills(ctx, &tenantv1.ListAgentSkillsRequest{Name: name})
			return err
		},
		"ListGrants": func(ctx context.Context, name string) error {
			_, err := svc.ListAgentSkillGrants(ctx, &tenantv1.ListAgentSkillGrantsRequest{Name: name})
			return err
		},
		"ListShared": func(ctx context.Context, _ string) error {
			_, err := svc.ListSharedAgentSkills(ctx, &tenantv1.ListSharedAgentSkillsRequest{})
			return err
		},
		"EnableShared": func(ctx context.Context, name string) error {
			_, err := svc.EnableSharedAgentSkill(ctx, &tenantv1.EnableSharedAgentSkillRequest{Name: name})
			return err
		},
		"Get": func(ctx context.Context, name string) error {
			_, err := svc.GetAgentSkill(ctx, &tenantv1.GetAgentSkillRequest{Name: name})
			return err
		},
		"Delete": func(ctx context.Context, name string) error {
			_, err := svc.DeleteAgentSkill(ctx, &tenantv1.DeleteAgentSkillRequest{Name: name})
			return err
		},
		"Grant": func(ctx context.Context, name string) error {
			_, err := svc.GrantAgentSkill(ctx, &tenantv1.GrantAgentSkillRequest{Name: name, SubjectKind: agent, SubjectId: "x"})
			return err
		},
		"Revoke": func(ctx context.Context, name string) error {
			_, err := svc.RevokeAgentSkill(ctx, &tenantv1.RevokeAgentSkillRequest{Name: name, SubjectKind: agent, SubjectId: "x"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.PermissionDenied, code(call(anon, "a")), "no tenant")
			if name != "ListShared" {
				assert.Equal(t, codes.InvalidArgument, code(call(f.ctx, bad)), "a bad name")
			}
		})
	}
}

func TestAgentSkillStatus_MapsEachClass(t *testing.T) {
	tests := []struct {
		err  error
		want codes.Code
	}{
		{agentskill.ErrOverLimit, codes.ResourceExhausted},
		{agentskill.ErrInvalidFolder, codes.InvalidArgument},
		{agentskillstore.ErrNotFound, codes.NotFound},
		{errSkillBackend, codes.Internal},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, code(agentSkillStatus("rpc", tt.err)), "error %v", tt.err)
	}
	assert.Equal(t, tenantv1.AgentSkillSource_AGENT_SKILL_SOURCE_UNSPECIFIED, agentSkillSourceProto("odd"))
}

// A name that the operator lists and cannot give is skipped.
func TestListSharedAgentSkills_SkipsAnOfferThatCannotBeRead(t *testing.T) {
	svc, f := faultySkillService(t, nil, nil)
	svc.shared = &vanishingShared{names: []string{"ghost"}}
	resp, err := svc.ListSharedAgentSkills(f.ctx, &tenantv1.ListSharedAgentSkillsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetEntries())
}

type vanishingShared struct{ names []string }

func (v *vanishingShared) Names() []string                     { return v.names }
func (v *vanishingShared) Get(string) (SharedAgentSkill, bool) { return SharedAgentSkill{}, false }

func TestNewAgentSkillService_NeedsEachDependency(t *testing.T) {
	f := newSkillFixture(t, nil)
	pull := f.svc.pull
	tests := []struct {
		name string
		make func() (*AgentSkillService, error)
	}{
		{"no store", func() (*AgentSkillService, error) { return NewAgentSkillService(nil, pull, f.fga, f.secrets, f.shared) }},
		{"no puller", func() (*AgentSkillService, error) {
			return NewAgentSkillService(f.store, nil, f.fga, f.secrets, f.shared)
		}},
		{"no authorizer", func() (*AgentSkillService, error) {
			return NewAgentSkillService(f.store, pull, nil, f.secrets, f.shared)
		}},
		{"no secrets", func() (*AgentSkillService, error) { return NewAgentSkillService(f.store, pull, f.fga, nil, f.shared) }},
		{"no shared source", func() (*AgentSkillService, error) { return NewAgentSkillService(f.store, pull, f.fga, f.secrets, nil) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := tt.make()
			require.Error(t, err)
			assert.Nil(t, svc)
		})
	}
}
