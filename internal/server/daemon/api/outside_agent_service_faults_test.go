// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// faultOutsideStore fails the calls that its fields name.
type faultOutsideStore struct {
	*memOutsideStore
	registerErr, listErr, getErr, deleteErr error
}

func (f *faultOutsideStore) Register(
	ctx context.Context, tenant string, e outsideagentstore.Entry,
) (*outsideagentstore.Entry, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	return f.memOutsideStore.Register(ctx, tenant, e)
}

func (f *faultOutsideStore) List(ctx context.Context, tenant string) ([]outsideagentstore.Entry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.memOutsideStore.List(ctx, tenant)
}

func (f *faultOutsideStore) Get(ctx context.Context, tenant, name string) (*outsideagentstore.Entry, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.memOutsideStore.Get(ctx, tenant, name)
}

func (f *faultOutsideStore) Delete(ctx context.Context, tenant, name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.memOutsideStore.Delete(ctx, tenant, name)
}

// faultyOutsideService is a service whose store and authorizer fail as given.
// The store holds the outside agent "scout".
func faultyOutsideService(
	t *testing.T, store func(*faultOutsideStore), fga func(*faultSkillFGA),
) (*OutsideAgentService, *outsideFixture) {
	t.Helper()
	f := registeredOutside(t)
	fs := &faultOutsideStore{memOutsideStore: f.store}
	ff := &faultSkillFGA{recordingAuthorizer: f.fga}
	if store != nil {
		store(fs)
	}
	if fga != nil {
		fga(ff)
	}
	svc, err := NewOutsideAgentService(fs, ff, f.svc.resolver, f.secrets)
	require.NoError(t, err)
	return svc, f
}

func TestOutsideAgentService_BackendFailuresAreMapped(t *testing.T) {
	const agent = "scout"
	tests := []struct {
		name  string
		store func(*faultOutsideStore)
		fga   func(*faultSkillFGA)
		call  func(s *OutsideAgentService, ctx context.Context) error
		want  codes.Code
	}{
		{"register: the store fails", func(s *faultOutsideStore) { s.registerErr = errSkillBackend }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.RegisterOutsideAgent(ctx, reg("new-one", outsideURL))
				return err
			}, codes.Internal},
		{"register: the owner tuple cannot be written", nil, func(f *faultSkillFGA) { f.writeErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.RegisterOutsideAgent(ctx, reg("new-one", outsideURL))
				return err
			}, codes.Internal},
		{"register: the CA bundle secret cannot be read", nil, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.RegisterOutsideAgent(ctx, &tenantv1.RegisterOutsideAgentRequest{
					Name: "new-one", A2AUrl: outsideURL, CaBundleSecret: "missing-ca"})
				return err
			}, codes.InvalidArgument},
		{"list: the store fails", func(s *faultOutsideStore) { s.listErr = errSkillBackend }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.ListOutsideAgents(ctx, &tenantv1.ListOutsideAgentsRequest{})
				return err
			}, codes.Internal},
		{"get: the record is not there", func(s *faultOutsideStore) { s.getErr = outsideagentstore.ErrNotFound }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.GetOutsideAgent(ctx, &tenantv1.GetOutsideAgentRequest{Name: agent})
				return err
			}, codes.NotFound},
		{"delete: the record is not there", func(s *faultOutsideStore) { s.getErr = outsideagentstore.ErrNotFound }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.DeleteOutsideAgent(ctx, &tenantv1.DeleteOutsideAgentRequest{Name: agent})
				return err
			}, codes.NotFound},
		{"delete: FGA cannot list the grants", nil, func(f *faultSkillFGA) { f.listErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.DeleteOutsideAgent(ctx, &tenantv1.DeleteOutsideAgentRequest{Name: agent})
				return err
			}, codes.Internal},
		{"delete: FGA cannot delete the tuples", nil, func(f *faultSkillFGA) { f.deleteErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.DeleteOutsideAgent(ctx, &tenantv1.DeleteOutsideAgentRequest{Name: agent})
				return err
			}, codes.Internal},
		{"delete: the store fails", func(s *faultOutsideStore) { s.deleteErr = errSkillBackend }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.DeleteOutsideAgent(ctx, &tenantv1.DeleteOutsideAgentRequest{Name: agent})
				return err
			}, codes.Internal},
		{"grant: the mission cannot be checked", nil, func(f *faultSkillFGA) { f.checkErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.GrantOutsideAgent(ctx, &tenantv1.GrantOutsideAgentRequest{Name: agent, MissionId: "m1"})
				return err
			}, codes.Internal},
		{"grant: the record is not there", func(s *faultOutsideStore) { s.getErr = outsideagentstore.ErrNotFound }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				s.fga.(*faultSkillFGA).allow("tenant:acme", "belongs_to", "mission:m1")
				_, err := s.GrantOutsideAgent(ctx, &tenantv1.GrantOutsideAgentRequest{Name: agent, MissionId: "m1"})
				return err
			}, codes.NotFound},
		{"grant: the grant cannot be written", nil, func(f *faultSkillFGA) { f.writeErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				s.fga.(*faultSkillFGA).allow("tenant:acme", "belongs_to", "mission:m1")
				_, err := s.GrantOutsideAgent(ctx, &tenantv1.GrantOutsideAgentRequest{Name: agent, MissionId: "m1"})
				return err
			}, codes.Internal},
		{"revoke: the grant cannot be deleted", nil, func(f *faultSkillFGA) { f.deleteErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.RevokeOutsideAgent(ctx, &tenantv1.RevokeOutsideAgentRequest{Name: agent, MissionId: "m1"})
				return err
			}, codes.Internal},
		{"grants: the record is not there", func(s *faultOutsideStore) { s.getErr = outsideagentstore.ErrNotFound }, nil,
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.ListOutsideAgentGrants(ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: agent})
				return err
			}, codes.NotFound},
		{"grants: FGA fails", nil, func(f *faultSkillFGA) { f.listErr = errSkillBackend },
			func(s *OutsideAgentService, ctx context.Context) error {
				_, err := s.ListOutsideAgentGrants(ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: agent})
				return err
			}, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, f := faultyOutsideService(t, tt.store, tt.fga)
			err := tt.call(svc, f.ctx)
			require.Error(t, err)
			assert.Equal(t, tt.want, code(err), "error = %v", err)
		})
	}
}

func TestOutsideAgentService_RefusesACallWithNoTenantOrABadName(t *testing.T) {
	svc, f := faultyOutsideService(t, nil, nil)
	const bad = "Not_A_Label"
	calls := map[string]func(ctx context.Context, name string) error{
		"Register": func(ctx context.Context, name string) error {
			_, err := svc.RegisterOutsideAgent(ctx, reg(name, outsideURL))
			return err
		},
		"List": func(ctx context.Context, _ string) error {
			_, err := svc.ListOutsideAgents(ctx, &tenantv1.ListOutsideAgentsRequest{})
			return err
		},
		"Get": func(ctx context.Context, name string) error {
			_, err := svc.GetOutsideAgent(ctx, &tenantv1.GetOutsideAgentRequest{Name: name})
			return err
		},
		"Delete": func(ctx context.Context, name string) error {
			_, err := svc.DeleteOutsideAgent(ctx, &tenantv1.DeleteOutsideAgentRequest{Name: name})
			return err
		},
		"Grant": func(ctx context.Context, name string) error {
			_, err := svc.GrantOutsideAgent(ctx, &tenantv1.GrantOutsideAgentRequest{Name: name, MissionId: "m1"})
			return err
		},
		"Revoke": func(ctx context.Context, name string) error {
			_, err := svc.RevokeOutsideAgent(ctx, &tenantv1.RevokeOutsideAgentRequest{Name: name, MissionId: "m1"})
			return err
		},
		"ListGrants": func(ctx context.Context, name string) error {
			_, err := svc.ListOutsideAgentGrants(ctx, &tenantv1.ListOutsideAgentGrantsRequest{Name: name})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.PermissionDenied, code(call(t.Context(), "scout")), "no tenant")
			if name != "List" {
				assertBadNameRefused(f.ctx, t, call, bad)
			}
		})
	}
}

func TestOutsideAgentService_AMissionIdThatIsNotValidIsRefused(t *testing.T) {
	svc, f := faultyOutsideService(t, nil, nil)
	for _, id := range []string{"", "  ", "a:b", "a#b", "a/b", "a b"} {
		_, err := svc.GrantOutsideAgent(f.ctx, &tenantv1.GrantOutsideAgentRequest{Name: "scout", MissionId: id})
		assert.Equal(t, codes.InvalidArgument, code(err), "grant with mission %q", id)
		_, err = svc.RevokeOutsideAgent(f.ctx, &tenantv1.RevokeOutsideAgentRequest{Name: "scout", MissionId: id})
		assert.Equal(t, codes.InvalidArgument, code(err), "revoke with mission %q", id)
	}
}

func TestOutsideAgentStatus_MapsEachClass(t *testing.T) {
	assert.Equal(t, codes.NotFound, code(outsideAgentStatus("rpc", outsideagentstore.ErrNotFound)))
	assert.Equal(t, codes.AlreadyExists, code(outsideAgentStatus("rpc", outsideagentstore.ErrConflict)))
	assert.Equal(t, codes.Internal, code(outsideAgentStatus("rpc", errSkillBackend)))
}

func TestValidateOutsideAgentURL_RefusesAURLThatDoesNotParse(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := ValidateOutsideAgentURL(context.Background(), f.svc.resolver, "https://a.example/%zz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not parse")
	_, err = ValidateOutsideAgentURL(context.Background(), f.svc.resolver, "https://agent.partner.example/a2a?")
	require.Error(t, err, "a bare question mark is a query")
}

func TestNewOutsideAgentService_NeedsEachDependency(t *testing.T) {
	f := newOutsideFixture(t)
	r := f.svc.resolver
	for name, make := range map[string]func() (*OutsideAgentService, error){
		"no store":    func() (*OutsideAgentService, error) { return NewOutsideAgentService(nil, f.fga, r, f.secrets) },
		"no authz":    func() (*OutsideAgentService, error) { return NewOutsideAgentService(f.store, nil, r, f.secrets) },
		"no resolver": func() (*OutsideAgentService, error) { return NewOutsideAgentService(f.store, f.fga, nil, f.secrets) },
		"no secrets":  func() (*OutsideAgentService, error) { return NewOutsideAgentService(f.store, f.fga, r, nil) },
	} {
		svc, err := make()
		require.Error(t, err, name)
		assert.Nil(t, svc, name)
	}
}
