// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// listingProviderStore lists a fixed set of provider configs of the tenant.
type listingProviderStore struct {
	stubProviderConfigStore
	configs []*providerconfig.ProviderConfig
}

func (s *listingProviderStore) List(context.Context, string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs, nil
}

func grantServer(t *testing.T) (*DaemonServer, *fakeAuthorizer) {
	t.Helper()
	az := newFakeAuthorizer().allow("user:user-test", "admin", "tenant:tenant-a")
	store := &listingProviderStore{configs: []*providerconfig.ProviderConfig{
		{Name: "my-openai", Type: llm.ProviderOpenAI, DefaultModel: "gpt-4o", Enabled: true},
		{Name: "off", Type: llm.ProviderGoogle, DefaultModel: "gemini-x", Enabled: false},
	}}
	s := newExecServer(store, func(llm.ProviderConfig) (llm.LLMProvider, error) { return &stubMockProvider{}, nil })
	s.logger = slog.Default()
	s.authorizer = az
	return s, az
}

func grantReq(kind tenantv1.GrantTargetKind, id string) *tenantv1.GrantAccessRequest {
	return &tenantv1.GrantAccessRequest{Grant: &tenantv1.AccessGrant{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER,
		SubjectId:   "alice",
		TargetKind:  kind,
		TargetId:    id,
	}}
}

// GrantAccess refuses a target that matches no registered provider type or
// known model, and accepts one that does.
func TestGrantAccess_RefusesATargetThatMatchesNothing(t *testing.T) {
	prov := tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER
	model := tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL
	cases := []struct {
		name string
		kind tenantv1.GrantTargetKind
		id   string
		want codes.Code
	}{
		{"provider type", prov, "openai", codes.OK},
		{"provider config name is not the gate name", prov, "my-openai", codes.InvalidArgument},
		{"free text provider", prov, "nonsense", codes.InvalidArgument},
		{"disabled provider", prov, "google", codes.InvalidArgument},
		{"default model", model, "gpt-4o", codes.OK},
		{"free text model", model, "no-such-model", codes.InvalidArgument},
		{"model of a disabled provider", model, "gemini-x", codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, az := grantServer(t)
			_, err := s.GrantAccess(tenantCtx("tenant-a"), grantReq(tc.kind, tc.id))
			assert.Equal(t, tc.want, status_grpc.Code(err), "%v", err)
			if tc.want != codes.OK {
				assert.Empty(t, az.writtenTuples(), "a refused grant must write no tuple")
			} else {
				require.Len(t, az.writtenTuples(), 1)
			}
		})
	}
}

// RevokeAccess keeps accepting any stored target, so an old row can be removed.
func TestRevokeAccess_AcceptsATargetThatMatchesNothing(t *testing.T) {
	s, _ := grantServer(t)
	_, err := s.RevokeAccess(tenantCtx("tenant-a"), &tenantv1.RevokeAccessRequest{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER,
		SubjectId:   "alice",
		TargetKind:  tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER,
		TargetId:    "free-text-from-an-old-row",
	})
	require.NoError(t, err)
}
