// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

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

// listingProvider is a provider whose live model list is fixed.
type listingProvider struct {
	stubMockProvider
	models []llm.ModelInfo
	err    error
}

func (p *listingProvider) Models(context.Context) ([]llm.ModelInfo, error) { return p.models, p.err }

func grantServer(t *testing.T) (*DaemonServer, *fakeAuthorizer) {
	t.Helper()
	az := newFakeAuthorizer().allow("user:user-test", "admin", "tenant:tenant-a")
	store := &listingProviderStore{configs: []*providerconfig.ProviderConfig{
		{Name: "my-openai", Type: llm.ProviderOpenAI, DefaultModel: "gpt-4o", Enabled: true},
		{Name: "off", Type: llm.ProviderGoogle, DefaultModel: "gemini-x", Enabled: false},
		{Name: "embed-only-type", Type: llm.ProviderVoyage, DefaultModel: "voyage-3", Enabled: true},
		{Name: "embed-capability", Type: llm.ProviderMistral, DefaultModel: "mistral-embed", Enabled: true,
			Capabilities: []string{providerconfig.CapabilityEmbedding}},
		{Name: "broken", Type: llm.ProviderCohere, DefaultModel: "command", Enabled: true},
	}}
	store.resolveFunc = func(_ context.Context, _, name string) (*providerconfig.DecryptedConfig, error) {
		dec := knownDecryptedConfig()
		dec.Name = name
		dec.Type = llm.ProviderType(map[string]string{"my-openai": "openai", "broken": "cohere"}[name])
		return dec, nil
	}
	s := newExecServer(store, func(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
		if cfg.Type == llm.ProviderCohere {
			return &listingProvider{err: errors.New("the list call failed")}, nil
		}
		return &listingProvider{models: []llm.ModelInfo{
			{Name: "gpt-4o-mini", Features: []string{"chat"}},
			{Name: "text-embedding-3", Features: []string{"embedding"}},
			{Name: "no-features-reported"},
		}}, nil
	})
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
		{"embedding-only type", prov, "voyage", codes.InvalidArgument},
		{"provider with only the embedding capability", prov, "mistral", codes.InvalidArgument},
		{"provider config name is not the gate name", prov, "my-openai", codes.InvalidArgument},
		{"free text provider", prov, "nonsense", codes.InvalidArgument},
		{"disabled provider", prov, "google", codes.InvalidArgument},
		{"default model", model, "gpt-4o", codes.OK},
		{"live chat model", model, "gpt-4o-mini", codes.OK},
		{"live model with no features reported", model, "no-features-reported", codes.OK},
		{"live embedding model", model, "text-embedding-3", codes.InvalidArgument},
		{"default model of an embedding-only config", model, "voyage-3", codes.InvalidArgument},
		{"default model of an embedding-capability config", model, "mistral-embed", codes.InvalidArgument},
		{"model of a provider whose list fails", model, "command-x", codes.InvalidArgument},
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

// blockingProvider waits for its context to end, as a provider that hangs does.
type blockingProvider struct{ stubMockProvider }

func (blockingProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("the list call ended: %w", ctx.Err())
}

// The live lists are asked at once under one deadline for all of them. A slow
// provider does not delay a model that another provider names, and a tenant with
// only hanging providers waits for one deadline, not one per provider.
func TestGrantAccess_ModelListsAreAskedAtOnceUnderOneDeadline(t *testing.T) {
	old := grantListTimeout
	grantListTimeout = 100 * time.Millisecond
	t.Cleanup(func() { grantListTimeout = old })

	configs := []*providerconfig.ProviderConfig{
		{Name: "slow-1", Type: llm.ProviderOpenAI, Enabled: true},
		{Name: "slow-2", Type: llm.ProviderMistral, Enabled: true},
		{Name: "quick", Type: llm.ProviderCohere, Enabled: true},
	}
	build := func(withQuick bool) *DaemonServer {
		store := &listingProviderStore{configs: configs}
		store.resolveFunc = func(_ context.Context, _, name string) (*providerconfig.DecryptedConfig, error) {
			dec := knownDecryptedConfig()
			dec.Name = name
			if name == "quick" {
				dec.Type = llm.ProviderCohere
			}
			return dec, nil
		}
		s := newExecServer(store, func(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
			if withQuick && cfg.Type == llm.ProviderCohere {
				return &listingProvider{models: []llm.ModelInfo{{Name: "wanted", Features: []string{"chat"}}}}, nil
			}
			return &blockingProvider{}, nil
		})
		s.logger = slog.Default()
		return s
	}

	start := time.Now()
	assert.True(t, build(true).anyProviderListsModel(context.Background(), "tenant-a", configs, "wanted"))
	assert.Less(t, time.Since(start), 90*time.Millisecond, "a quick answer must not wait for the slow providers")

	start = time.Now()
	assert.False(t, build(false).anyProviderListsModel(context.Background(), "tenant-a", configs, "wanted"))
	assert.Less(t, time.Since(start), 250*time.Millisecond, "three hanging providers must cost one deadline, not three")
}

// failingListStore fails the list call of the provider store.
type failingListStore struct{ stubProviderConfigStore }

func (failingListStore) List(context.Context, string) ([]*providerconfig.ProviderConfig, error) {
	return nil, errors.New("the store is down")
}

// A grant that the server cannot check is refused, never written.
func TestCheckGrantTarget_RefusesWhatItCannotCheck(t *testing.T) {
	prov := tenantv1.GrantTargetKind_GRANT_TARGET_KIND_PROVIDER
	t.Run("no provider store", func(t *testing.T) {
		s, _ := grantServer(t)
		s.providerConfig = nil
		assert.Equal(t, codes.FailedPrecondition, status_grpc.Code(s.checkGrantTarget(context.Background(), "tenant-a", prov, "openai")))
	})
	t.Run("the list fails", func(t *testing.T) {
		s, _ := grantServer(t)
		s.providerConfig = &failingListStore{}
		assert.Error(t, s.checkGrantTarget(context.Background(), "tenant-a", prov, "openai"))
	})
	for name, kind := range map[string]tenantv1.GrantTargetKind{
		"unspecified kind": tenantv1.GrantTargetKind_GRANT_TARGET_KIND_UNSPECIFIED,
		"unknown kind":     tenantv1.GrantTargetKind(99),
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := grantServer(t)
			assert.Equal(t, codes.InvalidArgument, status_grpc.Code(s.checkGrantTarget(context.Background(), "tenant-a", kind, "openai")))
		})
	}
}

// A provider that cannot be resolved, built or listed names no model. A tenant
// with no chat config names none either.
func TestProviderListsModel_NamesNothingWhenItFails(t *testing.T) {
	ctx := context.Background()
	cfg := &providerconfig.ProviderConfig{Name: "my-openai", Type: llm.ProviderOpenAI, Enabled: true}

	t.Run("resolve fails", func(t *testing.T) {
		s, _ := grantServer(t)
		store := &listingProviderStore{}
		store.resolveFunc = func(context.Context, string, string) (*providerconfig.DecryptedConfig, error) {
			return nil, errors.New("no credential")
		}
		s.providerConfig = store
		assert.False(t, s.providerListsModel(ctx, "tenant-a", cfg, "m"))
	})
	t.Run("factory fails", func(t *testing.T) {
		s, _ := grantServer(t)
		s.providerFactory = func(llm.ProviderConfig) (llm.LLMProvider, error) { return nil, errors.New("cannot build") }
		assert.False(t, s.providerListsModel(ctx, "tenant-a", cfg, "m"))
	})
	t.Run("default factory refuses an embedding-only type", func(t *testing.T) {
		s, _ := grantServer(t)
		store := &listingProviderStore{}
		store.resolveFunc = func(context.Context, string, string) (*providerconfig.DecryptedConfig, error) {
			dec := knownDecryptedConfig()
			dec.Type = llm.ProviderVoyage
			return dec, nil
		}
		s.providerConfig = store
		s.providerFactory = nil
		assert.False(t, s.providerListsModel(ctx, "tenant-a", cfg, "m"))
	})
	t.Run("no config", func(t *testing.T) {
		s, _ := grantServer(t)
		assert.False(t, s.anyProviderListsModel(ctx, "tenant-a", nil, "m"))
	})
}
