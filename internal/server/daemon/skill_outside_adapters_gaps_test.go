// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
)

// stubPool is a data-plane pool that the registration reads but never calls.
type stubPool struct{ datapool.Pool }

// stubAuthorizer is an authorizer that the registration reads but never calls.
type stubAuthorizer struct{ authz.Authorizer }

// pageKeysForTest builds the page token keys that a registration needs.
func pageKeysForTest(t *testing.T) *pagetoken.Keys {
	t.Helper()
	keys, err := pagetoken.NewKeys(bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	return keys
}

func TestRegisterAgentSkill_NeedsThePoolAndTheAuthorizer(t *testing.T) {
	ctx := context.Background()
	keys := pageKeysForTest(t)
	srv := grpc.NewServer()

	d := newMinimalDaemon(nil)
	require.ErrorContains(t, d.registerAgentSkill(ctx, srv, keys), "needs the per-tenant data pool")

	d.pool = stubPool{}
	require.ErrorContains(t, d.registerAgentSkill(ctx, srv, keys), "needs the authorizer")
	assert.Nil(t, d.agentSkillStore(), "no store before the registration")

	d.authorizer = stubAuthorizer{}
	require.NoError(t, d.registerAgentSkill(ctx, srv, keys))
	assert.NotNil(t, d.agentSkillStore())
	assert.NotNil(t, d.sharedAgentSkills, "an empty operator source is still a source")
	assert.Contains(t, srv.GetServiceInfo(), "gibson.tenant.v1.AgentSkillService")
}

func TestRegisterOutsideAgent_NeedsThePoolTheAuthorizerAndTheSecretStore(t *testing.T) {
	ctx := context.Background()
	keys := pageKeysForTest(t)
	srv := grpc.NewServer()

	d := newMinimalDaemon(nil)
	require.ErrorContains(t, d.registerOutsideAgent(ctx, srv, keys), "needs the per-tenant data pool")

	d.pool = stubPool{}
	require.ErrorContains(t, d.registerOutsideAgent(ctx, srv, keys), "needs the authorizer")

	d.authorizer = stubAuthorizer{}
	require.ErrorContains(t, d.registerOutsideAgent(ctx, srv, keys), "needs the tenant secret store")
	assert.Nil(t, d.outsideAgentStore())

	d.secretsService = &secrets.Service{}
	require.NoError(t, d.registerOutsideAgent(ctx, srv, keys))
	assert.NotNil(t, d.outsideAgentStore())
	assert.Contains(t, srv.GetServiceInfo(), "gibson.tenant.v1.OutsideAgentService")
}

func TestDaemonSecretReader_NeedsTheSecretsBroker(t *testing.T) {
	_, err := daemonSecretReader{d: &daemonImpl{}}.Resolve(context.Background(), "name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the secrets broker is not ready")
}

func TestOperatorSkillPuller_UsesTheKeychainOfTheCredentialDir(t *testing.T) {
	var dir string
	pull := operatorSkillPuller("/run/creds", func(d string) authn.Keychain {
		dir = d
		return authn.NewMultiKeychain()
	})
	assert.Equal(t, "/run/creds", dir)
	_, err := pull(context.Background(), "not a reference", "web-recon")
	require.Error(t, err, "a reference that does not parse is refused before any call")
}

// failingGateFGA fails the call that its field names.
type failingGateFGA struct {
	gateFGA
	listErr, writeErr, deleteErr error
}

func (f *failingGateFGA) ListObjects(ctx context.Context, u, r, o string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.gateFGA.ListObjects(ctx, u, r, o)
}

func (f *failingGateFGA) Write(ctx context.Context, t []authz.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.gateFGA.Write(ctx, t)
}

func (f *failingGateFGA) Delete(ctx context.Context, t []authz.Tuple) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.gateFGA.Delete(ctx, t)
}

func TestSeedSharedAgentSkillGate_FailuresAreReported(t *testing.T) {
	boom := errors.New("fga down")
	shared, _ := loadSharedAgentSkills(context.Background(), []config.SharedAgentSkillConfig{
		{Name: "web-recon", Reference: "r@sha256:a"},
	}, okPuller, discardLog())

	tests := []struct {
		name    string
		fga     *failingGateFGA
		wantErr string
	}{
		{"the list fails", &failingGateFGA{listErr: boom}, "list platform_enabled"},
		{"the write fails", &failingGateFGA{writeErr: boom}, "write 1 tuples"},
		{"the delete fails", &failingGateFGA{gateFGA: gateFGA{existing: []string{"agent_skill:_shared/retired", "agent_skill:_shared/web-recon"}}, deleteErr: boom},
			"delete 1 tuples"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := seedSharedAgentSkillGate(context.Background(), tt.fga, shared, discardLog())
			require.Error(t, err)
			require.ErrorIs(t, err, boom)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	bad, _ := loadSharedAgentSkills(context.Background(), []config.SharedAgentSkillConfig{
		{Name: "bad/name", Reference: "r@sha256:a"},
	}, okPuller, discardLog())
	err := seedSharedAgentSkillGate(context.Background(), &failingGateFGA{}, bad, discardLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shared Agent Skill gate")
}

// stubSkillStore is an Agent Skill store that the test never calls.
type stubSkillStore struct{ agentskillstore.Store }

// The files of a skill-script call read the store through a provider that
// answers nil, and not a typed nil, until the store is built.
func TestSkillFileStore_IsNilUntilTheStoreIsBuilt(t *testing.T) {
	d := &daemonImpl{}
	assert.Equal(t, harness.SkillFileStore(nil), d.skillFileStore(), "no store built: the provider must answer a nil interface")
	d.agentSkills = stubSkillStore{}
	assert.NotNil(t, d.skillFileStore(), "a built store must be served")
}
