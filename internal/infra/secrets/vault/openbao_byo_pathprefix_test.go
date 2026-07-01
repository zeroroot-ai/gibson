//go:build openbao_integration
// +build openbao_integration

// Package vault — openbao_byo_pathprefix_test.go
//
// BYO (path-prefix) mode integration guard for the broker-config codec slice
// (gibson#1108 / PRD gibson#1105 M2). The Hosted namespace-mode round-trip is
// covered by openbao_integration_test.go's
// TestOpenBao_TenantSecretColonFlatRoot_NamespaceMode; this file covers the
// second execution mode — a customer's own Vault addressed by a per-tenant KV
// path prefix (no namespaces on OSS OpenBao/Vault CE).
//
// The codec (internal/infra/secrets/vault/brokercodec) maps a BYO candidate
// to a vault.Config with Namespace="" (path-prefix mode). We cannot import
// that package here (it imports this one — an import cycle), so we assert the
// provider half directly: a path-prefix-mode Config Puts/Lists/Gets a
// colon-flat tenant secret UNDER the tenant-scoped prefix. Together with the
// brokercodec unit round-trip (candidate → PathPrefix intact), this closes the
// "BYO SetSecret stores + lists under the path prefix" acceptance criterion.
package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestOpenBao_TenantSecret_PathPrefixMode_BYO verifies that in path-prefix
// (BYO) mode — cfg.Namespace == "" — a colon-flat tenant secret is stored and
// listed under the tenant-scoped prefix, and is reachable by an independent
// admin client at secret/data/tenant/<id>/<key> (proving the prefix).
func TestOpenBao_TenantSecret_PathPrefixMode_BYO(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	tenantID, err := auth.NewTenantID(openbaoTestTenantID)
	require.NoError(t, err, "construct tenant ID")

	// Path-prefix mode: no namespace. This is the BYO shape the codec emits
	// for a VAULT_BYO candidate (Namespace empty, isolation via path prefix).
	cfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}
	require.Empty(t, cfg.Namespace, "BYO must be path-prefix mode (no namespace)")

	p, err := New(ctx, cfg)
	require.NoError(t, err, "New() in path-prefix mode")

	const key = "cred:openai-prod"
	want := []byte("byo-secret-value")
	require.NoError(t, p.Put(ctx, tenantID, key, want), "Put colon-flat key in path-prefix mode")

	// List must return the key from under the tenant prefix.
	names, err := p.List(ctx, tenantID, secrets.Filter{})
	require.NoError(t, err, "List in path-prefix mode")
	require.Contains(t, names, key,
		"colon-flat key must be listed under the tenant path prefix (BYO, gibson#1108)")

	// Get must round-trip the value.
	got, err := p.Get(ctx, tenantID, key)
	require.NoError(t, err, "Get after Put in path-prefix mode")
	require.Equal(t, want, got, "round-trip value in path-prefix mode")

	// Prove the storage location: an independent admin client reads the secret
	// at the expected prefixed logical path secret/data/tenant/<id>/<key>.
	adminCfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth:    AuthConfig{Method: AuthMethodToken, Token: openbaoDevRootToken},
	}
	admin, err := New(ctx, adminCfg)
	require.NoError(t, err, "build admin client")
	prefixedPath := "tenant/" + tenantID.String() + "/" + key
	kv, err := admin.client.KVv2(openbaoTestMount).Get(ctx, prefixedPath)
	require.NoError(t, err, "admin Get at prefixed path %q", prefixedPath)
	require.NotNil(t, kv, "secret must exist at the tenant-scoped prefix")

	// Cleanup.
	require.NoError(t, p.Delete(ctx, tenantID, key), "Delete")
}
