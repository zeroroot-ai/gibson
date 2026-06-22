//go:build openbao_integration

/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vault — openbao_integration_test.go
//
// Slice 5 of the OpenBao migration (PRD deploy#431, ADR-0024, #171).
//
// Integration test that exercises the operator's AdminClient end-to-end
// against a real OpenBao 2.5.x container via testcontainers-go.
//
// Outcome: proves that the operator's raw-HTTP path produces a Vault
// state shape that matches the daemon's read-side expectations, post
// EditionCommunity rip + bound_claims removal. If this passes, slice 6
// (chart kind-dev cutover) can rely on the operator's runtime
// behaviour matching the SDK's openbao_integration_test.go (sdk#90).
//
// API surfaces exercised:
//   - EnsureTenantNamespace creates `tenant/<id>` namespace + KV v2 mount
//   - policy + JWT role (the full provisioning chain)
//   - The resulting JWT role MUST carry bound_audiences=[gibson-saas] and
//     MUST NOT carry bound_claims (the slice 5 invariant subsuming #151)
//   - WriteInfraPostgres writes credentials inside the tenant namespace
//   - DeleteTenantNamespace tears the namespace down
//
// Build tag `openbao_integration` keeps this off the default `go test
// ./...` path. Run locally with:
//
//	go test -tags openbao_integration ./internal/clients/vault/...
//
// Skipped gracefully when Docker is unavailable.
package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

const (
	// openbaoImage matches the SDK's openbao_integration_test.go pin
	// (sdk#90). Bumping must be coordinated across both repos.
	openbaoImage = "openbao/openbao:2.5.3"

	// openbaoDevRootToken is the fixed root token used by OpenBao's
	// dev-mode server.
	openbaoDevRootToken = "dev-root-token"
)

// setupOpenBao starts an ephemeral OpenBao dev-mode container and returns
// the HTTP address. Skipped gracefully when Docker is unavailable.
func setupOpenBao(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping OpenBao integration test: %v", err)
		return ""
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping OpenBao integration test: %v", healthErr)
		return ""
	}

	req := testcontainers.ContainerRequest{
		Image: openbaoImage,
		Env: map[string]string{
			"BAO_DEV_ROOT_TOKEN_ID":  openbaoDevRootToken,
			"BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
			"SKIP_SETCAP":            "true",
			"BAO_LOG_LEVEL":          "info",
		},
		ExposedPorts: []string{"8200/tcp"},
		Cmd:          []string{"server", "-dev"},
		WaitingFor: wait.ForAll(
			wait.ForLog("==> OpenBao server started!").WithStartupTimeout(60*time.Second),
			wait.ForListeningPort("8200/tcp").WithStartupTimeout(60*time.Second),
		),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start OpenBao container")

	t.Cleanup(func() {
		if termErr := c.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate OpenBao container: %v", termErr)
		}
	})

	host, err := c.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := c.MappedPort(ctx, "8200")
	require.NoError(t, err)

	addr := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())
	time.Sleep(500 * time.Millisecond)
	return addr
}

// TestOpenBaoEnsureTenantNamespace exercises the full provisioning
// chain end-to-end against a real OpenBao container. This is the
// load-bearing slice 5 acceptance test.
//
// Asserts:
//   - EnsureTenantNamespace returns EditionEnterprise + nil error
//   - The expected JWT role exists at auth/jwt/role/gibson-plugin-acme
//   - The role has bound_audiences=[gibson-saas]
//   - The role MUST NOT have bound_claims (slice 5 invariant subsuming
//     tenant-operator#151)
//   - WriteInfraPostgres writes a payload inside the namespace
//   - DeleteTenantNamespace cleans up the namespace
//
// The OpenBao container is shared across this test's sub-tests via a
// single setupOpenBao call.
func TestOpenBaoEnsureTenantNamespace(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	c, err := New(Config{
		Address:          addr,
		AdminToken:       openbaoDevRootToken,
		JWTAuthMountPath: "auth/jwt",
		JWTBoundAudience: "gibson-saas",
	})
	require.NoError(t, err, "construct AdminClient against OpenBao")

	// Per-tenant JWT auth method is mounted by EnsureTenantNamespace
	// INSIDE the tenant namespace (slice 5 / #171). No root-level
	// auth/jwt mount is required for the per-tenant path — the chart's
	// vault-jwt-auth-init Job is no longer load-bearing for tenant
	// provisioning under OpenBao. (Slice 6 will remove the root mount
	// from the chart as part of the kind-dev cutover.)

	const tenantID = "acme"

	t.Run("EnsureTenantNamespace happy path", func(t *testing.T) {
		ed, err := c.EnsureTenantNamespace(ctx, tenantID)
		require.NoError(t, err, "EnsureTenantNamespace against OpenBao")
		require.Equal(t, EditionEnterprise, ed,
			"slice 5 returns EditionEnterprise for the OpenBao namespace-based path")
	})

	t.Run("role has bound_audiences, no bound_claims", func(t *testing.T) {
		// Read the role back via the AdminClient's `do` helper.
		client := c.(*httpClient)
		var resp struct {
			Data map[string]any `json:"data"`
		}
		fullNS := joinNamespace(client.cfg.RootNamespace, tenantNamespacePath(tenantID))
		require.NoError(t,
			client.do(ctx, "GET", "/v1/auth/jwt/role/gibson-plugin-"+tenantID, fullNS, nil, &resp),
			"read JWT role back from OpenBao",
		)
		require.NotNil(t, resp.Data, "role read returned nil data")

		// slice 5 invariant (subsuming #151): no bound_claims.
		if bc, ok := resp.Data["bound_claims"]; ok && bc != nil {
			// Vault returns map[string]interface{}; if it's truly absent it
			// shows up as nil or missing. Some Vault versions return an
			// empty map; treat that as "absent" too.
			if asMap, ok := bc.(map[string]interface{}); !ok || len(asMap) > 0 {
				t.Errorf("role MUST NOT carry bound_claims (slice 5 / #151); got %v", bc)
			}
		}

		// ADR-0009: bound_audiences MUST contain the configured audience.
		ba, _ := resp.Data["bound_audiences"].([]interface{})
		require.NotEmpty(t, ba, "bound_audiences absent or empty")
		require.Equal(t, "gibson-saas", ba[0], "bound_audiences[0]")
	})

	t.Run("WriteInfraPostgres writes inside the namespace", func(t *testing.T) {
		creds := pdataplane.PostgresCredentials{
			Host:     "platform-postgres-rw.gibson.svc",
			Port:     5432,
			Database: "tenant_" + tenantID,
			Role:     "tenant_" + tenantID,
			Password: "supersecret",
		}
		require.NoError(t, c.WriteInfraPostgres(ctx, tenantID, creds),
			"WriteInfraPostgres against OpenBao")
	})

	t.Run("idempotent rerun of EnsureTenantNamespace", func(t *testing.T) {
		ed, err := c.EnsureTenantNamespace(ctx, tenantID)
		require.NoError(t, err, "idempotent rerun")
		require.Equal(t, EditionEnterprise, ed)
	})

	t.Run("DeleteTenantNamespace tears down", func(t *testing.T) {
		require.NoError(t, c.DeleteTenantNamespace(ctx, tenantID),
			"DeleteTenantNamespace against OpenBao")
	})
}
