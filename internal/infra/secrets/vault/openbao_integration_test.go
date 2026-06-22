//go:build openbao_integration
// +build openbao_integration

// Package vault — openbao_integration_test.go
//
// OpenBao migration (PRD deploy#431, ADR-0024) — compat suite landed
// in slice 3 (#90); Go client swap to github.com/openbao/openbao/api/v2
// landed in slice 4 (#91). This suite exercises the SDK's Vault
// provider against a real OpenBao 2.5.x container using the OpenBao
// client library end-to-end.
//
// API surfaces exercised:
//   - Provider construction (detectKVVersion via
//     sys/internal/ui/mounts/<mount> since slice 4 — no
//     sys/mounts:read needed)
//   - Health() / Probe()
//   - KV v2 Put / Get / Delete via the SecretsBroker contract suite
//   - Token auth (root, ad-hoc child token)
//   - AppRole auth (login + token TTL semantics)
//   - JWT auth (ADR-0009 shape: audience-bound, no per-tenant claims)
//   - Namespace create / read / delete (the architectural reason for
//     the migration — Vault Community doesn't have these; OpenBao OSS
//     does, per release-notes 2.3+)
//   - sys/internal/ui/mounts/<mount> read (the narrower-permission
//     KV-version probe slice 4 will switch detectKVVersion to)
//
// Build tag `openbao_integration` keeps this off the default `go test
// ./...` path. Run locally with:
//
//	go test -tags openbao_integration ./secrets/providers/vault/...
//
// CI: `openbao-integration` job in .github/workflows/ci.yaml.
//
// Each test creates its own OpenBao container for hermeticity. This
// is slower than sharing a container across the suite, but matches
// the existing integration_test.go pattern and keeps individual test
// failures from contaminating siblings.
//
// Spec: deploy#431 slice sdk#90; ADR-0024 references this suite as
// the compat-claim validator that gates slice 4 (the actual Go client
// swap to github.com/openbao/openbao/api/v2).
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// setupOpenBao starts an ephemeral OpenBao dev-mode container and
// configures it for the integration suite. Returns the HTTP address.
//
// Mirrors setupVault from integration_test.go but uses OpenBao's
// BAO_DEV_* env vars and the openbaoImage pin from
// openbao_smoke_test.go (which is the single source of truth for the
// version we test against).
//
// Skips gracefully when Docker is unavailable.
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

	// Configure the tenant-isolation policy that all per-tenant
	// operations rely on. Mirrors setupVaultPolicies from
	// integration_test.go.
	setupOpenBaoPolicies(t, ctx, addr)

	return addr
}

// setupOpenBaoPolicies writes the tenant policy used by the contract
// suite. Mirrors setupVaultPolicies, kept as a separate function so
// the OpenBao-specific path is auditable in isolation.
func setupOpenBaoPolicies(t *testing.T, ctx context.Context, addr string) {
	t.Helper()

	adminCfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}

	adminProvider, err := New(ctx, adminCfg)
	require.NoError(t, err, "build admin OpenBao provider for setup")

	require.NoError(t, adminProvider.Health(ctx), "OpenBao health check after setup")

	policyHCL := fmt.Sprintf(`
path "secret/data/tenant/%s/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/tenant/%s/*" {
  capabilities = ["list", "read", "delete"]
}
path "secret/metadata/tenant/%s" {
  capabilities = ["list", "read"]
}
`, openbaoTestTenantID, openbaoTestTenantID, openbaoTestTenantID)

	err = adminProvider.client.Sys().PutPolicyWithContext(ctx,
		"openbao-integration-test-policy", policyHCL,
	)
	require.NoError(t, err, "write OpenBao policy")
}

// ---------------------------------------------------------------------------
// Compat: KV v2 round-trip with token auth
// ---------------------------------------------------------------------------

// TestOpenBao_KVv2RoundTrip exercises the SDK's Put/Get/Delete/List
// surface against OpenBao with static token auth. This is the
// load-bearing compat test — proves OpenBao satisfies the SDK's
// daily-bread KV v2 API contract through the existing
// hashicorp/vault/api Go client.
//
// Does NOT call contract.RunContract because that suite's
// list_with_prefix_filter sub-test fails identically against both
// Vault and OpenBao (tracked at sdk#96 — KV v2 LIST does not support
// arbitrary-prefix matching; that's a contract-suite bug, not an
// OpenBao compat finding). When sdk#96 is fixed, this test can switch
// to contract.RunContract directly.
func TestOpenBao_KVv2RoundTrip(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	cfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err, "New() with token auth against OpenBao")

	tenantID, err := auth.NewTenantID(openbaoTestTenantID)
	require.NoError(t, err, "construct tenant ID")

	// Put / Get round-trip.
	name := "compat-roundtrip"
	want := []byte("openbao compat payload")
	require.NoError(t, p.Put(ctx, tenantID, name, want), "Put")

	got, err := p.Get(ctx, tenantID, name)
	require.NoError(t, err, "Get after Put")
	require.Equal(t, want, got, "round-trip value")

	// Overwrite.
	want2 := []byte("openbao compat payload v2")
	require.NoError(t, p.Put(ctx, tenantID, name, want2), "Put overwrite")
	got, err = p.Get(ctx, tenantID, name)
	require.NoError(t, err, "Get after overwrite")
	require.Equal(t, want2, got, "post-overwrite value")

	// Delete.
	require.NoError(t, p.Delete(ctx, tenantID, name), "Delete")
	_, err = p.Get(ctx, tenantID, name)
	require.ErrorIs(t, err, secrets.ErrNotFound, "Get after Delete should return ErrNotFound")
}

// ---------------------------------------------------------------------------
// Compat: Health
// ---------------------------------------------------------------------------

func TestOpenBao_Health(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	cfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, p.Health(ctx), "Health() against running OpenBao")
}

// ---------------------------------------------------------------------------
// Compat: Probe (write-read-delete canary)
// ---------------------------------------------------------------------------

func TestOpenBao_Probe(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	cfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, p.Probe(ctx), "Probe() against running OpenBao")
}

// ---------------------------------------------------------------------------
// Compat: KV v1 rejection (cubbyhole always exists; not KV v2)
// ---------------------------------------------------------------------------

func TestOpenBao_KVv1Rejection(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	cfg := Config{
		Address: addr,
		KVMount: "cubbyhole",
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  openbaoDevRootToken,
		},
	}

	_, err := New(ctx, cfg)
	require.Error(t, err, "New() with cubbyhole (KV v1) mount should fail against OpenBao")
	t.Logf("expected KV v1 rejection error: %v", err)
}

// ---------------------------------------------------------------------------
// Compat: AppRole login + refresh
// ---------------------------------------------------------------------------

// TestOpenBao_AppRole verifies the AppRole login + token-lookup path
// works against OpenBao. Uses the same flow as setupAppRole +
// TestVaultTokenRefresh_TTLExpiry from integration_test.go but with
// the openbaoDevRootToken in place of devRootToken.
func TestOpenBao_AppRole(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	// Build admin client to enable + configure AppRole.
	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = addr
	adminClient, err := api.NewClient(vaultCfg)
	require.NoError(t, err, "create admin client")
	adminClient.SetToken(openbaoDevRootToken)

	authMethods, err := adminClient.Sys().ListAuthWithContext(ctx)
	require.NoError(t, err, "list auth methods")
	if _, ok := authMethods["approle/"]; !ok {
		err = adminClient.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &api.MountInput{
			Type: "approle",
		})
		require.NoError(t, err, "enable AppRole auth on OpenBao")
	}

	// AppRole test policy — production-realistic shape:
	//   - auth/token/lookup-self: needed for RefreshToken's TTL probe.
	//   - secret/data/* and secret/metadata/*: realistic per-tenant
	//     KV access. detectKVVersion (slice 4 / #91) uses
	//     sys/internal/ui/mounts/secret to detect the mount's KV
	//     version, and OpenBao/Vault permission this endpoint via the
	//     UNDERLYING MOUNT's capabilities — a token with read on any
	//     path under `secret/` implicitly gets read on
	//     sys/internal/ui/mounts/secret (per
	//     openbao.org/api-docs/system/internal-ui-mounts: "rely on
	//     permissions granted to the individual mount path").
	//
	// No sys/mounts grant. No cross-mount enumeration.
	refreshPolicyHCL := `
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list", "delete"]
}
`
	err = adminClient.Sys().PutPolicyWithContext(ctx, "openbao-approle-test-policy", refreshPolicyHCL)
	require.NoError(t, err, "write AppRole-test policy")

	roleName := "openbao-approle-test"
	_, err = adminClient.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName, map[string]interface{}{
		"token_policies": []string{"openbao-approle-test-policy"},
		"token_ttl":      60,
		"token_max_ttl":  120,
	})
	require.NoError(t, err, "create AppRole role")

	roleIDSec, err := adminClient.Logical().ReadWithContext(ctx, "auth/approle/role/"+roleName+"/role-id")
	require.NoError(t, err, "read role-id")
	require.NotNil(t, roleIDSec)
	roleID, _ := roleIDSec.Data["role_id"].(string)
	require.NotEmpty(t, roleID, "role_id empty")

	secretIDSec, err := adminClient.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName+"/secret-id", nil)
	require.NoError(t, err, "generate secret-id")
	require.NotNil(t, secretIDSec)
	secretID, _ := secretIDSec.Data["secret_id"].(string)
	require.NotEmpty(t, secretID, "secret_id empty")

	// Build a Provider via the SDK using AppRole credentials and assert
	// it logs in successfully against OpenBao.
	cfg := Config{
		Address: addr,
		KVMount: openbaoTestMount,
		Auth: AuthConfig{
			Method:          AuthMethodAppRole,
			AppRoleID:       roleID,
			AppRoleSecretID: secretID,
		},
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err, "New() with AppRole auth against OpenBao")
	require.NoError(t, p.Health(ctx), "Health() with AppRole-authenticated client")
}

// ---------------------------------------------------------------------------
// Compat: namespaces (the architectural motivator)
// ---------------------------------------------------------------------------

// TestOpenBao_Namespaces exercises the namespace API that OpenBao OSS
// ships (per release notes 2.3+) and that Vault Community Edition
// lacks. This is the architectural reason for the migration: the
// tenant-operator's EnsureTenantNamespace flow depends on this API
// being available.
//
// Asserts:
//   - Create a namespace via POST /v1/sys/namespaces/<name>
//   - Read it back via GET /v1/sys/namespaces/<name>
//   - Mount a KV v2 inside the namespace (X-Vault-Namespace header)
//   - Write a secret inside the namespace's KV
//   - Read the secret back
//   - Delete the namespace (cascading delete of its contents)
//
// If this test passes, slice 5 (operator's EnsureTenantNamespace +
// writeInfraSecret path) is unblocked from the OpenBao side.
func TestOpenBao_Namespaces(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = addr
	adminClient, err := api.NewClient(vaultCfg)
	require.NoError(t, err)
	adminClient.SetToken(openbaoDevRootToken)

	// OpenBao (and Vault Enterprise) require hierarchical namespaces
	// to be created level-by-level: each path component is a separate
	// API call to `sys/namespaces/<name>` against the PARENT's
	// namespace context. The full namespace path `tenant/<id>` is
	// therefore two calls:
	//   1. Create `tenant` in the root namespace.
	//   2. Create `<id>` from inside the `tenant` namespace.
	// OpenBao returns 400 "path must not contain /" if you try to
	// create `tenant/<id>` in one shot — this is the explicit
	// architectural shape the operator's EnsureTenantNamespace
	// (slice 5) will use.
	const (
		parentNS = "tenant"
		childNS  = "openbao-compat-test"
	)
	fullNS := parentNS + "/" + childNS

	// Step 1: create the parent namespace at the root.
	_, err = adminClient.Logical().WriteWithContext(ctx, "sys/namespaces/"+parentNS, nil)
	require.NoError(t, err, "create parent namespace %q on OpenBao", parentNS)

	// Step 2: create the child namespace, with the parent set as the
	// namespace header on the request.
	parentClient, err := api.NewClient(vaultCfg)
	require.NoError(t, err)
	parentClient.SetToken(openbaoDevRootToken)
	parentClient.SetNamespace(parentNS)

	_, err = parentClient.Logical().WriteWithContext(ctx, "sys/namespaces/"+childNS, nil)
	require.NoError(t, err, "create child namespace %q under %q on OpenBao", childNS, parentNS)

	// Read it back from the parent's context. The response shape echoes
	// upstream Vault Enterprise per OpenBao's namespace-API-compat claim
	// (release notes 2.3).
	nsResp, err := parentClient.Logical().ReadWithContext(ctx, "sys/namespaces/"+childNS)
	require.NoError(t, err, "read namespace %q", childNS)
	require.NotNil(t, nsResp, "namespace read returned nil — namespace not found?")

	// Mount KV v2 inside the child namespace.
	nsClient, err := api.NewClient(vaultCfg)
	require.NoError(t, err)
	nsClient.SetToken(openbaoDevRootToken)
	nsClient.SetNamespace(fullNS)

	err = nsClient.Sys().MountWithContext(ctx, "secret", &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
	require.NoError(t, err, "mount KV v2 inside namespace %q", fullNS)

	// Write a secret inside the namespace.
	_, err = nsClient.Logical().WriteWithContext(ctx, "secret/data/infra/postgres", map[string]interface{}{
		"data": map[string]interface{}{
			"value": "openbao-namespace-compat-payload",
		},
	})
	require.NoError(t, err, "write secret inside namespace")

	// Read it back.
	readResp, err := nsClient.Logical().ReadWithContext(ctx, "secret/data/infra/postgres")
	require.NoError(t, err, "read secret inside namespace")
	require.NotNil(t, readResp, "secret read returned nil")
	dataField, _ := readResp.Data["data"].(map[string]interface{})
	require.Equal(t, "openbao-namespace-compat-payload", dataField["value"],
		"namespace-scoped secret round-trip value mismatch")

	// Cleanup: delete the child namespace from the parent's context
	// (mirroring the create path). OpenBao requires deleting
	// hierarchically the same way; the parent stays in place.
	// (The container terminates on test cleanup anyway, so leaving
	// the parent is fine.)
	_, err = parentClient.Logical().DeleteWithContext(ctx, "sys/namespaces/"+childNS)
	require.NoError(t, err, "delete child namespace %q under %q on OpenBao", childNS, parentNS)
}

// ---------------------------------------------------------------------------
// Compat: sys/internal/ui/mounts/<mount> (narrower-permission probe)
// ---------------------------------------------------------------------------

// TestOpenBao_InternalUIMountsProbe verifies that
// /v1/sys/internal/ui/mounts/<mount> returns the same Options[version]
// data as /v1/sys/mounts, with read-on-the-mount permission instead of
// cross-mount enumeration. Slice 4 (sdk#91) will rewrite the SDK's
// detectKVVersion to use this endpoint; this test proves OpenBao
// supports it identically to upstream Vault.
//
// The endpoint is documented at
// https://developer.hashicorp.com/vault/api-docs/system/internal-ui-mounts
// — declared "unstable" but stable in practice; we are accepting the
// API risk for the policy-narrowing benefit (per ADR-0024).
func TestOpenBao_InternalUIMountsProbe(t *testing.T) {
	ctx := context.Background()
	addr := setupOpenBao(t)
	if addr == "" {
		return
	}

	probeURL := addr + "/v1/sys/internal/ui/mounts/" + openbaoTestMount
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", openbaoDevRootToken)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET %s", probeURL)
	defer func() { _ = resp.Body.Close() }()

	require.GreaterOrEqual(t, resp.StatusCode, 200)
	require.Less(t, resp.StatusCode, 300, "/sys/internal/ui/mounts/<mount> status (got %d)", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// The response shape mirrors Vault's:
	//   {"data": {"type": "kv", "options": {"version": "2"}, ...}, "request_id": "..."}
	var parsed struct {
		Data struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed),
		"parse /sys/internal/ui/mounts response: %s", string(body))

	require.Equal(t, "kv", parsed.Data.Type,
		"mount type for %q: got %q want %q", openbaoTestMount, parsed.Data.Type, "kv")
	require.Equal(t, "2", parsed.Data.Options["version"],
		"mount %q KV version: got %q want %q", openbaoTestMount, parsed.Data.Options["version"], "2")
}
