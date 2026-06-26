// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// EnsureTenantNamespace implements AdminClient. It is idempotent:
// ensures the namespace tenant-<id> exists, mounts KV v2 at "secret/"
// inside it, writes the tenant-<id>-app ACL policy scoped to that
// namespace, and configures a JWT auth role for plugin workloads.
//
// Each underlying Vault API call is itself idempotent (the policy and
// role write endpoints are upserts). Re-running for an
// already-provisioned tenant is a no-op.
//
// Always returns EditionEnterprise. The typed return preserves the
// upstream saga's recording shape; see Edition's godoc.
func (c *httpClient) EnsureTenantNamespace(ctx context.Context, tenantID string) (Edition, error) {
	if err := validateTenantID(tenantID); err != nil {
		return EditionUnknown, err
	}
	if err := c.ensureNamespace(ctx, tenantID); err != nil {
		return EditionUnknown, err
	}
	return EditionEnterprise, nil
}

// DeleteTenantNamespace implements AdminClient. Idempotent: 404s are
// treated as success (already gone).
func (c *httpClient) DeleteTenantNamespace(ctx context.Context, tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	return c.deleteNamespace(ctx, tenantID)
}

// ----- namespace-based provisioning ------------------------------------------

func (c *httpClient) ensureNamespace(ctx context.Context, tenantID string) error {
	nsPath := tenantNamespacePath(tenantID)

	// 1. Create the namespace (idempotent: Vault returns 400 with
	//    "namespace already exists" or 200 — we treat both as success).
	if err := c.createNamespace(ctx, nsPath); err != nil {
		return fmt.Errorf("create namespace %q: %w", nsPath, err)
	}

	// 2. Mount KV v2 at "secret/" inside the namespace. Idempotent: the
	//    write endpoint is an upsert; "path is already in use" -> success.
	fullNS := joinNamespace(c.cfg.RootNamespace, nsPath)
	if err := c.mountKVv2(ctx, fullNS, "secret"); err != nil {
		return fmt.Errorf("mount kv v2 in namespace %q: %w", fullNS, err)
	}

	// 3. Mount the JWT auth method inside the tenant namespace. The daemon
	//    authenticates per-tenant via /v1/auth/jwt/login WITH
	//    X-Vault-Namespace=tenant-<id>, so the JWT auth method needs to
	//    live inside each tenant's namespace (Vault/OpenBao routes the
	//    /auth/jwt path strictly by namespace header). Idempotent: the
	//    write is an upsert.
	if err := c.mountJWTAuth(ctx, fullNS); err != nil {
		return fmt.Errorf("mount jwt auth in namespace %q: %w", fullNS, err)
	}

	// 4. Write the tenant ACL policy. The policy is scoped to "secret/data/*"
	//    and "secret/metadata/*" *within* the namespace.
	policyName := tenantPolicyName(tenantID)
	policyHCL := tenantPolicyHCL()
	if err := c.writePolicy(ctx, fullNS, policyName, policyHCL); err != nil {
		return fmt.Errorf("write policy %q: %w", policyName, err)
	}

	// 5. Configure the JWT auth role for plugin workloads.
	if err := c.writeJWTRole(ctx, fullNS, tenantID, policyName); err != nil {
		return fmt.Errorf("write jwt role for tenant %q: %w", tenantID, err)
	}
	return nil
}

// mountJWTAuth enables the JWT auth method inside the given namespace.
// Idempotent: "path is already in use" is treated as success.
func (c *httpClient) mountJWTAuth(ctx context.Context, namespace string) error {
	body := map[string]any{
		"type": "jwt",
	}
	jwtPath := strings.TrimSuffix(c.cfg.JWTAuthMountPath, "/")
	jwtPath = strings.TrimPrefix(jwtPath, "auth/")
	path := "/v1/sys/auth/" + jwtPath
	err := c.do(ctx, http.MethodPost, path, namespace, body, nil)
	if err == nil {
		return nil
	}
	if errors.Is(err, clients.ErrInvalidInput) && containsAny(err.Error(), "path is already in use", "existing mount") {
		return nil
	}
	return err
}

func (c *httpClient) deleteNamespace(ctx context.Context, tenantID string) error {
	nsPath := tenantNamespacePath(tenantID)
	// DELETE /v1/sys/namespaces/<path>; 404 is treated as success.
	path := "/v1/sys/namespaces/" + nsPath
	err := c.do(ctx, http.MethodDelete, path, c.cfg.RootNamespace, nil, nil)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("vault: delete namespace %q: %w", nsPath, err)
}

func (c *httpClient) createNamespace(ctx context.Context, nsPath string) error {
	path := "/v1/sys/namespaces/" + nsPath
	err := c.do(ctx, http.MethodPost, path, c.cfg.RootNamespace, map[string]any{}, nil)
	if err == nil {
		return nil
	}
	// 400 "already exists" is success. Vault returns the message in the
	// errors array — do() wrapped it as ErrInvalidInput. Inspect the
	// message and treat the well-known idempotency case as no-op.
	if errors.Is(err, clients.ErrInvalidInput) && containsAny(err.Error(), "already exists", "already in use") {
		return nil
	}
	if errors.Is(err, clients.ErrConflict) {
		return nil
	}
	return err
}

func (c *httpClient) mountKVv2(ctx context.Context, namespace, mountPath string) error {
	body := map[string]any{
		"type": "kv",
		"options": map[string]any{
			"version": "2",
		},
	}
	path := "/v1/sys/mounts/" + strings.TrimSuffix(mountPath, "/")
	err := c.do(ctx, http.MethodPost, path, namespace, body, nil)
	if err == nil {
		return nil
	}
	if errors.Is(err, clients.ErrInvalidInput) && containsAny(err.Error(), "path is already in use", "existing mount") {
		return nil
	}
	return err
}

// ----- shared helpers --------------------------------------------------------

// writePolicy upserts an ACL policy at the given name. namespace, when
// non-empty, scopes the write to that Vault namespace.
func (c *httpClient) writePolicy(ctx context.Context, namespace, name, hcl string) error {
	body := map[string]any{"policy": hcl}
	path := "/v1/sys/policies/acl/" + name
	return c.do(ctx, http.MethodPut, path, namespace, body, nil)
}

// writeJWTRole upserts a Vault JWT auth role for the tenant's plugin
// principals. The role grants the tenant's ACL policy and is constrained
// by:
//
//   - `bound_audiences = [<configured-audience>]` (binds the role to
//     JWTs whose `aud` claim matches the platform-configured audience —
//     load-bearing per ADR-0009 / tenant-operator#147).
//
// Per-tenant isolation comes from the role NAME (`gibson-plugin-<tenantID>`),
// which selects the per-tenant ACL policy. The daemon (sole caller) is
// the trusted intermediary; ext-authz validates the request's tenant
// context, the daemon's FGA layer enforces it, and the daemon then picks
// the matching role name when authenticating to Vault.
//
// `bound_claims.gibson_tenant` was historically REQUIRED here but cannot
// be satisfied by SPIRE-minted JWT-SVIDs (SPIRE's Workload API does not
// support per-call custom claim injection — only audience). The daemon's
// JWTSource mints SPIRE JWT-SVIDs with audience only. Dropped per
// tenant-operator#151 / ADR-0009 amendment; subsumed into slice 5 of
// the OpenBao migration (PRD deploy#431, ADR-0024).
//
// JWTBoundAudience is enforced non-empty at operator boot in
// cmd/main.go buildWriteTenantBrokerConfigDeps; this function defends in
// depth and returns an error when JWTBoundAudience is empty so future
// call paths cannot accidentally provision a role that accepts any
// audience.
func (c *httpClient) writeJWTRole(ctx context.Context, namespace, tenantID, policyName string) error {
	if strings.TrimSpace(c.cfg.JWTBoundAudience) == "" {
		return fmt.Errorf("vault: JWTBoundAudience is required (ADR-0009 / tenant-operator#147): %w",
			clients.ErrInvalidInput)
	}
	body := map[string]any{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"token_policies":  []string{policyName},
		"token_ttl":       "30m",
		"token_max_ttl":   "1h",
		"bound_audiences": []string{c.cfg.JWTBoundAudience},
	}
	path := fmt.Sprintf("/v1/%s/role/%s", strings.TrimSuffix(c.cfg.JWTAuthMountPath, "/"), jwtRoleName(tenantID))
	return c.do(ctx, http.MethodPost, path, namespace, body, nil)
}

// ----- Neo4j infra credentials -----------------------------------------------

// WriteInfraNeo4j implements AdminClient. KV v2 write inside the
// tenant-<id> namespace at secret/data/infra/neo4j. Idempotent: Vault
// KV v2 write is an upsert.
//
// Future cleanup: replace this signature with WriteInfraNeo4jCredentials
// taking the full pdataplane.Neo4jCredentials struct, mirroring the
// other typed writers added in Phase 2.4.
func (c *httpClient) WriteInfraNeo4j(ctx context.Context, tenantID, username, password string) error {
	creds := pdataplane.Neo4jCredentials{
		Username: username,
		Password: password,
	}
	return c.writeInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraNeo4j, creds)
}

// DeleteInfraNeo4j implements AdminClient. Deletes all versions of the
// Neo4j credentials at "infra/neo4j" for tenantID inside the
// tenant-<id> namespace. Idempotent: 404 is treated as success.
func (c *httpClient) DeleteInfraNeo4j(ctx context.Context, tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	ns := joinNamespace(c.cfg.RootNamespace, tenantNamespacePath(tenantID))
	err := c.do(ctx, http.MethodDelete, "/v1/secret/metadata/infra/neo4j", ns, nil, nil)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return nil
	}
	return err
}

// ----- naming + HCL ---------------------------------------------------------

func tenantNamespacePath(tenantID string) string { return "tenant-" + tenantID }
func tenantPolicyName(tenantID string) string    { return "tenant-" + tenantID + "-app" }
func jwtRoleName(tenantID string) string         { return "gibson-plugin-" + tenantID }

// tenantPolicyHCL returns the policy granted INSIDE a per-tenant Vault
// namespace. The namespace already isolates the tenant's data from
// every other tenant; this policy further splits the secret/ KV v2 mount
// into four access levels:
//
//   - secret/metadata   — root metadata LIST so the daemon can enumerate all
//     secret names in the namespace (list only; no read of values). Required
//     because provider_cred keys use colon separators
//     (provider_cred:<name>:<field>) which are NOT vault path separators —
//     vault's KV LIST treats only "/" as a hierarchy separator, so colon-keyed
//     secrets live as flat keys at the KV root and can only be discovered via
//     a root LIST + client-side prefix filter.
//   - user/*           — secrets the daemon owns on the tenant's behalf. Full CRUD.
//   - infra/*          — secrets the operator writes (connection bundles, KEKs, etc.).
//     Read-only for the daemon so it cannot tamper with operator-managed
//     material; the operator authenticates with its own credentials to write.
//   - provider_cred*   — LLM provider credentials stored by the daemon's
//     providerconfig.brokerBackedStore. Key format: provider_cred:<name>:<field>
//     (colons, not slashes). The data glob must NOT include a leading slash
//     before * so it matches secret/data/provider_cred:openai:api_key.
//
// Note: sys/internal/ui/mounts/* is intentionally absent. In OpenBao/Vault
// child namespaces that path is root-restricted and cannot be granted via
// a regular policy (tested on OpenBao v2.5.3 — explicit grants return 403).
// The platform-clients vault Provider skips detectKVVersion when
// Config.Namespace != "" for exactly this reason; the operator always
// provisions KV v2 in namespace mode.
//
// Paths outside these prefixes are denied by default.
func tenantPolicyHCL() string {
	return `path "secret/metadata" {
  capabilities = ["list"]
}

path "secret/data/user/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/user/*" {
  capabilities = ["read", "list", "delete"]
}

path "secret/data/infra/*" {
  capabilities = ["read"]
}

path "secret/metadata/infra/*" {
  capabilities = ["read", "list"]
}

path "secret/data/provider_cred*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/provider_cred*" {
  capabilities = ["read", "list", "delete"]
}
`
}

// joinNamespace concatenates a parent namespace path with a child namespace
// path using Vault's "/" convention. Empty parent returns the child as-is.
func joinNamespace(parent, child string) string {
	parent = strings.Trim(parent, "/")
	child = strings.Trim(child, "/")
	if parent == "" {
		return child
	}
	return parent + "/" + child
}

// validateTenantID rejects empty or unsafe tenant identifiers. Vault path
// segments cannot contain "/", and we restrict to the same character class
// used by the Tenant CR name validator (RFC 1123 subdomain) so the path
// math above is unambiguous.
func validateTenantID(id string) error {
	if id == "" {
		return fmt.Errorf("vault: tenantID is required: %w", clients.ErrInvalidInput)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf("vault: tenantID %q contains invalid character %q: %w",
				id, string(r), clients.ErrInvalidInput)
		}
	}
	return nil
}

// containsAny returns true when s contains any of the substrings (case-insensitive
// only on the ASCII range, which is sufficient for matching Vault's English
// error strings). Used to detect the well-known idempotency-success messages.
func containsAny(s string, subs ...string) bool {
	low := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(low, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
