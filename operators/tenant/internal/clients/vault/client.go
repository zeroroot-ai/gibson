// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package vault is the operator's admin client for the Gibson SaaS Vault
// deployment. It is used by the provisioning saga to idempotently create
// per-tenant Vault namespaces (Enterprise) or path-prefix + ACL policies
// (Community) for new SaaS tenants per spec secrets-broker Requirement 10.3.
//
// This client is intentionally narrow — it exposes only the admin operations
// required to provision and tear down a tenant's secrets backend. It is NOT
// the runtime read/write client; the daemon's secrets package owns that path
// via the SDK's vault provider. Keeping the operator's surface narrow lets
// us depend on raw HTTP rather than pulling in github.com/hashicorp/vault/api
// as a transitive (which carries a heavy dependency tree).
//
// Authentication: a static admin token (Vault root or a long-lived admin
// token issued by the Gibson SaaS Vault root). The token is supplied by the
// operator via the GIBSON_VAULT_ADMIN_TOKEN env var and never logged.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// ErrTokenExpired marks a 403 that is caused by an expired (or non-renewable,
// lease-exhausted) Vault token rather than by genuinely insufficient
// permissions. Vault/OpenBao returns "permission denied" for BOTH cases, so we
// disambiguate by inspecting the error body for expiry/lease/ttl markers (see
// looksLikeTokenExpiry).
//
// This condition is TRANSIENT: restarting the operator pod (which re-reads the
// admin token from its mount) or waiting for periodic-token renewal recovers
// it. Callers classifying saga failures must NOT treat a chain that
// errors.Is(err, ErrTokenExpired) as permanent (tenant-operator#273). It is
// wrapped alongside clients.ErrUnauthorized, so existing errors.Is checks for
// ErrUnauthorized still match.
var ErrTokenExpired = errors.New("vault token expired")

// Edition identifies the namespace-capable Vault-API server the cluster is
// running. Today the chart ships OpenBao OSS 2.5.x, which provides
// Vault-Enterprise-API-compatible namespaces per OpenBao release notes 2.3+
// (PRD deploy#431, ADR-0024). The platform-Community path-prefix mode was
// dropped in slice tenant-operator#171; per-tenant isolation is now always
// namespace-based.
//
// The Edition type stays as the return value of EnsureTenantNamespace for
// upstream callers (saga record-keeping), even though there is only one
// non-Unknown value today. If we ever support a second secrets-engine
// backend the typed return value gives us a clean extension point.
type Edition string

const (
	// EditionUnknown is the zero value; never returned by a successful
	// EnsureTenantNamespace today.
	EditionUnknown Edition = ""

	// EditionEnterprise enables namespace-based isolation per tenant. Each
	// tenant gets its own Vault namespace under the configured root
	// namespace. Name kept "Enterprise" for backward source-compat with
	// callers; the runtime backend is OpenBao OSS.
	EditionEnterprise Edition = "enterprise"
)

// AdminClient is the narrow admin surface used by the tenant-operator. All
// methods are idempotent: re-running for an already-provisioned tenant is a
// no-op. Errors wrap the package-level sentinels in the operator's clients
// package (clients.ErrUnreachable, clients.ErrUnauthorized, etc.) so callers
// can classify with errors.Is.
type AdminClient interface {
	// EnsureTenantNamespace provisions the per-tenant Vault namespace for
	// tenantID. Idempotent.
	//
	// Inputs:
	//   - tenantID: the Tenant CR name (already validated upstream).
	//
	// Behaviour:
	//   - Creates namespace tenant-<id>, mounts KV v2 at secret/, writes
	//     the tenant-<id>-app ACL policy, configures the JWT auth role
	//     gibson-plugin-<id> bound to the configured platform audience.
	//
	// Returns:
	//   - the Edition used to provision (always EditionEnterprise today;
	//     the typed return stays for upstream saga record-keeping and
	//     future second-backend support).
	EnsureTenantNamespace(ctx context.Context, tenantID string) (Edition, error)

	// DeleteTenantNamespace tears down the per-tenant Vault namespace.
	// Idempotent: returns nil when the resources are already gone.
	DeleteTenantNamespace(ctx context.Context, tenantID string) error

	// Ping verifies the admin token is valid and the Vault server is
	// reachable. Returns clients.ErrUnreachable on transport failure,
	// clients.ErrUnauthorized when the token is rejected.
	Ping(ctx context.Context) error

	// VerifyJWTAuthMounted ensures the JWT auth backend is mounted at
	// "jwt/". EnsureTenantNamespace writes per-tenant roles under
	// auth/jwt/role/gibson-plugin-<id>; if the backend isn't mounted
	// the write 404s and every signup permanently fails at
	// ProvisionSecretsBackend (tenant-operator#132). The chart Vault
	// post-install Job (tenant-operator#133) is the source-of-truth
	// mount; this method is the operator-side guard that catches
	// regressions at startup instead of at first-signup time.
	VerifyJWTAuthMounted(ctx context.Context) error

	// ConfigureTenantJWTAuth writes `auth/jwt/config` inside the per-tenant
	// namespace tenant-<id>, mirroring the root namespace's config set by
	// the chart's openbao-jwt-auth-init Job (deploy#350). Without this
	// step, every daemon `auth/jwt/login` against the tenant namespace
	// fails with 400 "could not load configuration" and the dashboard
	// 412s on every API call. Idempotent: POST to auth/jwt/config is an
	// overwrite on Vault, so re-running this step on an existing tenant
	// is a no-op. tenant-operator#189.
	ConfigureTenantJWTAuth(ctx context.Context, tenantID string) error

	// WriteInfraNeo4j writes the Neo4j username and password for tenantID
	// into the per-tenant Vault secrets path at "infra/neo4j" inside the
	// tenant-<id> namespace. Idempotent: re-running overwrites the same
	// path with the same values.
	//
	// Deprecated: prefer WriteInfraNeo4jCredentials, which carries the bolt
	// URI in the typed payload so the daemon's broker.Get returns a complete
	// pdataplane.Neo4jCredentials in one call (no registry-table lookup).
	// This signature stays for backward compat with existing callers; new
	// code should use the typed form.
	WriteInfraNeo4j(ctx context.Context, tenantID, username, password string) error

	// WriteInfraNeo4jCredentials writes the full typed Neo4jCredentials
	// (BoltURI + Username + Password) to tenant/<id>/infra/neo4j.
	// Spec tenant-provisioning-unification-phase2 Requirement 1.7.
	WriteInfraNeo4jCredentials(ctx context.Context, tenantID string, creds pdataplane.Neo4jCredentials) error

	// DeleteInfraNeo4j removes the Neo4j credentials path "infra/neo4j" for
	// tenantID. Idempotent: returns nil when the path is already absent.
	// Does NOT delete the per-tenant namespace itself.
	DeleteInfraNeo4j(ctx context.Context, tenantID string) error

	// WriteInfraPostgres writes per-tenant Postgres credentials at
	// tenant/<id>/infra/postgres. See payloads.go.
	WriteInfraPostgres(ctx context.Context, tenantID string, creds pdataplane.PostgresCredentials) error
	// DeleteInfraPostgres removes the per-tenant Postgres credentials.
	DeleteInfraPostgres(ctx context.Context, tenantID string) error

	// WriteInfraRedis writes per-tenant Redis credentials at
	// tenant/<id>/infra/redis. See payloads.go.
	WriteInfraRedis(ctx context.Context, tenantID string, creds pdataplane.RedisCredentials) error
	// DeleteInfraRedis removes the per-tenant Redis credentials.
	DeleteInfraRedis(ctx context.Context, tenantID string) error

	// WriteInfraVector writes per-tenant Qdrant credentials at
	// tenant/<id>/infra/vector. See payloads.go.
	WriteInfraVector(ctx context.Context, tenantID string, creds pdataplane.VectorCredentials) error
	// DeleteInfraVector removes the per-tenant Qdrant credentials.
	DeleteInfraVector(ctx context.Context, tenantID string) error
}

// Config configures the admin client.
type Config struct {
	// Address is the Vault base URL (e.g. "https://vault.gibson.svc:8200").
	Address string

	// AdminToken is the static admin token used when TokenProvider is nil.
	// At least one of AdminToken or TokenProvider must be set.
	AdminToken string

	// TokenProvider, when non-nil, is called on every outgoing HTTP request
	// to retrieve the current live Vault token. This allows the caller to
	// wire in a lease-renewing token source (e.g. platform-clients
	// secrets/vault.Provider) so the admin client never hard-bakes a
	// static token that expires after pod uptime exceeds the token TTL.
	// When set, AdminToken is ignored after construction.
	TokenProvider func() string

	// RootNamespace is the parent Vault namespace under which per-tenant
	// namespaces are created. Empty means the root namespace.
	RootNamespace string

	// JWTAuthMountPath is the JWT auth method mount path used for plugin
	// workload authentication. Default "auth/jwt".
	JWTAuthMountPath string

	// JWTBoundAudience is the expected `aud` claim on plugin JWTs. Written
	// into `bound_audiences` on every per-tenant Vault role at provisioning
	// time (load-bearing per ADR-0009 / tenant-operator#147).
	//
	// NOTE: bound_issuer is enforced at the auth/jwt/ mount level (single
	// string per mount on Vault 1.18 / OpenBao 2.5). The mount lives INSIDE
	// the per-tenant namespace (one mount per tenant — see mountJWTAuth in
	// namespace.go), so bound_issuer must be written PER namespace via
	// WriteJWTAuthConfig below. See ADR-0009 amendment "Vault auth/jwt
	// mount is SPIRE-only" and the chart's openbao-jwt-auth-init Job
	// which writes the SAME config to the root namespace.
	JWTBoundAudience string

	// JWTBoundIssuer is the SPIRE OIDC issuer URL written into the per-tenant
	// auth/jwt mount's `bound_issuer` field. Vault rejects every
	// auth/jwt/login whose JWT `iss` claim doesn't match. Mirrors the root
	// namespace's `bound_issuer` set by the chart's openbao-jwt-auth-init
	// Job. REQUIRED — empty value fails LOUDLY at config-write time so a
	// half-provisioned per-tenant namespace cannot ship to production.
	// tenant-operator#189.
	JWTBoundIssuer string

	// JWKSURL is the JWKS URL Vault dials to fetch the SPIRE OIDC discovery
	// provider's signing keys. Written into the per-tenant auth/jwt config
	// alongside JWTBoundIssuer. Defaults to "<JWTBoundIssuer>/keys" if
	// empty.
	JWKSURL string

	// JWKSCAPEMPath is the path to a JWKS CA PEM file the operator reads at
	// saga time and forwards into the per-tenant auth/jwt config's
	// `jwks_ca_pem` field. Vault uses it to validate the HTTPS cert the
	// SPIRE OIDC discovery provider presents at JWKSURL. May be empty when
	// JWKSURL is plain HTTP (kind dev cluster). REQUIRED in production
	// overlays.
	JWKSCAPEMPath string

	// JWKSCAPEM is the PEM-encoded CA bundle Vault uses to validate the
	// HTTPS cert at JWKSURL. When non-empty, takes precedence over
	// JWKSCAPEMPath. Tests use this directly; production sets
	// JWKSCAPEMPath and the operator reads the file at saga time.
	JWKSCAPEM string

	// HTTPClient is the underlying HTTP client. If nil, a default 30s timeout
	// client is used.
	HTTPClient *http.Client
}

// httpClient is the concrete AdminClient implementation. It speaks raw HTTP
// to the Vault-API server (OpenBao OSS today) rather than depending on
// github.com/openbao/openbao/api/v2 so the operator's dependency footprint
// stays small.
type httpClient struct {
	baseURL *url.URL
	cfg     Config
	http    *http.Client
}

// New constructs an AdminClient from cfg. Validation:
//   - Address required, must be a valid URL.
//   - At least one of AdminToken or TokenProvider must be set.
//
// New does NOT make a network call; the client probes Vault lazily on the
// first AdminClient call. Use Ping to fail fast at startup.
func New(cfg Config) (AdminClient, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, fmt.Errorf("vault: Address is required: %w", clients.ErrInvalidInput)
	}
	if cfg.TokenProvider == nil && strings.TrimSpace(cfg.AdminToken) == "" {
		return nil, fmt.Errorf("vault: AdminToken is required (or set TokenProvider for lease renewal): %w", clients.ErrInvalidInput)
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid Address %q: %w", cfg.Address, clients.ErrInvalidInput)
	}
	if cfg.JWTAuthMountPath == "" {
		cfg.JWTAuthMountPath = "auth/jwt"
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &httpClient{
		baseURL: u,
		cfg:     cfg,
		http:    httpc,
	}, nil
}

// Ping implements AdminClient.
func (c *httpClient) Ping(ctx context.Context) error {
	// /sys/health is unauthenticated for status but accepts the admin token
	// without rejection. Use the token-validating /sys/auth/token/lookup-self
	// to actually verify the token.
	if err := c.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", "", nil, nil); err != nil {
		return err
	}
	return nil
}

// VerifyJWTAuthMounted implements AdminClient. Vault's GET /v1/sys/auth/<path>
// returns 200 when the auth mount exists and 400 ("path is not a mount") when
// it does not. We translate the absent case into a typed error naming the
// chart-side fix so operators can resolve the regression without grepping.
//
// 403 is preserved as clients.ErrUnauthorized so the caller can distinguish
// "token lacks sys/auth read permission" (backend may exist) from "backend
// definitely absent" and react accordingly.
func (c *httpClient) VerifyJWTAuthMounted(ctx context.Context) error {
	err := c.do(ctx, http.MethodGet, "/v1/sys/auth/jwt", "", nil, nil)
	if err == nil {
		return nil
	}
	if errors.Is(err, clients.ErrInvalidInput) || errors.Is(err, clients.ErrNotFound) {
		return fmt.Errorf("vault: jwt auth backend not mounted at jwt/ "+
			"(enable via chart Vault post-install Job, tenant-operator#133): %w",
			clients.ErrNotFound)
	}
	if errors.Is(err, clients.ErrUnauthorized) {
		// Wrap the original err (not a fresh clients.ErrUnauthorized) so the
		// ErrTokenExpired tag attached by do()/wrapErr for expired-token 403s
		// survives — a readiness probe (cmd/main.go) can then distinguish a
		// recoverable expiry from a genuine permission problem
		// (tenant-operator#273).
		return fmt.Errorf("vault: 403 reading /sys/auth/jwt "+
			"(token lacks sys/auth read permission; backend may still exist): %w",
			err)
	}
	return err
}

// do issues a single HTTP request to Vault. namespace, when non-empty, is
// forged onto the X-Vault-Namespace header (Enterprise scoping). body, when
// non-nil, is JSON-marshalled. out, when non-nil, is JSON-unmarshalled from
// the response body. Status mapping:
//
//	200,201,204 -> nil
//	400         -> clients.ErrInvalidInput
//	403         -> clients.ErrUnauthorized
//	404         -> clients.ErrNotFound
//	409         -> clients.ErrConflict
//	429         -> clients.ErrRateLimited
//	5xx         -> clients.ErrUnreachable
//	other       -> generic wrapped error
func (c *httpClient) do(
	ctx context.Context,
	method, path, namespace string,
	body, out any,
) error {
	full := *c.baseURL
	full.Path = strings.TrimRight(full.Path, "/") + path

	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: marshal request: %w", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, full.String(), rdr)
	if err != nil {
		return fmt.Errorf("vault: build request: %w", err)
	}
	// Prefer the live-renewed token when TokenProvider is wired; fall back to
	// the static AdminToken so existing callers that don't use the provider
	// continue to work (P1 fix: vault admin token env-baked, never renewed).
	token := c.cfg.AdminToken
	if c.cfg.TokenProvider != nil {
		if live := c.cfg.TokenProvider(); live != "" {
			token = live
		}
	}
	req.Header.Set("X-Vault-Token", token)
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %s %s: %w", method, path, errors.Join(err, clients.ErrUnreachable))
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(out)
	case resp.StatusCode == http.StatusBadRequest:
		return wrapErr(method, path, resp, clients.ErrInvalidInput)
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusUnauthorized:
		return wrapErr(method, path, resp, clients.ErrUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		return wrapErr(method, path, resp, clients.ErrNotFound)
	case resp.StatusCode == http.StatusConflict:
		return wrapErr(method, path, resp, clients.ErrConflict)
	case resp.StatusCode == http.StatusTooManyRequests:
		return wrapErr(method, path, resp, clients.ErrRateLimited)
	case resp.StatusCode >= 500:
		return wrapErr(method, path, resp, clients.ErrUnreachable)
	default:
		return wrapErr(method, path, resp, fmt.Errorf("unexpected status %d", resp.StatusCode))
	}
}

// wrapErr reads the response body (capped at 1 KiB) and wraps it with the
// supplied sentinel. Vault's standard error shape is {"errors": ["..."]} so
// we surface the joined errors when present, otherwise a truncated body.
func wrapErr(method, path string, resp *http.Response, sentinel error) error {
	const cap = 1 << 10
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, cap))
	var msg string
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(buf, &parsed) == nil && len(parsed.Errors) > 0 {
		msg = strings.Join(parsed.Errors, "; ")
	} else {
		msg = strings.TrimSpace(string(buf))
	}
	if msg == "" {
		msg = resp.Status
	}
	// A 403 caused by an expired/non-renewable token is transient, not a
	// permanent credential misconfiguration. Vault returns "permission denied"
	// for both, so disambiguate on the body. When it looks like token expiry we
	// join ErrTokenExpired into the chain alongside the supplied sentinel
	// (clients.ErrUnauthorized), so errors.Is(err, ErrUnauthorized) still holds
	// while callers can additionally test errors.Is(err, ErrTokenExpired) to
	// keep the saga retrying rather than blocking (tenant-operator#273).
	if errors.Is(sentinel, clients.ErrUnauthorized) && looksLikeTokenExpiry(msg) {
		return fmt.Errorf("vault: %s %s status=%d: %s: %w: %w",
			method, path, resp.StatusCode, msg, ErrTokenExpired, sentinel)
	}
	return fmt.Errorf("vault: %s %s status=%d: %s: %w", method, path, resp.StatusCode, msg, sentinel)
}

// looksLikeTokenExpiry reports whether a Vault 403 error body indicates the
// caller's token has expired / exhausted its lease, as opposed to the token
// being valid but lacking the required capability on the path. OpenBao/Vault
// emit "permission denied" for both, so we look for the additional lease/ttl/
// expiry vocabulary Vault attaches when the token itself is the problem.
//
// Conservative by design: a bare "permission denied" with no expiry markers is
// NOT matched, so a genuinely under-privileged or revoked admin token still
// surfaces as a permanent failure (the dashboard retry CTA). Only the markers
// that specifically point at token lifetime flip the classification.
func looksLikeTokenExpiry(msg string) bool {
	return containsAny(strings.ToLower(msg),
		"token expired",
		"token is expired",
		"token is not renewable",
		"lease is expired",
		"lease expired",
		"invalid token",
		"token not found",
		"failed to find accessor",
		"ttl expired",
	)
}
