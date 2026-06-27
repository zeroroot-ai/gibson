// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// jwt_auth_config.go: per-tenant auth/jwt/config writer. Closes the gap
// that left every fresh tenant's `auth/jwt/login` returning 400 "could
// not load configuration" (tenant-operator#189) — the saga mounted the
// JWT auth backend at auth/jwt and wrote the per-tenant role, but never
// wrote the mount's config (bound_issuer + jwks_url + jwks_ca_pem).
//
// The shape mirrors the chart's openbao-jwt-auth-init Job for the root
// namespace (deploy/helm/gibson-workloads/templates/auth/openbao-jwt-auth-init/job.yaml).
// Each per-tenant Vault namespace owns its own jwt mount (mountJWTAuth in
// namespace.go), so the config must be written per namespace.

package vault

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// ConfigureTenantJWTAuth implements AdminClient. Writes the
// `auth/jwt/config` document inside the per-tenant namespace, populated
// from the operator's wired-in SPIRE OIDC issuer + JWKS URL + JWKS CA
// PEM. Idempotent — POST to auth/jwt/config is an overwrite on Vault, so
// re-running on an existing tenant produces the same byte-for-byte
// state.
//
// Fails LOUDLY when JWTBoundIssuer is unset rather than writing a
// degraded config: a half-configured auth/jwt mount would silently
// accept any issuer (or reject every legitimate one), and the saga
// reporting success would mask the breakage until the daemon's first
// login attempt minutes later. See feedback_no_skippable_steps_for_required_artifacts.
func (c *httpClient) ConfigureTenantJWTAuth(ctx context.Context, tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	if strings.TrimSpace(c.cfg.JWTBoundIssuer) == "" {
		return fmt.Errorf("vault: JWTBoundIssuer is required for per-tenant auth/jwt/config "+
			"(tenant-operator#189; set GIBSON_VAULT_JWT_BOUND_ISSUER from the chart's "+
			"vault.jwtAuth.spireOidcIssuer): %w", clients.ErrInvalidInput)
	}

	jwksURL := strings.TrimSpace(c.cfg.JWKSURL)
	if jwksURL == "" {
		jwksURL = strings.TrimRight(c.cfg.JWTBoundIssuer, "/") + "/keys"
	}

	caPEM, err := c.resolveJWKSCAPEM()
	if err != nil {
		return err
	}

	body := map[string]any{
		"bound_issuer": c.cfg.JWTBoundIssuer,
		"jwks_url":     jwksURL,
	}
	// Only include jwks_ca_pem when we actually have one. Empty value would
	// force Vault to use the system CA bundle, which in-cluster doesn't
	// have the SPIRE-issued cert; the empty-string write is unambiguous
	// breakage when JWKS URL is https.
	if caPEM != "" {
		body["jwks_ca_pem"] = caPEM
	} else if strings.HasPrefix(strings.ToLower(jwksURL), "https://") {
		return fmt.Errorf("vault: JWKSCAPEM/JWKSCAPEMPath is required when JWKSURL is https "+
			"(tenant-operator#189; mount the spire-bundle ConfigMap into the "+
			"tenant-operator pod and set GIBSON_VAULT_JWKS_CA_PEM_PATH): %w",
			clients.ErrInvalidInput)
	}

	jwtPath := strings.TrimSuffix(c.cfg.JWTAuthMountPath, "/")
	path := "/v1/" + jwtPath + "/config"
	ns := joinNamespace(c.cfg.RootNamespace, tenantNamespacePath(tenantID))
	if err := c.do(ctx, http.MethodPost, path, ns, body, nil); err != nil {
		return fmt.Errorf("vault: write %s in namespace %q: %w", path, ns, err)
	}
	return nil
}

// resolveJWKSCAPEM returns the JWKS CA PEM the operator was wired with.
// Precedence: in-memory JWKSCAPEM (tests) → JWKSCAPEMPath (production).
//
// The chart mounts the SPIRE bundle as a ConfigMap at JWKSCAPEMPath. The
// ConfigMap content is JWKS form (x5c entries); we accept BOTH raw PEM
// (already wrapped, deployed via a sidecar that converts) AND JWKS form
// (we convert at runtime).
func (c *httpClient) resolveJWKSCAPEM() (string, error) {
	if c.cfg.JWKSCAPEM != "" {
		return c.cfg.JWKSCAPEM, nil
	}
	if strings.TrimSpace(c.cfg.JWKSCAPEMPath) == "" {
		return "", nil
	}
	raw, err := os.ReadFile(c.cfg.JWKSCAPEMPath)
	if err != nil {
		return "", fmt.Errorf("vault: read JWKS CA PEM at %q: %w", c.cfg.JWKSCAPEMPath, err)
	}
	content := strings.TrimSpace(string(raw))
	if content == "" {
		return "", fmt.Errorf("vault: JWKS CA PEM at %q is empty: %w", c.cfg.JWKSCAPEMPath, clients.ErrInvalidInput)
	}
	// If it already looks like PEM, pass through as-is.
	if strings.Contains(content, "-----BEGIN CERTIFICATE-----") {
		return content, nil
	}
	// Otherwise assume JWKS form (the SPIRE k8s_configmap BundlePublisher
	// output) and extract x509-svid x5c entries → PEM.
	pem, err := jwksToPEM(content)
	if err != nil {
		return "", fmt.Errorf("vault: convert JWKS at %q to PEM: %w", c.cfg.JWKSCAPEMPath, err)
	}
	if pem == "" {
		return "", fmt.Errorf("vault: JWKS at %q produced empty PEM bundle: %w", c.cfg.JWKSCAPEMPath, clients.ErrInvalidInput)
	}
	return pem, nil
}
