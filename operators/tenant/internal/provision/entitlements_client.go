// Package provision carries HTTP clients for the dashboard's admin provisioning
// routes. This file wires the entitlements endpoints
// (POST /api/admin/provisioning/entitlements/*) used by the
// controller.EntitlementsReconciler during every Tenant reconcile.
//
// Authentication uses a Zitadel service-account JWT obtained via the OAuth2
// client_credentials grant. The SPIFFE JWT-SVID mechanism that was used
// previously has been removed; the dashboard validates the incoming Bearer
// token against Zitadel's JWKS endpoint, not against a SPIFFE trust bundle.
//
// Spec: agent-authoring-and-tenant-entitlements tasks 23-25 + 26.
// Auth migration: unified-identity-and-authorization Phase 6.
package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// TokenSource provides a Bearer token for outbound HTTP requests to the
// dashboard's admin provisioning API. Keeping the contract narrow lets tests
// inject a static token without requiring a live Zitadel instance.
type TokenSource interface {
	// FetchToken returns a Bearer token string. The audience parameter is
	// passed through for implementations that need to scope the token (e.g.,
	// SPIFFE JWT-SVIDs). Zitadel client_credentials implementations may
	// ignore audience and always return the same access token.
	FetchToken(ctx context.Context, audience string) (string, error)
}

// OAuth2TokenSource adapts a golang.org/x/oauth2.TokenSource into the
// TokenSource interface. The audience parameter is ignored; Zitadel
// client_credentials tokens are scoped by the configured scopes, not per-call
// audiences. Safe for concurrent use (the underlying oauth2.TokenSource caches
// and refreshes tokens transparently before expiry).
type OAuth2TokenSource struct {
	Source oauth2.TokenSource
}

// FetchToken implements TokenSource.
func (o *OAuth2TokenSource) FetchToken(_ context.Context, _ string) (string, error) {
	tok, err := o.Source.Token()
	if err != nil {
		return "", fmt.Errorf("OAuth2TokenSource: %w", err)
	}
	return tok.AccessToken, nil
}

// EntitlementsHTTPClient POSTs to the dashboard's entitlements provisioning
// routes. Not an interface: the reconciler uses the controller.
// EntitlementsProvisioner interface directly and can be given either this
// concrete client or a test fake.
type EntitlementsHTTPClient struct {
	BaseURL    string // e.g. "https://gibson-dashboard:3000"
	Audience   string // JWT-SVID audience; defaults to "gibson-dashboard"
	HTTPClient *http.Client
	Tokens     TokenSource
}

// NewEntitlementsHTTPClient constructs a client with sensible defaults.
func NewEntitlementsHTTPClient(baseURL string, tokens TokenSource) *EntitlementsHTTPClient {
	return &EntitlementsHTTPClient{
		BaseURL:    baseURL,
		Audience:   "gibson-dashboard",
		HTTPClient: &http.Client{},
		Tokens:     tokens,
	}
}

// --- Provisioner interface implementation

// SetTenantZitadelOrg seeds the daemon's tenant -> Zitadel-org mapping
// (gibson#621). Legacy HTTP fallback; the primary path is the gRPC client
// calling DaemonOperatorService.SetTenantZitadelOrg directly. Idempotent.
func (c *EntitlementsHTTPClient) SetTenantZitadelOrg(ctx context.Context, tenantID, zitadelOrgID string) error {
	body := map[string]any{
		"tenant_id":      tenantID,
		"zitadel_org_id": zitadelOrgID,
	}
	_, err := c.post(ctx, "/api/admin/provisioning/entitlements/set-tenant-zitadel-org", body)
	return err
}

func (c *EntitlementsHTTPClient) ListFeatureTuples(ctx context.Context, tenantID string) ([]string, error) {
	body := map[string]any{"tenant_id": tenantID}
	raw, err := c.post(ctx, "/api/admin/provisioning/entitlements/list-feature-tuples", body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Relations []string `json:"relations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("entitlements: decode list-feature-tuples: %w", err)
	}
	return resp.Relations, nil
}

func (c *EntitlementsHTTPClient) WriteAccessTuples(ctx context.Context, add, del []string, reason string) error {
	body := map[string]any{
		"add":    tuplesFromStrings(add),
		"delete": tuplesFromStrings(del),
		"reason": reason,
	}
	_, err := c.post(ctx, "/api/admin/provisioning/entitlements/write-tuples", body)
	return err
}

func (c *EntitlementsHTTPClient) SeedCatalogTenantEnabled(ctx context.Context, tenantID string) error {
	body := map[string]any{"tenant_id": tenantID}
	_, err := c.post(ctx, "/api/admin/provisioning/entitlements/seed-catalog-tenant-enabled", body)
	return err
}

// tuplesFromStrings parses fully-qualified tuples "user#relation@object" into
// the {user, relation, object} JSON shape the daemon's AccessTuple expects.
func tuplesFromStrings(tuples []string) []map[string]string {
	out := make([]map[string]string, 0, len(tuples))
	for _, t := range tuples {
		// Parse strictly: u#r@o. If any part is missing we skip silently
		// to prevent a malformed tuple from aborting an entire reconcile.
		hashIdx := indexByte(t, '#')
		atIdx := indexByte(t, '@')
		if hashIdx <= 0 || atIdx <= hashIdx+1 || atIdx >= len(t)-1 {
			continue
		}
		out = append(out, map[string]string{
			"user":     t[:hashIdx],
			"relation": t[hashIdx+1 : atIdx],
			"object":   t[atIdx+1:],
		})
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// post is the shared HTTP transport. Wraps the JWT-SVID mint + POST +
// response read + error translation so each handler method is one line.
func (c *EntitlementsHTTPClient) post(ctx context.Context, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("entitlements: marshal body: %w", err)
	}
	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("entitlements: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Tokens != nil {
		tok, err := c.Tokens.FetchToken(ctx, c.Audience)
		if err != nil {
			return nil, fmt.Errorf("entitlements: fetch JWT-SVID: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// Transport error (DNS, dial, connection reset, TLS handshake, etc.)
		// is always transient — wrap as ErrUnreachable so the saga runner
		// keeps retrying instead of counting toward maxAttempts.
		return nil, fmt.Errorf("entitlements: %s: %w: %w", path, clients.ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		base := fmt.Errorf("entitlements: %s returned %d: %s", path, resp.StatusCode, string(raw))
		switch {
		case resp.StatusCode >= 500, resp.StatusCode == http.StatusTooManyRequests:
			// 5xx + 429 are transient (upstream daemon down, rate-limited,
			// connection-reset proxied through the dashboard). Saga should
			// retry indefinitely, not give up after a 20-second window.
			return nil, fmt.Errorf("%w: %w", clients.ErrUnreachable, base)
		case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
			return nil, fmt.Errorf("%w: %w", clients.ErrUnauthorized, base)
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			// 4xx (other than auth) is a validation problem. Don't retry.
			return nil, fmt.Errorf("%w: %w", clients.ErrInvalidInput, base)
		default:
			return nil, base
		}
	}
	return raw, nil
}
