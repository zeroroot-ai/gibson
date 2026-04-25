//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ZitadelClient wraps the Zitadel admin REST API.  It uses stdlib HTTP only
// (no zitadel SDK import) to avoid adding a heavy compile-time dependency.
// The PAT is never logged (Security NFR).
type ZitadelClient struct {
	baseURL    string // e.g. "https://auth.zero-day.local:30443" or "http://gibson-zitadel:8080"
	pat        string // service-account PAT loaded from in-cluster secret
	httpClient *http.Client
}

// NewZitadelClient creates a ZitadelClient.  pat may be empty if you
// call LoadPATFromCluster afterward.
//
// The HTTP client skips TLS verification because the Kind cluster uses a
// self-signed certificate.  This is intentional for e2e test infrastructure
// only — never use this in production code.
func NewZitadelClient(baseURL, pat string) *ZitadelClient {
	return &ZitadelClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		pat:     pat,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // e2e test; Kind self-signed cert
			},
		},
	}
}

// LoadPATFromCluster reads the Zitadel IAM admin PAT from the in-cluster
// Secret `iam-admin-pat` (namespace: gibson).  The PAT is stored in the
// `pat` key of the Secret (Helm chart convention; older docs said `token`).
//
// Call this after creating the client if the PAT is not known at construction
// time.
func (z *ZitadelClient) LoadPATFromCluster(ctx context.Context, kubeClient kubernetes.Interface) error {
	secret, err := kubeClient.CoreV1().Secrets("gibson").Get(ctx, "iam-admin-pat", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("zitadel_client: get iam-admin-pat secret: %w", err)
	}
	// The secret key is "pat" per the Helm chart.  Fall back to "token" for
	// clusters created before the key was renamed (SIGNUP-B23).
	// TrimSpace is required: Kubernetes secrets may have trailing newlines
	// when set from a file (echo "value" > file), and Go's net/http rejects
	// Authorization headers containing newlines.
	pat := strings.TrimSpace(string(secret.Data["pat"]))
	if pat == "" {
		pat = strings.TrimSpace(string(secret.Data["token"]))
	}
	if pat == "" {
		return fmt.Errorf("zitadel_client: iam-admin-pat secret has neither 'pat' nor 'token' key (SIGNUP-B23: check chart secret template)")
	}
	z.pat = pat
	return nil
}

// doRequest performs an authenticated HTTP request against the Zitadel admin
// API.  The Authorization header is set but NEVER logged.
func (z *ZitadelClient) doRequest(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	u := z.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, 0, fmt.Errorf("zitadel_client: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+z.pat)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("zitadel_client: %s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)
	return rawBody, resp.StatusCode, nil
}

// zitadelOrg is the subset of the Zitadel org API response we care about.
type zitadelOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// zitadelSearchOrgsResponse is the shape of POST /admin/v1/orgs/_search.
// The IAM admin API (not the management API) is used because the IAM PAT
// is a service account in the IAM context, not in any single org context.
// The management API requires an org-scoped token and returns 404 for IAM
// admin tokens (SIGNUP-B25: wrong Zitadel endpoint for org search).
type zitadelSearchOrgsResponse struct {
	Result []struct {
		OrgID   string `json:"id"`   // IAM admin API uses "id", not "orgId"
		OrgName string `json:"name"` // IAM admin API uses "name", not "orgName"
	} `json:"result"`
	Details struct {
		TotalResult string `json:"totalResult"` // string in Zitadel API
	} `json:"details"`
}

// OrgExistsBySlug queries the Zitadel IAM admin API for an organization whose
// name matches slug.  Returns (true, nil) if found, (false, nil) if not found,
// or an error on API failure.
//
// The "slug" in Gibson maps to an org "name" in Zitadel (the operator creates
// the org with the slug as the display name).
//
// Requirements: R1.5.
// Bug catalog: B4 (jwt_issuer missing → Zitadel org creation fails during saga
// because dashboard JWT is rejected), B6 (SPIFFE prefix causes FGA to reject
// the authorization check before Zitadel is even called),
// SIGNUP-B25 (wrong endpoint: /management/v1/ requires org-scoped token; use
// /admin/v1/ with the IAM PAT).
func (z *ZitadelClient) OrgExistsBySlug(ctx context.Context, slug string) (bool, error) {
	// POST /admin/v1/orgs/_search — the IAM admin endpoint.
	// The management API at /management/v1/orgs/_search returns 404 because
	// the IAM admin PAT is not in any single org's context (SIGNUP-B25).
	body := fmt.Sprintf(`{"queries":[{"nameQuery":{"name":%q,"method":"TEXT_QUERY_METHOD_EQUALS"}}]}`,
		slug)

	raw, status, err := z.doRequest(ctx, http.MethodPost, "/admin/v1/orgs/_search", strings.NewReader(body))
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("zitadel_client: search orgs returned HTTP %d: %s (SIGNUP-B25: check endpoint)", status, string(raw))
	}
	var resp zitadelSearchOrgsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, fmt.Errorf("zitadel_client: unmarshal orgs response: %w", err)
	}
	for _, org := range resp.Result {
		if org.OrgName == slug {
			return true, nil
		}
	}
	return false, nil
}

// DeleteOrgBySlug finds the organization with name matching slug and deletes
// it.  Used for idempotent cleanup before/after test runs (R1.9, R1.10).
// Returns nil if the org doesn't exist (tolerant of NotFound).
func (z *ZitadelClient) DeleteOrgBySlug(ctx context.Context, slug string) error {
	// First: find the org ID.
	body := fmt.Sprintf(`{"queries":[{"nameQuery":{"name":%q,"method":"TEXT_QUERY_METHOD_EQUALS"}}]}`,
		slug)

	// Use /admin/v1/orgs/_search (not /management/v1/) — SIGNUP-B25 fix.
	raw, status, err := z.doRequest(ctx, http.MethodPost, "/admin/v1/orgs/_search", strings.NewReader(body))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("zitadel_client: search orgs returned HTTP %d (SIGNUP-B25)", status)
	}
	var resp zitadelSearchOrgsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("zitadel_client: unmarshal orgs response: %w", err)
	}
	for _, org := range resp.Result {
		if org.OrgName != slug {
			continue
		}
		// DELETE /admin/v1/orgs/<id>
		_, delStatus, delErr := z.doRequest(ctx, http.MethodDelete, "/admin/v1/orgs/"+org.OrgID, nil)
		if delErr != nil {
			return fmt.Errorf("zitadel_client: delete org %s: %w", org.OrgID, delErr)
		}
		if delStatus != http.StatusOK && delStatus != http.StatusNoContent && delStatus != http.StatusNotFound {
			return fmt.Errorf("zitadel_client: delete org returned HTTP %d", delStatus)
		}
		return nil
	}
	// Org not found — idempotent.
	return nil
}

// zitadelUserSearchResponse is the shape of POST /v1/users/_search.
type zitadelUserSearchResponse struct {
	Result []struct {
		UserID string `json:"userId"`
	} `json:"result"`
}

// DeleteUserByEmail finds the Zitadel user with the given email and deletes
// it.  Used for idempotent cleanup (R1.9).
// Returns nil if the user doesn't exist.
func (z *ZitadelClient) DeleteUserByEmail(ctx context.Context, email string) error {
	// POST /v1/users/_search  with loginName query
	body := fmt.Sprintf(`{"queries":[{"loginNameQuery":{"loginName":%q,"method":"TEXT_QUERY_METHOD_EQUALS"}}]}`,
		email)

	raw, status, err := z.doRequest(ctx, http.MethodPost, "/v1/users/_search", strings.NewReader(body))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("zitadel_client: search users returned HTTP %d: %s", status, string(raw))
	}
	var resp zitadelUserSearchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("zitadel_client: unmarshal users response: %w", err)
	}
	for _, user := range resp.Result {
		_, delStatus, delErr := z.doRequest(ctx, http.MethodDelete,
			"/v1/users/"+url.PathEscape(user.UserID), nil)
		if delErr != nil {
			return fmt.Errorf("zitadel_client: delete user %s: %w", user.UserID, delErr)
		}
		if delStatus != http.StatusOK && delStatus != http.StatusNoContent && delStatus != http.StatusNotFound {
			return fmt.Errorf("zitadel_client: delete user returned HTTP %d", delStatus)
		}
		return nil // only need to delete the first match
	}
	return nil // not found — idempotent
}

// LoadZitadelURLFromCluster resolves the Zitadel base URL from the cluster.
//
// Resolution order:
//  1. E2E_ZITADEL_URL env var — set by the test runner (Makefile) when a
//     kubectl port-forward has been started, e.g. "http://localhost:38081".
//  2. `ZITADEL_BASE_URL` or `ZITADEL_DOMAIN` key in the `gibson-config`
//     ConfigMap (namespace: gibson).
//  3. The Envoy NodePort external URL for the Kind cluster:
//     "https://auth.zero-day.local:30443" — Envoy terminates TLS and proxies
//     /oauth/v2/*, /management/v1/*, /v1/* to Zitadel.  This is the correct
//     URL to use for out-of-cluster test runs against the Kind stack.
func LoadZitadelURLFromCluster(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	// Priority 1: caller-provided URL via env.
	if envURL := os.Getenv("E2E_ZITADEL_URL"); envURL != "" {
		return envURL, nil
	}
	// Priority 2: gibson-config ConfigMap overrides.
	cm, err := kubeClient.CoreV1().ConfigMaps("gibson").Get(ctx, "gibson-config", metav1.GetOptions{})
	if err == nil {
		if u, ok := cm.Data["ZITADEL_BASE_URL"]; ok && u != "" {
			return u, nil
		}
		if domain, ok := cm.Data["ZITADEL_DOMAIN"]; ok && domain != "" {
			return "https://" + domain, nil
		}
	}
	// Priority 3: Envoy NodePort external URL.
	// Zitadel is ClusterIP-only; out-of-cluster test runs must go through
	// the Envoy NodePort on auth.zero-day.local:30443.
	return "https://auth.zero-day.local:30443", nil
}

// LoadFGAURLFromCluster resolves the OpenFGA HTTP URL from the cluster.
//
// Resolution order:
//  1. E2E_FGA_URL env var — set by the test runner (Makefile) when a
//     kubectl port-forward has been started before the Go tests run.
//     e.g. "http://localhost:38080"
//  2. The gibson-fga Service exists in the cluster — returns the in-cluster
//     DNS address "http://gibson-fga.gibson.svc.cluster.local:8080".
//     This only works when the test binary runs INSIDE the cluster.
//
// For out-of-cluster test runs (the normal case: make test-signup-e2e), the
// Makefile starts a background port-forward and sets E2E_FGA_URL before
// invoking `go test`.
func LoadFGAURLFromCluster(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	// Priority 1: caller-provided URL via env (used by out-of-cluster test runner).
	if envURL := os.Getenv("E2E_FGA_URL"); envURL != "" {
		return envURL, nil
	}
	// Priority 2: verify the service exists, return in-cluster DNS.
	// This path works when the binary runs inside the cluster.
	_, err := kubeClient.CoreV1().Services("gibson").Get(ctx, "gibson-fga", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("zitadel_client: cannot find gibson-fga Service (B9: ext-authz may also be misconfigured): %w\n"+
			"Hint: run with E2E_FGA_URL=http://localhost:<port> after `kubectl port-forward svc/gibson-fga 38080:8080 -n gibson`", err)
	}
	return "http://gibson-fga.gibson.svc.cluster.local:8080", nil
}
