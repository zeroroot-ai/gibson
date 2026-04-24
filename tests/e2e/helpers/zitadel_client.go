//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
func NewZitadelClient(baseURL, pat string) *ZitadelClient {
	return &ZitadelClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		pat:        pat,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// LoadPATFromCluster reads the Zitadel IAM admin PAT from the in-cluster
// Secret `iam-admin-pat` (namespace: gibson).  The PAT is stored in the
// `token` key of the Secret.
//
// Call this after creating the client if the PAT is not known at construction
// time.
func (z *ZitadelClient) LoadPATFromCluster(ctx context.Context, kubeClient kubernetes.Interface) error {
	secret, err := kubeClient.CoreV1().Secrets("gibson").Get(ctx, "iam-admin-pat", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("zitadel_client: get iam-admin-pat secret: %w", err)
	}
	pat := string(secret.Data["token"])
	if pat == "" {
		return fmt.Errorf("zitadel_client: iam-admin-pat secret has no 'token' key")
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

// zitadelSearchOrgsResponse is the shape of GET /management/v1/orgs/_search.
type zitadelSearchOrgsResponse struct {
	Result []struct {
		OrgID   string `json:"orgId"`
		OrgName string `json:"orgName"`
	} `json:"result"`
	Details struct {
		TotalResult string `json:"totalResult"` // string in Zitadel API
	} `json:"details"`
}

// OrgExistsBySlug queries the Zitadel IAM API for an organization whose name
// matches slug.  Returns (true, nil) if found, (false, nil) if not found, or
// an error on API failure.
//
// The "slug" in Gibson maps to an org "name" in Zitadel (the operator creates
// the org with the slug as the display name).
//
// Requirements: R1.5.
// Bug catalog: B4 (jwt_issuer missing → Zitadel org creation fails during saga
// because dashboard JWT is rejected), B6 (SPIFFE prefix causes FGA to reject
// the authorization check before Zitadel is even called).
func (z *ZitadelClient) OrgExistsBySlug(ctx context.Context, slug string) (bool, error) {
	// Zitadel management API: search orgs by name.
	// POST /management/v1/orgs/_search  (v1 IAM API)
	// Body: {"queries":[{"nameQuery":{"name":"<slug>","method":"TEXT_QUERY_METHOD_EQUALS"}}]}
	body := fmt.Sprintf(`{"queries":[{"nameQuery":{"name":%q,"method":"TEXT_QUERY_METHOD_EQUALS"}}]}`,
		slug)

	raw, status, err := z.doRequest(ctx, http.MethodPost, "/management/v1/orgs/_search", strings.NewReader(body))
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("zitadel_client: search orgs returned HTTP %d: %s", status, string(raw))
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

	raw, status, err := z.doRequest(ctx, http.MethodPost, "/management/v1/orgs/_search", strings.NewReader(body))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("zitadel_client: search orgs returned HTTP %d", status)
	}
	var resp zitadelSearchOrgsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("zitadel_client: unmarshal orgs response: %w", err)
	}
	for _, org := range resp.Result {
		if org.OrgName != slug {
			continue
		}
		// DELETE /v1/orgs/<id>
		_, delStatus, delErr := z.doRequest(ctx, http.MethodDelete, "/v1/orgs/"+org.OrgID, nil)
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
// It reads the `ZITADEL_DOMAIN` or `ZITADEL_BASE_URL` key from the
// `gibson-config` ConfigMap (namespace: gibson), falling back to the
// known Kind NodePort address.
func LoadZitadelURLFromCluster(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	cm, err := kubeClient.CoreV1().ConfigMaps("gibson").Get(ctx, "gibson-config", metav1.GetOptions{})
	if err != nil {
		// Fall back to the Kind cluster default.
		return "http://gibson-zitadel.gibson.svc.cluster.local:8080", nil
	}
	if u, ok := cm.Data["ZITADEL_BASE_URL"]; ok && u != "" {
		return u, nil
	}
	if domain, ok := cm.Data["ZITADEL_DOMAIN"]; ok && domain != "" {
		return "https://" + domain, nil
	}
	return "http://gibson-zitadel.gibson.svc.cluster.local:8080", nil
}

// LoadFGAURLFromCluster resolves the OpenFGA HTTP URL from the cluster.
// Falls back to the known Kind in-cluster address.
func LoadFGAURLFromCluster(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	// The FGA service is always at gibson-fga:8080 (HTTP) per the chart convention.
	// We don't need to read the cluster for this — the port is fixed in the chart.
	// But we check the gibson-fga service exists as a sanity check.
	_, err := kubeClient.CoreV1().Services("gibson").Get(ctx, "gibson-fga", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("zitadel_client: cannot find gibson-fga Service (B9: ext-authz may also be misconfigured): %w", err)
	}
	return "http://gibson-fga.gibson.svc.cluster.local:8080", nil
}
