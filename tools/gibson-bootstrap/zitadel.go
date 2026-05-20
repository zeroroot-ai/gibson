package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// PATClientConfig holds the minimal configuration for PAT-authenticated requests.
type PATClientConfig struct {
	// Issuer is the Zitadel base URL used as the base for all management API
	// calls (e.g. http://gibson-zitadel.gibson.svc.cluster.local:8080).
	Issuer string

	// AdminPAT is the Personal Access Token with org-create / app-create scope.
	// NEVER log this value.
	AdminPAT string

	// HTTPTimeout is the per-request timeout. Defaults to 15 seconds.
	HTTPTimeout time.Duration
}

// loadPATClientConfig reads configuration from environment variables.
// Returns an error if required variables are missing.
func loadPATClientConfig() (PATClientConfig, error) {
	issuer := os.Getenv("ZITADEL_ISSUER")
	if issuer == "" {
		return PATClientConfig{}, fmt.Errorf("ZITADEL_ISSUER env must be set")
	}

	// Trim surrounding whitespace — Zitadel's setup Job writes its PAT to
	// a file with a trailing newline, which propagates into the
	// `iam-admin-pat` Secret. Without trimming, the value goes into an
	// HTTP Authorization header and Go's net/http rejects it with
	// "invalid header field value for Authorization".
	pat := strings.TrimSpace(os.Getenv("ZITADEL_ADMIN_PAT"))
	if pat == "" {
		return PATClientConfig{}, fmt.Errorf("ZITADEL_ADMIN_PAT env must be set")
	}

	return PATClientConfig{
		Issuer:      strings.TrimRight(issuer, "/"),
		AdminPAT:    pat,
		HTTPTimeout: 15 * time.Second,
	}, nil
}

// patClient makes authenticated requests to the Zitadel Management API using
// a Personal Access Token (PAT). The PAT is obtained once at startup from the
// bootstrap-secrets Job and is never stored to disk or logged.
type patClient struct {
	cfg        PATClientConfig
	httpClient *http.Client
}

// newPATClient constructs a patClient from the provided configuration.
func newPATClient(cfg PATClientConfig) *patClient {
	return &patClient{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// ---------------------------------------------------------------------------
// EnsureOrg
// ---------------------------------------------------------------------------

// EnsureOrgResult is the JSON output of zitadel-ensure-org.
type EnsureOrgResult struct {
	OrgID   string `json:"org_id"`
	Created bool   `json:"created"`
}

// EnsureOrg idempotently creates or fetches a Zitadel organisation by name.
// If the org already exists it returns its existing ID with Created=false.
func (c *patClient) EnsureOrg(ctx context.Context, name string) (*EnsureOrgResult, error) {
	slog.Info("ensuring org", "name", name)

	// Search for an existing org with an exact-match name query.
	type nameQuery struct {
		Name   string `json:"name"`
		Method string `json:"method"`
	}
	type orgQuery struct {
		NameQuery nameQuery `json:"nameQuery"`
	}
	searchBody := map[string]interface{}{
		"queries": []orgQuery{{NameQuery: nameQuery{
			Name:   name,
			Method: "TEXT_QUERY_METHOD_EQUALS",
		}}},
	}

	var searchResp struct {
		Result []struct {
			OrgID string `json:"id"`
		} `json:"result"`
	}

	if err := c.doRequest(ctx, http.MethodPost, "/admin/v1/orgs/_search", "", searchBody, &searchResp); err != nil {
		return nil, fmt.Errorf("searching for org: %w", err)
	}

	if len(searchResp.Result) > 0 && searchResp.Result[0].OrgID != "" {
		orgID := searchResp.Result[0].OrgID
		slog.Info("org already exists", "org_id", orgID, "name", name)
		return &EnsureOrgResult{OrgID: orgID, Created: false}, nil
	}

	// Org not found — create it.
	slog.Info("org not found, creating", "name", name)

	createBody := map[string]string{"name": name}
	var createResp struct {
		OrgID string `json:"id"`
	}

	// Org creation is at /management/v1/orgs in Zitadel v4+; the
	// previous /admin/v1/orgs endpoint returns 404. Search still lives
	// on /admin/v1/orgs/_search (admin = system-level inspection,
	// management = CRUD requiring IAM-level token, which the
	// iam-admin PAT carries).
	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/orgs", "", createBody, &createResp); err != nil {
		// 409 means another process raced us; treat as idempotent success by
		// re-searching once.
		if isConflict(err) {
			slog.Info("org creation conflict (race), re-searching", "name", name)
			if err2 := c.doRequest(ctx, http.MethodPost, "/admin/v1/orgs/_search", "", searchBody, &searchResp); err2 != nil {
				return nil, fmt.Errorf("re-searching after conflict: %w", err2)
			}
			if len(searchResp.Result) > 0 && searchResp.Result[0].OrgID != "" {
				return &EnsureOrgResult{OrgID: searchResp.Result[0].OrgID, Created: false}, nil
			}
			return nil, fmt.Errorf("org conflict on create but not found on re-search (name=%s)", name)
		}
		return nil, fmt.Errorf("creating org: %w", err)
	}

	if createResp.OrgID == "" {
		return nil, fmt.Errorf("create org response missing id field")
	}

	slog.Info("org created", "org_id", createResp.OrgID, "name", name)
	return &EnsureOrgResult{OrgID: createResp.OrgID, Created: true}, nil
}

// ---------------------------------------------------------------------------
// EnsureProject
// ---------------------------------------------------------------------------

// EnsureProjectResult is the JSON output of zitadel-ensure-project.
type EnsureProjectResult struct {
	ProjectID string `json:"project_id"`
	Created   bool   `json:"created"`
}

// EnsureProject idempotently creates or fetches a Zitadel project by name
// within the given organisation. If the project already exists it returns
// its existing ID with Created=false.
//
// Project APIs are namespaced under the Management surface and require the
// caller's PAT to be scoped to (or for) the target org. The org ID is
// forwarded as the `x-zitadel-orgid` header by doRequest.
func (c *patClient) EnsureProject(ctx context.Context, orgID, name string) (*EnsureProjectResult, error) {
	slog.Info("ensuring project", "name", name, "org_id", orgID)

	// Search for an existing project with an exact-match name query.
	type nameQuery struct {
		Name   string `json:"name"`
		Method string `json:"method"`
	}
	type projectQuery struct {
		NameQuery nameQuery `json:"nameQuery"`
	}
	searchBody := map[string]interface{}{
		"queries": []projectQuery{{NameQuery: nameQuery{
			Name:   name,
			Method: "TEXT_QUERY_METHOD_EQUALS",
		}}},
	}

	var searchResp struct {
		Result []struct {
			ProjectID string `json:"id"`
		} `json:"result"`
	}

	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/projects/_search", orgID, searchBody, &searchResp); err != nil {
		return nil, fmt.Errorf("searching for project: %w", err)
	}

	if len(searchResp.Result) > 0 && searchResp.Result[0].ProjectID != "" {
		projectID := searchResp.Result[0].ProjectID
		slog.Info("project already exists", "project_id", projectID, "name", name)
		return &EnsureProjectResult{ProjectID: projectID, Created: false}, nil
	}

	// Project not found — create it.
	slog.Info("project not found, creating", "name", name, "org_id", orgID)

	createBody := map[string]interface{}{
		"name":                 name,
		"projectRoleAssertion": true,
		"projectRoleCheck":     false,
		"hasProjectCheck":      false,
	}
	var createResp struct {
		ProjectID string `json:"id"`
	}

	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/projects", orgID, createBody, &createResp); err != nil {
		if isConflict(err) {
			slog.Info("project creation conflict (race), re-searching", "name", name)
			if err2 := c.doRequest(ctx, http.MethodPost, "/management/v1/projects/_search", orgID, searchBody, &searchResp); err2 != nil {
				return nil, fmt.Errorf("re-searching after conflict: %w", err2)
			}
			if len(searchResp.Result) > 0 && searchResp.Result[0].ProjectID != "" {
				return &EnsureProjectResult{ProjectID: searchResp.Result[0].ProjectID, Created: false}, nil
			}
			return nil, fmt.Errorf("project conflict on create but not found on re-search (name=%s, org=%s)", name, orgID)
		}
		return nil, fmt.Errorf("creating project: %w", err)
	}

	if createResp.ProjectID == "" {
		return nil, fmt.Errorf("create project response missing id field")
	}

	slog.Info("project created", "project_id", createResp.ProjectID, "name", name)
	return &EnsureProjectResult{ProjectID: createResp.ProjectID, Created: true}, nil
}

// ---------------------------------------------------------------------------
// MintOIDCClient
// ---------------------------------------------------------------------------

// MintOIDCClientRequest carries parameters for zitadel-mint-oidc-client.
type MintOIDCClientRequest struct {
	ClientName   string
	OrgID        string
	ProjectID    string
	RotateSecret bool
}

// MintOIDCClientResult is the JSON output of zitadel-mint-oidc-client.
type MintOIDCClientResult struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Rotated      bool   `json:"rotated"`
}

// MintOIDCClient idempotently creates (or retrieves) an OIDC application in
// the given project. The client shape mirrors exactly what the existing
// post-install Job creates today:
//   - appType:            OIDC_APP_TYPE_WEB (confidential)
//   - authMethodType:     OIDC_AUTH_METHOD_TYPE_BASIC (client_secret_basic)
//   - responseTypes:      [OIDC_RESPONSE_TYPE_CODE]
//   - grantTypes:         [OIDC_GRANT_TYPE_AUTHORIZATION_CODE, OIDC_GRANT_TYPE_REFRESH_TOKEN]
//   - accessTokenType:    OIDC_TOKEN_TYPE_JWT
//   - version:            OIDC_VERSION_1_0
//
// If the app already exists and --rotate-secret is NOT set, the existing
// client_id is returned but client_secret is intentionally blank in the
// result (Zitadel does not expose the secret after first creation).
// Callers that need the secret must pass --rotate-secret.
func (c *patClient) MintOIDCClient(ctx context.Context, req MintOIDCClientRequest) (*MintOIDCClientResult, error) {
	slog.Info("minting OIDC client", "name", req.ClientName, "project_id", req.ProjectID)

	issuerURL := c.cfg.Issuer

	// Build the OIDC application body matching the post-install Job's shape.
	appBody := map[string]interface{}{
		"name":                     req.ClientName,
		"redirectUris":             []string{issuerURL + "/callback"},
		"responseTypes":            []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes":               []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"},
		"appType":                  "OIDC_APP_TYPE_WEB",
		"authMethodType":           "OIDC_AUTH_METHOD_TYPE_BASIC",
		"version":                  "OIDC_VERSION_1_0",
		"devMode":                  false,
		"accessTokenType":          "OIDC_TOKEN_TYPE_JWT",
		"accessTokenRoleAssertion": true,
		"idTokenRoleAssertion":     true,
		"idTokenUserinfoAssertion": true,
		"clockSkew":                "1s",
	}

	path := "/management/v1/projects/" + req.ProjectID + "/apps/oidc"
	var createResp struct {
		AppID        string `json:"appId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}

	err := c.doRequest(ctx, http.MethodPost, path, req.OrgID, appBody, &createResp)
	if err == nil {
		// Freshly created — Zitadel returns the secret once here.
		if createResp.ClientID == "" {
			return nil, fmt.Errorf("create OIDC app response missing clientId")
		}
		slog.Info("OIDC client created", "app_id", createResp.AppID, "client_id", createResp.ClientID)
		return &MintOIDCClientResult{
			ClientID:     createResp.ClientID,
			ClientSecret: createResp.ClientSecret,
			Rotated:      false,
		}, nil
	}

	if !isConflict(err) {
		return nil, fmt.Errorf("creating OIDC app: %w", err)
	}

	// App already exists — find it by name.
	slog.Info("OIDC client already exists, looking up", "name", req.ClientName)

	type appNameQuery struct {
		Name   string `json:"name"`
		Method string `json:"method"`
	}
	type appQuery struct {
		NameQuery appNameQuery `json:"nameQuery"`
	}
	searchBody := map[string]interface{}{
		"queries": []appQuery{{NameQuery: appNameQuery{
			Name:   req.ClientName,
			Method: "TEXT_QUERY_METHOD_EQUALS",
		}}},
	}

	var searchResp struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}

	searchPath := "/management/v1/projects/" + req.ProjectID + "/apps/_search"
	if err2 := c.doRequest(ctx, http.MethodPost, searchPath, req.OrgID, searchBody, &searchResp); err2 != nil {
		return nil, fmt.Errorf("searching for existing OIDC app: %w", err2)
	}

	appID := ""
	for _, r := range searchResp.Result {
		if r.Name == req.ClientName {
			appID = r.ID
			break
		}
	}
	if appID == "" {
		return nil, fmt.Errorf("OIDC app conflict on create but not found on search (name=%s, project=%s)", req.ClientName, req.ProjectID)
	}

	// Fetch the OIDC config to read the actual client_id.
	appDetailPath := "/management/v1/projects/" + req.ProjectID + "/apps/" + appID
	var detailResp struct {
		App struct {
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"app"`
	}

	if err2 := c.doRequest(ctx, http.MethodGet, appDetailPath, req.OrgID, nil, &detailResp); err2 != nil {
		return nil, fmt.Errorf("fetching OIDC app detail: %w", err2)
	}

	clientID := detailResp.App.OIDCConfig.ClientID
	if clientID == "" {
		return nil, fmt.Errorf("OIDC app detail missing clientId (app_id=%s)", appID)
	}

	slog.Info("found existing OIDC client", "app_id", appID, "client_id", clientID)

	if !req.RotateSecret {
		// Return the client_id without a secret; the caller must --rotate-secret
		// if it needs the credentials (secret cannot be retrieved post-creation).
		return &MintOIDCClientResult{
			ClientID:     clientID,
			ClientSecret: "",
			Rotated:      false,
		}, nil
	}

	// Rotate the client secret.
	slog.Info("rotating OIDC client secret", "app_id", appID)

	rotatePath := "/management/v1/projects/" + req.ProjectID + "/apps/" + appID + "/oidc_client_secret"
	var rotateResp struct {
		ClientSecret string `json:"clientSecret"`
	}

	if err2 := c.doRequest(ctx, http.MethodPost, rotatePath, req.OrgID, map[string]interface{}{}, &rotateResp); err2 != nil {
		return nil, fmt.Errorf("rotating OIDC client secret: %w", err2)
	}

	if rotateResp.ClientSecret == "" {
		return nil, fmt.Errorf("rotate secret response missing clientSecret (app_id=%s)", appID)
	}

	slog.Info("OIDC client secret rotated", "app_id", appID)
	return &MintOIDCClientResult{
		ClientID:     clientID,
		ClientSecret: rotateResp.ClientSecret,
		Rotated:      true,
	}, nil
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// doRequest executes an authenticated request to the Zitadel Management or
// Admin API. The PAT is injected as a Bearer token. If orgID is non-empty it
// is sent as the x-zitadel-orgid header.
//
// body may be nil (for GET/DELETE). respBody may be nil (result discarded).
func (c *patClient) doRequest(ctx context.Context, method, path, orgID string, body interface{}, respBody interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := c.cfg.Issuer + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.AdminPAT)
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if respBody != nil {
			if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
				return fmt.Errorf("decoding response from %s %s: %w", method, path, err)
			}
		}
		return nil
	}

	// Parse the Zitadel error envelope.
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var ze struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []struct {
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	}
	_ = json.Unmarshal(rawBody, &ze)

	code := ""
	if len(ze.Details) > 0 {
		code = ze.Details[0].ErrorCode
	}
	if code == "" {
		code = fmt.Sprintf("%d", ze.Code)
	}

	return &bootstrapAPIError{
		status:  resp.StatusCode,
		code:    code,
		message: ze.Message,
	}
}

// bootstrapAPIError is returned when Zitadel responds with a non-2xx status.
type bootstrapAPIError struct {
	status  int
	code    string
	message string
}

func (e *bootstrapAPIError) Error() string {
	return fmt.Sprintf("zitadel API HTTP %d [%s]: %s", e.status, e.code, e.message)
}

// isConflict reports whether err is a 409 Conflict from the Zitadel API.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	var ae *bootstrapAPIError
	if ok := asBootstrapAPIError(err, &ae); ok {
		return ae.status == http.StatusConflict
	}
	return false
}

// asBootstrapAPIError unwraps err to find a *bootstrapAPIError.
func asBootstrapAPIError(err error, target **bootstrapAPIError) bool {
	if ae, ok := err.(*bootstrapAPIError); ok { //nolint:errorlint
		*target = ae
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

// writeJSON marshals v to a single compact JSON line on stdout.
// Logs and diagnostics go to stderr; this is the only stdout write in the
// entire binary — the calling bootstrap-secrets script reads it with jq.
func writeJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling output: %w", err)
	}
	// json.Marshal never emits a trailing newline; we add one for shell
	// script compatibility (so `VAR=$(gibson-bootstrap ...)` strips it cleanly).
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}
