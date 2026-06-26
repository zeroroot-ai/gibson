// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the Zitadel Management/Admin API surface the platform-operator
// needs for OIDC client minting + project provisioning + service-user
// PAT lifecycle. All mutating operations are idempotent: caller may
// safely retry; 409/already-exists is success, 404 is success on delete.
type Client interface {
	// EnsureProject creates the Zitadel project with the given name and
	// returns its ID. If the project already exists, the existing ID is
	// returned. Idempotent.
	EnsureProject(ctx context.Context, name string) (projectID string, err error)

	// GetProjectIDByName looks up a Zitadel project ID from its display
	// name. Returns ErrNotFound when no match.
	GetProjectIDByName(ctx context.Context, name string) (projectID string, err error)

	// CreateOIDCClient creates an OIDC application under projectID and
	// returns its (appID, clientID, clientSecret) triple. Zitadel
	// distinguishes the app's internal record id (used in management
	// URL paths) from the OAuth client_id advertised on /.well-known/
	// openid-configuration — they are NOT the same value. Idempotent:
	// if a client with the same name already exists, both ids are
	// returned and clientSecret is empty (Zitadel does not re-emit
	// existing secrets — call RotateClientSecret with appID to mint a
	// new one).
	CreateOIDCClient(ctx context.Context, req CreateOIDCClientRequest) (appID, clientID, clientSecret string, err error)

	// GetOIDCClient looks up an application by appID; returns
	// ErrNotFound when missing. Used by the reconciler's crash-recovery
	// path. The parameter is the management-API app id, NOT the OAuth
	// client_id.
	GetOIDCClient(ctx context.Context, projectID, appID string) (*OIDCClient, error)

	// GetOIDCClientByName looks up an application by its display name
	// within the project. Returns both AppID (management-API id) and
	// ClientID (OAuth client_id) so the controller can repair stale
	// status (older CRs from before the split persisted only ClientID).
	// Returns ErrNotFound when no match.
	GetOIDCClientByName(ctx context.Context, projectID, name string) (*OIDCClient, error)

	// RotateClientSecret regenerates the client secret for an existing
	// OIDC application and returns the new secret. The parameter is the
	// management-API app id, NOT the OAuth client_id.
	RotateClientSecret(ctx context.Context, projectID, appID string) (newSecret string, err error)

	// DeleteOIDCClient removes the application. Idempotent on 404. The
	// parameter is the management-API app id, NOT the OAuth client_id.
	DeleteOIDCClient(ctx context.Context, projectID, appID string) error

	// EnsureMachineUser creates a Zitadel Machine User (Service User)
	// with the given userName and returns its userID. Idempotent: an
	// existing machine user with the same userName has its ID returned
	// instead. Used by the OIDCClient reconciler's MACHINE_USER path
	// to mint the daemon's identity for the client_credentials grant.
	EnsureMachineUser(ctx context.Context, userName string) (userID string, err error)

	// AddMachineUserClientSecret generates a clientID + clientSecret
	// for the given machine user. Zitadel returns the secret exactly
	// once. Subsequent calls regenerate the secret (idempotent in
	// effect — the prior secret stops working). Used to materialise
	// the daemon's idp-admin-credentials Secret.
	AddMachineUserClientSecret(ctx context.Context, userID string) (clientID, clientSecret string, err error)

	// AddIAMMember adds the given user to the IAM with the given roles
	// (e.g. ["IAM_OWNER"]). Idempotent: if the user is already a member
	// the roles are merged in via PUT semantics. Used to grant the
	// daemon's machine user the IAM_OWNER role its admin API calls need.
	AddIAMMember(ctx context.Context, userID string, roles []string) error

	// AddOrgMember adds the given user to the organization identified by
	// orgID with the given org-scoped roles (e.g. ["ORG_OWNER"]).
	// Idempotent: if the user is already an org member the roles are
	// merged in via PUT semantics, mirroring AddIAMMember's 409→PUT
	// handling. Org-scoped roles are distinct from IAM (instance-scoped)
	// roles — Zitadel routes them through /management/v1/orgs/{orgID}/
	// members rather than /admin/v1/members. Used by the machine-user
	// reconciler path to grant signup-style bots their org roles.
	AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error

	// GetOrgIDForProject returns the Zitadel organization ID that owns
	// the given project (Zitadel's `details.resourceOwner` field). The
	// daemon's IDP admin client needs this to construct Zitadel admin
	// API URLs that require an x-zitadel-orgid header.
	GetOrgIDForProject(ctx context.Context, projectID string) (orgID string, err error)

	// VerifyClientSecret checks whether the given (clientID, clientSecret)
	// pair currently authenticates against the issuer at issuerURL. Returns
	// (true, nil) when Zitadel accepts the credentials, (false, nil) when
	// Zitadel rejects them as invalid (HTTP 401 / invalid_client), and
	// (false, err) on transport / TLS / unexpected errors so the caller
	// can distinguish "credentials are wrong" from "we couldn't tell."
	//
	// Implemented via the OIDC introspection endpoint
	// (issuerURL + /oauth/v2/introspect) with HTTP Basic client auth and a
	// throwaway token body — the body content is irrelevant; what matters
	// is that Zitadel validates the Basic header first and rejects with
	// 401 + error="invalid_client" when the secret is wrong, regardless
	// of the token value supplied.
	VerifyClientSecret(ctx context.Context, issuerURL, clientID, clientSecret string) (bool, error)

	// EnsureJWTAccessToken patches the OIDC app's accessTokenType to JWT
	// when it is currently set to anything else (OIDC_TOKEN_TYPE_BEARER,
	// unset, etc.). Returns true when a patch was applied, false when the
	// app was already configured for JWT. Idempotent.
	//
	// Required so Envoy's jwt_authn filter can validate access tokens
	// without an introspection round-trip — Zitadel's default
	// OIDC_TOKEN_TYPE_BEARER produces opaque tokens that look like
	// "v2_xxx..." and break every authenticated daemon call routed
	// through Envoy. See zeroroot-ai/platform-operator#23.
	EnsureJWTAccessToken(ctx context.Context, projectID, appID string) (changed bool, err error)

	// EnsureMachineUserJWTAccessToken patches the machine user's
	// accessTokenType to ACCESS_TOKEN_TYPE_JWT when it is currently set
	// to ACCESS_TOKEN_TYPE_BEARER (or unset). Returns true when a patch
	// was applied, false when already configured for JWT. Idempotent.
	//
	// Zitadel machine users have their own per-user accessTokenType that
	// is distinct from the OIDC app-level accessTokenType patched by
	// EnsureJWTAccessToken. Without this, client_credentials tokens
	// minted for MACHINE_USER OIDCClient entries are opaque bearer strings
	// ("v2_xxx...") that Envoy's jwt_authn filter rejects with
	// "Jwt is not in the form of Header.Payload.Signature".
	// See zeroroot-ai/platform-operator#65.
	EnsureMachineUserJWTAccessToken(ctx context.Context, userID, userName string) (changed bool, err error)

	// EnsureRegistrationDisabled enforces allowRegister=false on the
	// instance default login policy so Zitadel's hosted self-registration
	// page (/ui/v2/login/register) and the sign-in "Register" link are not
	// served. All human users are provisioned through the admin API
	// (controlled signup), so self-service registration must be off
	// (deploy#886). Idempotent: returns changed=false when already
	// disabled, changed=true when a PUT was applied.
	EnsureRegistrationDisabled(ctx context.Context) (changed bool, err error)
}

// CreateOIDCClientRequest is the input to CreateOIDCClient.
type CreateOIDCClientRequest struct {
	ProjectID              string
	Name                   string
	ApplicationType        string // WEB | NATIVE | USER_AGENT | SERVICE
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	ResponseTypes          []string
	// AccessTokenLifetime, when non-empty, sets the OIDC app's per-application
	// access-token lifetime (a Zitadel duration string, e.g. "900s"). Empty
	// leaves the instance default.
	AccessTokenLifetime string
}

// OIDCClient is the typed Zitadel application returned by GetOIDCClient
// and findOIDCClientByName. Distinguishes between the management-API
// `AppID` (used in URL paths) and the OAuth `ClientID` (advertised on
// /.well-known and used by every OAuth consumer).
type OIDCClient struct {
	AppID           string
	ClientID        string
	Name            string
	ProjectID       string
	ApplicationType string
}

// New constructs a Zitadel admin API client authenticated via PAT.
// apiURL is the Zitadel base URL (e.g. "https://zitadel.example.com").
// pat is the IAM_OWNER Personal Access Token. externalDomain is forged
// onto the Host header on every request so in-cluster Service-name
// callers route to the right Zitadel instance; pass empty to skip
// forgery.
func New(apiURL, pat, externalDomain string) Client {
	u, err := url.Parse(apiURL)
	if err != nil {
		return &errClient{err: fmt.Errorf("zitadel: invalid apiURL %q: %w", apiURL, err)}
	}
	// Defensive trim. Go's net/http rejects header values containing CR/LF
	// (CWE-93), so a single trailing 0x0a from `echo "$pat" | kubectl
	// create secret …` produces a permanent "invalid header field value
	// for Authorization" loop with no actual transient error. Trim once
	// here so every caller benefits.
	return &httpClient{
		baseURL:        u,
		pat:            strings.TrimSpace(pat),
		externalDomain: externalDomain,
		http:           &http.Client{Timeout: 30 * time.Second},
	}
}

type httpClient struct {
	baseURL        *url.URL
	pat            string
	externalDomain string
	http           *http.Client
}

// EnsureProject implements Client.
//
// Zitadel v4: POST /management/v1/projects (self-scoped via
// x-zitadel-orgid header — caller's PAT is IAM_OWNER).
func (c *httpClient) EnsureProject(ctx context.Context, name string) (string, error) {
	body := map[string]any{"name": name}
	var resp struct {
		ID string `json:"id"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/management/v1/projects", body, &resp)
	if err != nil {
		if IsConflict(err) || IsAlreadyExists(err) {
			id, lerr := c.GetProjectIDByName(ctx, name)
			if lerr != nil {
				return "", fmt.Errorf("EnsureProject: conflict lookup: %w", lerr)
			}
			return id, nil
		}
		return "", fmt.Errorf("EnsureProject %q: %w", name, err)
	}
	return resp.ID, nil
}

// GetProjectIDByName implements Client.
//
// Zitadel v4: POST /management/v1/projects/_search with a nameQuery.
func (c *httpClient) GetProjectIDByName(ctx context.Context, name string) (string, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}},
		},
	}
	var resp struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/management/v1/projects/_search", body, &resp); err != nil {
		return "", fmt.Errorf("GetProjectIDByName %q: %w", name, err)
	}
	for _, p := range resp.Result {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("GetProjectIDByName %q: %w", name, ErrNotFound)
}

// CreateOIDCClient implements Client.
//
// Zitadel v4: POST /management/v1/projects/{projectID}/apps/oidc returns
// (appId, clientId, clientSecret). The appId is the management-API
// record id (used in subsequent URL paths); the clientId is the OAuth
// client_id advertised on /.well-known. Idempotent on 409 via name
// lookup.
func (c *httpClient) CreateOIDCClient(ctx context.Context, req CreateOIDCClientRequest) (string, string, string, error) {
	body := map[string]any{
		"name":                   req.Name,
		"redirectUris":           req.RedirectURIs,
		"postLogoutRedirectUris": req.PostLogoutRedirectURIs,
		"responseTypes":          mapStrings(req.ResponseTypes, oidcResponseTypeToZitadel),
		"grantTypes":             mapStrings(req.GrantTypes, oidcGrantTypeToZitadel),
		"appType":                applicationTypeToZitadelAppType(req.ApplicationType),
		"authMethodType":         authMethodForAppType(req.ApplicationType),
		// JWT (not opaque bearer) so Envoy's jwt_authn filter can
		// validate the access token without an introspection round-trip.
		// Zitadel's default is OIDC_TOKEN_TYPE_BEARER, which silently
		// breaks every downstream daemon call. See
		// zeroroot-ai/platform-operator#23.
		"accessTokenType": "OIDC_TOKEN_TYPE_JWT",
	}
	// Per-app access-token lifetime override (gibson#622: bounds the CLI
	// session-revocation window to 15m). Zitadel expects a duration string.
	// NOTE: verify the wire shape against the deployed Zitadel version in the
	// deploy auth-e2e smoke; if the instance rejects a per-app override the
	// lifetime falls back to the instance OIDC setting.
	if req.AccessTokenLifetime != "" {
		body["accessTokenLifetime"] = req.AccessTokenLifetime
	}
	var resp struct {
		AppID        string `json:"appId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	path := fmt.Sprintf("/management/v1/projects/%s/apps/oidc", url.PathEscape(req.ProjectID))
	err := c.doJSON(ctx, http.MethodPost, path, body, &resp)
	if err != nil {
		if IsConflict(err) || IsAlreadyExists(err) {
			existing, lerr := c.findOIDCClientByName(ctx, req.ProjectID, req.Name)
			if lerr != nil {
				return "", "", "", fmt.Errorf("CreateOIDCClient: conflict lookup: %w", lerr)
			}
			// Zitadel does not re-emit the secret for an existing app;
			// caller must RotateClientSecret if it needs the value.
			return existing.AppID, existing.ClientID, "", nil
		}
		return "", "", "", fmt.Errorf("CreateOIDCClient %q: %w", req.Name, err)
	}
	return resp.AppID, resp.ClientID, resp.ClientSecret, nil
}

// GetOIDCClient implements Client.
//
// Zitadel v4: GET /management/v1/projects/{projectID}/apps/{appID}.
// The path parameter is the app's management-API id, NOT the OAuth
// client_id.
func (c *httpClient) GetOIDCClient(ctx context.Context, projectID, appID string) (*OIDCClient, error) {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/%s",
		url.PathEscape(projectID), url.PathEscape(appID))
	var resp struct {
		App struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			OIDC *struct {
				AppType  string `json:"appType"`
				ClientID string `json:"clientId"`
			} `json:"oidcConfig,omitempty"`
		} `json:"app"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("GetOIDCClient project=%s app=%s: %w", projectID, appID, err)
	}
	out := &OIDCClient{
		AppID:     resp.App.ID,
		Name:      resp.App.Name,
		ProjectID: projectID,
	}
	if resp.App.OIDC != nil {
		out.ApplicationType = zitadelAppTypeToApplicationType(resp.App.OIDC.AppType)
		out.ClientID = resp.App.OIDC.ClientID
	}
	return out, nil
}

// RotateClientSecret implements Client. The path parameter is the
// management-API app id, NOT the OAuth client_id.
//
// Zitadel v4: POST /management/v1/projects/{projectID}/apps/{appID}/oidc_config/_generate_client_secret
// returns the new client secret exactly once.
func (c *httpClient) RotateClientSecret(ctx context.Context, projectID, appID string) (string, error) {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/%s/oidc_config/_generate_client_secret",
		url.PathEscape(projectID), url.PathEscape(appID))
	var resp struct {
		ClientSecret string `json:"clientSecret"`
	}
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return "", fmt.Errorf("RotateClientSecret project=%s app=%s: %w", projectID, appID, err)
	}
	return resp.ClientSecret, nil
}

// DeleteOIDCClient implements Client. The path parameter is the
// management-API app id, NOT the OAuth client_id.
//
// Zitadel v4: DELETE /management/v1/projects/{projectID}/apps/{appID}.
// Idempotent: 404 is treated as success.
func (c *httpClient) DeleteOIDCClient(ctx context.Context, projectID, appID string) error {
	path := fmt.Sprintf("/management/v1/projects/%s/apps/%s",
		url.PathEscape(projectID), url.PathEscape(appID))
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil)
	if err != nil && IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("DeleteOIDCClient project=%s app=%s: %w", projectID, appID, err)
	}
	return nil
}

// GetOIDCClientByName implements Client by delegating to the unexported
// findOIDCClientByName so callers outside this package can resolve
// AppID + ClientID from the spec's display name (crash-recovery path).
func (c *httpClient) GetOIDCClientByName(ctx context.Context, projectID, name string) (*OIDCClient, error) {
	return c.findOIDCClientByName(ctx, projectID, name)
}

// EnsureJWTAccessToken implements Client.
//
// Zitadel v4 update path: PUT /management/v1/projects/{projectID}/apps/{appID}/oidc_config
// requires the FULL oidc_config — partial updates would zero out the
// other fields. We GET the current config first, splice in
// accessTokenType=JWT, and PUT the merged shape back.
//
// Returns (true, nil) when a patch was applied, (false, nil) when the
// app was already JWT, and (false, err) for transport / API errors.
func (c *httpClient) EnsureJWTAccessToken(ctx context.Context, projectID, appID string) (bool, error) {
	getPath := fmt.Sprintf("/management/v1/projects/%s/apps/%s",
		url.PathEscape(projectID), url.PathEscape(appID))
	var getResp struct {
		App struct {
			OIDCConfig map[string]any `json:"oidcConfig"`
		} `json:"app"`
	}
	if err := c.doJSON(ctx, http.MethodGet, getPath, nil, &getResp); err != nil {
		return false, fmt.Errorf("EnsureJWTAccessToken: get %s: %w", appID, err)
	}
	cfg := getResp.App.OIDCConfig
	if cfg == nil {
		return false, fmt.Errorf("EnsureJWTAccessToken: app %s has no oidcConfig", appID)
	}
	// Zitadel returns accessTokenType when set; missing or
	// OIDC_TOKEN_TYPE_BEARER both mean "opaque bearer (not JWT)".
	if t, ok := cfg["accessTokenType"].(string); ok && t == "OIDC_TOKEN_TYPE_JWT" {
		return false, nil
	}
	cfg["accessTokenType"] = "OIDC_TOKEN_TYPE_JWT"
	putPath := fmt.Sprintf("/management/v1/projects/%s/apps/%s/oidc_config",
		url.PathEscape(projectID), url.PathEscape(appID))
	if err := c.doJSON(ctx, http.MethodPut, putPath, cfg, nil); err != nil {
		return false, fmt.Errorf("EnsureJWTAccessToken: put %s: %w", appID, err)
	}
	return true, nil
}

// VerifyClientSecret implements Client.
//
// POSTs to issuerURL + /oauth/v2/introspect with HTTP Basic auth using
// (clientID, clientSecret) and a throwaway token body. Returns:
//   - (true, nil)   — HTTP 200 (token validation result irrelevant; what
//     matters is that Zitadel accepted the Basic auth).
//   - (false, nil)  — HTTP 401 (invalid_client). The secret is wrong.
//   - (false, err)  — transport / TLS / unexpected status codes (5xx).
//     Caller should treat as unknown and proceed with whatever
//     fallback policy applies (typically: don't rotate, log, retry
//     on next reconcile).
func (c *httpClient) VerifyClientSecret(ctx context.Context, issuerURL, clientID, clientSecret string) (bool, error) {
	base, err := url.Parse(issuerURL)
	if err != nil {
		return false, fmt.Errorf("VerifyClientSecret: parse issuerURL %q: %w", issuerURL, ErrInvalidInput)
	}
	full, err := base.Parse("/oauth/v2/introspect")
	if err != nil {
		return false, fmt.Errorf("VerifyClientSecret: build introspect path: %w", ErrInvalidInput)
	}
	// A non-empty token body keeps Zitadel happy with the request shape;
	// the actual value is never validated when Basic auth fails first.
	form := url.Values{"token": []string{"verify-client-secret-probe"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full.String(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("VerifyClientSecret: new request: %w", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.externalDomain != "" {
		req.Host = c.externalDomain
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("VerifyClientSecret: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case 200:
		return true, nil
	case 401:
		return false, nil
	default:
		return false, fmt.Errorf("VerifyClientSecret: unexpected status %d: %w",
			resp.StatusCode, ErrUnreachable)
	}
}

// findOIDCClientByName searches a project's apps for a name match.
// Used by CreateOIDCClient's 409 idempotency path.
//
// Critical: Zitadel's _search response distinguishes between the app's
// internal record id (`id`) and the OAuth `clientId` advertised on the
// /.well-known/openid-configuration document. These are NOT the same
// value. The OAuth flow (browser authorize, client_credentials grant,
// JWT `azp` claim, etc.) uses `oidcConfig.clientId`. Returning the
// internal `id` here previously caused Zitadel to respond
// `Errors.App.NotFound` on every browser login after a re-reconcile,
// because the dashboard was sending the app id as client_id.
func (c *httpClient) findOIDCClientByName(ctx context.Context, projectID, name string) (*OIDCClient, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}},
		},
	}
	var resp struct {
		Result []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			OIDCConfig *struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig,omitempty"`
		} `json:"result"`
	}
	path := fmt.Sprintf("/management/v1/projects/%s/apps/_search", url.PathEscape(projectID))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	for _, a := range resp.Result {
		if a.Name != name {
			continue
		}
		oc := &OIDCClient{AppID: a.ID, Name: a.Name, ProjectID: projectID}
		if a.OIDCConfig != nil {
			oc.ClientID = a.OIDCConfig.ClientID
		}
		return oc, nil
	}
	return nil, ErrNotFound
}

// doJSON issues an authenticated JSON request and decodes the response
// into out (or discards on out==nil). Maps HTTP status codes to sentinel
// errors.
func (c *httpClient) doJSON(ctx context.Context, method, path string, body, out any) error {
	return c.doJSONWithHeaders(ctx, method, path, body, out, nil)
}

// doJSONWithHeaders is doJSON with caller-supplied extra request headers
// (e.g. x-zitadel-orgid to scope an org-member grant to a specific org).
// nil headers behaves exactly like doJSON.
func (c *httpClient) doJSONWithHeaders(ctx context.Context, method, path string, body, out any, headers map[string]string) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("zitadel: marshal body: %w: %w", err, ErrInvalidInput)
		}
		bodyReader = bytes.NewReader(buf)
	}
	full, err := c.baseURL.Parse(path)
	if err != nil {
		return fmt.Errorf("zitadel: path %q: %w", path, ErrInvalidInput)
	}
	req, err := http.NewRequestWithContext(ctx, method, full.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("zitadel: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.pat)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.externalDomain != "" {
		req.Host = c.externalDomain
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("zitadel: decode %s %s: %w", method, path, err)
		}
		return nil
	}
	switch {
	case resp.StatusCode == 404:
		return fmt.Errorf("zitadel %s %s 404: %w", method, path, ErrNotFound)
	case resp.StatusCode == 409:
		return fmt.Errorf("zitadel %s %s 409: %w", method, path, ErrAlreadyExists)
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return WrapPermanent(fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, ErrUnauthorized, string(raw)))
	case resp.StatusCode == 429:
		return fmt.Errorf("zitadel %d: %w", resp.StatusCode, ErrRateLimited)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, ErrInvalidInput, string(raw))
	default:
		return fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, ErrUnreachable, string(raw))
	}
}

// applicationTypeToZitadelAppType maps our enum to Zitadel's wire enum.
func applicationTypeToZitadelAppType(t string) string {
	switch t {
	case "WEB":
		return "OIDC_APP_TYPE_WEB"
	case "NATIVE":
		return "OIDC_APP_TYPE_NATIVE"
	case "USER_AGENT":
		return "OIDC_APP_TYPE_USER_AGENT"
	case "SERVICE":
		// Zitadel's "user agent" + token-exchange grants approximates a
		// service M2M client; the actual machine-user path is separate.
		return "OIDC_APP_TYPE_USER_AGENT"
	}
	return "OIDC_APP_TYPE_WEB"
}

// authMethodForAppType picks a sane default OIDC auth method per type.
func authMethodForAppType(t string) string {
	switch t {
	case "WEB", "SERVICE":
		return "OIDC_AUTH_METHOD_TYPE_BASIC"
	case "NATIVE", "USER_AGENT":
		return "OIDC_AUTH_METHOD_TYPE_NONE"
	}
	return "OIDC_AUTH_METHOD_TYPE_BASIC"
}

// oidcGrantTypeToZitadel maps the OIDCClient CR grant-type vocabulary onto
// Zitadel's wire enum names. Zitadel does not recognize the bare names and
// silently drops them, falling back to the app-type's default grant set — so
// e.g. DEVICE_CODE never reaches the minted app and `gibson login`'s device
// flow fails at the token endpoint (platform-operator#84). Already-prefixed
// values pass through unchanged.
func oidcGrantTypeToZitadel(g string) string {
	switch g {
	case "AUTHORIZATION_CODE":
		return "OIDC_GRANT_TYPE_AUTHORIZATION_CODE"
	case "IMPLICIT":
		return "OIDC_GRANT_TYPE_IMPLICIT"
	case "REFRESH_TOKEN":
		return "OIDC_GRANT_TYPE_REFRESH_TOKEN"
	case "DEVICE_CODE":
		return "OIDC_GRANT_TYPE_DEVICE_CODE"
	case "CLIENT_CREDENTIALS":
		return "OIDC_GRANT_TYPE_CLIENT_CREDENTIALS"
	}
	return g
}

// oidcResponseTypeToZitadel maps the OIDCClient CR response-type vocabulary
// onto Zitadel's wire enum names. Same silent-drop hazard as grant types.
func oidcResponseTypeToZitadel(rt string) string {
	switch rt {
	case "CODE":
		return "OIDC_RESPONSE_TYPE_CODE"
	case "ID_TOKEN":
		return "OIDC_RESPONSE_TYPE_ID_TOKEN"
	case "ID_TOKEN_TOKEN":
		return "OIDC_RESPONSE_TYPE_ID_TOKEN_TOKEN"
	}
	return rt
}

// mapStrings returns a new slice with f applied to each element. nil in, nil
// out (so an absent field stays absent in the request body).
func mapStrings(in []string, f func(string) string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

// zitadelAppTypeToApplicationType reverses applicationTypeToZitadelAppType.
func zitadelAppTypeToApplicationType(t string) string {
	switch t {
	case "OIDC_APP_TYPE_WEB":
		return "WEB"
	case "OIDC_APP_TYPE_NATIVE":
		return "NATIVE"
	case "OIDC_APP_TYPE_USER_AGENT":
		return "USER_AGENT"
	}
	return "WEB"
}

// errClient is returned when New cannot parse its inputs; every call
// surface returns the construction error.
type errClient struct{ err error }

func (e *errClient) EnsureProject(ctx context.Context, name string) (string, error) {
	return "", e.err
}
func (e *errClient) GetProjectIDByName(ctx context.Context, name string) (string, error) {
	return "", e.err
}
func (e *errClient) CreateOIDCClient(ctx context.Context, req CreateOIDCClientRequest) (string, string, string, error) {
	return "", "", "", e.err
}
func (e *errClient) GetOIDCClient(ctx context.Context, projectID, appID string) (*OIDCClient, error) {
	return nil, e.err
}
func (e *errClient) GetOIDCClientByName(ctx context.Context, projectID, name string) (*OIDCClient, error) {
	return nil, e.err
}
func (e *errClient) VerifyClientSecret(ctx context.Context, issuerURL, clientID, clientSecret string) (bool, error) {
	return false, e.err
}
func (e *errClient) EnsureJWTAccessToken(ctx context.Context, projectID, appID string) (bool, error) {
	return false, e.err
}
func (e *errClient) RotateClientSecret(ctx context.Context, projectID, appID string) (string, error) {
	return "", e.err
}
func (e *errClient) DeleteOIDCClient(ctx context.Context, projectID, appID string) error {
	return e.err
}
func (e *errClient) EnsureMachineUser(ctx context.Context, userName string) (string, error) {
	return "", e.err
}
func (e *errClient) EnsureMachineUserJWTAccessToken(ctx context.Context, userID, userName string) (bool, error) {
	return false, e.err
}
func (e *errClient) AddMachineUserClientSecret(ctx context.Context, userID string) (string, string, error) {
	return "", "", e.err
}
func (e *errClient) AddIAMMember(ctx context.Context, userID string, roles []string) error {
	return e.err
}
func (e *errClient) AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error {
	return e.err
}
func (e *errClient) EnsureRegistrationDisabled(ctx context.Context) (bool, error) {
	return false, e.err
}
func (e *errClient) GetOrgIDForProject(ctx context.Context, projectID string) (string, error) {
	return "", e.err
}

// GetOrgIDForProject implements Client.
//
// Zitadel v4: GET /management/v1/projects/{projectID} returns the
// project resource whose `details.resourceOwner` field is the owning
// org ID.
func (c *httpClient) GetOrgIDForProject(ctx context.Context, projectID string) (string, error) {
	path := fmt.Sprintf("/management/v1/projects/%s", url.PathEscape(projectID))
	var resp struct {
		Project struct {
			Details struct {
				ResourceOwner string `json:"resourceOwner"`
			} `json:"details"`
		} `json:"project"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", fmt.Errorf("GetOrgIDForProject project=%s: %w", projectID, err)
	}
	if resp.Project.Details.ResourceOwner == "" {
		return "", fmt.Errorf("GetOrgIDForProject project=%s: empty resourceOwner in response", projectID)
	}
	return resp.Project.Details.ResourceOwner, nil
}

// EnsureMachineUser implements Client.
//
// Zitadel v4: POST /management/v1/users/machine with body
// `{userName, name, accessTokenType: "ACCESS_TOKEN_TYPE_JWT"}`.
// 409 (already exists) is resolved by searching for the same userName.
// JWT is set at creation time so new machine users immediately emit JWTs;
// existing users are patched via EnsureMachineUserJWTAccessToken.
func (c *httpClient) EnsureMachineUser(ctx context.Context, userName string) (string, error) {
	body := map[string]any{
		"userName":        userName,
		"name":            userName,
		"description":     "platform-operator-managed",
		"accessTokenType": "ACCESS_TOKEN_TYPE_JWT",
	}
	var resp struct {
		UserID string `json:"userId"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/management/v1/users/machine", body, &resp)
	if err != nil {
		if IsConflict(err) || IsAlreadyExists(err) {
			id, lerr := c.findMachineUserByName(ctx, userName)
			if lerr != nil {
				return "", fmt.Errorf("EnsureMachineUser: conflict lookup: %w", lerr)
			}
			return id, nil
		}
		return "", fmt.Errorf("EnsureMachineUser %q: %w", userName, err)
	}
	if resp.UserID == "" {
		// Conflict-shaped success — list to resolve.
		id, lerr := c.findMachineUserByName(ctx, userName)
		if lerr != nil {
			return "", fmt.Errorf("EnsureMachineUser: post-create lookup: %w", lerr)
		}
		return id, nil
	}
	return resp.UserID, nil
}

// EnsureMachineUserJWTAccessToken implements Client.
//
// Zitadel v4: GET /management/v1/users/{userId} to check the current
// accessTokenType, then PUT /management/v1/users/{userId}/machine with
// accessTokenType=ACCESS_TOKEN_TYPE_JWT if it is not already set.
//
// The PUT endpoint requires the full machine-user body (userName + name
// are mandatory), so we thread userName through from the caller rather
// than doing an extra GET to recover it.
func (c *httpClient) EnsureMachineUserJWTAccessToken(ctx context.Context, userID, userName string) (bool, error) {
	getPath := fmt.Sprintf("/management/v1/users/%s", url.PathEscape(userID))
	var getResp struct {
		User struct {
			Machine *struct {
				AccessTokenType string `json:"accessTokenType"`
			} `json:"machine"`
		} `json:"user"`
	}
	if err := c.doJSON(ctx, http.MethodGet, getPath, nil, &getResp); err != nil {
		return false, fmt.Errorf("EnsureMachineUserJWTAccessToken: get user %s: %w", userID, err)
	}
	// Zitadel omits the field when it is the default (BEARER). Only skip
	// the PUT when it is already explicitly set to JWT.
	if getResp.User.Machine != nil &&
		getResp.User.Machine.AccessTokenType == "ACCESS_TOKEN_TYPE_JWT" {
		return false, nil
	}
	putPath := fmt.Sprintf("/management/v1/users/%s/machine", url.PathEscape(userID))
	body := map[string]any{
		"userName":        userName,
		"name":            userName,
		"description":     "platform-operator-managed",
		"accessTokenType": "ACCESS_TOKEN_TYPE_JWT",
	}
	if err := c.doJSON(ctx, http.MethodPut, putPath, body, nil); err != nil {
		return false, fmt.Errorf("EnsureMachineUserJWTAccessToken: put user %s: %w", userID, err)
	}
	return true, nil
}

// findMachineUserByName resolves a machine-user userName to its userID.
// Used by EnsureMachineUser's 409 idempotency path.
func (c *httpClient) findMachineUserByName(ctx context.Context, userName string) (string, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{"userNameQuery": map[string]any{
				"userName": userName,
				"method":   "TEXT_QUERY_METHOD_EQUALS",
			}},
			{"typeQuery": map[string]any{"type": "TYPE_MACHINE"}},
		},
	}
	var resp struct {
		Result []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/management/v1/users/_search", body, &resp); err != nil {
		return "", fmt.Errorf("findMachineUserByName %q: %w", userName, err)
	}
	for _, u := range resp.Result {
		if u.UserName == userName {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("findMachineUserByName %q: %w", userName, ErrNotFound)
}

// AddMachineUserClientSecret implements Client.
//
// Zitadel v4: PUT /management/v1/users/{userId}/secret regenerates the
// client_id + client_secret for a machine user. The secret is returned
// in plaintext exactly once.
func (c *httpClient) AddMachineUserClientSecret(ctx context.Context, userID string) (string, string, error) {
	path := fmt.Sprintf("/management/v1/users/%s/secret", url.PathEscape(userID))
	var resp struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := c.doJSON(ctx, http.MethodPut, path, struct{}{}, &resp); err != nil {
		return "", "", fmt.Errorf("AddMachineUserClientSecret user=%s: %w", userID, err)
	}
	return resp.ClientID, resp.ClientSecret, nil
}

// AddIAMMember implements Client.
//
// Zitadel v4: POST /admin/v1/iam/members with body
// `{userId, roles: [...]}` adds the user; 409 → PUT the same body to
// merge roles. We treat 409 as idempotent success without re-PUTting
// because the role set is exactly what we want anyway.
func (c *httpClient) AddIAMMember(ctx context.Context, userID string, roles []string) error {
	body := map[string]any{
		"userId": userID,
		"roles":  roles,
	}
	err := c.doJSON(ctx, http.MethodPost, "/admin/v1/members", body, nil)
	if err == nil {
		return nil
	}
	if IsConflict(err) || IsAlreadyExists(err) {
		// PUT to merge roles — Zitadel's PUT endpoint uses /admin/v1/members/{userId}.
		path := fmt.Sprintf("/admin/v1/members/%s", url.PathEscape(userID))
		body := map[string]any{"roles": roles}
		if perr := c.doJSON(ctx, http.MethodPut, path, body, nil); perr != nil {
			return fmt.Errorf("AddIAMMember user=%s: PUT after 409: %w", userID, perr)
		}
		return nil
	}
	return fmt.Errorf("AddIAMMember user=%s: %w", userID, err)
}

// AddOrgMember implements Client.
//
// Zitadel v4: POST /management/v1/orgs/{orgID}/members with body
// `{userId, roles: [...]}` adds the user as an org member; 409 → PUT the
// same role set to /management/v1/orgs/{orgID}/members/{userId} to merge.
// The x-zitadel-orgid header pins the request to orgID so the grant lands
// on the project's owning org rather than the PAT's default org. Mirrors
// AddIAMMember's idempotency contract: 409/already-exists is success.
func (c *httpClient) AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error {
	if orgID == "" {
		return fmt.Errorf("AddOrgMember user=%s: empty orgID: %w", userID, ErrInvalidInput)
	}
	headers := map[string]string{"x-zitadel-orgid": orgID}
	postPath := fmt.Sprintf("/management/v1/orgs/%s/members", url.PathEscape(orgID))
	body := map[string]any{
		"userId": userID,
		"roles":  roles,
	}
	err := c.doJSONWithHeaders(ctx, http.MethodPost, postPath, body, nil, headers)
	if err == nil {
		return nil
	}
	if IsConflict(err) || IsAlreadyExists(err) {
		putPath := fmt.Sprintf("/management/v1/orgs/%s/members/%s",
			url.PathEscape(orgID), url.PathEscape(userID))
		putBody := map[string]any{"roles": roles}
		if perr := c.doJSONWithHeaders(ctx, http.MethodPut, putPath, putBody, nil, headers); perr != nil {
			return fmt.Errorf("AddOrgMember org=%s user=%s: PUT after 409: %w", orgID, userID, perr)
		}
		return nil
	}
	return fmt.Errorf("AddOrgMember org=%s user=%s: %w", orgID, userID, err)
}

// updatableLoginPolicyFields are the keys the Admin UpdateLoginPolicy
// (PUT /admin/v1/policies/login) request accepts. We copy these verbatim
// from the current GET response so a PUT preserves every live setting and
// only flips allowRegister — Zitadel's PUT replaces the policy with the
// body, so omitting a field would silently reset it (e.g. zeroing an MFA
// lifetime). Read-only GET fields (details, isDefault) are NOT in this set
// and are dropped, since echoing them back is rejected with 400.
var updatableLoginPolicyFields = []string{
	"allowUsernamePassword",
	"allowRegister",
	"allowExternalIdp",
	"forceMfa",
	"forceMfaLocalOnly",
	"passwordlessType",
	"hidePasswordReset",
	"ignoreUnknownUsernames",
	"allowDomainDiscovery",
	"disableLoginWithEmail",
	"disableLoginWithPhone",
	"defaultRedirectUri",
	"passwordCheckLifetime",
	"externalLoginCheckLifetime",
	"mfaInitSkipLifetime",
	"secondFactorCheckLifetime",
	"multiFactorCheckLifetime",
}

// EnsureRegistrationDisabled implements Client.
//
// Zitadel v4: GET /admin/v1/policies/login returns the instance default
// login policy under `policy`; its `allowRegister` flag gates the hosted
// Login-V2 self-registration page (/ui/v2/login/register) and the
// "Register" link on the sign-in screen. The platform provisions all human
// users through the admin API (the dashboard's controlled signup,
// POST /v2/users/human), which does NOT consult this flag, so registration
// must be off — otherwise anyone can mint an account outside the controlled
// signup (no plan / Stripe / Tenant CR / FGA owner tuple). See deploy#886.
//
// DefaultInstance.LoginPolicy in the Zitadel chart config only applies at
// FIRST-INSTANCE creation, so already-running instances need this runtime
// enforcement. Idempotent: GET first, no-op when allowRegister is already
// false; otherwise PUT /admin/v1/policies/login echoing every live field
// with allowRegister flipped to false. Returns changed=true only when a
// PUT was applied.
func (c *httpClient) EnsureRegistrationDisabled(ctx context.Context) (bool, error) {
	var current struct {
		Policy map[string]any `json:"policy"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/admin/v1/policies/login", nil, &current); err != nil {
		return false, fmt.Errorf("EnsureRegistrationDisabled: GET login policy: %w", err)
	}
	if current.Policy == nil {
		return false, fmt.Errorf("EnsureRegistrationDisabled: empty login policy in response: %w", ErrPermanent)
	}
	// Zitadel (protojson) omits allowRegister from the GET response once it is
	// false — protojson drops false booleans — so a MISSING key also means
	// registration is already disabled. Treat anything other than an explicit
	// true as already-disabled. The previous `ok && !allow` check only no-oped
	// when the key was present AND false, so on every reconcile after the first
	// it re-PUT allowRegister=false; Zitadel rejected that no-op change with
	// `400 Default Login Policy has not been changed (INSTANCE-5M9vdd)`, which
	// the caller classified as a transient error and retried forever — wedging
	// PlatformBootstrap (ZitadelProjectReady=Unknown) so the KEK was never
	// minted and the daemon never started. deploy#886 regression.
	if allow, _ := current.Policy["allowRegister"].(bool); !allow {
		// Already disabled (false or omitted) — nothing to do.
		return false, nil
	}

	body := make(map[string]any, len(updatableLoginPolicyFields))
	for _, k := range updatableLoginPolicyFields {
		if v, ok := current.Policy[k]; ok {
			body[k] = v
		}
	}
	body["allowRegister"] = false

	if err := c.doJSON(ctx, http.MethodPut, "/admin/v1/policies/login", body, nil); err != nil {
		return false, fmt.Errorf("EnsureRegistrationDisabled: PUT login policy: %w", err)
	}
	return true, nil
}
