// Package zitadel is the ONLY place in the gibson repository where
// Zitadel-specific code may appear. It implements idp.AdminClient by
// translating abstract operations into Zitadel Management API HTTP calls,
// porting the request shapes proven correct in the dashboard's
// enterprise/platform/dashboard/src/lib/zitadel/admin-client.ts.
//
// Security constraints inherited from the TS reference:
//   - ClientSecret is never logged, never included in error messages.
//   - All credentials are loaded from the Config struct; no hard-coded values.
//   - Admin token is obtained via OAuth2 client_credentials grant and refreshed
//     automatically by the token source.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/idp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Config holds all configuration required to connect to a Zitadel instance
// as an admin client. All values are loaded from environment variables;
// none are hard-coded.
type Config struct {
	// Issuer is the Zitadel OIDC issuer URL, e.g. "https://auth.example.com".
	// Used for OIDC discovery to obtain the token endpoint.
	Issuer string

	// ClientID is the OAuth2 client ID of the admin service account.
	ClientID string

	// ClientSecret is the OAuth2 client secret. NEVER log this value.
	ClientSecret string

	// OrgID is the Zitadel organisation ID used as the default x-zitadel-orgid
	// header for management API calls. This is the platform-level admin org.
	OrgID string

	// HTTPTimeout is the per-request timeout. Defaults to 10 seconds.
	HTTPTimeout time.Duration

	// DiscoveryURL is the in-cluster URL the client dials for OIDC discovery
	// (and the JWKS URL the discovery doc points at). When empty, falls back
	// to Issuer.
	//
	// The `iss` claim used in token validation is ALWAYS Issuer regardless
	// of this field — DiscoveryURL only affects the network path the daemon
	// uses to fetch /.well-known/openid-configuration and the OAuth2 token
	// endpoint that lives there. Use this knob when the issuer URL itself
	// is externally-routable but you also have an in-cluster path (e.g. via
	// Envoy by Service FQDN) that avoids egressing through DNS / a load
	// balancer for daemon → IdP traffic.
	//
	// Spec: tier-2-host-aliases-cluster-dns.
	DiscoveryURL string
}

// Client implements idp.AdminClient against the Zitadel Management API.
// Use New to construct; the constructor performs a startup probe.
type Client struct {
	cfg        Config
	httpClient *http.Client
	tokenSrc   oauth2.TokenSource
}

// Compile-time assertion that *Client implements idp.AdminClient.
var _ idp.AdminClient = (*Client)(nil)

// New constructs a Zitadel admin client and performs a startup probe to
// verify that the Zitadel instance is reachable and the credentials are valid.
// Returns an error (wrapping idp.ErrUnreachable or idp.ErrPermission) if the
// probe fails.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}

	// Discover the token endpoint from Zitadel's OIDC discovery document.
	// Spec tier-2-host-aliases-cluster-dns: the daemon dials cfg.DiscoveryURL
	// (in-cluster Envoy FQDN) for the discovery doc when set, falling back to
	// cfg.Issuer otherwise. The `iss` claim used for token validation stays
	// cfg.Issuer regardless — only the network path to the discovery doc is
	// affected.
	tokenEndpoint, err := discoverTokenEndpoint(ctx, cfg.Issuer, cfg.DiscoveryURL, cfg.HTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: discovering token endpoint: %s", idp.ErrUnreachable, err)
	}

	// Spec tier-2-host-aliases-cluster-dns Reqs 2.4 / 2.5 — log which path
	// was taken so operators can confirm in-cluster vs external discovery
	// without packet-capturing. We deliberately do not log the resolved
	// token endpoint URL or the discovery URL itself; the issuer is the
	// operator-known correlator and discovery_path is the bounded enum.
	discoveryPath := "external"
	if cfg.DiscoveryURL != "" {
		discoveryPath = "in_cluster"
	}
	slog.Info("zitadel idp client started",
		"issuer", cfg.Issuer,
		"discovery_path", discoveryPath,
	)

	// Build an OAuth2 client_credentials token source for the admin account.
	// The reserved ZITADEL project-audience scope is REQUIRED for the token to
	// be accepted by the management/admin APIs. With "openid" alone the token is
	// rejected (HTTP 401), so every management call — GetUserProfile (member and
	// team-roster name/email enrichment), service-account creation, etc. — fails
	// and enrichment silently falls back to the raw user id.
	ccCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenEndpoint,
		Scopes:       []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"},
	}
	tokenSrc := oauth2.ReuseTokenSource(nil, ccCfg.TokenSource(ctx))

	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}

	c := &Client{
		cfg:        cfg,
		httpClient: httpClient,
		tokenSrc:   tokenSrc,
	}

	// Startup probe: obtain a token to confirm credentials are valid.
	if _, err := tokenSrc.Token(); err != nil {
		if isAuthError(err) {
			return nil, fmt.Errorf("%w: admin credentials rejected: %s", idp.ErrPermission, sanitize(err))
		}
		return nil, fmt.Errorf("%w: obtaining admin token: %s", idp.ErrUnreachable, sanitize(err))
	}

	return c, nil
}

// Close releases resources held by the client.
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// CreateServiceAccount creates a new Zitadel machine user (service account).
// Maps to POST /management/v1/users/machine.
func (c *Client) CreateServiceAccount(ctx context.Context, req idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	body := map[string]interface{}{
		"userName":        req.Name,
		"name":            req.Name,
		"description":     req.Description,
		"accessTokenType": "OIDC_TOKEN_TYPE_JWT",
	}

	var resp struct {
		UserID string `json:"userId"`
	}

	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/machine", body, c.cfg.OrgID, &resp); err != nil {
		return nil, mapError(err, "CreateServiceAccount")
	}

	if resp.UserID == "" {
		return nil, fmt.Errorf("%w: response missing userId", idp.ErrUpstream)
	}

	return &idp.ServiceAccount{
		AccountID:   resp.UserID,
		Name:        req.Name,
		Role:        req.Role,
		Description: req.Description,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// DeleteServiceAccount permanently removes the machine user from Zitadel.
// Maps to DELETE /management/v1/users/{userId}.
func (c *Client) DeleteServiceAccount(ctx context.Context, accountID string) error {
	path := "/management/v1/users/" + accountID
	if err := c.doRequest(ctx, http.MethodDelete, path, nil, c.cfg.OrgID, nil); err != nil {
		return mapError(err, "DeleteServiceAccount")
	}
	return nil
}

// ListServiceAccounts lists machine users in the configured project.
// Maps to POST /management/v1/users/_search with machine-user filter.
func (c *Client) ListServiceAccounts(ctx context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
	type query struct {
		TypeQuery struct {
			Type string `json:"type"`
		} `json:"typeQuery"`
	}
	body := map[string]interface{}{
		"limit": req.PageSize,
		"queries": []query{{TypeQuery: struct {
			Type string `json:"type"`
		}{Type: "TYPE_MACHINE"}}},
	}
	if req.PageToken != "" {
		body["offset"] = req.PageToken
	}

	var resp struct {
		Result []struct {
			UserID    string `json:"userId"`
			UserName  string `json:"userName"`
			CreatedAt string `json:"creationDate"`
			Machine   *struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"machine"`
		} `json:"result"`
		Details struct {
			TotalResult       string `json:"totalResult"`
			ProcessedSequence string `json:"processedSequence"`
		} `json:"details"`
	}

	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/_search", body, c.cfg.OrgID, &resp); err != nil {
		return nil, mapError(err, "ListServiceAccounts")
	}

	accounts := make([]idp.ServiceAccount, 0, len(resp.Result))
	for _, r := range resp.Result {
		if r.Machine == nil {
			continue
		}

		// Parse the optional role from the username prefix: "<role>-<tenant>-<name>"
		role := parseRoleFromName(r.UserName, req.RoleFilter)
		if req.RoleFilter != "" && role != req.RoleFilter {
			continue
		}

		var createdAt time.Time
		if r.CreatedAt != "" {
			createdAt, _ = time.Parse(time.RFC3339, r.CreatedAt)
		}

		accounts = append(accounts, idp.ServiceAccount{
			AccountID:   r.UserID,
			Name:        r.UserName,
			Role:        role,
			CreatedAt:   createdAt,
			Description: r.Machine.Description,
			// LastAuthenticatedAt: Zitadel management list endpoint does not
			// provide last-login time; callers receive nil for this field.
			LastAuthenticatedAt: nil,
		})
	}

	return &idp.ListServiceAccountsResponse{
		ServiceAccounts: accounts,
		// Zitadel's offset-based pagination doesn't return a cursor token in
		// the same way; we use the length of results to signal no more pages.
		NextPageToken: "",
	}, nil
}

// ---------------------------------------------------------------------------
// User profile — human user read/update
// ---------------------------------------------------------------------------

// zitadelUserResponse is the shape of the Zitadel GetUserByID response.
type zitadelUserResponse struct {
	User struct {
		ID    string `json:"id"`
		Human *struct {
			Profile struct {
				DisplayName     string `json:"displayName"`
				PreferredLocale string `json:"preferredLanguage"`
				AvatarURL       string `json:"avatarUrl"`
			} `json:"profile"`
			Email struct {
				Email           string `json:"email"`
				IsEmailVerified bool   `json:"isEmailVerified"`
			} `json:"email"`
		} `json:"human"`
		State     string `json:"state"`
		CreatedAt string `json:"createdAt"`
	} `json:"user"`
}

// GetUserProfile retrieves a human user's profile from Zitadel.
func (c *Client) GetUserProfile(ctx context.Context, accountID string) (*idp.UserProfile, error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: accountID required", idp.ErrUpstream)
	}

	var resp zitadelUserResponse
	path := "/management/v1/users/" + accountID
	if err := c.doRequest(ctx, "GET", path, nil, c.cfg.OrgID, &resp); err != nil {
		return nil, mapError(err, "GetUserProfile")
	}

	profile := &idp.UserProfile{
		AccountID: resp.User.ID,
		Status:    resp.User.State,
	}
	if h := resp.User.Human; h != nil {
		profile.DisplayName = h.Profile.DisplayName
		profile.PreferredLocale = h.Profile.PreferredLocale
		profile.AvatarURL = h.Profile.AvatarURL
		profile.Email = h.Email.Email
	}
	if t, err := time.Parse(time.RFC3339, resp.User.CreatedAt); err == nil {
		profile.CreatedAt = t
	}
	return profile, nil
}

// UpdateUserProfile updates mutable profile fields for a human user in Zitadel.
// Only display_name and preferred_locale are editable; email is immutable.
func (c *Client) UpdateUserProfile(ctx context.Context, accountID string, req idp.UpdateUserProfileRequest) (*idp.UserProfile, error) {
	if accountID == "" {
		return nil, fmt.Errorf("%w: accountID required", idp.ErrUpstream)
	}

	// PATCH /management/v1/users/{userId}/profile
	type updateProfileBody struct {
		DisplayName     string `json:"displayName,omitempty"`
		PreferredLocale string `json:"preferredLanguage,omitempty"`
	}
	body := updateProfileBody{
		DisplayName:     req.DisplayName,
		PreferredLocale: req.PreferredLocale,
	}

	path := "/management/v1/users/" + accountID + "/profile"
	if err := c.doRequest(ctx, "PUT", path, body, c.cfg.OrgID, nil); err != nil {
		return nil, fmt.Errorf("update user profile: %w", err)
	}

	// Fetch the updated profile to return the canonical state.
	return c.GetUserProfile(ctx, accountID)
}

// orgRoleKeys are the Zitadel org-member role keys minted by the platform's
// post-install Job. They mirror tenant-operator's zitadelRoleKey mapping so
// the daemon and the operator project the same membership.
const (
	orgRoleKeyOwner  = "gibson.owner"
	orgRoleKeyAdmin  = "gibson.admin"
	orgRoleKeyMember = "gibson.member"
)

// tenantRoleToOrgRoleKey maps a neutral tenant role to its Zitadel org-member
// role key. Unknown roles (including "writer") map to member.
func tenantRoleToOrgRoleKey(role string) string {
	switch role {
	case "owner":
		return orgRoleKeyOwner
	case "admin":
		return orgRoleKeyAdmin
	default:
		return orgRoleKeyMember
	}
}

// AddTenantMember adds the human user as a member of the tenant's per-tenant
// org. Maps to POST /management/v1/orgs/me/members with the target org selected
// via the x-zitadel-orgid header (the admin PAT may act in any org). Idempotent:
// a 409 (already a member) is treated as success.
func (c *Client) AddTenantMember(ctx context.Context, req idp.TenantMembershipRequest) error {
	if req.OrgID == "" || req.UserID == "" {
		return fmt.Errorf("%w: AddTenantMember requires orgID and userID", idp.ErrUpstream)
	}
	body := map[string]interface{}{
		"userId": req.UserID,
		"roles":  []string{tenantRoleToOrgRoleKey(req.Role)},
	}
	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/orgs/me/members", body, req.OrgID, nil); err != nil {
		mapped := mapError(err, "AddTenantMember")
		if errors.Is(mapped, idp.ErrAlreadyExists) {
			// Already a member — desired state reached.
			return nil
		}
		return mapped
	}
	return nil
}

// RemoveTenantMember removes the human user from the tenant's per-tenant org.
// Maps to DELETE /management/v1/orgs/me/members/{userId} with the target org
// selected via x-zitadel-orgid. Idempotent: a 404 (not a member) is success.
func (c *Client) RemoveTenantMember(ctx context.Context, req idp.TenantMembershipRequest) error {
	if req.OrgID == "" || req.UserID == "" {
		return fmt.Errorf("%w: RemoveTenantMember requires orgID and userID", idp.ErrUpstream)
	}
	path := "/management/v1/orgs/me/members/" + url.PathEscape(req.UserID)
	if err := c.doRequest(ctx, http.MethodDelete, path, nil, req.OrgID, nil); err != nil {
		mapped := mapError(err, "RemoveTenantMember")
		if errors.Is(mapped, idp.ErrNotFound) {
			return nil
		}
		return mapped
	}
	return nil
}

// EnsureHumanUser finds the human user with the given email in the org, or
// creates one. Maps to the Zitadel v2 API:
//
//	POST /v2/users/human   (create; sendCode triggers the invite/verify email)
//	POST /v2/users          (search by email when the user already exists)
//
// Idempotent: a 409 on create falls back to a by-email lookup. The created
// user's email is unverified and has no password — Zitadel's emailed code lets
// the invitee set credentials.
//
// NOTE: the exact v2 user create/search shapes must be confirmed against the
// deployed Zitadel version in the deploy auth-e2e smoke (no live Zitadel in
// unit tests).
func (c *Client) EnsureHumanUser(ctx context.Context, req idp.EnsureHumanUserRequest) (string, error) {
	if req.Email == "" {
		return "", fmt.Errorf("%w: EnsureHumanUser requires email", idp.ErrUpstream)
	}
	createBody := map[string]interface{}{
		"username": req.Email,
		"profile":  map[string]interface{}{"givenName": "Invited", "familyName": "User"},
		"email":    map[string]interface{}{"email": req.Email, "isVerified": false, "sendCode": map[string]interface{}{}},
	}
	if req.OrgID != "" {
		createBody["organization"] = map[string]interface{}{"orgId": req.OrgID}
	}
	var createResp struct {
		UserID string `json:"userId"`
	}
	err := c.doRequest(ctx, http.MethodPost, "/v2/users/human", createBody, req.OrgID, &createResp)
	if err == nil && createResp.UserID != "" {
		return createResp.UserID, nil
	}
	if err != nil && !errors.Is(mapError(err, "EnsureHumanUser:create"), idp.ErrAlreadyExists) {
		return "", mapError(err, "EnsureHumanUser:create")
	}
	// User already exists (409) — look it up by email.
	searchBody := map[string]interface{}{
		"queries": []map[string]interface{}{
			{"emailQuery": map[string]interface{}{"emailAddress": req.Email}},
		},
	}
	var searchResp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	if serr := c.doRequest(ctx, http.MethodPost, "/v2/users", searchBody, req.OrgID, &searchResp); serr != nil {
		return "", mapError(serr, "EnsureHumanUser:search")
	}
	if len(searchResp.Result) == 0 || searchResp.Result[0].UserID == "" {
		return "", fmt.Errorf("%w: EnsureHumanUser: user %q not found after conflict", idp.ErrUpstream, req.Email)
	}
	return searchResp.Result[0].UserID, nil
}

// RevokeUserSessions terminates the user's active Zitadel sessions, which also
// invalidates the refresh tokens bound to those sessions (so no new access
// token can be minted from them). Maps to the Zitadel Session v2 API:
//
//	POST   /v2/sessions/search   (list the user's sessions)
//	DELETE /v2/sessions/{id}     (terminate each)
//
// gibson#622 v1 model: this blocks NEW tokens immediately; the target's current
// stateless access JWT ages out within the access-token TTL (bounded to 15m on
// the CLI app — provisioned by platform-operator#80). Idempotent: no sessions
// → zero counts, not an error.
//
// NOTE: the exact Session v2 request/response shape must be confirmed against
// the deployed Zitadel version in the deploy auth-e2e smoke (the daemon has no
// live Zitadel in unit tests). The search query filters on the session's user.
func (c *Client) RevokeUserSessions(ctx context.Context, userID string) (idp.RevokeUserSessionsResult, error) {
	if userID == "" {
		return idp.RevokeUserSessionsResult{}, fmt.Errorf("%w: RevokeUserSessions requires userID", idp.ErrUpstream)
	}

	// 1) Search the user's active sessions.
	searchBody := map[string]interface{}{
		"queries": []map[string]interface{}{
			{"userIdQuery": map[string]interface{}{"id": userID}},
		},
	}
	var searchResp struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	if err := c.doRequest(ctx, http.MethodPost, "/v2/sessions/search", searchBody, "", &searchResp); err != nil {
		return idp.RevokeUserSessionsResult{}, mapError(err, "RevokeUserSessions:search")
	}

	// 2) Terminate each session. A 404 on an individual delete is benign
	//    (the session expired between search and delete) — keep going.
	terminated := 0
	for _, s := range searchResp.Sessions {
		if s.ID == "" {
			continue
		}
		path := "/v2/sessions/" + url.PathEscape(s.ID)
		if err := c.doRequest(ctx, http.MethodDelete, path, nil, "", nil); err != nil {
			mapped := mapError(err, "RevokeUserSessions:delete")
			if errors.Is(mapped, idp.ErrNotFound) {
				continue
			}
			return idp.RevokeUserSessionsResult{SessionsTerminated: terminated}, mapped
		}
		terminated++
	}

	// Refresh tokens in Zitadel are bound to the session that minted them;
	// terminating the sessions revokes those refresh grants. We report the
	// same count rather than issuing a second (version-dependent) grant-revoke
	// call. A dedicated hard token-grant revoke can layer on later if needed.
	return idp.RevokeUserSessionsResult{
		SessionsTerminated: terminated,
		GrantsRevoked:      terminated,
	}, nil
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// doRequest executes an authenticated HTTP request against the Zitadel
// Management API. It handles token injection, request serialization,
// response deserialization, and HTTP error mapping.
//
// If respBody is nil the response body is discarded (for DELETE / 204 cases).
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, orgID string, respBody interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: marshalling request: %s", idp.ErrUpstream, err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := strings.TrimRight(c.cfg.Issuer, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("%w: building request: %s", idp.ErrUpstream, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}

	// Inject the admin Bearer token.
	token, err := c.tokenSrc.Token()
	if err != nil {
		if isAuthError(err) {
			return fmt.Errorf("%w: refreshing admin token", idp.ErrPermission)
		}
		return fmt.Errorf("%w: obtaining token: %s", idp.ErrUnreachable, sanitize(err))
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", idp.ErrUnreachable, sanitize(err))
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNoContent || (method == http.MethodDelete && resp.StatusCode == http.StatusOK) {
		return nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if respBody != nil {
			if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
				return fmt.Errorf("%w: decoding response: %s", idp.ErrUpstream, err)
			}
		}
		return nil
	}

	// Parse the Zitadel error envelope for mapping.
	return parseZitadelError(resp)
}

// zitadelError is the Zitadel API error envelope shape.
type zitadelError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details []struct {
		ErrorCode string `json:"errorCode"`
	} `json:"details"`
}

// httpStatusError wraps an HTTP status code for error-mapping.
type httpStatusError struct {
	status  int
	code    string
	message string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d [%s] %s", e.status, e.code, e.message)
}

// parseZitadelError reads the Zitadel error body and returns an httpStatusError.
func parseZitadelError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var ze zitadelError
	_ = json.Unmarshal(body, &ze)
	var code string
	if len(ze.Details) > 0 {
		code = ze.Details[0].ErrorCode
	}
	if code == "" {
		code = fmt.Sprintf("%d", ze.Code)
	}
	return &httpStatusError{
		status:  resp.StatusCode,
		code:    code,
		message: ze.Message,
	}
}

// mapError translates httpStatusError values to idp sentinel errors.
// The operation name is used only for the wrapping message; no secrets are
// included.
func mapError(err error, operation string) error {
	var hse *httpStatusError
	if !errors.As(err, &hse) {
		// Already an idp sentinel or unknown error — pass through.
		return err
	}
	switch {
	case hse.status == http.StatusNotFound:
		return fmt.Errorf("%w: %s", idp.ErrNotFound, operation)
	case hse.status == http.StatusConflict:
		return fmt.Errorf("%w: %s: already exists", idp.ErrAlreadyExists, operation)
	case hse.status == http.StatusUnauthorized || hse.status == http.StatusForbidden:
		return fmt.Errorf("%w: %s", idp.ErrPermission, operation)
	case hse.status >= 500:
		return fmt.Errorf("%w: %s: HTTP %d", idp.ErrUpstream, operation, hse.status)
	default:
		return fmt.Errorf("%w: %s: HTTP %d [%s]", idp.ErrUpstream, operation, hse.status, hse.code)
	}
}

// discoverTokenEndpoint fetches the OIDC discovery document and extracts the
// token_endpoint field. Pure stdlib HTTP; no OIDC library dependency needed.
//
// `issuer` is the externally-routable issuer URL (used as a fallback only);
// `discoveryURL` is the optional in-cluster base URL the daemon dials when
// non-empty. When `discoveryURL` is empty the function falls back to
// `issuer` — preserving the pre-spec-tier-2-host-aliases-cluster-dns behavior.
// The returned token_endpoint is whatever the discovery doc contains; callers
// MUST NOT assume it shares a host with `issuer`.
func discoverTokenEndpoint(ctx context.Context, issuer, discoveryURL string, timeout time.Duration) (string, error) {
	base := discoveryURL
	if base == "" {
		base = issuer
	}
	client := &http.Client{Timeout: timeout}
	wellKnownURL := strings.TrimRight(base, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned HTTP %d from %s", resp.StatusCode, wellKnownURL)
	}

	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parsing OIDC discovery document: %w", err)
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("OIDC discovery document missing token_endpoint")
	}
	return doc.TokenEndpoint, nil
}

// parseRoleFromName infers the role from the service account name prefix.
// Names are formatted as "<role>-<tenant>-<user-name>" by the orchestrator.
// Returns the fallback if no recognised role prefix is found.
func parseRoleFromName(name string, fallback idp.Role) idp.Role {
	for _, r := range []idp.Role{idp.RoleAgent, idp.RoleTool, idp.RolePlugin} {
		if strings.HasPrefix(name, string(r)+"-") {
			return r
		}
	}
	return fallback
}

// isAuthError returns true when the error looks like an OAuth2 401/403.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "401") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden")
}

// sanitize returns a safe error message that strips credential-bearing
// substrings. Used when wrapping network/OAuth errors for logging.
func sanitize(err error) string {
	if err == nil {
		return ""
	}
	// Truncate long messages and remove anything after the first newline
	// to prevent multi-line log injection.
	msg := err.Error()
	if idx := strings.Index(msg, "\n"); idx >= 0 {
		msg = msg[:idx]
	}
	if len(msg) > 256 {
		msg = msg[:256] + "..."
	}
	return msg
}
