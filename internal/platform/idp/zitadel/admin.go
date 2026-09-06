// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
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

	// DiscoveryURL is the in-cluster base URL the client dials for ALL
	// Zitadel HTTP traffic: OIDC discovery, the JWKS URL the discovery doc
	// points at, AND every Management API call (see apiBaseURL). When empty,
	// the client falls back to Issuer for all of these.
	//
	// The `iss` claim used in token validation is ALWAYS Issuer regardless
	// of this field — DiscoveryURL only affects the network path the daemon
	// uses. Use this knob when the issuer URL itself is externally-routable
	// but you also have an in-cluster path (e.g. via Envoy by Service FQDN)
	// that avoids egressing through DNS / a load balancer for daemon → IdP
	// traffic.
	//
	// WHY MANAGEMENT CALLS MUST FOLLOW THIS PATH TOO (gibson#1560): the
	// external Issuer host is fronted by the customer API gateway (Envoy's
	// jwt_authn + ext_authz chain). That gateway lets OIDC discovery, the
	// token exchange, and read-only searches through, but DENIES admin
	// writes such as human-user creation with a bare 403 — the daemon's
	// admin token carries the reserved `zitadel` project audience, not the
	// `gibson-platform` audience the gateway requires. The in-cluster Envoy
	// listener the daemon is meant to dial (gibson-envoy.<ns>.svc) proxies
	// the Zitadel Management API straight through with no ext_authz, so
	// admin writes must ride the DiscoveryURL path, not the Issuer path.
	// Sending discovery + token in-cluster but the actual API calls out to
	// the public gateway was the missing half of this split.
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
			// The management v1 users/_search row carries the user id as
			// `id`, NOT `userId` (verified against a live Zitadel: row keys
			// are id/userName/machine/…). Decoding `userId` silently yielded
			// "" for every row, so ListAgentIdentities built the principal id
			// as `agent_principal:` and the FGA tenant-scope intersection
			// dropped every identity — `gibson agent list` showed nothing
			// right after a successful enroll.
			UserID   string `json:"id"`
			UserName string `json:"userName"`
			Machine  *struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"machine"`
			Details *struct {
				CreatedAt string `json:"creationDate"`
			} `json:"details"`
			// creationDate also appears at the row's top level on some
			// Zitadel versions; keep reading it as the fallback.
			CreatedAt string `json:"creationDate"`
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

		created := r.CreatedAt
		if created == "" && r.Details != nil {
			created = r.Details.CreatedAt
		}
		var createdAt time.Time
		if created != "" {
			createdAt, _ = time.Parse(time.RFC3339, created)
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
// creates one. Maps to the Zitadel Management (v1) API:
//
//	POST /management/v1/users/human    (create)
//	POST /management/v1/users/_search  (search by email when it already exists)
//
// The Management API — not the v2 resource API (/v2/users…) — is used on
// purpose: it is the surface the platform's in-cluster Zitadel proxy exposes
// to the daemon (gibson#1560). The target org is selected by the
// x-zitadel-orgid header, so no `organization` block goes in the body.
//
// Idempotent: a 409 on create falls back to a by-email lookup. The created
// user has no password and an unverified email — Zitadel's init flow emails
// the invitee a code to set credentials.
func (c *Client) EnsureHumanUser(ctx context.Context, req idp.EnsureHumanUserRequest) (string, error) {
	if req.Email == "" {
		return "", fmt.Errorf("%w: EnsureHumanUser requires email", idp.ErrUpstream)
	}
	createBody := map[string]interface{}{
		"userName": req.Email,
		"profile":  map[string]interface{}{"firstName": "Invited", "lastName": "User"},
		"email":    map[string]interface{}{"email": req.Email, "isEmailVerified": false},
	}
	var createResp struct {
		UserID string `json:"userId"`
	}
	err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/human", createBody, req.OrgID, &createResp)
	if err == nil && createResp.UserID != "" {
		return createResp.UserID, nil
	}
	if err != nil && !errors.Is(mapError(err, "EnsureHumanUser:create"), idp.ErrAlreadyExists) {
		return "", mapError(err, "EnsureHumanUser:create")
	}
	// User already exists (409) — look it up by email. Same read-only search
	// FindUserIDByEmail performs; no credential write follows it here either.
	userID, serr := c.findUserIDByEmail(ctx, req.Email, req.OrgID)
	switch {
	case errors.Is(serr, idp.ErrNotFound):
		return "", fmt.Errorf("%w: EnsureHumanUser: user %q not found after conflict", idp.ErrUpstream, req.Email)
	case serr != nil:
		return "", serr
	}
	return userID, nil
}

// CreateHumanUser provisions a password-bearing human user for self-serve
// signup and for the self-hosted first-admin bootstrap. It issues exactly
// ONE upstream call:
//
//	POST /management/v1/users/human   (create with profile + email + initialPassword)
//
// SECURITY — create-only, never resume. An email conflict returns
// idp.ErrAlreadyExists and nothing else happens. There is deliberately no
// second call on that path.
//
// The previous shape resumed instead: on a 409 it searched for the existing
// user by email and reset that user's password to the value in the request.
// The credential in the request comes from whoever filled in the signup form,
// and the form does not establish that they are the account holder — so the
// resume branch let an unrelated request overwrite an existing account's
// password. Signup does not set credentials on accounts it did not just
// create; changing an existing account's password belongs to the IdP's own
// reset flow, which proves mailbox control first.
//
// Callers handle ErrAlreadyExists as a terminal outcome. In the signup path the
// duplicate address is disclosed only to the mailbox that owns it, never in the
// RPC response.
//
// The Management (v1) user API is used, not the v2 resource API: it is the
// surface the platform's in-cluster Zitadel proxy exposes to the daemon
// (gibson#1560). The target org is selected by the x-zitadel-orgid header, so
// no `organization` block goes in the body.
func (c *Client) CreateHumanUser(ctx context.Context, req idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
	if req.Email == "" {
		return idp.CreateHumanUserResult{}, fmt.Errorf("%w: CreateHumanUser requires email", idp.ErrUpstream)
	}
	if req.Password == "" {
		return idp.CreateHumanUserResult{}, fmt.Errorf("%w: CreateHumanUser requires password", idp.ErrUpstream)
	}

	createBody := map[string]interface{}{
		"userName": req.Email,
		"profile": map[string]interface{}{
			"firstName": req.GivenName,
			"lastName":  req.FamilyName,
		},
		"email": map[string]interface{}{
			"email":           req.Email,
			"isEmailVerified": req.EmailVerified,
		},
		"initialPassword": req.Password,
	}

	var createResp struct {
		UserID string `json:"userId"`
	}
	err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/human", createBody, req.OrgID, &createResp)
	if err == nil {
		if createResp.UserID == "" {
			return idp.CreateHumanUserResult{}, fmt.Errorf("%w: CreateHumanUser: response missing userId", idp.ErrUpstream)
		}
		return idp.CreateHumanUserResult{UserID: createResp.UserID}, nil
	}

	// Every failure, including a 409 email conflict, is returned as-is. The
	// conflict maps to idp.ErrAlreadyExists; no lookup and no credential write
	// follow it.
	return idp.CreateHumanUserResult{}, mapError(err, "CreateHumanUser:create")
}

// SetHumanPassword sets a known password on an existing human user (Zitadel
// Management POST /management/v1/users/{userId}/password). noChangeRequired is
// true: the self-hosted operator sets this credential for their OWN account and
// is told to rotate it after first login, so forcing a change on first sign-in
// would just be a second hoop. Used by the first-admin bootstrap to activate the
// founding-owner account the invitation flow created without a usable credential.
func (c *Client) SetHumanPassword(ctx context.Context, req idp.SetHumanPasswordRequest) error {
	if req.UserID == "" {
		return fmt.Errorf("%w: SetHumanPassword requires userId", idp.ErrUpstream)
	}
	if req.Password == "" {
		return fmt.Errorf("%w: SetHumanPassword requires password", idp.ErrUpstream)
	}
	body := map[string]interface{}{
		"password":         req.Password,
		"noChangeRequired": true,
	}
	path := "/management/v1/users/" + req.UserID + "/password"
	if err := c.doRequest(ctx, http.MethodPost, path, body, req.OrgID, nil); err != nil {
		return mapError(err, "SetHumanPassword")
	}
	return nil
}

// FindUserIDByEmail returns the id of the human user with the given email, or
// idp.ErrNotFound when there is none. Maps to POST /management/v1/users/_search.
//
// Read-only by construction: it is the search half of the old create-or-resume
// pair, with the password write dropped. Callers use it to decide what to put
// in an email — a verification link for an address with no account, an
// "account already exists" notice for one that has — never to decide whether
// to mutate an existing account.
func (c *Client) FindUserIDByEmail(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("%w: FindUserIDByEmail requires email", idp.ErrUpstream)
	}
	return c.findUserIDByEmail(ctx, email, c.cfg.OrgID)
}

// FindUserIDByEmailInOrg is FindUserIDByEmail scoped to an explicit org instead
// of the admin client's configured org. The founding-owner bootstrap creates
// the owner in the TENANT's org, not the daemon's admin org, so its re-run
// resolve MUST search that tenant org — searching c.cfg.OrgID returned
// idp.ErrNotFound and stranded every first-admin re-run and every post-upgrade
// hook (gibson#1560).
func (c *Client) FindUserIDByEmailInOrg(ctx context.Context, email, orgID string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("%w: FindUserIDByEmailInOrg requires email", idp.ErrUpstream)
	}
	if orgID == "" {
		return "", fmt.Errorf("%w: FindUserIDByEmailInOrg requires orgID", idp.ErrUpstream)
	}
	return c.findUserIDByEmail(ctx, email, orgID)
}

// findUserIDByEmail is the shared read-only by-email search. Returns
// idp.ErrNotFound on an empty result set.
func (c *Client) findUserIDByEmail(ctx context.Context, email, orgID string) (string, error) {
	searchBody := map[string]interface{}{
		"queries": []map[string]interface{}{
			{"emailQuery": map[string]interface{}{"emailAddress": email}},
		},
	}
	// The Management /users/_search row carries the user id as `id`, NOT
	// `userId` (the same field name ListServiceAccounts reads). Decoding
	// `userId` here silently yielded "" for every row.
	var searchResp struct {
		Result []struct {
			UserID string `json:"id"`
		} `json:"result"`
	}
	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/_search", searchBody, orgID, &searchResp); err != nil {
		return "", mapError(err, "FindUserIDByEmail")
	}
	if len(searchResp.Result) == 0 || searchResp.Result[0].UserID == "" {
		return "", idp.ErrNotFound
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

// sessionSearchResult is the subset of the Zitadel Session v2
// POST /v2/sessions/search response this package consumes. The full response
// carries factors, sequence, and metadata we do not need. userAgent is
// populated by the Login UI at session creation; for device-grant CLI logins
// that is the approving browser.
//
// NOTE (matches the RevokeUserSessions note above): the exact Session v2
// response shape must be confirmed against the deployed Zitadel version in the
// deploy auth-e2e smoke; the daemon has no live Zitadel in unit tests. Any
// field the IdP omits is left zero rather than failing the listing.
type sessionSearchResult struct {
	Sessions []struct {
		ID           string `json:"id"`
		CreationDate string `json:"creationDate"`
		ChangeDate   string `json:"changeDate"`
		UserAgent    struct {
			IP          string `json:"ip"`
			Description string `json:"description"`
		} `json:"userAgent"`
	} `json:"sessions"`
}

// parseTime parses an RFC3339 timestamp, returning the zero time on empty or
// unparseable input (a missing timestamp must not fail the listing).
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ListUserSessions returns the user's active Zitadel sessions with the metadata
// the IdP records. Maps to POST /v2/sessions/search filtered by user id.
func (c *Client) ListUserSessions(ctx context.Context, userID string) ([]idp.SessionInfo, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: ListUserSessions requires userID", idp.ErrUpstream)
	}
	searchBody := map[string]interface{}{
		"queries": []map[string]interface{}{
			{"userIdQuery": map[string]interface{}{"id": userID}},
		},
	}
	var resp sessionSearchResult
	if err := c.doRequest(ctx, http.MethodPost, "/v2/sessions/search", searchBody, "", &resp); err != nil {
		return nil, mapError(err, "ListUserSessions:search")
	}

	out := make([]idp.SessionInfo, 0, len(resp.Sessions))
	for _, s := range resp.Sessions {
		if s.ID == "" {
			continue
		}
		out = append(out, idp.SessionInfo{
			ID:           s.ID,
			IP:           s.UserAgent.IP,
			Browser:      s.UserAgent.Description,
			CreatedAt:    parseTime(s.CreationDate),
			LastActiveAt: parseTime(s.ChangeDate),
		})
	}
	return out, nil
}

// RevokeSession terminates a single Zitadel session by id. A 404 is treated as
// success (the session already expired). Maps to DELETE /v2/sessions/{id}.
func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("%w: RevokeSession requires sessionID", idp.ErrUpstream)
	}
	path := "/v2/sessions/" + url.PathEscape(sessionID)
	if err := c.doRequest(ctx, http.MethodDelete, path, nil, "", nil); err != nil {
		mapped := mapError(err, "RevokeSession:delete")
		if errors.Is(mapped, idp.ErrNotFound) {
			return nil
		}
		return mapped
	}
	return nil
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// apiBaseURL returns the base URL for Management API calls. It prefers
// DiscoveryURL (the in-cluster path) over Issuer for the reasons documented
// on Config.DiscoveryURL (gibson#1560): the external Issuer host is the
// ext_authz-gated public gateway, which 403s admin writes, whereas the
// in-cluster listener proxies the Management API straight to Zitadel. When
// DiscoveryURL is empty the client falls back to Issuer, preserving the
// single-host behaviour for deployments that do not split the path.
func (c *Client) apiBaseURL() string {
	base := c.cfg.DiscoveryURL
	if base == "" {
		base = c.cfg.Issuer
	}
	return strings.TrimRight(base, "/")
}

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

	reqURL := c.apiBaseURL() + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
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

// HumanPasswordChangedAt reports when the human user's password was last set,
// as Zitadel records it. A zero time means Zitadel holds no change timestamp:
// the password is still the one written when the user was created.
//
// This exists so the first-admin bootstrap can tell a SPENT initial credential
// from a live one. The credential Secret it writes is annotated "sign in,
// change it, then delete this Secret", and operators reliably do the first two
// and skip the third — leaving a Secret that reads as the admin password long
// after Zitadel stopped accepting it. Comparing this timestamp against the
// Secret's own creation time turns that into something the bootstrap can see.
//
// Read from the v2 user endpoint: the v1 Management row carries profile and
// email but not the credential timestamp.
func (c *Client) HumanPasswordChangedAt(ctx context.Context, userID string) (time.Time, error) {
	if userID == "" {
		return time.Time{}, fmt.Errorf("%w: HumanPasswordChangedAt requires userID", idp.ErrUpstream)
	}
	var resp struct {
		User struct {
			Human struct {
				PasswordChanged string `json:"passwordChanged"`
			} `json:"human"`
		} `json:"user"`
	}
	if err := c.doRequest(ctx, http.MethodGet, "/v2/users/"+userID, nil, c.cfg.OrgID, &resp); err != nil {
		return time.Time{}, mapError(err, "HumanPasswordChangedAt")
	}
	raw := resp.User.Human.PasswordChanged
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: parse passwordChanged %q: %w", idp.ErrUpstream, raw, err)
	}
	return t, nil
}
