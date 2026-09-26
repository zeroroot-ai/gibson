// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
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
	// (e.g. ["IAM_OWNER"]). Idempotent: if the user is already a member,
	// Zitadel's PUT on 409 REPLACES the member's role list with the given
	// roles — it is not a merge, confirmed against Zitadel's own API
	// documentation ("The whole roles list will be updated. Make sure to
	// include roles that you don't want to change (remove)."). Passing
	// the caller's full desired role set on every call therefore gives
	// exact-set semantics. Used to grant a machine user its declared
	// IAM-scoped roles.
	AddIAMMember(ctx context.Context, userID string, roles []string) error

	// RemoveIAMMember revokes the given user's IAM membership entirely
	// (DELETE /admin/v1/members/{userId}). Idempotent: 404 (never a
	// member, or already removed) is success. Used when a machine user's
	// declared role set has no IAM_-prefixed roles, so any role it
	// previously held is revoked rather than left in place.
	RemoveIAMMember(ctx context.Context, userID string) error

	// AddOrgMember adds the given user to the organization identified by
	// orgID with the given org-scoped roles (e.g. ["ORG_OWNER"]).
	// Idempotent: if the user is already an org member, Zitadel's PUT on
	// 409 REPLACES the member's role list (same exact-set semantics as
	// AddIAMMember). Org-scoped roles are distinct from IAM
	// (instance-scoped) roles — Zitadel routes them through
	// /management/v1/orgs/{orgID}/members rather than /admin/v1/members.
	// Used by the machine-user reconciler path to grant signup-style
	// bots their org roles.
	AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error

	// RemoveOrgMember revokes the given user's membership in orgID
	// entirely (DELETE /management/v1/orgs/{orgID}/members/{userId}).
	// Idempotent: 404 is success. Used when a machine user's declared
	// role set has no ORG_-prefixed roles.
	RemoveOrgMember(ctx context.Context, orgID, userID string) error

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

	// EnsureLoginPolicy makes the instance default login policy equal want.
	// It folds in what used to be the separate EnsureRegistrationDisabled
	// method (allowRegister is one of want's fields) — one codepath for the
	// instance login policy, not two that can race or disagree.
	//
	// Returns one short string per corrected item ("forceMfa",
	// "+SECOND_FACTOR_TYPE_U2F", "-SECOND_FACTOR_TYPE_OTP_SMS"), empty when
	// nothing changed. It never sends a no-op PUT, add or remove — Zitadel
	// rejects a no-op PUT with 400 (INSTANCE-5M9vdd, the deploy#886 wedge)
	// and a no-op add/remove with 409/not-found (MFA.AlreadyExists /
	// MFA.NotExisting), and either would put the reconciler into an
	// unrecoverable retry loop.
	EnsureLoginPolicy(ctx context.Context, want LoginPolicy) (corrected []string, err error)

	// EnsureDomainPolicy makes the instance default domain policy equal
	// want, echoing back the other live booleans (validateOrgDomains,
	// smtpSenderAddressMatchesInstanceDomain) so a PUT never resets them.
	// Idempotent: returns changed=false when already equal.
	EnsureDomainPolicy(ctx context.Context, want DomainPolicy) (changed bool, err error)

	// EnsureProjectRoles makes the project's role set exactly roles: it
	// adds a missing key, renames a key whose display name differs, and
	// removes a project role that is not declared (ADR-0093 decision 2,
	// owner decision D4). Removing a role cascades in Zitadel to every
	// project grant and user grant that named it. Idempotent: returns
	// changed=false when the project already holds exactly roles.
	EnsureProjectRoles(ctx context.Context, projectID string, roles []tenantrole.Def) (changed bool, err error)

	// --- Platform owner (ADR-0093 decision 6/8, hosted#201) ---------------

	// EnsureHumanUserNoPassword creates a human user in orgID with NO
	// password field on the request at all — Zitadel never mints or stores
	// one (ADR-0093: "no stored passwords"). email is marked verified on
	// creation so AddHumanUser does not also fire Zitadel's separate
	// email-verification-code flow; the invite-code flow
	// (CreateSetupInviteCode) is the platform's one setup-link mechanism.
	// Idempotent: on 409/already-exists, resolves the existing user's id via
	// FindHumanUserByEmail.
	//
	// Zitadel v4.18.0, Connect-protocol path (matches the fake in
	// zitadelconntest/identity.go): POST
	// /zitadel.user.v2.UserService/AddHumanUser.
	EnsureHumanUserNoPassword(ctx context.Context, orgID, email, givenName, familyName string) (userID string, err error)

	// FindHumanUserByEmail resolves a human user's id from their exact email
	// address across the instance. Returns ErrNotFound when no match.
	//
	// Zitadel v4.18.0: POST /zitadel.user.v2.UserService/ListUsers with an
	// emailQuery.
	FindHumanUserByEmail(ctx context.Context, email string) (userID string, err error)

	// CreateSetupInviteCode creates a one-time setup-link code for userID via
	// Zitadel's own invite-code flow. When send is true, Zitadel emails the
	// link built from urlTemplate and the returned code is empty. When send
	// is false, nothing is sent and the raw code is returned so the caller
	// can build the link itself — the offline-mode path (ADR-0093 decision
	// 8), which writes a one-time, expiring link to a Secret instead of
	// relying on mail. Creating a new code invalidates any code created
	// earlier for the same user (Zitadel's own documented behavior), which is
	// exactly what platformOwner.setupGeneration needs on a reset.
	//
	// urlTemplate is always supplied explicitly (Go template placeholders
	// {{.UserID}}, {{.OrgID}}, {{.Code}}) rather than relying on a Zitadel
	// default invite path, so the emitted link is the same shape whether
	// Zitadel sends it or the caller embeds it in the offline Secret.
	//
	// Zitadel v4.18.0: POST /zitadel.user.v2.UserService/CreateInviteCode.
	CreateSetupInviteCode(ctx context.Context, userID, urlTemplate string, send bool) (code string, err error)

	// ClearHumanFactors removes every second factor Zitadel has on file for
	// userID (TOTP and U2F/passkey — the only two the Platform owner's login
	// policy allows, ADR-0093 decision 9) so a subsequent
	// CreateSetupInviteCode forces a fresh enrollment. Used by
	// platformOwner.setupGeneration's reset path (ADR-0093 decision 12).
	// Idempotent: a user with no factors on file is a no-op.
	//
	// Zitadel v4.18.0: POST
	// /zitadel.user.v2.UserService/ListAuthenticationMethodTypes to
	// enumerate, then POST .../RemoveTOTP or .../RemoveU2F per entry.
	ClearHumanFactors(ctx context.Context, userID string) error
}

// LoginPolicy is the desired instance default login policy. EnsureLoginPolicy
// makes the live policy equal every field below — this is a full-replace PUT
// on the Zitadel side, so every field the operator cares about must be named
// here, not left to "whatever the instance happened to default to."
type LoginPolicy struct {
	AllowUsernamePassword bool
	AllowRegister         bool
	AllowExternalIDP      bool
	ForceMFA              bool
	ForceMFALocalOnly     bool
	PasswordlessAllowed   bool
	AllowDomainDiscovery  bool
	MFAInitSkipLifetime   time.Duration
	SecondFactors         []string // enum names, e.g. "SECOND_FACTOR_TYPE_OTP"
	MultiFactors          []string // enum names, e.g. "MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION"
}

// DomainPolicy is the desired instance default domain policy.
type DomainPolicy struct {
	UserLoginMustBeDomain bool
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
func (e *errClient) RemoveIAMMember(_ context.Context, _ string) error {
	return e.err
}
func (e *errClient) AddOrgMember(ctx context.Context, orgID, userID string, roles []string) error {
	return e.err
}
func (e *errClient) RemoveOrgMember(_ context.Context, _, _ string) error {
	return e.err
}
func (e *errClient) EnsureLoginPolicy(_ context.Context, _ LoginPolicy) ([]string, error) {
	return nil, e.err
}
func (e *errClient) EnsureDomainPolicy(_ context.Context, _ DomainPolicy) (bool, error) {
	return false, e.err
}
func (e *errClient) GetOrgIDForProject(ctx context.Context, projectID string) (string, error) {
	return "", e.err
}
func (e *errClient) EnsureProjectRoles(_ context.Context, _ string, _ []tenantrole.Def) (bool, error) {
	return false, e.err
}
func (e *errClient) EnsureHumanUserNoPassword(_ context.Context, _, _, _, _ string) (string, error) {
	return "", e.err
}
func (e *errClient) FindHumanUserByEmail(_ context.Context, _ string) (string, error) {
	return "", e.err
}
func (e *errClient) CreateSetupInviteCode(_ context.Context, _, _ string, _ bool) (string, error) {
	return "", e.err
}
func (e *errClient) ClearHumanFactors(_ context.Context, _ string) error {
	return e.err
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

// RemoveIAMMember implements Client.
//
// Zitadel v4: DELETE /admin/v1/members/{userId} revokes the user's IAM
// membership entirely. 404 (never a member) is treated as idempotent
// success per the Client interface's contract.
func (c *httpClient) RemoveIAMMember(ctx context.Context, userID string) error {
	path := "/admin/v1/members/" + url.PathEscape(userID)
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil)
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("RemoveIAMMember user=%s: %w", userID, err)
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

// RemoveOrgMember implements Client.
//
// Zitadel v4: DELETE /management/v1/orgs/{orgID}/members/{userId} revokes
// the user's org membership entirely. The x-zitadel-orgid header pins the
// request to orgID, mirroring AddOrgMember. 404 is idempotent success.
func (c *httpClient) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	if orgID == "" {
		return fmt.Errorf("RemoveOrgMember user=%s: empty orgID: %w", userID, ErrInvalidInput)
	}
	headers := map[string]string{"x-zitadel-orgid": orgID}
	path := fmt.Sprintf("/management/v1/orgs/%s/members/%s",
		url.PathEscape(orgID), url.PathEscape(userID))
	err := c.doJSONWithHeaders(ctx, http.MethodDelete, path, nil, nil, headers)
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("RemoveOrgMember org=%s user=%s: %w", orgID, userID, err)
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

// EnsureLoginPolicy implements Client.
//
// Zitadel v4: GET /admin/v1/policies/login returns the instance default
// login policy under `policy`. A PUT to the same path fully replaces the
// policy, so every field the operator cares about — not just the one it
// wants to flip — must be echoed back, or Zitadel silently resets it (e.g.
// zeroing an MFA lifetime). This folds in what used to be the standalone
// EnsureRegistrationDisabled (allowRegister is one of want's fields) and
// adds MFA enforcement, factor selection and external-IdP gating
// (ADR-0093 section 9).
//
// protojson drops false booleans, zero enums and empty lists from the GET
// response, so a MISSING key means false / the zero enum, never "unset."
// The idempotency checks below all treat a missing key that way. Getting
// this wrong wedges the reconciler: a PUT that changes nothing fails with
// 400 (INSTANCE-5M9vdd), which the caller classifies as transient and
// retries forever (deploy#886).
//
// second_factors and multi_factors are a different sub-resource
// (list/add/remove, not part of the policy body) — see syncFactors.
// Returns one short string per corrected item, empty when nothing changed.
func (c *httpClient) EnsureLoginPolicy(ctx context.Context, want LoginPolicy) ([]string, error) {
	var current struct {
		Policy map[string]any `json:"policy"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/admin/v1/policies/login", nil, &current); err != nil {
		return nil, fmt.Errorf("EnsureLoginPolicy: GET login policy: %w", err)
	}
	if current.Policy == nil {
		return nil, fmt.Errorf("EnsureLoginPolicy: empty login policy in response: %w", ErrPermanent)
	}

	body := make(map[string]any, len(updatableLoginPolicyFields))
	for _, k := range updatableLoginPolicyFields {
		if v, ok := current.Policy[k]; ok {
			body[k] = v
		}
	}

	var corrected []string
	setBool := func(key string, wantVal bool) {
		live, _ := current.Policy[key].(bool) // missing = false (protojson)
		if live != wantVal {
			corrected = append(corrected, key)
		}
		body[key] = wantVal
	}
	setBool("allowUsernamePassword", want.AllowUsernamePassword)
	setBool("allowRegister", want.AllowRegister)
	setBool("allowExternalIdp", want.AllowExternalIDP)
	setBool("forceMfa", want.ForceMFA)
	setBool("forceMfaLocalOnly", want.ForceMFALocalOnly)
	setBool("allowDomainDiscovery", want.AllowDomainDiscovery)

	wantPasswordless := "PASSWORDLESS_TYPE_NOT_ALLOWED"
	if want.PasswordlessAllowed {
		wantPasswordless = "PASSWORDLESS_TYPE_ALLOWED"
	}
	livePasswordless, _ := current.Policy["passwordlessType"].(string)
	if livePasswordless == "" {
		livePasswordless = "PASSWORDLESS_TYPE_NOT_ALLOWED" // missing = zero enum
	}
	if livePasswordless != wantPasswordless {
		corrected = append(corrected, "passwordlessType")
	}
	body["passwordlessType"] = wantPasswordless

	liveSkip := parseProtoDuration(current.Policy["mfaInitSkipLifetime"])
	if liveSkip != want.MFAInitSkipLifetime {
		corrected = append(corrected, "mfaInitSkipLifetime")
	}
	body["mfaInitSkipLifetime"] = protoDuration(want.MFAInitSkipLifetime)

	if len(corrected) > 0 {
		if err := c.doJSON(ctx, http.MethodPut, "/admin/v1/policies/login", body, nil); err != nil {
			return corrected, fmt.Errorf("EnsureLoginPolicy: PUT login policy: %w", err)
		}
	}

	secondCorrected, err := c.syncFactors(ctx, "second_factors", want.SecondFactors)
	corrected = append(corrected, secondCorrected...)
	if err != nil {
		return corrected, err
	}
	multiCorrected, err := c.syncFactors(ctx, "multi_factors", want.MultiFactors)
	corrected = append(corrected, multiCorrected...)
	if err != nil {
		return corrected, err
	}

	return corrected, nil
}

// syncFactors makes the live second_factors or multi_factors set (kind is
// "second_factors" or "multi_factors") equal want. Adds happen before
// removes, so the login policy is never left with zero factors while
// forceMfa is on. Returns "+TYPE" / "-TYPE" per correction.
func (c *httpClient) syncFactors(ctx context.Context, kind string, want []string) ([]string, error) {
	var resp struct {
		Result []string `json:"result"`
	}
	searchPath := fmt.Sprintf("/admin/v1/policies/login/%s/_search", kind)
	if err := c.doJSON(ctx, http.MethodPost, searchPath, map[string]any{}, &resp); err != nil {
		return nil, fmt.Errorf("EnsureLoginPolicy: list %s: %w", kind, err)
	}
	live := make(map[string]bool, len(resp.Result))
	for _, t := range resp.Result {
		live[t] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, t := range want {
		wantSet[t] = true
	}

	corrected := make([]string, 0, len(want)+len(resp.Result))
	for _, t := range want {
		if live[t] {
			continue
		}
		addPath := "/admin/v1/policies/login/" + kind
		if err := c.doJSON(ctx, http.MethodPost, addPath, map[string]any{"type": t}, nil); err != nil {
			return corrected, fmt.Errorf("EnsureLoginPolicy: add %s %s: %w", kind, t, err)
		}
		corrected = append(corrected, "+"+t)
	}
	for _, t := range resp.Result {
		if wantSet[t] {
			continue
		}
		delPath := fmt.Sprintf("/admin/v1/policies/login/%s/%s", kind, url.PathEscape(t))
		if err := c.doJSON(ctx, http.MethodDelete, delPath, nil, nil); err != nil {
			return corrected, fmt.Errorf("EnsureLoginPolicy: remove %s %s: %w", kind, t, err)
		}
		corrected = append(corrected, "-"+t)
	}
	return corrected, nil
}

// EnsureDomainPolicy implements Client. A missing userLoginMustBeDomain
// means false (protojson drops false booleans). Echoes back the other live
// booleans so a PUT never resets validateOrgDomains or
// smtpSenderAddressMatchesInstanceDomain.
func (c *httpClient) EnsureDomainPolicy(ctx context.Context, want DomainPolicy) (bool, error) {
	var current struct {
		Policy map[string]any `json:"policy"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/admin/v1/policies/domain", nil, &current); err != nil {
		return false, fmt.Errorf("EnsureDomainPolicy: GET domain policy: %w", err)
	}
	live, _ := current.Policy["userLoginMustBeDomain"].(bool)
	if live == want.UserLoginMustBeDomain {
		return false, nil
	}

	body := map[string]any{
		"userLoginMustBeDomain": want.UserLoginMustBeDomain,
	}
	if v, ok := current.Policy["validateOrgDomains"]; ok {
		body["validateOrgDomains"] = v
	}
	if v, ok := current.Policy["smtpSenderAddressMatchesInstanceDomain"]; ok {
		body["smtpSenderAddressMatchesInstanceDomain"] = v
	}
	if err := c.doJSON(ctx, http.MethodPut, "/admin/v1/policies/domain", body, nil); err != nil {
		return false, fmt.Errorf("EnsureDomainPolicy: PUT domain policy: %w", err)
	}
	return true, nil
}

// parseProtoDuration parses a protojson duration string (e.g. "2592000s",
// "0s"). A missing/unparseable value is zero, matching protojson's
// convention of dropping zero-valued fields from GET responses.
func parseProtoDuration(v any) time.Duration {
	s, _ := v.(string)
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// protoDuration renders d as the protojson duration string Zitadel expects
// (e.g. "0s", "2592000s").
func protoDuration(d time.Duration) string {
	return fmt.Sprintf("%ds", int64(d/time.Second))
}

// connectJSON posts a Connect unary JSON request to
// /<service>/<method> (e.g. "zitadel.project.v2.ProjectService",
// "ListProjectRoles"), the calling convention of Zitadel's v2 services:
// they have no REST (google.api.http) mapping, only Connect-over-HTTP.
// Error mapping reuses doJSON's HTTP-status switch: the Connect protocol
// answers failed_precondition and invalid_argument with 400,
// already_exists with 409 and not_found with 404, which already collapse
// onto this client's existing sentinels.
func (c *httpClient) connectJSON(ctx context.Context, service, method string, body, out any) error {
	return c.doJSON(ctx, http.MethodPost, "/"+service+"/"+method, body, out)
}

// EnsureProjectRoles implements Client.
//
// Lists the project's current roles (ListProjectRoles), then converges to
// exactly `roles`: AddProjectRole for a missing key, UpdateProjectRole for
// a key whose display name differs, and RemoveProjectRole for a key not in
// `roles` (owner decision D4). RemoveProjectRole cascades in Zitadel to
// every project grant and user grant that named the removed key.
func (c *httpClient) EnsureProjectRoles(ctx context.Context, projectID string, roles []tenantrole.Def) (bool, error) {
	const projectService = "zitadel.project.v2.ProjectService"

	var listResp struct {
		Roles []struct {
			RoleKey     string `json:"roleKey"`
			DisplayName string `json:"displayName"`
		} `json:"roles"`
	}
	if err := c.connectJSON(ctx, projectService, "ListProjectRoles", map[string]any{"projectId": projectID}, &listResp); err != nil {
		return false, fmt.Errorf("EnsureProjectRoles: ListProjectRoles project=%s: %w", projectID, err)
	}

	current := make(map[string]string, len(listResp.Roles))
	for _, r := range listResp.Roles {
		current[r.RoleKey] = r.DisplayName
	}
	want := make(map[string]string, len(roles))
	for _, d := range roles {
		want[string(d.Key)] = d.DisplayName
	}

	changed := false
	for _, d := range roles {
		displayName, exists := current[string(d.Key)]
		switch {
		case !exists:
			if err := c.connectJSON(ctx, projectService, "AddProjectRole", map[string]any{
				"projectId": projectID, "roleKey": string(d.Key), "displayName": d.DisplayName,
			}, nil); err != nil && !IsAlreadyExists(err) {
				return changed, fmt.Errorf("EnsureProjectRoles: AddProjectRole %s: %w", d.Key, err)
			}
			changed = true
		case displayName != d.DisplayName:
			if err := c.connectJSON(ctx, projectService, "UpdateProjectRole", map[string]any{
				"projectId": projectID, "roleKey": string(d.Key), "displayName": d.DisplayName,
			}, nil); err != nil {
				return changed, fmt.Errorf("EnsureProjectRoles: UpdateProjectRole %s: %w", d.Key, err)
			}
			changed = true
		}
	}
	for key := range current {
		if _, wanted := want[key]; wanted {
			continue
		}
		if err := c.connectJSON(ctx, projectService, "RemoveProjectRole", map[string]any{
			"projectId": projectID, "roleKey": key,
		}, nil); err != nil && !IsNotFound(err) {
			return changed, fmt.Errorf("EnsureProjectRoles: RemoveProjectRole %s: %w", key, err)
		}
		changed = true
	}
	return changed, nil
}

// --- Platform owner (ADR-0093 decision 6/8, hosted#201) --------------------
//
// These calls target Zitadel v2's UserService over connectJSON, the same
// Connect-protocol unary-over-HTTP convention EnsureProjectRoles above uses
// for the v2 ProjectService, and the one the fake in
// zitadelconn/zitadelconntest/identity.go serves. doJSON's existing
// status-code classification (404 -> ErrNotFound, 409 -> ErrAlreadyExists,
// 401/403 -> permanent ErrUnauthorized) applies unchanged: Zitadel's Connect
// JSON error body maps the same "already_exists" / "not_found" /
// "permission_denied" codes onto those same HTTP statuses.
const userService = "zitadel.user.v2.UserService"

// EnsureHumanUserNoPassword implements Client.
func (c *httpClient) EnsureHumanUserNoPassword(ctx context.Context, orgID, email, givenName, familyName string) (string, error) {
	body := map[string]any{
		"username":     email,
		"organization": map[string]any{"orgId": orgID},
		"profile": map[string]any{
			"givenName":  givenName,
			"familyName": familyName,
		},
		// isVerified: true — no separate email-verification-code flow;
		// CreateSetupInviteCode is the one setup-link mechanism this client
		// uses. No "password" field at all: Zitadel mints none (ADR-0093).
		"email": map[string]any{"email": email, "isVerified": true},
	}
	var resp struct {
		UserID string `json:"userId"`
	}
	err := c.connectJSON(ctx, userService, "AddHumanUser", body, &resp)
	if err != nil {
		if IsAlreadyExists(err) || IsConflict(err) {
			id, lerr := c.FindHumanUserByEmail(ctx, email)
			if lerr != nil {
				return "", fmt.Errorf("EnsureHumanUserNoPassword: conflict lookup: %w", lerr)
			}
			return id, nil
		}
		return "", fmt.Errorf("EnsureHumanUserNoPassword %q: %w", email, err)
	}
	return resp.UserID, nil
}

// FindHumanUserByEmail implements Client.
func (c *httpClient) FindHumanUserByEmail(ctx context.Context, email string) (string, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{"emailQuery": map[string]any{"email": email}},
		},
	}
	var resp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	if err := c.connectJSON(ctx, userService, "ListUsers", body, &resp); err != nil {
		return "", fmt.Errorf("FindHumanUserByEmail %q: %w", email, err)
	}
	if len(resp.Result) == 0 {
		return "", fmt.Errorf("FindHumanUserByEmail %q: %w", email, ErrNotFound)
	}
	return resp.Result[0].UserID, nil
}

// CreateSetupInviteCode implements Client.
func (c *httpClient) CreateSetupInviteCode(ctx context.Context, userID, urlTemplate string, send bool) (string, error) {
	body := map[string]any{"userId": userID}
	if send {
		body["sendCode"] = map[string]any{"urlTemplate": urlTemplate}
	} else {
		body["returnCode"] = map[string]any{}
	}
	var resp struct {
		InviteCode string `json:"inviteCode"`
	}
	if err := c.connectJSON(ctx, userService, "CreateInviteCode", body, &resp); err != nil {
		return "", fmt.Errorf("CreateSetupInviteCode user=%s: %w", userID, err)
	}
	return resp.InviteCode, nil
}

// authMethodTOTP / authMethodU2F / authMethodPasskey are the entries
// ListAuthenticationMethodTypes reports.
const (
	authMethodTOTP    = "AUTHENTICATION_METHOD_TYPE_TOTP"
	authMethodU2F     = "AUTHENTICATION_METHOD_TYPE_U2F"
	authMethodPasskey = "AUTHENTICATION_METHOD_TYPE_PASSKEY"
)

// ClearHumanFactors implements Client.
func (c *httpClient) ClearHumanFactors(ctx context.Context, userID string) error {
	var listResp struct {
		AuthMethodTypes []string `json:"authMethodTypes"`
	}
	listBody := map[string]any{"userId": userID}
	if err := c.connectJSON(ctx, userService, "ListAuthenticationMethodTypes", listBody, &listResp); err != nil {
		return fmt.Errorf("ClearHumanFactors: list user=%s: %w", userID, err)
	}
	for _, t := range listResp.AuthMethodTypes {
		switch t {
		case authMethodTOTP:
			if err := c.connectJSON(ctx, userService, "RemoveTOTP", map[string]any{"userId": userID}, nil); err != nil && !IsNotFound(err) {
				return fmt.Errorf("ClearHumanFactors: RemoveTOTP user=%s: %w", userID, err)
			}
		case authMethodU2F:
			if err := c.removeAllCredentials(ctx, userID, "ListU2F", "RemoveU2F", "u2fId"); err != nil {
				return fmt.Errorf("ClearHumanFactors: %w", err)
			}
		case authMethodPasskey:
			if err := c.removeAllCredentials(ctx, userID, "ListPasskeys", "RemovePasskey", "passkeyId"); err != nil {
				return fmt.Errorf("ClearHumanFactors: %w", err)
			}
		}
	}
	return nil
}

// removeAllCredentials lists a per-credential factor (U2F or passkey — both
// can have more than one registered device) via the named ListX v2 call and
// removes each one via the named RemoveX call, keyed by idField. Idempotent:
// an empty list is a no-op.
func (c *httpClient) removeAllCredentials(ctx context.Context, userID, listMethod, removeMethod, idField string) error {
	var listResp struct {
		Result []map[string]any `json:"result"`
	}
	listBody := map[string]any{"userId": userID}
	if err := c.connectJSON(ctx, userService, listMethod, listBody, &listResp); err != nil {
		return fmt.Errorf("%s user=%s: %w", listMethod, userID, err)
	}
	for _, cred := range listResp.Result {
		id, _ := cred[idField].(string)
		if id == "" {
			continue
		}
		removeBody := map[string]any{"userId": userID, idField: id}
		if err := c.connectJSON(ctx, userService, removeMethod, removeBody, nil); err != nil && !IsNotFound(err) {
			return fmt.Errorf("%s user=%s %s=%s: %w", removeMethod, userID, idField, id, err)
		}
	}
	return nil
}
