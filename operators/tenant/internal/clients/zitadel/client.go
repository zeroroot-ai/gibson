// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package zitadel is the operator's client to the Zitadel Management API for
// provisioning per-tenant organizations and user memberships. Auth uses a
// Personal Access Token (PAT) mounted into the operator from the
// <release>-zitadel-iam-admin-pat Secret.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// Client is the Zitadel Management API interface. All mutating operations are
// idempotent: callers may safely retry; 409/already-exists responses are
// treated as success.
type Client interface {
	// CreateOrganization creates a Zitadel organization with the given name
	// and slug. Returns the Zitadel org ID. Idempotent: if an org with the
	// same name already exists, returns the existing org's ID.
	CreateOrganization(ctx context.Context, name, slug string) (orgID string, err error)

	// GetOrganization fetches an organization by its Zitadel org ID.
	GetOrganization(ctx context.Context, orgID string) (org *Organization, err error)

	// DeleteOrganization removes the Zitadel organization. Idempotent: 404 is
	// treated as success (already gone).
	DeleteOrganization(ctx context.Context, orgID string) error

	// AddMember adds a Zitadel user to an organization with the given roles.
	// Returns the membership ID. Idempotent: existing membership is returned.
	AddMember(ctx context.Context, orgID, userID string, roles []string) (membershipID string, err error)

	// RemoveMember removes a Zitadel user from an organization. Idempotent:
	// 404 is treated as success.
	RemoveMember(ctx context.Context, orgID, userID string) error

	// SendInvitation dispatches an invitation email to the given address and
	// adds the user to the organization with the specified roles. Returns the
	// Zitadel invitation/human user ID.
	SendInvitation(ctx context.Context, orgID, email string, roles []string) (invitationID string, err error)

	// CreateServiceAccount creates a Zitadel machine user (service account)
	// scoped to orgID with the given display name. Returns the stable
	// accountID (used with DeleteServiceAccount). clientID and clientSecret
	// are the OAuth2 client credentials for the account; clientSecret is
	// returned exactly once and must be stored by the caller immediately.
	// Idempotent: if a machine user with the same name already exists in the
	// org, the existing accountID and clientID are returned and clientSecret
	// is empty (the caller cannot retrieve the secret again).
	CreateServiceAccount(ctx context.Context, orgID, name string) (accountID, clientID, clientSecret string, err error)

	// DeleteServiceAccount removes the service account identified by accountID
	// from the given org. Idempotent: 404 is treated as success.
	DeleteServiceAccount(ctx context.Context, orgID, accountID string) error
}

// Organization represents a Zitadel organization.
type Organization struct {
	ID   string
	Name string
	Slug string
}

// httpClient implements Client against the Zitadel Management REST API v1.
type httpClient struct {
	baseURL *url.URL
	pat     string
	// externalDomain is forged onto the HTTP Host header on every request.
	// Zitadel routes to the correct instance by matching Host against its
	// registered ExternalDomain — when the operator calls via the cluster
	// Service (e.g. gibson-zitadel:8080) the default Host would be the
	// service name and fail instance lookup with a 404. Empty = don't forge.
	externalDomain string
	http           *http.Client
}

// New constructs a Zitadel Management API client authenticated via PAT.
// apiURL must be the Zitadel base URL (e.g. "https://zitadel.example.com").
// pat is the Personal Access Token mounted into the operator.
// externalDomain is the configured Zitadel ExternalDomain — forged on every
// request's Host header so in-cluster callers (reaching Zitadel via its
// Service name) still route to the right Zitadel instance. Pass empty to
// skip forgery when the caller already uses the external hostname.
func New(apiURL, pat, externalDomain string) Client {
	u, err := url.Parse(apiURL)
	if err != nil {
		return &errClient{err: fmt.Errorf("zitadel: invalid apiURL %q: %w", apiURL, err)}
	}
	return &httpClient{
		baseURL:        u,
		pat:            pat,
		externalDomain: externalDomain,
		http:           &http.Client{Timeout: 30 * time.Second},
	}
}

// CreateOrganization implements Client.
//
// Zitadel v4 retired the `/management/v1/organizations` endpoint; the
// replacement lives at `POST /v2/organizations`. Response shape is the same
// (`{organizationId, details}`), so the only client change is the path.
func (c *httpClient) CreateOrganization(ctx context.Context, name, slug string) (string, error) {
	body := map[string]any{
		"name": name,
	}
	var resp struct {
		OrganizationID string `json:"organizationId"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v2/organizations", body, &resp)
	if err != nil {
		// 409 = already exists; caller must look up by name to get the ID.
		if isConflict(err) {
			org, lerr := c.getOrgByName(ctx, name)
			if lerr != nil {
				return "", fmt.Errorf("CreateOrganization: conflict lookup: %w", lerr)
			}
			return org.ID, nil
		}
		return "", fmt.Errorf("CreateOrganization: %w", err)
	}
	return resp.OrganizationID, nil
}

// GetOrganization implements Client.
//
// Zitadel v4 does not expose a single-org GET in v2; we issue a search by
// id-query instead. Response list is one element (or zero → ErrNotFound).
func (c *httpClient) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{
				"idQuery": map[string]any{
					"id": orgID,
				},
			},
		},
	}
	var resp struct {
		Result []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			PrimaryDomain string `json:"primaryDomain"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v2/organizations/_search", body, &resp); err != nil {
		return nil, fmt.Errorf("GetOrganization %s: %w", orgID, err)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("GetOrganization %s: %w", orgID, clients.ErrNotFound)
	}
	return &Organization{
		ID:   resp.Result[0].ID,
		Name: resp.Result[0].Name,
		Slug: resp.Result[0].PrimaryDomain,
	}, nil
}

// DeleteOrganization implements Client.
//
// Zitadel v4: `DELETE /v2/organizations/{id}`.
func (c *httpClient) DeleteOrganization(ctx context.Context, orgID string) error {
	path := fmt.Sprintf("/v2/organizations/%s", url.PathEscape(orgID))
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil)
	if err != nil && isNotFound(err) {
		return nil // already gone — idempotent
	}
	if err != nil {
		return fmt.Errorf("DeleteOrganization %s: %w", orgID, err)
	}
	return nil
}

// AddMember implements Client.
//
// Zitadel v4 dropped `/management/v1/orgs/{orgID}/members` in favour of a
// self-scoped `/management/v1/orgs/me/members` path that takes the target
// org via the `x-zitadel-orgid` header. We follow that pattern here — the
// caller's PAT (IAM_OWNER) has the privilege to act in any org, and
// `x-zitadel-orgid` selects which one.
func (c *httpClient) AddMember(ctx context.Context, orgID, userID string, roles []string) (string, error) {
	body := map[string]any{
		"userId": userID,
		"roles":  roles,
	}
	var resp struct {
		// Zitadel org members don't have a discrete membership ID; we return
		// a composite of orgID+userID as a stable idempotency key.
		Details struct {
			Sequence string `json:"sequence"`
		} `json:"details"`
	}
	err := c.doJSONWithOrg(ctx, http.MethodPost, "/management/v1/orgs/me/members", orgID, body, &resp)
	if err != nil {
		if isConflict(err) {
			// Member already added; return a deterministic composite ID.
			return fmt.Sprintf("%s/%s", orgID, userID), nil
		}
		return "", fmt.Errorf("AddMember org=%s user=%s: %w", orgID, userID, err)
	}
	return fmt.Sprintf("%s/%s", orgID, userID), nil
}

// RemoveMember implements Client.
//
// v4: same self-scoped `/orgs/me/...` pattern as AddMember.
func (c *httpClient) RemoveMember(ctx context.Context, orgID, userID string) error {
	path := fmt.Sprintf("/management/v1/orgs/me/members/%s", url.PathEscape(userID))
	err := c.doJSONWithOrg(ctx, http.MethodDelete, path, orgID, nil, nil)
	if err != nil && isNotFound(err) {
		return nil // already removed — idempotent
	}
	if err != nil {
		return fmt.Errorf("RemoveMember org=%s user=%s: %w", orgID, userID, err)
	}
	return nil
}

// SendInvitation implements Client. Creates a human user scoped to the org,
// triggers the email verification / invitation flow, and grants the given
// roles. Returns the newly created Zitadel user ID as the invitation ID.
//
// v4: user creation moves to `/v2/users/human` with org scoping via the
// `organization.orgId` body field. The v1 `/management/v1/orgs/{id}/users/human`
// path is gone.
func (c *httpClient) SendInvitation(ctx context.Context, orgID, email string, roles []string) (string, error) {
	// Step 1: create human user inside the org via v2 API.
	body := map[string]any{
		"organization": map[string]any{
			"orgId": orgID,
		},
		"username": email,
		"profile": map[string]any{
			"givenName":  "Invited",
			"familyName": "User",
		},
		"email": map[string]any{
			"email":      email,
			"isVerified": false,
			"sendCode":   map[string]any{}, // triggers invitation email
		},
	}
	var resp struct {
		UserID string `json:"userId"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v2/users/human", body, &resp)
	if err != nil && !isConflict(err) {
		return "", fmt.Errorf("SendInvitation org=%s email=%s: create user: %w", orgID, email, err)
	}
	userID := resp.UserID
	if isConflict(err) || userID == "" {
		// User exists; look up by login name to get their ID.
		uid, lerr := c.getUserIDByEmail(ctx, orgID, email)
		if lerr != nil {
			return "", fmt.Errorf("SendInvitation: existing user lookup: %w", lerr)
		}
		userID = uid
	}

	// Step 2: grant org membership with the requested roles.
	if _, err := c.AddMember(ctx, orgID, userID, roles); err != nil {
		return "", fmt.Errorf("SendInvitation: add member: %w", err)
	}
	return userID, nil
}

// CreateServiceAccount implements Client.
//
// Zitadel v4: machine users live under /v2/users/machine with
// organization scoping via the body's "organization.orgId" field.
// After creating the user, we generate a client-secret key pair via
// POST /v2/users/{id}/keys so the caller receives OAuth2 credentials.
func (c *httpClient) CreateServiceAccount(ctx context.Context, orgID, name string) (accountID, clientID, clientSecret string, err error) {
	body := map[string]any{
		"organization": map[string]any{
			"orgId": orgID,
		},
		"name":            name,
		"accessTokenType": "ACCESS_TOKEN_TYPE_JWT",
	}
	var resp struct {
		UserID string `json:"userId"`
	}
	err = c.doJSON(ctx, http.MethodPost, "/v2/users/machine", body, &resp)
	if err != nil && !isConflict(err) {
		return "", "", "", fmt.Errorf("CreateServiceAccount org=%s name=%s: %w", orgID, name, err)
	}

	userID := resp.UserID
	if isConflict(err) || userID == "" {
		// Machine user already exists; look up by login name.
		uid, lerr := c.getMachineUserIDByName(ctx, orgID, name)
		if lerr != nil {
			return "", "", "", fmt.Errorf("CreateServiceAccount: existing user lookup: %w", lerr)
		}
		// Return existing accountID and clientID; secret is not retrievable.
		return uid, uid, "", nil
	}

	// Generate client credentials (client key) for the machine user.
	keyBody := map[string]any{}
	var keyResp struct {
		KeyID     string `json:"keyId"`
		KeyDetail string `json:"keyDetail"` // JSON-encoded private key or client secret
	}
	keyPath := fmt.Sprintf("/v2/users/%s/keys", url.PathEscape(userID))
	if kerr := c.doJSONWithOrg(ctx, http.MethodPost, keyPath, orgID, keyBody, &keyResp); kerr != nil {
		// Key generation failed; still return the userID so the caller can
		// clean up. Return an error but include the accountID so it is not
		// lost.
		return userID, userID, "", fmt.Errorf("CreateServiceAccount: generate key: %w", kerr)
	}

	// keyDetail is the raw client secret.
	return userID, keyResp.KeyID, keyResp.KeyDetail, nil
}

// DeleteServiceAccount implements Client.
//
// Zitadel v4: DELETE /v2/users/{id}.
func (c *httpClient) DeleteServiceAccount(ctx context.Context, _, accountID string) error {
	path := fmt.Sprintf("/v2/users/%s", url.PathEscape(accountID))
	err := c.doJSON(ctx, http.MethodDelete, path, nil, nil)
	if err != nil && isNotFound(err) {
		return nil // already gone — idempotent
	}
	if err != nil {
		return fmt.Errorf("DeleteServiceAccount %s: %w", accountID, err)
	}
	return nil
}

// getMachineUserIDByName looks up a machine user by name within an org.
// Used for conflict resolution in CreateServiceAccount.
func (c *httpClient) getMachineUserIDByName(ctx context.Context, orgID, name string) (string, error) {
	body := map[string]any{
		"organization": map[string]any{
			"orgId": orgID,
		},
		"queries": []map[string]any{
			{
				"userNameQuery": map[string]any{
					"userName": name,
					"method":   "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}
	var resp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v2/users", body, &resp); err != nil {
		return "", fmt.Errorf("getMachineUserIDByName org=%s name=%s: %w", orgID, name, err)
	}
	if len(resp.Result) == 0 {
		return "", fmt.Errorf("getMachineUserIDByName org=%s name=%s: %w", orgID, name, clients.ErrNotFound)
	}
	return resp.Result[0].UserID, nil
}

// getOrgByName looks up an organization by display name (used for 409
// conflict resolution in CreateOrganization).
func (c *httpClient) getOrgByName(ctx context.Context, name string) (*Organization, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{
				"nameQuery": map[string]any{
					"name":   name,
					"method": "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}
	var resp struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v2/organizations/_search", body, &resp); err != nil {
		return nil, fmt.Errorf("getOrgByName %q: %w", name, err)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("getOrgByName %q: %w", name, clients.ErrNotFound)
	}
	return &Organization{ID: resp.Result[0].ID, Name: resp.Result[0].Name}, nil
}

// getUserIDByEmail looks up a user's Zitadel ID by email within an org
// (used for 409 conflict resolution in SendInvitation).
//
// v4: the per-org user search path `/management/v1/orgs/{id}/users/_search`
// is gone. The v2 user search replaces it; scope is supplied by the
// `organization.orgId` field in the request body.
func (c *httpClient) getUserIDByEmail(ctx context.Context, orgID, email string) (string, error) {
	body := map[string]any{
		"organization": map[string]any{
			"orgId": orgID,
		},
		"queries": []map[string]any{
			{
				"emailQuery": map[string]any{
					"emailAddress": email,
					"method":       "TEXT_QUERY_METHOD_EQUALS",
				},
			},
		},
	}
	var resp struct {
		Result []struct {
			// v2 uses userId, not id.
			UserID string `json:"userId"`
		} `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v2/users", body, &resp); err != nil {
		return "", fmt.Errorf("getUserIDByEmail org=%s email=%s: %w", orgID, email, err)
	}
	if len(resp.Result) == 0 {
		return "", fmt.Errorf("getUserIDByEmail org=%s email=%s: %w", orgID, email, clients.ErrNotFound)
	}
	return resp.Result[0].UserID, nil
}

// doJSON wraps doJSONWithOrg for callers that do not need org-scoped routing
// (e.g. instance-level admin APIs, v2 endpoints that embed orgId in the body).
func (c *httpClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	return c.doJSONWithOrg(ctx, method, path, "", body, out)
}

// doJSONWithOrg sends a JSON request to Zitadel, optionally adding the
// `x-zitadel-orgid` header so the caller's Management-API call resolves against
// the named org. Required by v4 for any write scoped to a non-caller org
// (AddMember, RemoveMember, org-scoped user search) since Zitadel dropped the
// `/management/v1/orgs/{id}/...` path in favour of `/management/v1/orgs/me/...`
// + header-based instance/org routing.
func (c *httpClient) doJSONWithOrg(ctx context.Context, method, path, orgID string, body any, out any) error {
	ref, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("zitadel: path %q: %w", path, clients.ErrInvalidInput)
	}
	u := c.baseURL.ResolveReference(ref)

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("zitadel: marshal: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("zitadel: build request: %w", err)
	}
	// Forge Host so Zitadel routes this to the configured ExternalDomain
	// instance even when the TCP target is the cluster Service name. Go's
	// stdlib sends req.Host as the HTTP Host header when it is non-empty.
	if c.externalDomain != "" {
		req.Host = c.externalDomain
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.pat != "" {
		req.Header.Set("Authorization", "Bearer "+c.pat)
	}
	if orgID != "" {
		// Zitadel's cross-org selector — scopes the request to the named
		// org for endpoints that would otherwise act on the caller's own
		// org (IAM admin = the IAM-admin org). Required for v4.
		req.Header.Set("x-zitadel-orgid", orgID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel: %v: %w", err, clients.ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("zitadel: decode: %w", err)
		}
		return nil
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("zitadel %s %s 404: %w", method, path, clients.ErrNotFound)
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("zitadel %s %s 409: %w", method, path, clients.ErrAlreadyExists)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return clients.WrapPermanent(fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, clients.ErrUnauthorized, string(raw)))
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("zitadel %d: %w", resp.StatusCode, clients.ErrRateLimited)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, clients.ErrInvalidInput, string(raw))
	default:
		return fmt.Errorf("zitadel %d: %w: %s", resp.StatusCode, clients.ErrUnreachable, string(raw))
	}
}

// isConflict reports whether err wraps clients.ErrAlreadyExists.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	return isClientError(err, clients.ErrAlreadyExists)
}

// isNotFound reports whether err wraps clients.ErrNotFound.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return isClientError(err, clients.ErrNotFound)
}

func isClientError(err, target error) bool {
	// Use string matching on wrapped errors — errors.Is works here because
	// doJSON uses %w wrapping throughout.
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}

// errClient is a no-op Client that always returns a construction error.
// Returned by New when the apiURL is unparseable.
type errClient struct {
	err error
}

func (e *errClient) CreateOrganization(_ context.Context, _, _ string) (string, error) {
	return "", e.err
}
func (e *errClient) GetOrganization(_ context.Context, _ string) (*Organization, error) {
	return nil, e.err
}
func (e *errClient) DeleteOrganization(_ context.Context, _ string) error { return e.err }
func (e *errClient) AddMember(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", e.err
}
func (e *errClient) RemoveMember(_ context.Context, _, _ string) error { return e.err }
func (e *errClient) SendInvitation(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", e.err
}
func (e *errClient) CreateServiceAccount(_ context.Context, _, _ string) (string, string, string, error) {
	return "", "", "", e.err
}
func (e *errClient) DeleteServiceAccount(_ context.Context, _, _ string) error { return e.err }

// NoopClient was a Client implementation that silently succeeded on every
// call. It used to be injected when ZITADEL_PAT_PATH was unset, so the
// operator booted in degraded mode and every EnsureZitadelOrg step
// returned ErrUnreachable.
//
// Per epic one-code-path (deploy#186), slice deploy#196: the NoopClient
// degradation surface has been DELETED. Zitadel is structurally required;
// cmd/main.go now exits 1 at startup when ZITADEL_URL is empty or the PAT
// is unreadable. Re-introducing this type would reopen the silent-no-op
// failure mode the slice exists to prevent.
