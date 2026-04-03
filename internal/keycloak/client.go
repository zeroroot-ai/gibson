// Package keycloak provides an HTTP client for the Keycloak Admin REST API.
//
// Authentication uses the OAuth2 client credentials grant against the master
// realm. The access token is cached in memory and refreshed automatically when
// it reaches 80% of its expiry. A single retry is performed on 401 responses
// to handle edge cases where the cached token expires between the cache check
// and the actual HTTP call.
//
// All write operations that may produce a 409 Conflict (resource already
// exists) treat that response as a successful no-op, making create operations
// safe to call idempotently.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client provides access to the Keycloak Admin REST API.
//
// Safe for concurrent use. Token refresh is serialized with a mutex so that
// concurrent callers that all see an expired token will only issue one refresh
// request.
type Client struct {
	baseURL      string // e.g., "http://keycloak:8080"
	masterRealm  string // e.g., "master"
	clientID     string
	clientSecret string
	httpClient   *http.Client
	token        tokenCache
	logger       *slog.Logger
}

// tokenCache holds the cached access token with its expiry time.
type tokenCache struct {
	mu        sync.RWMutex
	token     string
	expiresAt time.Time
}

// tokenResponse is the JSON structure returned by the token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// NewClient creates a Keycloak Admin REST API client.
//
// baseURL is the scheme+host of the Keycloak instance (e.g., "http://keycloak:8080").
// masterRealm is the admin realm used for client credentials authentication (typically "master").
// clientID and clientSecret are the credentials of a service account with admin privileges.
func NewClient(baseURL, masterRealm, clientID, clientSecret string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		masterRealm:  masterRealm,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// -------------------------------------------------------------------------
// Token management
// -------------------------------------------------------------------------

// getToken returns a valid access token, refreshing from Keycloak if the
// cached token has reached 80% of its lifetime.
func (c *Client) getToken(ctx context.Context) (string, error) {
	// Fast path: valid cached token.
	c.token.mu.RLock()
	token := c.token.token
	expiresAt := c.token.expiresAt
	c.token.mu.RUnlock()

	if token != "" && time.Now().Before(expiresAt) {
		return token, nil
	}

	// Slow path: need to refresh.
	return c.refreshToken(ctx)
}

// refreshToken fetches a new access token from the Keycloak token endpoint
// and stores it in the cache. Serialized by the write lock so only one
// goroutine performs the refresh when many see the cache as expired.
func (c *Client) refreshToken(ctx context.Context) (string, error) {
	c.token.mu.Lock()
	defer c.token.mu.Unlock()

	// Double-check after acquiring write lock — another goroutine may have
	// refreshed while we were waiting.
	if c.token.token != "" && time.Now().Before(c.token.expiresAt) {
		return c.token.token, nil
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		c.baseURL, url.PathEscape(c.masterRealm))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("keycloak: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("keycloak: parse token response: %w", err)
	}

	if tr.AccessToken == "" {
		return "", fmt.Errorf("keycloak: empty access_token in response")
	}

	// Cache token with 80% of the reported expiry as the effective TTL so we
	// proactively refresh before it actually expires.
	ttl := time.Duration(float64(tr.ExpiresIn)*0.8) * time.Second
	c.token.token = tr.AccessToken
	c.token.expiresAt = time.Now().Add(ttl)

	c.logger.DebugContext(ctx, "keycloak token refreshed",
		slog.Duration("ttl", ttl),
		slog.Int("expires_in", tr.ExpiresIn),
	)

	return tr.AccessToken, nil
}

// -------------------------------------------------------------------------
// Core HTTP helper
// -------------------------------------------------------------------------

// doRequest executes an authenticated Admin REST API request.
//
// method is the HTTP verb. path is appended directly to baseURL, so it must
// include the leading slash. body, when non-nil, is JSON-encoded as the request
// body. On a 401 response the token is refreshed and the request is retried
// exactly once.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("keycloak: authenticate: %w", err)
	}

	resp, err := c.executeRequest(ctx, method, path, body, token)
	if err != nil {
		return nil, err
	}

	// On 401 the cached token may have just expired between our check and the
	// actual call. Force a single refresh and retry.
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		c.logger.DebugContext(ctx, "keycloak: 401 received, refreshing token and retrying",
			slog.String("method", method),
			slog.String("path", path),
		)

		// Invalidate cache to force refreshToken to fetch a new one.
		c.token.mu.Lock()
		c.token.token = ""
		c.token.mu.Unlock()

		token, err = c.refreshToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("keycloak: token refresh after 401: %w", err)
		}

		resp, err = c.executeRequest(ctx, method, path, body, token)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// executeRequest builds and dispatches a single HTTP request with the
// supplied bearer token. It is the low-level primitive used by doRequest.
func (c *Client) executeRequest(ctx context.Context, method, path string, body interface{}, token string) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("keycloak: marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("keycloak: build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak: %s %s: %w", method, path, err)
	}

	return resp, nil
}

// readBody reads and closes the response body, returning an error that
// includes the HTTP status code when the status is not one of the accepted
// codes. Pass all codes that the caller considers successful.
func readBody(resp *http.Response, acceptedCodes ...int) ([]byte, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	for _, code := range acceptedCodes {
		if resp.StatusCode == code {
			return body, nil
		}
	}

	return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
}

// locationID extracts the last path segment from the Location header of a
// 201 Created response. Keycloak uses this convention to return the UUID of
// newly created resources.
func locationID(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// PrimeTokenCache injects a pre-obtained access token into the cache so that
// integration tests can supply a token acquired via the password grant (e.g.
// against admin-cli in the master realm) without needing a service-account
// client that supports the client_credentials grant.
//
// The token will be served from cache until expiresAt; after that the normal
// refresh path is used. Callers should set expiresAt to at least
// time.Now().Add(5*time.Minute) to cover typical test execution time.
func (c *Client) PrimeTokenCache(token string, expiresAt time.Time) {
	c.token.mu.Lock()
	defer c.token.mu.Unlock()
	c.token.token = token
	c.token.expiresAt = expiresAt
}

// -------------------------------------------------------------------------
// Health
// -------------------------------------------------------------------------

// Health checks whether Keycloak is ready to serve requests.
//
// Calls GET /health/ready and returns nil on HTTP 200. This endpoint does not
// require authentication.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health/ready", nil)
	if err != nil {
		return fmt.Errorf("keycloak: health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak: health check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keycloak: health check returned %d", resp.StatusCode)
	}

	return nil
}

// -------------------------------------------------------------------------
// Realm operations
// -------------------------------------------------------------------------

// CreateRealm creates a new realm in Keycloak.
//
// A 409 Conflict response is treated as success so the call is safe to make
// idempotently.
func (c *Client) CreateRealm(ctx context.Context, cfg RealmConfig) error {
	accessTokenLifespan := cfg.AccessTokenLifespan
	if accessTokenLifespan == 0 {
		accessTokenLifespan = 300
	}

	ssoSessionMax := cfg.SSOSessionMax
	if ssoSessionMax == 0 {
		ssoSessionMax = 36000
	}

	payload := map[string]interface{}{
		"realm":               cfg.Name,
		"displayName":         cfg.DisplayName,
		"enabled":             cfg.Enabled,
		"registrationAllowed": cfg.RegistrationAllowed,
		"loginTheme":          cfg.LoginTheme,
		"accessTokenLifespan": accessTokenLifespan,
		"ssoSessionMaxLifespan": ssoSessionMax,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/admin/realms", payload)
	if err != nil {
		return fmt.Errorf("keycloak: create realm %q: %w", cfg.Name, err)
	}

	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: realm already exists, skipping",
			slog.String("realm", cfg.Name))
		return nil
	}

	if _, err := readBody(resp, http.StatusCreated); err != nil {
		return fmt.Errorf("keycloak: create realm %q: %w", cfg.Name, err)
	}

	c.logger.InfoContext(ctx, "keycloak: realm created", slog.String("realm", cfg.Name))
	return nil
}

// DisableRequiredAction disables a specific required action on a realm.
// Call this AFTER GrantSelfAdminOnRealm so the service account has permissions.
func (c *Client) DisableRequiredAction(ctx context.Context, realm, actionAlias string) {
	c.disableRequiredAction(ctx, realm, actionAlias)
}

// ConfigureUserProfile updates the realm's User Profile configuration to:
// - Add tenant_id as a recognized user attribute (Keycloak 24+ silently drops unknown attrs)
// - Remove username-prohibited-characters validation (allows email-as-username with @)
// Call this AFTER GrantSelfAdminOnRealm.
func (c *Client) ConfigureUserProfile(ctx context.Context, realm string) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/profile"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		c.logger.WarnContext(ctx, "keycloak: could not get user profile config",
			slog.String("realm", realm))
		return
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return
	}

	var profile map[string]interface{}
	if err := json.Unmarshal(body, &profile); err != nil {
		return
	}

	attrs, ok := profile["attributes"].([]interface{})
	if !ok {
		return
	}

	// Check if tenant_id already exists
	hasTenantID := false
	for _, a := range attrs {
		attr, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := attr["name"].(string)
		if name == "tenant_id" {
			hasTenantID = true
		}
		// Remove username-prohibited-characters validation
		if name == "username" {
			if validations, ok := attr["validations"].(map[string]interface{}); ok {
				delete(validations, "username-prohibited-characters")
				delete(validations, "up-username-not-idn-homograph")
			}
		}
	}

	if !hasTenantID {
		attrs = append(attrs, map[string]interface{}{
			"name":        "tenant_id",
			"displayName": "Tenant ID",
			"permissions": map[string]interface{}{
				"view": []string{"admin", "user"},
				"edit": []string{"admin"},
			},
			"multivalued": false,
		})
		profile["attributes"] = attrs
	}

	putResp, err := c.doRequest(ctx, http.MethodPut, path, profile)
	if err != nil {
		c.logger.WarnContext(ctx, "keycloak: could not update user profile config",
			slog.String("realm", realm))
		return
	}
	putResp.Body.Close()

	c.logger.InfoContext(ctx, "keycloak: configured user profile",
		slog.String("realm", realm),
		slog.Bool("tenant_id_added", !hasTenantID))
}

func (c *Client) disableRequiredAction(ctx context.Context, realm, actionAlias string) {
	path := "/admin/realms/" + url.PathEscape(realm) +
		"/authentication/required-actions/" + url.PathEscape(actionAlias)

	// Get current config
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		c.logger.WarnContext(ctx, "keycloak: could not get required action",
			slog.String("realm", realm), slog.String("action", actionAlias))
		return
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return
	}

	var action map[string]interface{}
	if err := json.Unmarshal(body, &action); err != nil {
		return
	}

	// Disable it
	action["enabled"] = false
	action["defaultAction"] = false

	putResp, err := c.doRequest(ctx, http.MethodPut, path, action)
	if err != nil {
		c.logger.WarnContext(ctx, "keycloak: could not disable required action",
			slog.String("realm", realm), slog.String("action", actionAlias))
		return
	}
	putResp.Body.Close()

	c.logger.InfoContext(ctx, "keycloak: disabled required action",
		slog.String("realm", realm), slog.String("action", actionAlias))
}

// GetRealm retrieves the representation of a realm by name.
func (c *Client) GetRealm(ctx context.Context, realmName string) (*RealmRepresentation, error) {
	resp, err := c.doRequest(ctx, http.MethodGet,
		"/admin/realms/"+url.PathEscape(realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get realm %q: %w", realmName, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get realm %q: %w", realmName, err)
	}

	var realm RealmRepresentation
	if err := json.Unmarshal(body, &realm); err != nil {
		return nil, fmt.Errorf("keycloak: parse realm %q: %w", realmName, err)
	}

	return &realm, nil
}

// DeleteRealm deletes a realm by name.
func (c *Client) DeleteRealm(ctx context.Context, realmName string) error {
	resp, err := c.doRequest(ctx, http.MethodDelete,
		"/admin/realms/"+url.PathEscape(realmName), nil)
	if err != nil {
		return fmt.Errorf("keycloak: delete realm %q: %w", realmName, err)
	}

	if _, err := readBody(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("keycloak: delete realm %q: %w", realmName, err)
	}

	c.logger.InfoContext(ctx, "keycloak: realm deleted", slog.String("realm", realmName))
	return nil
}

// ListRealms returns all realms visible to the admin client.
func (c *Client) ListRealms(ctx context.Context) ([]RealmRepresentation, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/admin/realms", nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list realms: %w", err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list realms: %w", err)
	}

	var realms []RealmRepresentation
	if err := json.Unmarshal(body, &realms); err != nil {
		return nil, fmt.Errorf("keycloak: parse realms list: %w", err)
	}

	return realms, nil
}

// -------------------------------------------------------------------------
// OIDC client operations
// -------------------------------------------------------------------------

// CreateOIDCClient creates a confidential OIDC client within the specified realm.
//
// Returns the UUID of the newly created client. A 409 Conflict response
// indicates the client already exists; in that case ("", nil) is returned.
func (c *Client) CreateOIDCClient(ctx context.Context, realm string, cfg OIDCClientConfig) (string, error) {
	payload := map[string]interface{}{
		"clientId":     cfg.ClientID,
		"protocol":     "openid-connect",
		"publicClient": false,
		"secret":       cfg.Secret,
		"redirectUris": cfg.RedirectURIs,
		"webOrigins":   cfg.WebOrigins,
		"enabled":      true,
	}

	resp, err := c.doRequest(ctx, http.MethodPost,
		"/admin/realms/"+url.PathEscape(realm)+"/clients", payload)
	if err != nil {
		return "", fmt.Errorf("keycloak: create OIDC client %q in realm %q: %w", cfg.ClientID, realm, err)
	}

	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: OIDC client already exists, skipping",
			slog.String("realm", realm),
			slog.String("client_id", cfg.ClientID),
		)
		return "", nil
	}

	body, err := readBody(resp, http.StatusCreated)
	if err != nil {
		return "", fmt.Errorf("keycloak: create OIDC client %q in realm %q: %w", cfg.ClientID, realm, err)
	}
	_ = body

	id := locationID(resp)
	c.logger.InfoContext(ctx, "keycloak: OIDC client created",
		slog.String("realm", realm),
		slog.String("client_id", cfg.ClientID),
		slog.String("uuid", id),
	)

	return id, nil
}

// -------------------------------------------------------------------------
// User operations
// -------------------------------------------------------------------------

// CreateUser creates a new user within the specified realm.
//
// Returns the UUID of the newly created user. A 409 Conflict response
// indicates the username or email already exists; in that case ("", nil) is
// returned.
func (c *Client) CreateUser(ctx context.Context, realm string, cfg UserConfig) (string, error) {
	payload := map[string]interface{}{
		"username":      cfg.Username,
		"enabled":       cfg.Enabled,
		"emailVerified": cfg.EmailVerified,
	}
	// Only include non-empty fields to avoid Keycloak treating empty strings
	// as intentional "clear this field" directives.
	if cfg.Email != "" {
		payload["email"] = cfg.Email
	}
	if cfg.FirstName != "" {
		payload["firstName"] = cfg.FirstName
	}
	if cfg.LastName != "" {
		payload["lastName"] = cfg.LastName
	}
	if len(cfg.RequiredActions) > 0 {
		payload["requiredActions"] = cfg.RequiredActions
	}
	if len(cfg.Attributes) > 0 {
		payload["attributes"] = cfg.Attributes
	}

	if cfg.Password != "" {
		payload["credentials"] = []map[string]interface{}{
			{
				"type":      "password",
				"value":     cfg.Password,
				"temporary": cfg.TemporaryPassword,
			},
		}
	}

	resp, err := c.doRequest(ctx, http.MethodPost,
		"/admin/realms/"+url.PathEscape(realm)+"/users", payload)
	if err != nil {
		return "", fmt.Errorf("keycloak: create user %q in realm %q: %w", cfg.Username, realm, err)
	}

	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: user already exists, skipping",
			slog.String("realm", realm),
			slog.String("username", cfg.Username),
		)
		return "", nil
	}

	body, err := readBody(resp, http.StatusCreated)
	if err != nil {
		return "", fmt.Errorf("keycloak: create user %q in realm %q: %w", cfg.Username, realm, err)
	}
	_ = body

	id := locationID(resp)
	c.logger.InfoContext(ctx, "keycloak: user created",
		slog.String("realm", realm),
		slog.String("username", cfg.Username),
		slog.String("user_id", id),
	)

	return id, nil
}

// GetUser retrieves a user by their UUID within the specified realm.
func (c *Client) GetUser(ctx context.Context, realm, userID string) (*UserRepresentation, error) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/" + url.PathEscape(userID)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get user %q in realm %q: %w", userID, realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get user %q in realm %q: %w", userID, realm, err)
	}

	var user UserRepresentation
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("keycloak: parse user %q: %w", userID, err)
	}

	return &user, nil
}

// ListUsers returns users in the specified realm filtered by the provided options.
func (c *Client) ListUsers(ctx context.Context, realm string, opts ListUsersOpts) ([]UserRepresentation, error) {
	q := url.Values{}
	if opts.Search != "" {
		q.Set("search", opts.Search)
	}
	if opts.Email != "" {
		q.Set("email", opts.Email)
	}
	if opts.First > 0 {
		q.Set("first", fmt.Sprintf("%d", opts.First))
	}

	max := opts.Max
	if max == 0 {
		max = 100
	}
	q.Set("max", fmt.Sprintf("%d", max))

	path := "/admin/realms/" + url.PathEscape(realm) + "/users"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list users in realm %q: %w", realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list users in realm %q: %w", realm, err)
	}

	var users []UserRepresentation
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("keycloak: parse users list in realm %q: %w", realm, err)
	}

	return users, nil
}

// UpdateUser applies partial updates to a user. The updates map may contain
// any subset of the UserRepresentation fields supported by the Keycloak Admin
// REST API.
func (c *Client) UpdateUser(ctx context.Context, realm, userID string, updates map[string]interface{}) error {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/" + url.PathEscape(userID)

	resp, err := c.doRequest(ctx, http.MethodPut, path, updates)
	if err != nil {
		return fmt.Errorf("keycloak: update user %q in realm %q: %w", userID, realm, err)
	}

	if _, err := readBody(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("keycloak: update user %q in realm %q: %w", userID, realm, err)
	}

	return nil
}

// DeleteUser removes a user from the specified realm.
func (c *Client) DeleteUser(ctx context.Context, realm, userID string) error {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/" + url.PathEscape(userID)

	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("keycloak: delete user %q in realm %q: %w", userID, realm, err)
	}

	if _, err := readBody(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("keycloak: delete user %q in realm %q: %w", userID, realm, err)
	}

	c.logger.InfoContext(ctx, "keycloak: user deleted",
		slog.String("realm", realm),
		slog.String("user_id", userID),
	)

	return nil
}

// GetUserSessions returns all active sessions for a user.
func (c *Client) GetUserSessions(ctx context.Context, realm, userID string) ([]SessionRepresentation, error) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/" + url.PathEscape(userID) + "/sessions"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get sessions for user %q in realm %q: %w", userID, realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get sessions for user %q in realm %q: %w", userID, realm, err)
	}

	var sessions []SessionRepresentation
	if err := json.Unmarshal(body, &sessions); err != nil {
		return nil, fmt.Errorf("keycloak: parse sessions for user %q: %w", userID, err)
	}

	return sessions, nil
}

// -------------------------------------------------------------------------
// Role operations
// -------------------------------------------------------------------------

// CreateRealmRole creates a realm-level role.
//
// A 409 Conflict response indicates the role already exists and is treated as
// a successful no-op.
func (c *Client) CreateRealmRole(ctx context.Context, realm, roleName, description string) error {
	payload := map[string]interface{}{
		"name":        roleName,
		"description": description,
	}

	resp, err := c.doRequest(ctx, http.MethodPost,
		"/admin/realms/"+url.PathEscape(realm)+"/roles", payload)
	if err != nil {
		return fmt.Errorf("keycloak: create role %q in realm %q: %w", roleName, realm, err)
	}

	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: role already exists, skipping",
			slog.String("realm", realm),
			slog.String("role", roleName),
		)
		return nil
	}

	if _, err := readBody(resp, http.StatusCreated); err != nil {
		return fmt.Errorf("keycloak: create role %q in realm %q: %w", roleName, realm, err)
	}

	c.logger.InfoContext(ctx, "keycloak: realm role created",
		slog.String("realm", realm),
		slog.String("role", roleName),
	)

	return nil
}

// getRealmRole retrieves a realm-level role by name, returning its full
// representation including the opaque UUID required for role-mapping calls.
func (c *Client) getRealmRole(ctx context.Context, realm, roleName string) (*RoleRepresentation, error) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/roles/" + url.PathEscape(roleName)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get role %q in realm %q: %w", roleName, realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get role %q in realm %q: %w", roleName, realm, err)
	}

	var role RoleRepresentation
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, fmt.Errorf("keycloak: parse role %q: %w", roleName, err)
	}

	return &role, nil
}

// AssignRealmRoles assigns one or more realm-level roles to a user.
//
// Each role name is resolved to its full representation (including UUID) before
// the assignment is submitted. This requires one GET per role name.
func (c *Client) AssignRealmRoles(ctx context.Context, realm, userID string, roleNames []string) error {
	if len(roleNames) == 0 {
		return nil
	}

	roles := make([]RoleRepresentation, 0, len(roleNames))
	for _, name := range roleNames {
		role, err := c.getRealmRole(ctx, realm, name)
		if err != nil {
			return fmt.Errorf("keycloak: resolve role %q for assignment: %w", name, err)
		}
		roles = append(roles, *role)
	}

	path := "/admin/realms/" + url.PathEscape(realm) +
		"/users/" + url.PathEscape(userID) + "/role-mappings/realm"

	resp, err := c.doRequest(ctx, http.MethodPost, path, roles)
	if err != nil {
		return fmt.Errorf("keycloak: assign roles to user %q in realm %q: %w", userID, realm, err)
	}

	if _, err := readBody(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("keycloak: assign roles to user %q in realm %q: %w", userID, realm, err)
	}

	return nil
}

// GetUserRealmRoles returns the realm-level roles currently assigned to a user.
func (c *Client) GetUserRealmRoles(ctx context.Context, realm, userID string) ([]RoleRepresentation, error) {
	path := "/admin/realms/" + url.PathEscape(realm) +
		"/users/" + url.PathEscape(userID) + "/role-mappings/realm"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get roles for user %q in realm %q: %w", userID, realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: get roles for user %q in realm %q: %w", userID, realm, err)
	}

	var roles []RoleRepresentation
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("keycloak: parse roles for user %q: %w", userID, err)
	}

	return roles, nil
}

// -------------------------------------------------------------------------
// Group operations
// -------------------------------------------------------------------------

// CreateGroup creates a top-level group within the specified realm.
//
// Returns the UUID of the newly created group. A 409 Conflict response
// indicates the group already exists; in that case ("", nil) is returned.
func (c *Client) CreateGroup(ctx context.Context, realm, groupName string, attrs map[string][]string) (string, error) {
	payload := map[string]interface{}{
		"name":       groupName,
		"attributes": attrs,
	}

	resp, err := c.doRequest(ctx, http.MethodPost,
		"/admin/realms/"+url.PathEscape(realm)+"/groups", payload)
	if err != nil {
		return "", fmt.Errorf("keycloak: create group %q in realm %q: %w", groupName, realm, err)
	}

	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: group already exists, skipping",
			slog.String("realm", realm),
			slog.String("group", groupName),
		)
		return "", nil
	}

	body, err := readBody(resp, http.StatusCreated)
	if err != nil {
		return "", fmt.Errorf("keycloak: create group %q in realm %q: %w", groupName, realm, err)
	}
	_ = body

	id := locationID(resp)
	c.logger.InfoContext(ctx, "keycloak: group created",
		slog.String("realm", realm),
		slog.String("group", groupName),
		slog.String("group_id", id),
	)

	return id, nil
}

// AddUserToGroup adds a user to a group. Both IDs must be UUIDs.
func (c *Client) AddUserToGroup(ctx context.Context, realm, userID, groupID string) error {
	path := "/admin/realms/" + url.PathEscape(realm) +
		"/users/" + url.PathEscape(userID) +
		"/groups/" + url.PathEscape(groupID)

	resp, err := c.doRequest(ctx, http.MethodPut, path, nil)
	if err != nil {
		return fmt.Errorf("keycloak: add user %q to group %q in realm %q: %w", userID, groupID, realm, err)
	}

	if _, err := readBody(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("keycloak: add user %q to group %q in realm %q: %w", userID, groupID, realm, err)
	}

	return nil
}

// ListGroups returns all top-level groups in the specified realm.
func (c *Client) ListGroups(ctx context.Context, realm string) ([]GroupRepresentation, error) {
	resp, err := c.doRequest(ctx, http.MethodGet,
		"/admin/realms/"+url.PathEscape(realm)+"/groups", nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list groups in realm %q: %w", realm, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("keycloak: list groups in realm %q: %w", realm, err)
	}

	var groups []GroupRepresentation
	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, fmt.Errorf("keycloak: parse groups list in realm %q: %w", realm, err)
	}

	return groups, nil
}

// -------------------------------------------------------------------------
// Protocol mapper operations
// -------------------------------------------------------------------------

// AddProtocolMapper adds a protocol mapper to an OIDC client.
//
// clientUUID is the opaque UUID of the client (not the clientId string).
func (c *Client) AddProtocolMapper(ctx context.Context, realm, clientUUID string, mapper ProtocolMapperConfig) error {
	payload := map[string]interface{}{
		"name":           mapper.Name,
		"protocol":       mapper.Protocol,
		"protocolMapper": mapper.ProtocolMapper,
		"config":         mapper.Config,
	}

	path := "/admin/realms/" + url.PathEscape(realm) +
		"/clients/" + url.PathEscape(clientUUID) + "/protocol-mappers/models"

	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return fmt.Errorf("keycloak: add protocol mapper %q to client %q in realm %q: %w",
			mapper.Name, clientUUID, realm, err)
	}

	// Keycloak returns 201 on success and 409 if a mapper with the same name
	// already exists on the client.
	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		c.logger.DebugContext(ctx, "keycloak: protocol mapper already exists, skipping",
			slog.String("realm", realm),
			slog.String("client_uuid", clientUUID),
			slog.String("mapper", mapper.Name),
		)
		return nil
	}

	if _, err := readBody(resp, http.StatusCreated); err != nil {
		return fmt.Errorf("keycloak: add protocol mapper %q to client %q in realm %q: %w",
			mapper.Name, clientUUID, realm, err)
	}

	return nil
}

// AddDefaultClientScope adds a client scope as a default scope on an OIDC client.
// This ensures tokens issued by the client include the claims from that scope.
func (c *Client) AddDefaultClientScope(ctx context.Context, realm, clientUUID, scopeName string) error {
	// 1. Find the scope UUID by listing realm client scopes
	listPath := "/admin/realms/" + url.PathEscape(realm) + "/client-scopes"
	listResp, err := c.doRequest(ctx, http.MethodGet, listPath, nil)
	if err != nil {
		return fmt.Errorf("keycloak: list client scopes in realm %q: %w", realm, err)
	}
	body, err := readBody(listResp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("keycloak: list client scopes in realm %q: %w", realm, err)
	}

	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &scopes); err != nil {
		return fmt.Errorf("keycloak: parse client scopes: %w", err)
	}

	var scopeUUID string
	for _, s := range scopes {
		if s.Name == scopeName {
			scopeUUID = s.ID
			break
		}
	}
	if scopeUUID == "" {
		return fmt.Errorf("keycloak: scope %q not found in realm %q", scopeName, realm)
	}

	// 2. Add it as a default scope on the client
	putPath := "/admin/realms/" + url.PathEscape(realm) +
		"/clients/" + url.PathEscape(clientUUID) +
		"/default-client-scopes/" + url.PathEscape(scopeUUID)

	putResp, err := c.doRequest(ctx, http.MethodPut, putPath, nil)
	if err != nil {
		return fmt.Errorf("keycloak: add default scope %q to client %q: %w", scopeName, clientUUID, err)
	}
	putResp.Body.Close()

	if putResp.StatusCode != http.StatusNoContent && putResp.StatusCode != http.StatusOK {
		return fmt.Errorf("keycloak: add default scope: unexpected status %d", putResp.StatusCode)
	}

	c.logger.InfoContext(ctx, "keycloak: added default client scope",
		slog.String("realm", realm),
		slog.String("scope", scopeName),
		slog.String("client_uuid", clientUUID))

	return nil
}

// -------------------------------------------------------------------------
// Service account self-admin for new realms
// -------------------------------------------------------------------------

// GrantSelfAdminOnRealm grants this client's own service account admin
// permissions on a newly created realm. When Keycloak creates a realm,
// it produces a `{realm}-realm` client in the master realm with management
// roles. This method finds that client, resolves key roles, and assigns
// them to the service account user.
func (c *Client) GrantSelfAdminOnRealm(ctx context.Context, realmName string) error {
	realmClientID := realmName + "-realm"
	path := "/admin/realms/" + url.PathEscape(c.masterRealm) +
		"/clients?clientId=" + url.QueryEscape(realmClientID) + "&max=1"

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("keycloak: find %s client: %w", realmClientID, err)
	}

	body, err := readBody(resp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("keycloak: find %s client: %w", realmClientID, err)
	}

	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &clients); err != nil || len(clients) == 0 {
		return fmt.Errorf("keycloak: %s client not found in master realm", realmClientID)
	}
	clientUUID := clients[0].ID

	saPath := "/admin/realms/" + url.PathEscape(c.masterRealm) +
		"/users?username=service-account-" + url.QueryEscape(c.clientID) + "&max=1"

	saResp, err := c.doRequest(ctx, http.MethodGet, saPath, nil)
	if err != nil {
		return fmt.Errorf("keycloak: find service account: %w", err)
	}

	saBody, err := readBody(saResp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("keycloak: find service account: %w", err)
	}

	var saUsers []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(saBody, &saUsers); err != nil || len(saUsers) == 0 {
		return fmt.Errorf("keycloak: service account user not found for client %s", c.clientID)
	}
	saUserID := saUsers[0].ID

	wantedRoles := []string{"manage-users", "manage-clients", "manage-realm", "manage-events",
		"view-users", "view-clients", "view-realm", "create-client", "manage-authorization",
		"manage-identity-providers", "view-authorization", "view-events", "view-identity-providers",
		"query-users", "query-clients", "query-groups", "query-realms", "impersonation"}

	rolesPath := "/admin/realms/" + url.PathEscape(c.masterRealm) +
		"/clients/" + url.PathEscape(clientUUID) + "/roles"

	rolesResp, err := c.doRequest(ctx, http.MethodGet, rolesPath, nil)
	if err != nil {
		return fmt.Errorf("keycloak: list %s roles: %w", realmClientID, err)
	}

	rolesBody, err := readBody(rolesResp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("keycloak: list %s roles: %w", realmClientID, err)
	}

	var allRoles []map[string]interface{}
	if err := json.Unmarshal(rolesBody, &allRoles); err != nil {
		return fmt.Errorf("keycloak: parse %s roles: %w", realmClientID, err)
	}

	wantedSet := make(map[string]bool)
	for _, r := range wantedRoles {
		wantedSet[r] = true
	}

	var rolesToAssign []map[string]interface{}
	for _, r := range allRoles {
		name, _ := r["name"].(string)
		if wantedSet[name] {
			rolesToAssign = append(rolesToAssign, r)
		}
	}

	if len(rolesToAssign) == 0 {
		c.logger.WarnContext(ctx, "no matching roles found on realm client",
			slog.String("realm", realmName), slog.String("client", realmClientID))
		return nil
	}

	assignPath := "/admin/realms/" + url.PathEscape(c.masterRealm) +
		"/users/" + url.PathEscape(saUserID) +
		"/role-mappings/clients/" + url.PathEscape(clientUUID)

	assignResp, err := c.doRequest(ctx, http.MethodPost, assignPath, rolesToAssign)
	if err != nil {
		return fmt.Errorf("keycloak: assign %s roles to service account: %w", realmClientID, err)
	}

	if assignResp.StatusCode != http.StatusNoContent && assignResp.StatusCode != http.StatusOK {
		assignBody, _ := io.ReadAll(assignResp.Body)
		assignResp.Body.Close()
		return fmt.Errorf("keycloak: assign %s roles: unexpected status %d: %s",
			realmClientID, assignResp.StatusCode, string(assignBody))
	}
	assignResp.Body.Close()

	c.logger.InfoContext(ctx, "granted service account admin on new realm",
		slog.String("realm", realmName),
		slog.Int("roles_assigned", len(rolesToAssign)))

	// Force token refresh so the next request uses a token that includes
	// the newly assigned roles. Without this, cached tokens issued before
	// the role grant will still get 403 on the new realm's resources.
	c.invalidateToken()

	return nil
}

// invalidateToken clears the cached access token, forcing the next API call
// to acquire a fresh token from Keycloak.
func (c *Client) invalidateToken() {
	c.token.mu.Lock()
	defer c.token.mu.Unlock()
	c.token.token = ""
	c.token.expiresAt = time.Time{}
}
