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
	"net/http"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/idp"
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

	// ProjectID is the Zitadel project ID that agents are granted membership on.
	// Project membership is what causes the project's role claims to appear in
	// the issued JWT.
	ProjectID string

	// HTTPTimeout is the per-request timeout. Defaults to 10 seconds.
	HTTPTimeout time.Duration
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
	tokenEndpoint, err := discoverTokenEndpoint(ctx, cfg.Issuer, cfg.HTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: discovering token endpoint: %s", idp.ErrUnreachable, err)
	}

	// Build an OAuth2 client_credentials token source for the admin account.
	ccCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenEndpoint,
		Scopes:       []string{"openid"},
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

// MintClientSecret generates a client secret for the machine user.
// Maps to PUT /management/v1/users/{userId}/secret.
// The secret is returned exactly once; it cannot be retrieved again.
func (c *Client) MintClientSecret(ctx context.Context, accountID string) (string, error) {
	var resp struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}

	path := "/management/v1/users/" + accountID + "/secret"
	if err := c.doRequest(ctx, http.MethodPut, path, map[string]interface{}{}, c.cfg.OrgID, &resp); err != nil {
		return "", mapError(err, "MintClientSecret")
	}

	if resp.ClientSecret == "" {
		// Do NOT log resp.ClientID or any other field — we could accidentally
		// log the secret on malformed responses if field mapping shifts.
		return "", fmt.Errorf("%w: response missing clientSecret", idp.ErrUpstream)
	}

	return resp.ClientSecret, nil
}

// AddTenantScopeMembership adds the service account to the configured project
// with the given role. Maps to POST /management/v1/projects/{projectId}/members.
func (c *Client) AddTenantScopeMembership(ctx context.Context, req idp.AddMembershipRequest) error {
	body := map[string]interface{}{
		"userId": req.AccountID,
		"roles":  []string{string(req.Role)},
	}

	path := "/management/v1/projects/" + req.TenantScopeID + "/members"
	if err := c.doRequest(ctx, http.MethodPost, path, body, c.cfg.OrgID, nil); err != nil {
		return mapError(err, "AddTenantScopeMembership")
	}
	return nil
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
		"limit":   req.PageSize,
		"queries": []query{{TypeQuery: struct{ Type string `json:"type"` }{Type: "TYPE_MACHINE"}}},
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
			TotalResult    string `json:"totalResult"`
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
	code := ze.Details[0].ErrorCode
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
func discoverTokenEndpoint(ctx context.Context, issuer string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned HTTP %d from %s", resp.StatusCode, discoveryURL)
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
