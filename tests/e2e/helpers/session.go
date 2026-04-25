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
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// ---------------------------------------------------------------------------
// Playwright storage state types
// ---------------------------------------------------------------------------

// PlaywrightStorageState is the shape of the JSON written by
// Playwright's context.storageState({ path: "..." }).
// We only need the cookies array; other fields (origins, localStorage) are
// ignored by the session helper.
type PlaywrightStorageState struct {
	Cookies []PlaywrightCookie `json:"cookies"`
}

// PlaywrightCookie is a single cookie entry in the Playwright storage state.
// Only the fields the Go http.Cookie type needs are mapped.
type PlaywrightCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`  // unix seconds (float in Playwright JSON)
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
}

// ---------------------------------------------------------------------------
// MeResponse — typed shape of the /api/me JSON response
// ---------------------------------------------------------------------------

// MeResponse is the subset of the /api/me response that the e2e test asserts
// on.  Additional fields (avatar, settings, etc.) are not checked here.
type MeResponse struct {
	Email  string     `json:"email"`
	Tenant MeTenant   `json:"tenant"`
	User   MeUserMeta `json:"user"`
}

// MeTenant holds the tenant-scoped fields returned by /api/me.
type MeTenant struct {
	Slug string `json:"slug"`
	Role string `json:"role"`
	ID   string `json:"id"`
}

// MeUserMeta holds user-level metadata from /api/me.
type MeUserMeta struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ---------------------------------------------------------------------------
// UserProfileResponse — typed shape of /api/users/profile JSON response
// ---------------------------------------------------------------------------

// UserProfileResponse is the shape returned by GET /api/users/profile.
// The dashboard wraps the profile in a "profile" key when the daemon RPC is
// unavailable (fallback path); it also may return the profile at the top level
// when the daemon RPC succeeds. We parse both shapes.
type UserProfileResponse struct {
	// Direct shape (when daemon RPC succeeds)
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	TenantID string   `json:"tenantId"`
	Roles    []string `json:"roles"`
	// Wrapped shape (fallback, daemon RPC unavailable)
	Profile *struct {
		ID       string   `json:"id"`
		Email    string   `json:"email"`
		TenantID string   `json:"tenantId"`
		Roles    []string `json:"roles"`
	} `json:"profile"`
}

// ResolvedEmail returns the email from either the direct or wrapped profile shape.
func (r *UserProfileResponse) ResolvedEmail() string {
	if r.Email != "" {
		return r.Email
	}
	if r.Profile != nil {
		return r.Profile.Email
	}
	return ""
}

// ResolvedTenantID returns the tenantId from either the direct or wrapped profile shape.
func (r *UserProfileResponse) ResolvedTenantID() string {
	if r.TenantID != "" {
		return r.TenantID
	}
	if r.Profile != nil {
		return r.Profile.TenantID
	}
	return ""
}

// FetchUserProfile makes a GET /api/users/profile request using the provided
// cookie jar and returns the parsed response.
//
// LOGIN-B3 fix: /api/me doesn't exist in the dashboard; the real endpoint is
// /api/users/profile. Returns an error if the HTTP request fails, if the
// endpoint returns a non-200 status, or if the JSON cannot be parsed.
//
// Requirements: R1.6.
func FetchUserProfile(ctx context.Context, cookies []*PlaywrightCookie, baseURL string) (*UserProfileResponse, error) {
	body, err := FetchProtectedJSON(ctx, cookies, baseURL, "/api/users/profile")
	if err != nil {
		return nil, fmt.Errorf("session: FetchUserProfile: %w", err)
	}
	var profile UserProfileResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("session: FetchUserProfile: unmarshal response: %w (body: %.200s)", err, string(body))
	}
	return &profile, nil
}

// ---------------------------------------------------------------------------
// ExpiredSessionResult — written by Playwright, read by Go test
// ---------------------------------------------------------------------------

// ExpiredSessionResult is the JSON written by the Playwright expired-session
// negative test case.  The Go side reads this file and asserts the fields.
type ExpiredSessionResult struct {
	RedirectedToLogin  bool   `json:"redirectedToLogin"`
	HasRedirectToParam bool   `json:"hasRedirectToParam"`
	FinalURL           string `json:"finalUrl"`
}

// ---------------------------------------------------------------------------
// Cookie jar management
// ---------------------------------------------------------------------------

// LoadCookieJar reads a Playwright storage state JSON file and returns the
// cookies as a []*PlaywrightCookie slice.
//
// The file is the output of Playwright's context.storageState({ path }) call.
// Returns an error if the file is missing or malformed.
//
// Security: The function NEVER logs cookie values — only names and presence.
//
// Requirements: R1.6, R2.3, R2.4, R2.5.
func LoadCookieJar(t *testing.T, statePath string) ([]*PlaywrightCookie, error) {
	t.Helper()
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("session: LoadCookieJar: read %s: %w", statePath, err)
	}
	var state PlaywrightStorageState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("session: LoadCookieJar: unmarshal %s: %w", statePath, err)
	}
	ptrs := make([]*PlaywrightCookie, len(state.Cookies))
	for i := range state.Cookies {
		ptrs[i] = &state.Cookies[i]
	}
	// Log names only (not values) — Security NFR.
	names := make([]string, len(ptrs))
	for i, c := range ptrs {
		names[i] = c.Name
	}
	t.Logf("session: LoadCookieJar: loaded %d cookie(s) from %s (names: %v; values redacted)",
		len(ptrs), statePath, names)
	return ptrs, nil
}

// StorageStateExists checks whether the file at statePath exists.
// Returns (info, nil) on success, (nil, error) if missing.
// Used by the Go test to conditionally skip assertions when the Playwright
// spec hasn't written the file yet.
func StorageStateExists(statePath string) (os.FileInfo, error) {
	info, err := os.Stat(statePath)
	if err != nil {
		return nil, fmt.Errorf("session: StorageStateExists: %s: %w", statePath, err)
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// HTTP client with injected cookie jar
// ---------------------------------------------------------------------------

// newHTTPClientWithCookies builds an *http.Client that:
//   - Accepts self-signed TLS (Kind dev cluster).
//   - Pre-seeds a cookiejar with the given Playwright cookies for baseURL.
//   - Does NOT follow redirects automatically (so the caller can inspect the
//     redirect status code).
//
// Security: cookies are never logged.
func newHTTPClientWithCookies(cookies []*PlaywrightCookie, baseURL string) (*http.Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("session: newHTTPClientWithCookies: create jar: %w", err)
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("session: newHTTPClientWithCookies: parse base URL %q: %w", baseURL, err)
	}

	httpCookies := make([]*http.Cookie, 0, len(cookies))
	for _, pc := range cookies {
		httpCookies = append(httpCookies, &http.Cookie{
			Name:     pc.Name,
			Value:    pc.Value,
			Domain:   pc.Domain,
			Path:     pc.Path,
			HttpOnly: pc.HTTPOnly,
			Secure:   pc.Secure,
		})
	}
	jar.SetCookies(parsed, httpCookies)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Kind dev only
	}

	client := &http.Client{
		Transport: tr,
		// Do NOT follow redirects — the caller checks the status code.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
	return client, nil
}

// ---------------------------------------------------------------------------
// Public API: FetchMe, FetchProtectedJSON, FetchMeUnauthenticated, TamperCookie
// ---------------------------------------------------------------------------

// FetchMe makes a GET /api/me request using the provided cookie jar and
// returns the parsed response.
//
// Returns an error if the HTTP request fails, if /api/me returns a non-200
// status, or if the JSON cannot be parsed into MeResponse.
//
// Security: cookie values are NOT logged; only the response status is logged.
//
// Requirements: R1.6.
func FetchMe(ctx context.Context, cookies []*PlaywrightCookie, baseURL string) (*MeResponse, error) {
	body, err := FetchProtectedJSON(ctx, cookies, baseURL, "/api/me")
	if err != nil {
		return nil, fmt.Errorf("session: FetchMe: %w", err)
	}
	var me MeResponse
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, fmt.Errorf("session: FetchMe: unmarshal response: %w (body: %.200s)", err, string(body))
	}
	return &me, nil
}

// FetchProtectedJSON makes a GET request to baseURL+path using the provided
// cookie jar.  Returns the raw response body.
//
// Returns an error if:
//   - The HTTP request fails (network error, TLS error).
//   - The response status is not 200 (authentication rejected, server error).
//
// Security: cookie values are NOT logged.
//
// Requirements: R1.7, R2.3.
func FetchProtectedJSON(ctx context.Context, cookies []*PlaywrightCookie, baseURL, path string) ([]byte, error) {
	client, err := newHTTPClientWithCookies(cookies, baseURL)
	if err != nil {
		return nil, err
	}

	reqURL := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("session: FetchProtectedJSON: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session: FetchProtectedJSON: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"session: FetchProtectedJSON: GET %s returned HTTP %d (body: %.200s) — "+
				"session cookie may be invalid or expired (see LOGIN-B catalog in design.md)",
			path, resp.StatusCode, string(rawBody),
		)
	}
	return rawBody, nil
}

// FetchMeUnauthenticated makes a GET /api/users/profile request WITHOUT any
// session cookie and returns the HTTP status code.
//
// LOGIN-B5 FIX: /api/me does not exist (404). The real protected endpoint is
// /api/users/profile which properly returns 401 when unauthenticated.
//
// Used by the R2.3 negative test: no-cookie → 401 or redirect to /login.
//
// Requirements: R2.3.
func FetchMeUnauthenticated(ctx context.Context, baseURL string) (int, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Kind dev only
	}
	client := &http.Client{
		Transport: tr,
		// Do NOT follow redirects — we want to see the raw 302/401 status.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqURL := strings.TrimRight(baseURL, "/") + "/api/users/profile"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("session: FetchMeUnauthenticated: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("session: FetchMeUnauthenticated: GET /api/users/profile: %w", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// FetchMeWithCookies makes a GET /api/users/profile request with the provided
// cookies and returns the HTTP status code (without consuming the body).
//
// LOGIN-B5 FIX: /api/me does not exist (404). Use /api/users/profile which
// properly rejects tampered session cookies.
//
// Used by the R2.4 tampered-cookie negative test.
//
// Requirements: R2.4.
func FetchMeWithCookies(ctx context.Context, cookies []*PlaywrightCookie, baseURL string) (int, error) {
	client, err := newHTTPClientWithCookies(cookies, baseURL)
	if err != nil {
		return 0, err
	}

	reqURL := strings.TrimRight(baseURL, "/") + "/api/users/profile"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("session: FetchMeWithCookies: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("session: FetchMeWithCookies: GET /api/users/profile: %w", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// SessionCookieName is the Auth.js v5 session cookie name.
//
// Auth.js v5 uses the __Secure- prefix when served over HTTPS (which the Kind
// cluster does via Envoy TLS termination). The fallback without the prefix
// applies when served over HTTP (local dev only).
//
// The old Auth.js v4 name was "next-auth.session-token" — that is NOT used.
//
// Requirements: R3.2 (realigned for Auth.js v5 cookie naming).
const SessionCookieName = "__Secure-authjs.session-token"

// SessionCookieNameInsecure is the Auth.js v5 cookie name without the
// __Secure- prefix, used when the cluster is served over HTTP.
const SessionCookieNameInsecure = "authjs.session-token"

// HasSessionCookie returns true if the cookie jar contains an Auth.js v5
// session cookie (either the __Secure- prefixed name for HTTPS or the plain
// name for HTTP).
//
// Auth.js v4's "next-auth.session-token" is NOT recognised — those cookies
// will not pass this check (any remaining v4 cookies indicate a version
// migration issue in the dashboard).
//
// Security: cookie values are NOT logged — only cookie names.
//
// Requirements: R3.2.
func HasSessionCookie(cookies []*PlaywrightCookie) bool {
	for _, c := range cookies {
		if c.Name == SessionCookieName || c.Name == SessionCookieNameInsecure {
			return true
		}
	}
	return false
}

// TamperCookie finds the cookie matching any of the Auth.js v5 session cookie
// names and returns a new slice with that cookie's value deterministically
// corrupted (one byte flipped at a fixed offset).
//
// The name parameter accepts either the exact name OR a substring. The first
// matching cookie is tampered. If no matching cookie exists, the slice is
// returned unchanged.
//
// The corruption is deterministic (not random) so tests are reproducible.
//
// Security: neither the original nor the tampered value is logged — only
// the cookie name and the fact that corruption was applied.
//
// Requirements: R2.4.
func TamperCookie(cookies []*PlaywrightCookie, name string) []*PlaywrightCookie {
	result := make([]*PlaywrightCookie, len(cookies))
	for i, c := range cookies {
		// Match by exact name or by substring (handles v5 __Secure- prefix variants).
		matches := c.Name == name ||
			(name == "authjs.session-token" && (c.Name == SessionCookieName || c.Name == SessionCookieNameInsecure))
		if !matches || len(c.Value) == 0 {
			result[i] = c
			continue
		}
		// Flip the last byte of the value (deterministic, reproducible).
		// We copy the struct so we don't mutate the caller's slice.
		tampered := *c
		runes := []rune(tampered.Value)
		lastIdx := len(runes) - 1
		// XOR the last character with 0x01 (minimal, deterministic change).
		runes[lastIdx] = runes[lastIdx] ^ 1
		tampered.Value = string(runes)
		result[i] = &tampered
		// Log name only (not values) — Security NFR.
	}
	return result
}

// FetchStatusWithCookies makes a GET request to baseURL+path with the provided
// cookies and returns the HTTP status code (without consuming the body).
//
// Unlike FetchProtectedJSON, this helper does NOT treat non-200 status codes as
// errors — it simply returns the status. This is intentional for negative probes
// (e.g., the cross-tenant isolation test expects 403, not 200).
//
// Security: cookie values are NOT logged.
//
// Requirements: R3.3, R3.4, R3.5.
func FetchStatusWithCookies(ctx context.Context, cookies []*PlaywrightCookie, baseURL, path string) (int, error) {
	client, err := newHTTPClientWithCookies(cookies, baseURL)
	if err != nil {
		return 0, err
	}

	reqURL := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("session: FetchStatusWithCookies: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("session: FetchStatusWithCookies: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// LoadExpiredSessionResult reads the JSON file written by the Playwright
// expired-session negative test case.
//
// File path: /tmp/login-negative-expired-<slug>.json
// Requirements: R2.5.
func LoadExpiredSessionResult(path string) (*ExpiredSessionResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("session: LoadExpiredSessionResult: read %s: %w", path, err)
	}
	var result ExpiredSessionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("session: LoadExpiredSessionResult: unmarshal %s: %w", path, err)
	}
	return &result, nil
}
