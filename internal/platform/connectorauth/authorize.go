// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

// authorize.go owns the FRONT half of a connector's OAuth grant: the daemon
// runs the whole authorization-code flow itself so no human pastes a URL and
// no local listener runs by hand (ADR-0014, "What ConnectorAuthService must
// change").
//
// The daemon:
//   1. discovers the vendor's authorization-server metadata (RFC 8414, with an
//      RFC 9728 protected-resource fallback off the MCP endpoint);
//   2. registers a public PKCE client (RFC 7591);
//   3. mints a PKCE pair and a random state, and holds them server-side in a
//      short-TTL store keyed by state;
//   4. builds the authorize URL the operator opens;
//   5. on the callback, exchanges the code + verifier for a Grant.
//
// The refresh token is minted, stored and rotated entirely in the daemon tier;
// only the short-lived access token ever leaves. That is why the code, not the
// refresh token, crosses the CompleteConnectorAuthorization API.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CallbackPath is the daemon pre-auth route the vendor redirects the operator's
// browser back to after they approve. It mounts on the same listener as
// /.well-known/gibson-login, so it is reachable before the browser holds any
// gibson credential.
const CallbackPath = "/connectors/oauth/callback"

// DefaultPendingTTL bounds how long a started authorization waits for its
// browser round trip before the pending record is dropped. Five minutes is
// enough for a human to approve and short enough to bound the CSRF window.
const DefaultPendingTTL = 5 * time.Minute

// ---------------------------------------------------------------------------
// PKCE + state
// ---------------------------------------------------------------------------

// PKCE holds one RFC 7636 code_verifier / code_challenge pair. Method is always
// S256 — gibson never emits a plain challenge.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

// GeneratePKCE mints a fresh S256 PKCE pair. The verifier is 32 random bytes as
// base64url (43 chars), inside the RFC 7636 length window; the challenge is the
// base64url SHA-256 of the verifier.
func GeneratePKCE() (PKCE, error) {
	verifier, err := randomURLToken(32)
	if err != nil {
		return PKCE{}, fmt.Errorf("connectorauth: generate pkce verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:    "S256",
	}, nil
}

// GenerateState mints an unguessable state value (32 random bytes, base64url).
// The state is the CSRF binding between the authorize request and the callback.
func GenerateState() (string, error) {
	s, err := randomURLToken(32)
	if err != nil {
		return "", fmt.Errorf("connectorauth: generate state: %w", err)
	}
	return s, nil
}

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("connectorauth: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Pending-authorization store
// ---------------------------------------------------------------------------

// PendingAuthorization is the server-side half of one in-flight authorization.
// It is held only between StartConnectorAuthorization and the callback, keyed
// by State, and is never persisted: a lost pending record just means the
// operator starts again.
type PendingAuthorization struct {
	State              string
	Verifier           string // PKCE code_verifier
	Connector          string
	TokenEndpoint      string
	ClientID           string
	ClientSecret       string // empty for a public PKCE client
	RedirectURI        string
	Scope              string
	RevocationEndpoint string
	// AuthorizedBy is the FGA user reference of the human who started the flow,
	// captured from the authenticated Start call. AuthorizedTenant is that
	// human's tenant. Both travel with the pending so the UNAUTHENTICATED
	// callback can complete the grant under the right tenant and record the
	// right human.
	AuthorizedBy     string
	AuthorizedTenant string
	CreatedAt        time.Time
}

// PendingStore is an in-memory TTL store of in-flight authorizations, keyed by
// state. Entries expire after the TTL and are consumed on the first Take, so a
// state is single-use.
type PendingStore struct {
	mu  sync.Mutex
	m   map[string]*PendingAuthorization
	ttl time.Duration
	now func() time.Time
}

// NewPendingStore builds an empty store. A non-positive ttl uses
// DefaultPendingTTL; a nil now uses time.Now.
func NewPendingStore(ttl time.Duration, now func() time.Time) *PendingStore {
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	if now == nil {
		now = time.Now
	}
	return &PendingStore{m: map[string]*PendingAuthorization{}, ttl: ttl, now: now}
}

// Put stores a pending authorization keyed by its state, and drops any entries
// that have aged past the TTL on the way in.
func (p *PendingStore) Put(pa *PendingAuthorization) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	p.m[pa.State] = pa
}

// Take returns and removes the pending authorization for a state, or false when
// none is stored or it has expired. A state is single-use: even an expired
// entry is deleted, so a stale link cannot be replayed.
func (p *PendingStore) Take(state string) (*PendingAuthorization, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pa, ok := p.m[state]
	if !ok {
		return nil, false
	}
	delete(p.m, state)
	if p.now().Sub(pa.CreatedAt) > p.ttl {
		return nil, false
	}
	return pa, true
}

func (p *PendingStore) gcLocked() {
	cutoff := p.now().Add(-p.ttl)
	for k, v := range p.m {
		if v.CreatedAt.Before(cutoff) {
			delete(p.m, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Discovery — RFC 8414 + RFC 9728
// ---------------------------------------------------------------------------

// AuthServerMetadata is the subset of RFC 8414 authorization-server metadata
// gibson acts on. The same fields cover an OIDC discovery document.
type AuthServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// protectedResourceMetadata is the subset of RFC 9728 protected-resource
// metadata gibson reads: the authorization servers that protect the MCP
// endpoint.
type protectedResourceMetadata struct {
	AuthorizationServers []string `json:"authorization_servers"`
}

// Discover resolves a vendor's OAuth authorization-server metadata for a
// connector instance. It tries, in order:
//
//  1. RFC 9728 protected-resource metadata off the MCP endpoint, which names
//     the authorization server, then that server's RFC 8414 metadata;
//  2. RFC 8414 authorization-server metadata derived from the instance URL;
//  3. the OIDC discovery document as a last resort.
//
// The first document that carries both an authorization and a token endpoint
// wins. For gitlab.com the instance URL is https://gitlab.com and the winning
// document is https://gitlab.com/.well-known/oauth-authorization-server.
func Discover(ctx context.Context, client *http.Client, instanceURL, mcpEndpoint string) (*AuthServerMetadata, error) {
	if client == nil {
		client = defaultHTTPClient()
	}

	var candidates []string

	// 1. RFC 9728 off the MCP endpoint — the resource the daemon actually calls.
	if mcpEndpoint != "" {
		for _, prURL := range wellKnownURLs(mcpEndpoint, "oauth-protected-resource") {
			pr, err := fetchProtectedResource(ctx, client, prURL)
			if err != nil {
				continue
			}
			for _, as := range pr.AuthorizationServers {
				candidates = append(candidates, wellKnownURLs(as, "oauth-authorization-server")...)
				candidates = append(candidates, wellKnownURLs(as, "openid-configuration")...)
			}
			break
		}
	}

	// 2 + 3. RFC 8414 / OIDC derived from the instance URL.
	candidates = append(candidates, wellKnownURLs(instanceURL, "oauth-authorization-server")...)
	candidates = append(candidates, wellKnownURLs(instanceURL, "openid-configuration")...)

	var lastErr error
	for _, c := range candidates {
		meta, err := fetchAuthServerMetadata(ctx, client, c)
		if err != nil {
			lastErr = err
			continue
		}
		if meta.AuthorizationEndpoint != "" && meta.TokenEndpoint != "" {
			return meta, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no authorization-server metadata document found")
	}
	return nil, fmt.Errorf("connectorauth: discover authorization server for %q: %w", instanceURL, lastErr)
}

// wellKnownURLs returns the RFC 8414 §3.1 candidate metadata URLs for a base:
// the well-known suffix on the origin, and — when the base carries a path — the
// path-aware form with the path after the well-known suffix.
func wellKnownURLs(base, wk string) []string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	urls := []string{origin + "/.well-known/" + wk}
	if p := strings.Trim(u.Path, "/"); p != "" {
		urls = append(urls, origin+"/.well-known/"+wk+"/"+p)
	}
	return urls
}

func fetchProtectedResource(ctx context.Context, client *http.Client, u string) (*protectedResourceMetadata, error) {
	var pr protectedResourceMetadata
	if err := getJSON(ctx, client, u, &pr); err != nil {
		return nil, err
	}
	if len(pr.AuthorizationServers) == 0 {
		return nil, errors.New("connectorauth: protected-resource metadata names no authorization server")
	}
	return &pr, nil
}

func fetchAuthServerMetadata(ctx context.Context, client *http.Client, u string) (*AuthServerMetadata, error) {
	var meta AuthServerMetadata
	if err := getJSON(ctx, client, u, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("connectorauth: build metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connectorauth: fetch metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("connectorauth: read metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connectorauth: GET %s: status %d", u, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("connectorauth: decode %s: %w", u, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Dynamic client registration — RFC 7591
// ---------------------------------------------------------------------------

// clientRegistrationRequest is the RFC 7591 registration body gibson sends for a
// public PKCE client using the authorization-code grant.
type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

// ClientRegistration is the subset of the RFC 7591 registration response gibson
// keeps. ClientSecret is empty for a public client.
type ClientRegistration struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// RegisterClient performs RFC 7591 dynamic client registration for a public
// PKCE client at the discovered registration endpoint.
func RegisterClient(ctx context.Context, client *http.Client, registrationEndpoint, redirectURI, scope string) (*ClientRegistration, error) {
	if registrationEndpoint == "" {
		return nil, errors.New("connectorauth: vendor advertises no registration endpoint")
	}
	if client == nil {
		client = defaultHTTPClient()
	}
	body, err := json.Marshal(clientRegistrationRequest{
		ClientName:              "gibson-connector",
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none", // public client + PKCE
		Scope:                   scope,
	})
	if err != nil {
		return nil, fmt.Errorf("connectorauth: marshal registration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("connectorauth: build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("connectorauth: registration endpoint unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("connectorauth: read registration response")
	}
	// RFC 7591 §3.2.1: a successful registration returns 201; some servers
	// answer 200. Both are fine.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connectorauth: client registration refused (%d): %s",
			resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var reg ClientRegistration
	if err := json.Unmarshal(respBody, &reg); err != nil {
		return nil, errors.New("connectorauth: registration response is not valid JSON")
	}
	if reg.ClientID == "" {
		return nil, errors.New("connectorauth: registration response carried no client_id")
	}
	return &reg, nil
}

// ---------------------------------------------------------------------------
// Authorize URL + code exchange
// ---------------------------------------------------------------------------

// BuildAuthorizeURL renders the RFC 6749 authorization-request URL for a public
// PKCE client. Query parameters already present on the endpoint are preserved.
func BuildAuthorizeURL(authorizationEndpoint, clientID, redirectURI, scope, state, challenge string) (string, error) {
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("connectorauth: parse authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	if scope != "" {
		q.Set("scope", scope)
	}
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode redeems an authorization code for a Grant at the pending
// authorization's token endpoint, proving possession with the PKCE verifier.
// The returned Grant is ready to store and prove; the refresh token stays
// daemon-side.
func ExchangeCode(ctx context.Context, client *http.Client, pa *PendingAuthorization, code string, now func() time.Time) (*Grant, error) {
	if client == nil {
		client = defaultHTTPClient()
	}
	if now == nil {
		now = time.Now
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pa.RedirectURI},
		"client_id":     {pa.ClientID},
		"code_verifier": {pa.Verifier},
	}
	if pa.ClientSecret != "" {
		form.Set("client_secret", pa.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pa.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("connectorauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// The credential travels in the body, so the URL leaks nothing, but the
		// endpoint would leak at every retry; name the connector instead.
		return nil, fmt.Errorf("connectorauth: token endpoint unreachable for connector %q", pa.Connector)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("connectorauth: read token response for connector %q", pa.Connector)
	}
	if resp.StatusCode != http.StatusOK {
		// The body of an OAuth error is an error code, not a credential, and it
		// is the only thing that tells "denied" from "misconfigured client".
		return nil, fmt.Errorf("connectorauth: connector %q code exchange refused (%d): %s",
			pa.Connector, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("connectorauth: connector %q token response is not valid JSON", pa.Connector)
	}
	if tr.RefreshToken == "" {
		// Without a refresh token the daemon cannot own the rotation, which is
		// the whole point (ADR-0014). Request offline access on the scope.
		return nil, fmt.Errorf("connectorauth: connector %q code exchange returned no refresh_token", pa.Connector)
	}

	scope := tr.Scope
	if scope == "" {
		scope = pa.Scope
	}
	return &Grant{
		RefreshToken:       tr.RefreshToken,
		TokenEndpoint:      pa.TokenEndpoint,
		ClientID:           pa.ClientID,
		ClientSecret:       pa.ClientSecret,
		Scope:              scope,
		RevocationEndpoint: pa.RevocationEndpoint,
		AuthorizedBy:       pa.AuthorizedBy,
		AuthorizedAt:       now().UTC(),
	}, nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
