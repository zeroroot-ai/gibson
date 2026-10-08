// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

const (
	// DefaultSystemKeyPath is the mount point the chart guarantees for the
	// SYSTEM_OWNER RSA private key. Overridable via ZITADEL_SYSTEM_KEY_PATH.
	DefaultSystemKeyPath = "/etc/zitadel-system/private-key.pem"

	// SystemUserFile is the file, next to the private key, that names the
	// System API user the key belongs to. The chart projects the key and the
	// user of the active slot together, so a rotation that moves to the
	// other user moves both at once (ADR-0171, row platform-generated-secrets).
	SystemUserFile = "user"

	// systemJWTTTL is how long each signed JWT assertion remains valid.
	// The JWT is used directly as the System API bearer token; short TTL
	// keeps replay windows tight, the client caches one signed assertion
	// for ~TTL-10s before re-signing.
	systemJWTTTL = 60 * time.Second
)

// SystemClient is the Zitadel System API surface the platform-operator needs
// to mint the Zitadel admin token (gibson#794). Authentication is via a
// signed JWT assertion (RFC 7523) using the RSA private key provisioned at
// chart install time for the SYSTEM_OWNER machine user.
//
// Unlike the Admin-API Client (PAT-based), SystemClient caches the access
// token in memory and refreshes it automatically when it expires.
type SystemClient interface {
	// MintAdminToken mints a personal access token for the IAM_OWNER machine
	// user userName of the default organization, and creates that user and its
	// IAM_OWNER membership when they do not exist (gibson#794). The system
	// user needs the System roles SYSTEM_OWNER and IAM_OWNER; no admin token
	// has to exist before. It returns the user id and the token.
	MintAdminToken(ctx context.Context, userName string, expires time.Time) (userID string, tok PAT, err error)

	// AdminTokenValid reports whether pat still authorizes an admin call. A
	// refused token is (false, nil); a transport fault is an error.
	AdminTokenValid(ctx context.Context, pat string) (bool, error)

	// MintUserToken mints a personal access token for the machine user
	// userName of the default organization, which must exist. It creates no
	// user and grants no role. It returns the user id and the token.
	MintUserToken(ctx context.Context, userName string, expires time.Time) (userID string, tok PAT, err error)

	// TokenValid reports whether pat still authenticates any call (the
	// caller's own user). A refused token is (false, nil).
	TokenValid(ctx context.Context, pat string) (bool, error)

	// RemoveOtherTokens removes each personal access token of the user userID
	// of the default organization except keepID, and returns how many it
	// removed (ADR-0171: the last step of a token rotation).
	RemoveOtherTokens(ctx context.Context, userID, keepID string) (int, error)
}

// PAT is one personal access token: the id Zitadel lists it under, and the
// secret, which Zitadel returns only when it mints the token.
type PAT struct {
	ID    string
	Token string
}

// NewSystemClient constructs a SystemClient.
//
// connectURL is the in-cluster Zitadel Service base URL (for example
// "http://gibson-zitadel.gibson.svc.cluster.local:8080") and externalDomain is
// the public host the client claims. Both go through zitadelconn (ADR-0092):
// every request carries the x-zitadel-instance-host header, and no request
// sets the Host header by hand. A ported externalDomain is refused, which
// also keeps the JWT audience portless (see audience).
//
// systemUserName is the SYSTEM_OWNER machine user name used as JWT iss/sub.
// keyPath is the file-system path of the RSA private key PEM; pass "" to fall
// back to DefaultSystemKeyPath / ZITADEL_SYSTEM_KEY_PATH env.
func NewSystemClient(connectURL, systemUserName, externalDomain, keyPath string) (SystemClient, error) {
	keyPath = ResolveSystemKeyPath(keyPath)

	key, err := loadRSAKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("zitadel system client: load key %q: %w", keyPath, err)
	}

	ep, err := zitadelconn.New(connectURL, externalDomain)
	if err != nil {
		return nil, fmt.Errorf("zitadel system client: %w: %w", err, ErrInvalidInput)
	}
	return &systemHTTPClient{
		endpoint:       ep,
		systemUserName: systemUserName,
		audience:       "https://" + ep.Host(),
		key:            key,
		http:           ep.HTTPClient(requestTimeout),
	}, nil
}

// ResolveSystemKeyPath returns keyPath, or ZITADEL_SYSTEM_KEY_PATH when keyPath
// is empty, or DefaultSystemKeyPath when both are empty.
func ResolveSystemKeyPath(keyPath string) string {
	if keyPath == "" {
		keyPath = os.Getenv("ZITADEL_SYSTEM_KEY_PATH")
	}
	if keyPath == "" {
		keyPath = DefaultSystemKeyPath
	}
	return keyPath
}

// ReadSystemUser returns the System API user name from the SystemUserFile
// next to the private key at keyPath (resolved as ResolveSystemKeyPath does).
// A missing or empty file is an error: the key alone does not say which user
// it signs for.
func ReadSystemUser(keyPath string) (string, error) {
	path := filepath.Clean(filepath.Join(filepath.Dir(ResolveSystemKeyPath(keyPath)), SystemUserFile))
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("zitadel system user: read %q: %w", path, err)
	}
	name := strings.TrimSpace(string(raw))
	if name == "" {
		return "", fmt.Errorf("zitadel system user: %q is empty: %w", path, ErrInvalidInput)
	}
	return name, nil
}

// LoadRSAKey reads and parses an RSA private key PEM file. Exported so
// cmd/main.go can perform the readyz check without constructing a full client.
func LoadRSAKey(path string) (*rsa.PrivateKey, error) {
	return loadRSAKey(path)
}

func loadRSAKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// systemHTTPClient implements SystemClient.
type systemHTTPClient struct {
	endpoint       zitadelconn.Endpoint
	systemUserName string
	// audience is the JWT aud claim: the portless public origin
	// "https://<ZITADEL_EXTERNAL_DOMAIN>". Zitadel requires the exact string,
	// and a port in it made every System API call answer 401 (deploy#1633).
	// It is a claimed string and is never dialed.
	audience string
	key      *rsa.PrivateKey
	http     *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// token returns a valid bearer token, refreshing if the cached copy has
// expired (or never existed).
//
// Zitadel's System API ("/system/v1/*") authenticates via a self-signed
// JWT carried directly in `Authorization: Bearer …` — NOT via the OIDC
// token-exchange endpoint. This client previously POSTed the assertion
// to `/oauth/v2/token` with `grant_type=urn:ietf:params:oauth:grant-
// type:jwt-bearer`, which routes through Zitadel's per-instance OIDC
// flow and fails with `Errors.AuthNKey.NotFound` because SystemAPIUsers
// are config-loaded (no per-instance authn_keys2 row).
//
// Authoritative reference:
// https://zitadel.com/docs/guides/integrate/zitadel-apis/access-zitadel-system-api
func (c *systemHTTPClient) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}
	tok, expiry, err := c.mintAssertion()
	if err != nil {
		return "", err
	}
	c.cachedToken = tok
	c.tokenExpiry = expiry
	_ = ctx
	return tok, nil
}

// mintAssertion produces a fresh self-signed JWT for direct use as the
// `Authorization: Bearer …` header on Zitadel System API calls. No HTTP
// round-trip — Zitadel verifies the signature against the public key
// loaded from the SystemAPIUsers config block on every request.
func (c *systemHTTPClient) mintAssertion() (string, time.Time, error) {
	aud := c.audience

	now := time.Now()
	exp := now.Add(systemJWTTTL)

	assertion, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": c.systemUserName,
		"sub": c.systemUserName,
		"aud": aud,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}).SignedString(c.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign JWT: %w", err)
	}

	// Shave 10 s off expiry so we refresh before the JWT actually expires
	// under load.
	return assertion, exp.Add(-10 * time.Second), nil
}

// doJSON issues an authenticated JSON request using a Bearer token and
// decodes the response into out (or discards when out==nil). Maps HTTP
// status codes to the same sentinel errors used by the PAT-based client.
func (c *systemHTTPClient) doJSON(ctx context.Context, token, method, path string, body, out any) error {
	return c.doJSONOrg(ctx, token, "", method, path, body, out)
}

// doJSONOrg is doJSON with the organization of a Management API call in the
// x-zitadel-orgid header. An empty orgID sends no header.
func (c *systemHTTPClient) doJSONOrg(ctx context.Context, token, orgID, method, path string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("zitadel system: marshal body: %w: %w", err, ErrInvalidInput)
		}
		bodyReader = bytes.NewReader(buf)
	}

	full, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("zitadel system: path %q: %w", path, ErrInvalidInput)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint.URL(full.RequestURI()), bodyReader)
	if err != nil {
		return fmt.Errorf("zitadel system: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel system: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("zitadel system: decode %s %s: %w", method, path, err)
		}
		return nil
	}

	switch {
	case resp.StatusCode == 404:
		return fmt.Errorf("zitadel system %s %s 404: %w", method, path, ErrNotFound)
	case resp.StatusCode == 409:
		return fmt.Errorf("zitadel system %s %s 409: %w", method, path, ErrAlreadyExists)
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return WrapPermanent(fmt.Errorf("zitadel system %d: %w: %s",
			resp.StatusCode, ErrUnauthorized, string(raw)))
	case resp.StatusCode == 429:
		return fmt.Errorf("zitadel system %d: %w", resp.StatusCode, ErrRateLimited)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("zitadel system %d: %w: %s",
			resp.StatusCode, ErrInvalidInput, string(raw))
	default:
		return fmt.Errorf("zitadel system %d: %w: %s",
			resp.StatusCode, ErrUnreachable, string(raw))
	}
}

// isAlreadyExistsBody reports whether the error message text contains
// "already exists" or "AlreadyExists", covering Zitadel 400-level
// responses that signal idempotency without using HTTP 409.
func isAlreadyExistsBody(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "AlreadyExists") ||
		strings.Contains(msg, "ALREADY_EXISTS")
}

// MintAdminToken implements SystemClient. Each step was proven on Zitadel
// v4.19.4 with a system user that holds the System roles SYSTEM_OWNER and
// IAM_OWNER (gibson#794).
func (c *systemHTTPClient) MintAdminToken(
	ctx context.Context, userName string, expires time.Time,
) (userID string, tok PAT, err error) {
	if userName == "" {
		return "", PAT{}, fmt.Errorf("zitadel system: MintAdminToken: user name is required: %w", ErrInvalidInput)
	}
	access, orgID, err := c.tokenAndDefaultOrg(ctx)
	if err != nil {
		return "", PAT{}, err
	}
	userID, err = c.ensureMachineUser(ctx, access, orgID, userName)
	if err != nil {
		return "", PAT{}, err
	}
	member := map[string]any{"userId": userID, "roles": []string{"IAM_OWNER"}}
	if err := c.doJSON(ctx, access, http.MethodPost, "/admin/v1/members", member, nil); err != nil &&
		!errors.Is(err, ErrAlreadyExists) && !isAlreadyExistsBody(err) {
		return "", PAT{}, fmt.Errorf("zitadel system: IAM_OWNER membership of %s: %w", userName, err)
	}
	tok, err = c.mintPAT(ctx, access, orgID, userID, userName, expires)
	if err != nil {
		return "", PAT{}, err
	}
	return userID, tok, nil
}

// MintUserToken implements SystemClient.
func (c *systemHTTPClient) MintUserToken(
	ctx context.Context, userName string, expires time.Time,
) (userID string, tok PAT, err error) {
	if userName == "" {
		return "", PAT{}, fmt.Errorf("zitadel system: MintUserToken: user name is required: %w", ErrInvalidInput)
	}
	access, orgID, err := c.tokenAndDefaultOrg(ctx)
	if err != nil {
		return "", PAT{}, err
	}
	userID, err = c.findMachineUser(ctx, access, orgID, userName)
	if err != nil {
		return "", PAT{}, err
	}
	if userID == "" {
		return "", PAT{}, fmt.Errorf("zitadel system: machine user %s does not exist: %w", userName, ErrNotFound)
	}
	tok, err = c.mintPAT(ctx, access, orgID, userID, userName, expires)
	if err != nil {
		return "", PAT{}, err
	}
	return userID, tok, nil
}

// TokenValid implements SystemClient.
func (c *systemHTTPClient) TokenValid(ctx context.Context, pat string) (bool, error) {
	if pat == "" {
		return false, nil
	}
	err := c.doJSON(ctx, pat, http.MethodGet, "/auth/v1/users/me", nil, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrUnauthorized):
		return false, nil
	default:
		return false, err
	}
}

// RemoveOtherTokens implements SystemClient.
func (c *systemHTTPClient) RemoveOtherTokens(ctx context.Context, userID, keepID string) (int, error) {
	if userID == "" || keepID == "" {
		return 0, fmt.Errorf("zitadel system: RemoveOtherTokens: user id and kept token id are required: %w", ErrInvalidInput)
	}
	tok, orgID, err := c.tokenAndDefaultOrg(ctx)
	if err != nil {
		return 0, err
	}
	var listed struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	userPath := "/management/v1/users/" + url.PathEscape(userID) + "/pats"
	if err := c.doJSONOrg(ctx, tok, orgID, http.MethodPost, userPath+"/_search", map[string]any{}, &listed); err != nil {
		return 0, fmt.Errorf("zitadel system: list the personal access tokens of %s: %w", userID, err)
	}
	removed := 0
	for _, p := range listed.Result {
		if p.ID == "" || p.ID == keepID {
			continue
		}
		err := c.doJSONOrg(ctx, tok, orgID, http.MethodDelete, userPath+"/"+url.PathEscape(p.ID), nil, nil)
		switch {
		case errors.Is(err, ErrNotFound):
			// Gone already, which is the goal. Not counted.
		case err != nil:
			return removed, fmt.Errorf("zitadel system: remove personal access token %s of %s: %w", p.ID, userID, err)
		default:
			removed++
		}
	}
	return removed, nil
}

// tokenAndDefaultOrg returns the System API access token and the id of the
// default organization.
func (c *systemHTTPClient) tokenAndDefaultOrg(ctx context.Context) (access, orgID string, err error) {
	access, err = c.token(ctx)
	if err != nil {
		return "", "", err
	}
	var org struct {
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
	}
	if err := c.doJSON(ctx, access, http.MethodGet, "/admin/v1/orgs/default", nil, &org); err != nil {
		return "", "", fmt.Errorf("zitadel system: default org: %w", err)
	}
	if org.Org.ID == "" {
		return "", "", fmt.Errorf("zitadel system: default org has no id: %w", ErrNotFound)
	}
	return access, org.Org.ID, nil
}

// mintPAT mints a personal access token for the user userID.
func (c *systemHTTPClient) mintPAT(
	ctx context.Context, tok, orgID, userID, userName string, expires time.Time,
) (PAT, error) {
	var minted struct {
		TokenID string `json:"tokenId"`
		Token   string `json:"token"`
	}
	body := map[string]any{"expirationDate": expires.UTC().Format(time.RFC3339)}
	if err := c.doJSONOrg(ctx, tok, orgID, http.MethodPost,
		"/management/v1/users/"+url.PathEscape(userID)+"/pats", body, &minted); err != nil {
		return PAT{}, fmt.Errorf("zitadel system: personal access token of %s: %w", userName, err)
	}
	if minted.Token == "" || minted.TokenID == "" {
		return PAT{}, fmt.Errorf("zitadel system: the personal access token of %s has no token or no id: %w", userName, ErrInvalidInput)
	}
	return PAT{ID: minted.TokenID, Token: minted.Token}, nil
}

// ensureMachineUser returns the id of the machine user userName of the
// organization orgID, and creates the user when it does not exist.
func (c *systemHTTPClient) ensureMachineUser(ctx context.Context, tok, orgID, userName string) (string, error) {
	id, err := c.findMachineUser(ctx, tok, orgID, userName)
	if err != nil || id != "" {
		return id, err
	}
	create := map[string]any{"userName": userName, "name": userName, "accessTokenType": "ACCESS_TOKEN_TYPE_BEARER"}
	var created struct {
		UserID string `json:"userId"`
	}
	if err := c.doJSONOrg(ctx, tok, orgID, http.MethodPost, "/management/v1/users/machine", create, &created); err != nil {
		return "", fmt.Errorf("zitadel system: create machine user %s: %w", userName, err)
	}
	if created.UserID == "" {
		return "", fmt.Errorf("zitadel system: machine user %s has no id: %w", userName, ErrInvalidInput)
	}
	return created.UserID, nil
}

// findMachineUser returns the id of the user userName of the organization
// orgID, or "" when no such user exists.
func (c *systemHTTPClient) findMachineUser(ctx context.Context, tok, orgID, userName string) (string, error) {
	search := map[string]any{"queries": []any{map[string]any{
		"userNameQuery": map[string]any{"userName": userName, "method": "TEXT_QUERY_METHOD_EQUALS"},
	}}}
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := c.doJSONOrg(ctx, tok, orgID, http.MethodPost, "/management/v1/users/_search", search, &found); err != nil {
		return "", fmt.Errorf("zitadel system: search user %s: %w", userName, err)
	}
	if len(found.Result) > 0 && found.Result[0].ID != "" {
		return found.Result[0].ID, nil
	}
	return "", nil
}

// AdminTokenValid implements SystemClient.
func (c *systemHTTPClient) AdminTokenValid(ctx context.Context, pat string) (bool, error) {
	if pat == "" {
		return false, nil
	}
	err := c.doJSON(ctx, pat, http.MethodGet, "/admin/v1/orgs/default", nil, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrUnauthorized):
		return false, nil
	default:
		return false, err
	}
}
