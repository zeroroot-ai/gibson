// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package vault is platform-operator's internal Vault HTTP client.
// Owns the minimum API surface for PlatformBootstrap's vault-transit
// init step: ensure the transit secret engine is mounted and the named
// key exists.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrNotFound    = errors.New("vault: not found")
	ErrUnreachable = errors.New("vault: unreachable")
	ErrInvalid     = errors.New("vault: invalid input")
)

// Client is the Vault HTTP client surface.
type Client interface {
	// EnsureTransitMounted mounts the transit secret engine at the
	// "transit/" path. Idempotent (409 = already mounted = success).
	EnsureTransitMounted(ctx context.Context) error

	// EnsureTransitKey creates a transit encryption key with the given
	// name. Idempotent (409 = already exists = success).
	EnsureTransitKey(ctx context.Context, keyName string) error
}

// TokenFunc is a function that returns the current Vault admin token. It is
// called on every API request so that a lease-renewing token source (e.g.
// vaulttoken.Renewer) can supply a fresh-enough token without requiring a
// new Client to be constructed after each renewal.
type TokenFunc func() (string, error)

// New returns an HTTP client at the given base URL that fetches its
// authentication token from tokenFn on every request. The token function is
// called exactly once per HTTP request; a non-nil error aborts the call with
// that error.
//
// Callers that previously passed a static string should wrap it:
//
//	vault.New(apiURL, func() (string, error) { return myToken, nil })
func New(apiURL string, tokenFn TokenFunc) (Client, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid apiURL %q: %w", apiURL, ErrInvalid)
	}
	if tokenFn == nil {
		return nil, fmt.Errorf("vault: nil tokenFn: %w", ErrInvalid)
	}
	return &httpClient{
		baseURL: u,
		tokenFn: tokenFn,
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type httpClient struct {
	baseURL *url.URL
	tokenFn TokenFunc
	http    *http.Client
}

func (c *httpClient) EnsureTransitMounted(ctx context.Context) error {
	body := map[string]any{
		"type":        "transit",
		"description": "gibson platform transit engine",
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/sys/mounts/transit", body, nil)
	if err != nil && isAlreadyMounted(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("EnsureTransitMounted: %w", err)
	}
	return nil
}

func (c *httpClient) EnsureTransitKey(ctx context.Context, keyName string) error {
	path := fmt.Sprintf("/v1/transit/keys/%s", url.PathEscape(keyName))
	body := map[string]any{
		"type":       "aes256-gcm96",
		"derived":    false,
		"exportable": false,
	}
	err := c.doJSON(ctx, http.MethodPost, path, body, nil)
	if err != nil {
		// Vault returns 204 No Content on first create AND on subsequent
		// no-op (because POST is idempotent by spec). Any non-success is
		// a real error.
		return fmt.Errorf("EnsureTransitKey %q: %w", keyName, err)
	}
	return nil
}

func isAlreadyMounted(err error) bool {
	if err == nil {
		return false
	}
	return errorsContains(err, "path is already in use")
}

func errorsContains(err error, sub string) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (c *httpClient) doJSON(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: marshal: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	full, err := c.baseURL.Parse(path)
	if err != nil {
		return fmt.Errorf("vault: path %q: %w", path, ErrInvalid)
	}
	req, err := http.NewRequestWithContext(ctx, method, full.String(), rdr)
	if err != nil {
		return fmt.Errorf("vault: new request: %w", err)
	}
	tok, err := c.tokenFn()
	if err != nil {
		return fmt.Errorf("vault: token unavailable: %w", err)
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, out)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("vault %s %s 404: %w", method, path, ErrNotFound)
	}
	return fmt.Errorf("vault %s %s %d: %s", method, path, resp.StatusCode, string(raw))
}
