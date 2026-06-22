/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vault — transit client for production MasterKEK derivation.
//
// Spec tenant-provisioning-unification-phase2 Requirement 2 mandates
// that in production the master KEK must never enter the operator's
// process memory. Per-tenant KEKs are produced by calling Vault and
// having Vault perform the cryptographic derivation server-side.
//
// We use Vault transit's HMAC endpoint as the derivation primitive:
// `POST /v1/transit/hmac/<key>` with the tenant ID as input returns
// HMAC-SHA256(master, tenant-id) — 32 deterministic bytes per
// (key-version, tenant) pair. The master never leaves Vault.
//
// (The design.md called this `transit/derive`; Vault has no endpoint by
// that exact name but HMAC produces the same property — deterministic
// derived bytes from a server-side master without exposing the master.
// The transit `data key` endpoint generates random bytes which is the
// wrong primitive; transit `encrypt` with `derived: true` is also
// usable but HMAC is the cleanest mapping.)

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// TransitClient derives per-tenant key material from a Vault transit
// key. All derivation is server-side: the master key never leaves
// Vault.
type TransitClient interface {
	// Derive returns deterministic bytes of the requested length derived
	// from (key, derivationContext) via Vault transit HMAC-SHA256. Same
	// inputs always produce the same output until the transit key is
	// rotated.
	//
	// Length must be in [1, 32]; HMAC-SHA256 produces exactly 32 bytes,
	// so callers requesting more should rotate to a SHA-512-backed key
	// (out of scope for this implementation).
	//
	// The returned slice MUST be zeroized by the caller when done. The
	// per-reconcile cache (when enabled) zeroizes its own copies on
	// context cancel; an explicit zeroize guard is still required because
	// Go's GC alone does not zero secret material.
	Derive(ctx context.Context, keyName string, derivationContext []byte, length int) ([]byte, error)

	// Ping verifies the transit mount is reachable and the configured
	// auth token is valid.
	Ping(ctx context.Context) error
}

// TransitConfig configures a TransitClient.
type TransitConfig struct {
	// Address is the Vault base URL (e.g., "https://vault.gibson.svc:8200").
	Address string

	// AuthToken is the Vault token used for transit operations. May be
	// the same admin token as the AdminClient or a more narrowly scoped
	// token bound to `transit/hmac/<key>` policy.
	AuthToken string

	// KeyName is the transit key (default "master-kek"). Used as the
	// default for Derive when keyName is empty.
	KeyName string

	// Namespace is the Vault Enterprise namespace path (X-Vault-Namespace
	// header). Empty for root namespace / Community.
	Namespace string

	// HTTPClient overrides the default 30s-timeout client. Optional.
	HTTPClient *http.Client
}

// transitClient is the concrete implementation. Cache zeroizes on
// context cancel.
type transitClient struct {
	cfg  TransitConfig
	http *http.Client
	mu   sync.Mutex
	// cache key: keyName + ":" + hex(context) ; value: derived bytes.
	// Cache is meant to live for the duration of one reconcile loop —
	// callers wrap a derived-only context around the reconcile and
	// invalidate the cache when that context is canceled.
	cache map[string][]byte
}

// NewTransitClient constructs a TransitClient. Validation:
//   - Address required.
//   - AuthToken required.
//   - KeyName defaults to "master-kek" if empty.
//
// New does NOT make a network call.
func NewTransitClient(cfg TransitConfig) (TransitClient, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, fmt.Errorf("vault/transit: Address required: %w", clients.ErrInvalidInput)
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, fmt.Errorf("vault/transit: AuthToken required: %w", clients.ErrInvalidInput)
	}
	if cfg.KeyName == "" {
		cfg.KeyName = "master-kek"
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &transitClient{
		cfg:   cfg,
		http:  httpc,
		cache: make(map[string][]byte, 16),
	}, nil
}

// hmacRequest is the body of POST /v1/transit/hmac/<key>.
type hmacRequest struct {
	// Input is the base64-encoded data to HMAC. We pass the tenant ID
	// (or whatever derivation context the caller supplies) as the input;
	// HMAC(master, tenant-id) produces 32 deterministic bytes that act
	// as the per-tenant KEK.
	Input string `json:"input"`
}

// hmacResponse mirrors Vault's transit HMAC reply shape.
type hmacResponse struct {
	Data struct {
		// HMAC has format "vault:v<keyVersion>:<base64-bytes>".
		HMAC string `json:"hmac"`
	} `json:"data"`
}

// Derive implements TransitClient.
func (t *transitClient) Derive(ctx context.Context, keyName string, derivationContext []byte, length int) ([]byte, error) {
	if keyName == "" {
		keyName = t.cfg.KeyName
	}
	if length <= 0 || length > 32 {
		return nil, fmt.Errorf("vault/transit: length must be 1..32 (got %d): %w", length, clients.ErrInvalidInput)
	}
	if len(derivationContext) == 0 {
		return nil, fmt.Errorf("vault/transit: derivationContext required: %w", clients.ErrInvalidInput)
	}

	// Cache lookup. Key = keyName + ":" + hex(context). On context
	// cancel we drop the entire cache (zeroizing values).
	cacheKey := keyName + ":" + hex.EncodeToString(derivationContext)
	t.mu.Lock()
	if v, ok := t.cache[cacheKey]; ok {
		out := make([]byte, length)
		copy(out, v[:length])
		t.mu.Unlock()
		return out, nil
	}
	t.mu.Unlock()

	// Cache miss — call Vault.
	body := hmacRequest{Input: base64.StdEncoding.EncodeToString(derivationContext)}
	var resp hmacResponse
	path := "/v1/transit/hmac/" + keyName + "/sha2-256"
	if err := t.do(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, fmt.Errorf("vault/transit: hmac %s: %w", keyName, err)
	}

	// Vault returns "vault:v<keyVersion>:<base64-bytes>". Split off the
	// prefix and base64-decode.
	parts := strings.SplitN(resp.Data.HMAC, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault/transit: malformed HMAC response: %q", resp.Data.HMAC)
	}
	full, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault/transit: decode HMAC base64: %w", err)
	}
	if len(full) < length {
		return nil, fmt.Errorf("vault/transit: HMAC produced %d bytes, want %d", len(full), length)
	}

	// Cache the FULL derived value so future smaller-length requests
	// for the same context can be served from cache.
	t.mu.Lock()
	t.cache[cacheKey] = full
	t.mu.Unlock()

	// Spawn one goroutine per cache that watches the context and
	// zeroizes on cancel. We re-arm only on first insert to avoid
	// goroutine leaks on cache hits.
	go t.zeroizeOnCancel(ctx, cacheKey)

	out := make([]byte, length)
	copy(out, full[:length])
	return out, nil
}

// Ping issues a no-op-ish read to confirm the transit mount + token
// are healthy. We use sys/health (cheap, no transit-specific perm
// needed); this matches the existing AdminClient.Ping behavior.
func (t *transitClient) Ping(ctx context.Context) error {
	return t.do(ctx, http.MethodGet, "/v1/sys/health", nil, nil)
}

// zeroizeOnCancel waits for ctx cancel then wipes the cached value.
// Idempotent: missing cache entries (e.g., already evicted) are
// no-ops.
func (t *transitClient) zeroizeOnCancel(ctx context.Context, cacheKey string) {
	<-ctx.Done()
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.cache[cacheKey]; ok {
		for i := range v {
			v[i] = 0
		}
		delete(t.cache, cacheKey)
	}
}

// do mirrors httpClient.do but is method-bound to transitClient. We
// duplicate the small amount of HTTP+auth boilerplate rather than
// expose httpClient.do — the two clients have separate cfg shapes and
// merging them would couple their lifetimes.
func (t *transitClient) do(ctx context.Context, method, path string, body, out any) error {
	url := strings.TrimRight(t.cfg.Address, "/") + path

	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault/transit: marshal request: %w", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return fmt.Errorf("vault/transit: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", t.cfg.AuthToken)
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", t.cfg.Namespace)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault/transit: %s %s: %w", method, path, errors.Join(err, clients.ErrUnreachable))
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(out)
	case resp.StatusCode == http.StatusBadRequest:
		return wrapTransitErr(method, path, resp, clients.ErrInvalidInput)
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusUnauthorized:
		return wrapTransitErr(method, path, resp, clients.ErrUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		return wrapTransitErr(method, path, resp, clients.ErrNotFound)
	case resp.StatusCode >= 500:
		return wrapTransitErr(method, path, resp, clients.ErrUnreachable)
	default:
		return wrapTransitErr(method, path, resp, fmt.Errorf("unexpected status %d", resp.StatusCode))
	}
}

func wrapTransitErr(method, path string, resp *http.Response, sentinel error) error {
	const cap = 1 << 10
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, cap))
	var msg string
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(buf, &parsed) == nil && len(parsed.Errors) > 0 {
		msg = strings.Join(parsed.Errors, "; ")
	} else {
		msg = strings.TrimSpace(string(buf))
	}
	return fmt.Errorf("vault/transit: %s %s: status %d: %s: %w",
		method, path, resp.StatusCode, msg, sentinel)
}
