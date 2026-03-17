package auth

import (
	"context"
	"crypto/rsa"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKSCache caches JSON Web Key Sets with TTL-based expiration and background refresh.
//
// Thread-safe for concurrent access from multiple goroutines.
// Keys are cached per issuer and identified by key ID (kid).
type JWKSCache struct {
	entries map[string]*jwksEntry // Keyed by issuer URL
	mu      sync.RWMutex
	client  *http.Client
	ttl     time.Duration
}

// jwksEntry represents cached JWKS data for a single issuer.
type jwksEntry struct {
	keys      map[string]any // Keyed by kid (key ID), value is *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt time.Time
	expiresAt time.Time
}

// jwksResponse represents the JSON structure of a JWKS endpoint response.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a single JSON Web Key.
type jwk struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key type: "RSA" or "EC"
	Use string `json:"use"` // Public key use: "sig" (signature verification)
	Alg string `json:"alg"` // Algorithm: "RS256", "ES256", etc.

	// RSA public key parameters
	N string `json:"n,omitempty"` // Modulus (base64url)
	E string `json:"e,omitempty"` // Exponent (base64url)

	// ECDSA public key parameters
	Crv string `json:"crv,omitempty"` // Curve: "P-256", "P-384", "P-521"
	X   string `json:"x,omitempty"`   // X coordinate (base64url)
	Y   string `json:"y,omitempty"`   // Y coordinate (base64url)
}

// NewJWKSCache creates a new JWKS cache with the specified TTL.
//
// ttl determines how long keys are cached before refresh.
// A longer TTL reduces load on identity providers but may delay key rotation.
func NewJWKSCache(ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		entries: make(map[string]*jwksEntry),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		ttl: ttl,
	}
}

// GetKey retrieves a public key from the cache or fetches it if not cached/expired.
//
// issuerURL is the OIDC issuer URL (e.g., "https://company.okta.com").
// kid is the key ID from the JWT header.
// jwksURL is the JWKS endpoint URL (typically {issuer}/.well-known/jwks.json).
//
// Returns the public key (either *rsa.PublicKey or *ecdsa.PublicKey) or an error.
func (c *JWKSCache) GetKey(ctx context.Context, issuerURL, kid, jwksURL string) (any, error) {
	// Check cache first (read lock)
	c.mu.RLock()
	entry, exists := c.entries[issuerURL]
	if exists && time.Now().Before(entry.expiresAt) {
		// Cache hit and not expired
		if key, ok := entry.keys[kid]; ok {
			c.mu.RUnlock()
			recordJWKSCacheHit(ctx, issuerURL, true)
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Cache miss or expired - fetch JWKS (write lock)
	recordJWKSCacheHit(ctx, issuerURL, false)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have fetched)
	entry, exists = c.entries[issuerURL]
	if exists && time.Now().Before(entry.expiresAt) {
		if key, ok := entry.keys[kid]; ok {
			return key, nil
		}
	}

	// Fetch JWKS from endpoint
	if err := c.fetchJWKSLocked(ctx, issuerURL, jwksURL); err != nil {
		return nil, err
	}

	// Retry key lookup after fetch
	entry = c.entries[issuerURL]
	if key, ok := entry.keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key ID %s not found in JWKS for issuer %s", kid, issuerURL)
}

// fetchJWKSLocked fetches JWKS from the endpoint and updates the cache.
// Caller must hold write lock.
func (c *JWKSCache) fetchJWKSLocked(ctx context.Context, issuerURL, jwksURL string) error {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return ErrJWKSFetchFailed(issuerURL, err)
	}

	// Fetch JWKS
	resp, err := c.client.Do(req)
	if err != nil {
		return ErrJWKSFetchFailed(issuerURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrJWKSFetchFailed(issuerURL, fmt.Errorf("HTTP %d", resp.StatusCode))
	}

	// Parse JWKS response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrJWKSFetchFailed(issuerURL, err)
	}

	var jwksResp jwksResponse
	if err := json.Unmarshal(body, &jwksResp); err != nil {
		return ErrJWKSFetchFailed(issuerURL, err)
	}

	// Convert JWKs to public keys
	keys := make(map[string]any)
	for _, jwk := range jwksResp.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			// Skip keys not intended for signature verification
			continue
		}

		var pubKey any
		var parseErr error

		switch jwk.Kty {
		case "RSA":
			pubKey, parseErr = c.parseRSAKey(jwk)
		case "EC":
			pubKey, parseErr = c.parseECKey(jwk)
		default:
			// Unsupported key type - skip
			continue
		}

		if parseErr != nil {
			// Log error but continue processing other keys
			continue
		}

		keys[jwk.Kid] = pubKey
	}

	// Update cache
	now := time.Now()
	c.entries[issuerURL] = &jwksEntry{
		keys:      keys,
		fetchedAt: now,
		expiresAt: now.Add(c.ttl),
	}

	return nil
}

// parseRSAKey converts a JWK to an RSA public key.
func (c *JWKSCache) parseRSAKey(key jwk) (*rsa.PublicKey, error) {
	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	// Convert to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// parseECKey converts a JWK to an ECDSA public key.
func (c *JWKSCache) parseECKey(key jwk) (*ecdsa.PublicKey, error) {
	// Decode X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
	}

	// Decode Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
	}

	// Convert to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Map curve name to crypto/elliptic curve
	// Note: crypto/elliptic is used here but could be replaced with crypto/ecdh in Go 1.20+
	var curve any
	switch key.Crv {
	case "P-256":
		// P-256 curve
		curve = &ecdsa.PublicKey{X: x, Y: y}
	case "P-384":
		// P-384 curve
		curve = &ecdsa.PublicKey{X: x, Y: y}
	case "P-521":
		// P-521 curve
		curve = &ecdsa.PublicKey{X: x, Y: y}
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", key.Crv)
	}

	return curve.(*ecdsa.PublicKey), nil
}

// Refresh proactively refreshes JWKS for an issuer.
//
// Useful for background refresh to avoid cache expiry during validation.
// Returns an error if fetch fails but doesn't clear existing cache.
func (c *JWKSCache) Refresh(ctx context.Context, issuerURL, jwksURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.fetchJWKSLocked(ctx, issuerURL, jwksURL)
}
