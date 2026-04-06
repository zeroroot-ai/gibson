package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// DaemonJWKSCache caches JSON Web Key Sets with TTL-based expiration.
//
// Thread-safe for concurrent access. Keys are cached per issuer and
// identified by key ID (kid). Supports both HTTPS and HTTP URLs
// (internal Keycloak runs on HTTP within the cluster).
type DaemonJWKSCache struct {
	entries map[string]*daemonJWKSEntry
	mu      sync.RWMutex
	client  *http.Client
	ttl     time.Duration
}

type daemonJWKSEntry struct {
	keys      map[string]any // kid -> *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt time.Time
	expiresAt time.Time
}

type jwksResponsePayload struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// NewDaemonJWKSCache creates a new JWKS cache with the specified TTL.
func NewDaemonJWKSCache(ttl time.Duration) *DaemonJWKSCache {
	return &DaemonJWKSCache{
		entries: make(map[string]*daemonJWKSEntry),
		client:  &http.Client{Timeout: 10 * time.Second},
		ttl:     ttl,
	}
}

// GetKey retrieves a public key from the cache or fetches it.
//
// Returns the public key (*rsa.PublicKey or *ecdsa.PublicKey) or a
// descriptive error including the kid and available keys.
func (c *DaemonJWKSCache) GetKey(ctx context.Context, issuer, kid, jwksURL string) (any, error) {
	// Check cache (read lock)
	c.mu.RLock()
	entry, exists := c.entries[issuer]
	if exists && time.Now().Before(entry.expiresAt) {
		if key, ok := entry.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Cache miss — fetch (write lock)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after lock
	entry, exists = c.entries[issuer]
	if exists && time.Now().Before(entry.expiresAt) {
		if key, ok := entry.keys[kid]; ok {
			return key, nil
		}
	}

	// Fetch JWKS
	if err := c.fetchLocked(ctx, issuer, jwksURL); err != nil {
		return nil, fmt.Errorf("jwks_fetch_failed: GET %s: %w", jwksURL, err)
	}

	// Retry lookup
	entry = c.entries[issuer]
	if key, ok := entry.keys[kid]; ok {
		return key, nil
	}

	// Key not found — list available keys for debugging
	available := make([]string, 0, len(entry.keys))
	for k := range entry.keys {
		available = append(available, k)
	}
	return nil, fmt.Errorf("unknown_key_id: kid=%s not found in JWKS for issuer %s (available keys: %v)", kid, issuer, available)
}

func (c *DaemonJWKSCache) fetchLocked(ctx context.Context, issuer, jwksURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var jwksResp jwksResponsePayload
	if err := json.Unmarshal(body, &jwksResp); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	keys := make(map[string]any)
	for _, k := range jwksResp.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		var pubKey any
		var parseErr error

		switch k.Kty {
		case "RSA":
			pubKey, parseErr = parseRSAPublicKey(k)
		case "EC":
			pubKey, parseErr = parseECPublicKey(k)
		default:
			continue
		}

		if parseErr != nil {
			continue
		}
		keys[k.Kid] = pubKey
	}

	now := time.Now()
	c.entries[issuer] = &daemonJWKSEntry{
		keys:      keys,
		fetchedAt: now,
		expiresAt: now.Add(c.ttl),
	}

	return nil
}

func parseRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func parseECPublicKey(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode Y: %w", err)
	}

	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}

	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
}
