// Package cgjwt verifies daemon-minted capability-grant JWTs (CG-JWTs)
// presented by agents on harness callbacks. The actual JWT parsing and
// claim validation lives in the SDK (sdk/capabilitygrant); this
// package adds an HTTP-backed JWKS fetcher with caching tailored to
// ext-authz's request-path latency budget.
//
// Spec: unified-identity-and-authorization Requirements 5.4-5.7.
//
// Layered defense for non-plugin secret isolation: this verifier is
// Layer 4 of the structural guarantee that only plugin recipients can
// reach a tenant credential value. It is independent of Layer 3 (the
// daemon's CG-JWT minter, which refuses to issue secret-resolution
// grants to non-plugin recipients in the first place). Even a CG-JWT
// signed with the daemon's KMS key but carrying a forged
// non-plugin recipient class would be refused here because the FGA
// tuple set the tenant-operator writes (per non-plugin-secret-
// isolation Requirement 3 and secrets-broker Requirement 8) does not
// include a (agent_principal|tool_principal, can_resolve, secret:*)
// row. The two layers fail independently and either alone is enough
// to enforce the property; they exist in concert by design. Cross-
// reference: secrets-broker R8 and non-plugin-secret-isolation R6.
package cgjwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Verifier verifies CG-JWTs against a JWKS endpoint published by the
// Gibson daemon at /.well-known/jwks.json. It caches keys for the
// configured TTL and refetches transparently when a kid is unknown
// or when the cache expires.
//
// Verifier is safe for concurrent use.
type Verifier struct {
	jwksURL          string
	httpClient       *http.Client
	ttl              time.Duration
	expectedIssuer   string
	expectedAudience string

	mu       sync.RWMutex
	cache    map[string]ed25519.PublicKey // kid -> public key
	cacheExp time.Time
}

// Config configures a Verifier at construction.
type Config struct {
	// JWKSURL is the daemon's published JWKS endpoint, e.g.
	// "https://api.zeroroot.ai/.well-known/jwks.json". Required.
	JWKSURL string

	// TTL controls how long fetched keys are cached. Default 1 hour
	// per Requirement 5.7.
	TTL time.Duration

	// HTTPClient is used to fetch the JWKS. Defaults to a client
	// with a 5-second timeout when nil.
	HTTPClient *http.Client

	// ExpectedIssuer is the iss value CG-JWTs must carry. Required;
	// matches the daemon's CG authority URL.
	ExpectedIssuer string

	// ExpectedAudience is the aud value CG-JWTs must carry.
	// Required; the daemon's identifier ("gibson-daemon" by default).
	ExpectedAudience string
}

// NewVerifier constructs a Verifier. Returns an error if required
// configuration is missing.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("cgjwt: JWKSURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("cgjwt: ExpectedIssuer required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("cgjwt: ExpectedAudience required")
	}
	v := &Verifier{
		jwksURL:          cfg.JWKSURL,
		ttl:              cfg.TTL,
		httpClient:       cfg.HTTPClient,
		expectedIssuer:   cfg.ExpectedIssuer,
		expectedAudience: cfg.ExpectedAudience,
		cache:            map[string]ed25519.PublicKey{},
	}
	if v.ttl <= 0 {
		v.ttl = time.Hour
	}
	if v.httpClient == nil {
		v.httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return v, nil
}

// Verify parses, signature-checks, and structurally validates a
// capability-grant JWT. Delegates the heavy lifting to
// capabilitygrant.Verify in the SDK; this method's job is to bridge
// the SDK's JWKSFetcher interface to the HTTP+cache backing.
func (v *Verifier) Verify(ctx context.Context, token string) (capabilitygrant.Claims, error) {
	return capabilitygrant.Verify(ctx, jwksFetcher{v: v}, token, capabilitygrant.VerifyOptions{
		ExpectedIssuer:   v.expectedIssuer,
		ExpectedAudience: v.expectedAudience,
	})
}

// jwksFetcher adapts Verifier to the SDK's JWKSFetcher interface.
type jwksFetcher struct{ v *Verifier }

func (f jwksFetcher) Fetch(ctx context.Context, kid string) (any, error) {
	// First try the cache.
	f.v.mu.RLock()
	if time.Now().Before(f.v.cacheExp) {
		if k, ok := f.v.cache[kid]; ok {
			f.v.mu.RUnlock()
			cgjwtCacheHits.Inc()
			return k, nil
		}
	}
	f.v.mu.RUnlock()

	// Miss: refetch.
	cgjwtCacheMisses.Inc()
	if err := f.v.refresh(ctx); err != nil {
		return nil, fmt.Errorf("cgjwt: refresh JWKS: %w", err)
	}

	f.v.mu.RLock()
	defer f.v.mu.RUnlock()
	if k, ok := f.v.cache[kid]; ok {
		return k, nil
	}
	cgjwtUnknownKid.Inc()
	return nil, fmt.Errorf("cgjwt: unknown kid %q", kid)
}

// refresh fetches the JWKS from the daemon and replaces the cached
// keys. Held under a single in-flight guard to prevent thundering herd.
var refreshLock sync.Mutex

func (v *Verifier) refresh(ctx context.Context) error {
	refreshLock.Lock()
	defer refreshLock.Unlock()

	// Double-check after acquiring lock — another goroutine may have
	// refreshed while we waited.
	v.mu.RLock()
	if time.Now().Before(v.cacheExp) && len(v.cache) > 0 {
		v.mu.RUnlock()
		return nil
	}
	v.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	v.mu.Lock()
	v.cache = keys
	v.cacheExp = time.Now().Add(v.ttl)
	v.mu.Unlock()
	cgjwtJWKSRefreshTotal.Inc()
	return nil
}

// jwk is the on-the-wire JWK shape for Ed25519 public keys (OKP key
// type, Ed25519 curve). We support only this type because the
// daemon's CG-JWT signing is EdDSA-only.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

func parseJWKS(body []byte) (map[string]ed25519.PublicKey, error) {
	var s jwkSet
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range s.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			// Skip non-Ed25519 keys silently; the daemon may publish
			// other algs in the future for other purposes.
			continue
		}
		if k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("kid %q: bad x: %w", k.Kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("kid %q: ed25519 key length %d != %d", k.Kid, len(raw), ed25519.PublicKeySize)
		}
		out[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS contains no usable Ed25519 keys")
	}
	return out, nil
}

var (
	cgjwtCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_cache_hits_total",
		Help: "Capability-grant JWKS cache hits.",
	})
	cgjwtCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_cache_misses_total",
		Help: "Capability-grant JWKS cache misses (caused a refetch).",
	})
	cgjwtUnknownKid = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_unknown_kid_total",
		Help: "Capability-grant JWKS lookups that found no matching kid after refetch.",
	})
	cgjwtJWKSRefreshTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_jwks_refresh_total",
		Help: "Capability-grant JWKS refetches.",
	})
)
