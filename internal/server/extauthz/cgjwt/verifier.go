// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package cgjwt verifies daemon-minted capability-grant JWTs (CG-JWTs)
// presented by agents on harness callbacks. The actual JWT parsing and
// claim validation lives in the SDK (sdk/capabilitygrant); this
// package adds an HTTP-backed per-kid key resolver with caching
// tailored to ext-authz's request-path latency budget.
//
// Spec: unified-identity-and-authorization Requirements 5.4-5.7.
// ADR-0045 (one verification path keyed by kid; see keydoc.go).
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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Verifier verifies daemon-minted dispatch CG-JWTs — the task-scoped tokens
// Minter.Mint stamps with the daemon's own kid, which carry their own
// tenant/subject/allowed_rpcs claims.
//
// It resolves the signing key from the daemon's per-kid key endpoint
// (GET {KeysBaseURL}/{kid}) and caches it for the configured TTL. Only the
// daemon's own key is accepted: a key document that carries a component
// binding (principal/tenant/status) is refused, so a registered component
// cannot self-sign a token that this verifier treats as daemon-minted.
// ComponentVerifier is the path for component-signed tokens, and it makes the
// mirror-image check.
//
// Verifier is safe for concurrent use.
type Verifier struct {
	keysBaseURL      string
	httpClient       *http.Client
	ttl              time.Duration
	expectedIssuer   string
	expectedAudience string

	mu    sync.RWMutex
	cache map[string]cachedKey // kid -> daemon public key
}

type cachedKey struct {
	key ed25519.PublicKey
	exp time.Time
}

// Config configures a Verifier at construction.
type Config struct {
	// KeysBaseURL is the daemon per-kid key endpoint base, e.g.
	// "https://gibson:8086/capabilitygrant/v1/keys". The kid is appended as
	// the final path segment. Required. Shared with
	// ComponentConfig.KeysBaseURL — there is one key endpoint (ADR-0045).
	KeysBaseURL string

	// TTL controls how long a resolved key is cached. Default 1 hour
	// per Requirement 5.7.
	TTL time.Duration

	// HTTPClient fetches key documents. REQUIRED — there is no default.
	//
	// The document this client returns IS the trust anchor: it decides which
	// key the verifier will accept a signature from. So the caller must hand
	// over a client whose transport authenticates the daemon it is talking to
	// (GHSA-8m76-9r77-xvh3) — in production the SVID-pinned mTLS client
	// cmd/ext-authz builds, the same one the authz-registry fetch uses.
	//
	// Defaulting this to a bare http.Client is exactly the state that must not
	// be constructible, so nil is a constructor error rather than a fallback.
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
	if cfg.KeysBaseURL == "" {
		return nil, errors.New("cgjwt: KeysBaseURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("cgjwt: ExpectedIssuer required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("cgjwt: ExpectedAudience required")
	}
	if cfg.HTTPClient == nil {
		return nil, errors.New("cgjwt: Config.HTTPClient required (the key document is the trust anchor; its transport must authenticate the daemon)")
	}
	v := &Verifier{
		keysBaseURL:      strings.TrimRight(cfg.KeysBaseURL, "/"),
		ttl:              cfg.TTL,
		httpClient:       cfg.HTTPClient,
		expectedIssuer:   cfg.ExpectedIssuer,
		expectedAudience: cfg.ExpectedAudience,
		cache:            map[string]cachedKey{},
	}
	if v.ttl <= 0 {
		v.ttl = time.Hour
	}
	return v, nil
}

// Verify parses, signature-checks, and structurally validates a
// capability-grant JWT. Delegates the heavy lifting to
// capabilitygrant.Verify in the SDK; this method's job is to bridge
// the SDK's JWKSFetcher interface to the HTTP+cache backing.
func (v *Verifier) Verify(ctx context.Context, token string) (capabilitygrant.Claims, error) {
	claims, err := capabilitygrant.Verify(ctx, keyFetcher{v: v}, token, capabilitygrant.VerifyOptions{
		ExpectedIssuer:   v.expectedIssuer,
		ExpectedAudience: v.expectedAudience,
	})
	if err != nil {
		return capabilitygrant.Claims{}, fmt.Errorf("cgjwt verify: %w", err)
	}
	return claims, nil
}

// keyFetcher adapts Verifier to the SDK's JWKSFetcher interface. The interface
// is already per-kid; the backing is the daemon's per-kid key endpoint.
type keyFetcher struct{ v *Verifier }

func (f keyFetcher) Fetch(ctx context.Context, kid string) (any, error) {
	f.v.mu.RLock()
	if k, ok := f.v.cache[kid]; ok && time.Now().Before(k.exp) {
		f.v.mu.RUnlock()
		cgjwtCacheHits.Inc()
		return k.key, nil
	}
	f.v.mu.RUnlock()

	cgjwtCacheMisses.Inc()
	key, err := f.v.resolve(ctx, kid)
	if err != nil {
		cgjwtUnknownKid.Inc()
		return nil, err
	}
	f.v.mu.Lock()
	f.v.cache[kid] = cachedKey{key: key, exp: time.Now().Add(f.v.ttl)}
	f.v.mu.Unlock()
	cgjwtKeyFetchTotal.Inc()
	return key, nil
}

// resolve fetches and validates the key document for kid.
//
// A dispatch CG-JWT is only ever signed by the daemon, so only the daemon's
// bare key document is accepted here. Refusing a component key document is
// what preserves the property the retired JWKS-wide document had implicitly:
// that document contained the daemon key and nothing else, so a component kid
// could never resolve on this path. Per-kid resolution can reach every
// registered component key, so the check has to be explicit.
func (v *Verifier) resolve(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	doc, err := fetchKeyDoc(ctx, v.httpClient, v.keysBaseURL, kid)
	if err != nil {
		return nil, fmt.Errorf("cgjwt: resolve kid %q: %w", kid, err)
	}
	if !doc.isBare() {
		cgjwtComponentKidRejected.Inc()
		return nil, fmt.Errorf("cgjwt: kid %q is a component key, not the daemon dispatch key", kid)
	}
	key, err := ed25519FromKeyDoc(doc, kid)
	if err != nil {
		return nil, fmt.Errorf("cgjwt: resolve kid %q: %w", kid, err)
	}
	return key, nil
}

var (
	cgjwtCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_cache_hits_total",
		Help: "Capability-grant dispatch-key cache hits.",
	})
	cgjwtCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_cache_misses_total",
		Help: "Capability-grant dispatch-key cache misses (caused a fetch).",
	})
	cgjwtUnknownKid = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_unknown_kid_total",
		Help: "Capability-grant dispatch-key lookups that resolved no usable key.",
	})
	cgjwtKeyFetchTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_key_fetch_total",
		Help: "Capability-grant dispatch-key fetches from the daemon per-kid key endpoint.",
	})
	cgjwtComponentKidRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_kid_rejected_total",
		Help: "Dispatch CG-JWTs whose kid resolved to a component key document rather than the daemon dispatch key.",
	})
)
