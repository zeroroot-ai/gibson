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
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Reuse the SDK's verification sentinels so the ext-authz server's error switch
// classifies component-token failures identically to daemon-minted ones.
var (
	ErrMalformed  = capabilitygrant.ErrMalformed
	ErrUnknownKey = capabilitygrant.ErrUnknownKey
	ErrSignature  = capabilitygrant.ErrSignature
	ErrExpired    = capabilitygrant.ErrExpired
)

// ComponentVerifier verifies a component's self-signed per-RPC CG-JWT
// (the SDK's agent+jwt: typ=agent+jwt, kid=<agent row id>, signed with the
// component's registered Ed25519 key). It is the ext-authz side of ADR-0045 /
// gibson#648.
//
// Unlike Verifier (which verifies daemon-minted dispatch CG-JWTs whose claims
// are self-contained), a component token carries no tenant/principal — the
// authoritative binding lives at the daemon. So ComponentVerifier resolves the
// per-kid DESCRIPTOR from the daemon
// (GET {KeysBaseURL}/{kid} → {keys, principal, tenant, status}), verifies the
// signature for key-possession, then returns the daemon-asserted principal +
// tenant. ext-authz runs its normal per-method FGA check on that principal — the
// token is never trusted for identity beyond proving possession of the key.
//
// ComponentVerifier is safe for concurrent use.
type ComponentVerifier struct {
	keysBaseURL string
	httpClient  *http.Client
	ttl         time.Duration

	mu    sync.RWMutex
	cache map[string]cachedDescriptor // kid -> descriptor
}

type cachedDescriptor struct {
	key       ed25519.PublicKey
	principal string
	tenant    string
	status    string
	exp       time.Time
}

// ComponentIdentity is the verified, daemon-asserted identity of a component.
type ComponentIdentity struct {
	// Principal is the typed FGA principal ref, e.g. "agent_principal:<acct>".
	// ext-authz uses it directly as the FGA user.
	Principal string
	// Tenant is the component's tenant (for rule-mode object derivation).
	Tenant string
	// Subject is the token `sub` (the agent row id / kid) — for logging only.
	Subject string
}

// ComponentConfig configures a ComponentVerifier.
type ComponentConfig struct {
	// KeysBaseURL is the daemon per-kid key endpoint base (through Envoy), e.g.
	// "http://gibson-native-login:8085/capabilitygrant/v1/keys". The kid is
	// appended as the final path segment. Required.
	KeysBaseURL string
	// TTL caches a resolved descriptor for this long. Default 5 minutes —
	// short, so a revoked/expired agent (served as non-active or 404) stops
	// verifying promptly. Bounded further by the token's own ~55s expiry.
	TTL time.Duration
	// HTTPClient fetches descriptors; defaults to a 5s-timeout client.
	HTTPClient *http.Client
}

// NewComponentVerifier constructs a ComponentVerifier.
func NewComponentVerifier(cfg ComponentConfig) (*ComponentVerifier, error) {
	if cfg.KeysBaseURL == "" {
		return nil, errors.New("cgjwt: ComponentConfig.KeysBaseURL required")
	}
	v := &ComponentVerifier{
		keysBaseURL: strings.TrimRight(cfg.KeysBaseURL, "/"),
		httpClient:  cfg.HTTPClient,
		ttl:         cfg.TTL,
		cache:       map[string]cachedDescriptor{},
	}
	if v.ttl <= 0 {
		v.ttl = 5 * time.Minute
	}
	if v.httpClient == nil {
		v.httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return v, nil
}

// Verify parses and signature-checks a component agent+jwt and returns the
// daemon-asserted identity. The token proves only key-possession; identity is
// the daemon's descriptor, never the token's own (absent) claims.
//
// Errors mirror the SDK sentinels for caller metrics:
//   - ErrMalformed   — unparseable, wrong typ, or missing kid
//   - ErrUnknownKey   — descriptor lookup failed / agent not active
//   - ErrSignature    — signature invalid
//   - ErrExpired      — exp in the past
func (v *ComponentVerifier) Verify(ctx context.Context, token string) (ComponentIdentity, error) {
	// Peek the header for kid + typ without trusting the signature yet.
	kid, typ, err := peekHeader(token)
	if err != nil {
		return ComponentIdentity{}, err
	}
	if typ != "agent+jwt" {
		return ComponentIdentity{}, fmt.Errorf("%w: unexpected typ %q", ErrMalformed, typ)
	}
	if kid == "" {
		return ComponentIdentity{}, fmt.Errorf("%w: missing kid", ErrMalformed)
	}

	desc, err := v.resolve(ctx, kid)
	if err != nil {
		return ComponentIdentity{}, fmt.Errorf("%w: kid %s: %w", ErrUnknownKey, kid, err)
	}
	if desc.status != "active" {
		componentRejectedTotal.WithLabelValues("inactive").Inc()
		return ComponentIdentity{}, fmt.Errorf("%w: kid %s status %q", ErrUnknownKey, kid, desc.status)
	}
	if desc.principal == "" || desc.tenant == "" {
		// A component kid must carry a principal+tenant binding; a bare key
		// document (the daemon's own dispatch kid) is not a component.
		return ComponentIdentity{}, fmt.Errorf("%w: kid %s is not a component key", ErrUnknownKey, kid)
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrSignature, t.Method.Alg())
		}
		return desc.key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			componentRejectedTotal.WithLabelValues("expired").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrExpired, err)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrSignatureInvalid):
			componentRejectedTotal.WithLabelValues("signature").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrSignature, err)
		default:
			componentRejectedTotal.WithLabelValues("malformed").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
	}
	if !parsed.Valid {
		componentRejectedTotal.WithLabelValues("malformed").Inc()
		return ComponentIdentity{}, ErrMalformed
	}

	sub := ""
	if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
		sub, _ = mc["sub"].(string)
	}
	componentVerifiedTotal.Inc()
	return ComponentIdentity{
		Principal: desc.principal,
		Tenant:    desc.tenant,
		Subject:   sub,
	}, nil
}

// resolve returns the cached descriptor for kid, fetching on miss/expiry.
func (v *ComponentVerifier) resolve(ctx context.Context, kid string) (cachedDescriptor, error) {
	v.mu.RLock()
	if d, ok := v.cache[kid]; ok && time.Now().Before(d.exp) {
		v.mu.RUnlock()
		componentCacheHits.Inc()
		return d, nil
	}
	v.mu.RUnlock()

	componentCacheMisses.Inc()
	d, err := v.fetch(ctx, kid)
	if err != nil {
		return cachedDescriptor{}, err
	}
	v.mu.Lock()
	v.cache[kid] = d
	v.mu.Unlock()
	return d, nil
}

// descriptorDoc is the wire shape of the per-kid descriptor (a JWKS superset).
type descriptorDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	} `json:"keys"`
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	Status    string `json:"status"`
}

func (v *ComponentVerifier) fetch(ctx context.Context, kid string) (cachedDescriptor, error) {
	url := v.keysBaseURL + "/" + kid
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return cachedDescriptor{}, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return cachedDescriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cachedDescriptor{}, fmt.Errorf("descriptor fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return cachedDescriptor{}, err
	}
	var doc descriptorDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return cachedDescriptor{}, fmt.Errorf("descriptor decode: %w", err)
	}
	key, err := ed25519FromDescriptor(doc, kid)
	if err != nil {
		return cachedDescriptor{}, err
	}
	return cachedDescriptor{
		key:       key,
		principal: doc.Principal,
		tenant:    doc.Tenant,
		status:    doc.Status,
		exp:       time.Now().Add(v.ttl),
	}, nil
}

// ed25519FromDescriptor extracts the Ed25519 key matching kid (or the sole key).
func ed25519FromDescriptor(doc descriptorDoc, kid string) (ed25519.PublicKey, error) {
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		if k.Kid != "" && k.Kid != kid {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("kid %q: bad x: %w", kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("kid %q: ed25519 key length %d", kid, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("descriptor for kid %q has no usable Ed25519 key", kid)
}

// peekHeader base64url-decodes the JWT header (without verifying) to read kid
// and typ. Used to resolve the verifying key before signature check.
func peekHeader(token string) (kid, typ string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("%w: not a compact JWT", ErrMalformed)
	}
	raw, derr := base64.RawURLEncoding.DecodeString(parts[0])
	if derr != nil {
		return "", "", fmt.Errorf("%w: header base64: %w", ErrMalformed, derr)
	}
	var h struct {
		Kid string `json:"kid"`
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if jerr := json.Unmarshal(raw, &h); jerr != nil {
		return "", "", fmt.Errorf("%w: header json: %w", ErrMalformed, jerr)
	}
	return h.Kid, h.Typ, nil
}

var (
	componentVerifiedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_verified_total",
		Help: "Component CG-JWTs verified successfully (signature + active descriptor).",
	})
	componentRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_rejected_total",
		Help: "Component CG-JWTs rejected, by reason.",
	}, []string{"reason"})
	componentCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_descriptor_cache_hits_total",
		Help: "Component key-descriptor cache hits.",
	})
	componentCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_descriptor_cache_misses_total",
		Help: "Component key-descriptor cache misses (caused a fetch).",
	})
)
