// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// ErrReplayed is returned when a component token's (kid, jti) pair has
// already been accepted by this ext-authz process. It is deliberately its
// own sentinel rather than one of the SDK's: a replayed token is perfectly
// well-formed and correctly signed, and conflating it with ErrMalformed
// would hide replay attempts inside the ordinary parse-failure metric.
var ErrReplayed = errors.New("cgjwt: token replay")

// ErrMethodMismatch is returned when a component token's `method` claim does
// not match the gRPC method of the request presenting it (gibson#1246). Like
// ErrReplayed it is its own sentinel: the token is well-formed and correctly
// signed but bound to a different RPC, so folding it into ErrMalformed would
// hide a cross-RPC replay attempt inside the ordinary parse-failure metric.
var ErrMethodMismatch = errors.New("cgjwt: token method mismatch")

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
	maxLifetime time.Duration
	audiences   []string
	replay      *replayCache

	mu    sync.RWMutex
	cache map[string]cachedDescriptor // kid -> descriptor
}

// DefaultComponentMaxLifetime bounds how long a component token may live.
// Component tokens are signed per RPC and the SDK gives them ~55 seconds;
// this is the outer bound ext-authz will accept, generous enough to absorb
// clock skew between a sandbox and the gateway without accepting a token
// that is useful to whoever picks it out of a log.
const DefaultComponentMaxLifetime = 5 * time.Minute

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
	// ComponentScope is the token's `component_scope` claim in its canonical
	// "component:<name>" form — the component identifier the daemon bound to
	// this agent at Capability-Grant registration time (ADR-0045). It is read
	// only AFTER the signature check below, so it is as trustworthy as the
	// key that signed the token.
	//
	// It is empty when the token carries no such claim. Verify deliberately
	// does not require it: rejecting scope-less tokens here would fail every
	// component minted by an older SDK. The consumer that needs a scope
	// (fga.resolveObject's component_from_identity deriver) fails closed on
	// the empty value instead, so an absent claim denies exactly the requests
	// that depend on it and nothing else.
	ComponentScope string
}

// ComponentConfig configures a ComponentVerifier.
type ComponentConfig struct {
	// KeysBaseURL is the daemon per-kid key endpoint base, e.g.
	// "https://gibson:8086/capabilitygrant/v1/keys". The kid is appended as
	// the final path segment. Required.
	KeysBaseURL string
	// TTL caches a resolved descriptor for this long. Default 5 minutes —
	// short, so a revoked/expired agent (served as non-active or 404) stops
	// verifying promptly. Bounded further by the token's own ~55s expiry.
	TTL time.Duration
	// HTTPClient fetches descriptors. REQUIRED — there is no default.
	//
	// The descriptor this client returns IS the identity assertion: it names
	// the FGA principal and tenant ext-authz will attribute the caller to, and
	// the key whose signature it will accept. Whoever answers the fetch
	// therefore decides who the caller is, so the transport must authenticate
	// the daemon (GHSA-8m76-9r77-xvh3). In production this is the SVID-pinned
	// mTLS client cmd/ext-authz builds, the same one the authz-registry fetch
	// uses.
	//
	// Defaulting this to a bare http.Client is exactly the state that must not
	// be constructible, so nil is a constructor error rather than a fallback.
	HTTPClient *http.Client

	// MaxLifetime is the longest token lifetime (exp - iat) ext-authz will
	// accept, and the furthest into the future an exp may sit. Defaults to
	// DefaultComponentMaxLifetime. A token whose exp outruns it is rejected
	// however well it is signed — a component key must not be able to mint
	// itself a long-lived bearer token.
	MaxLifetime time.Duration

	// ExpectedAudiences pins the token `aud` claim: the token must name one
	// of these. REQUIRED and non-empty — NewComponentVerifier rejects an
	// empty list rather than treating it as "accept any audience".
	//
	// As of gibson#1246 the audience is a fixed protocol constant both SDKs
	// mint, capabilitygrant.AudienceGibsonDaemon ("zeroroot.ai/gibson-daemon"),
	// so cmd/ext-authz pins exactly that one value. It is no longer the dialled
	// gRPC target — request binding now lives in the `method` claim, which the
	// per-request Verify(method) argument matches. The audience is a coarse
	// "these tokens are for this daemon" check; the method claim is the tight
	// per-RPC binding.
	//
	// Unset still means unpinned, which made the whole aud check dead — so the
	// constructor keeps rejecting an empty list as defense in depth.
	ExpectedAudiences []string

	// ReplayCacheMaxEntries bounds the per-process (kid, jti) replay cache.
	// Defaults to DefaultReplayCacheMaxEntries. See replayCache for what
	// the cache does and does not guarantee across replicas.
	ReplayCacheMaxEntries int
}

// NewComponentVerifier constructs a ComponentVerifier.
func NewComponentVerifier(cfg ComponentConfig) (*ComponentVerifier, error) {
	if cfg.KeysBaseURL == "" {
		return nil, errors.New("cgjwt: ComponentConfig.KeysBaseURL required")
	}
	// Fail closed on an unpinned audience. A verifier that accepts any aud
	// is the defect this constructor exists to prevent, so it is not a
	// constructible state — not for main.go, not for a future caller.
	auds := make([]string, 0, len(cfg.ExpectedAudiences))
	for _, a := range cfg.ExpectedAudiences {
		if a = strings.TrimSpace(a); a != "" {
			auds = append(auds, a)
		}
	}
	if len(auds) == 0 {
		return nil, errors.New("cgjwt: ComponentConfig.ExpectedAudiences required and must be non-empty (an unpinned audience accepts a token minted for any other target)")
	}
	// Same reasoning as the audience pin: a verifier whose descriptor source
	// is unauthenticated is not a constructible state.
	if cfg.HTTPClient == nil {
		return nil, errors.New("cgjwt: ComponentConfig.HTTPClient required (the descriptor is the identity assertion; its transport must authenticate the daemon)")
	}
	v := &ComponentVerifier{
		keysBaseURL: strings.TrimRight(cfg.KeysBaseURL, "/"),
		httpClient:  cfg.HTTPClient,
		ttl:         cfg.TTL,
		maxLifetime: cfg.MaxLifetime,
		audiences:   auds,
		replay:      newReplayCache(cfg.ReplayCacheMaxEntries),
		cache:       map[string]cachedDescriptor{},
	}
	if v.ttl <= 0 {
		v.ttl = 5 * time.Minute
	}
	if v.maxLifetime <= 0 {
		v.maxLifetime = DefaultComponentMaxLifetime
	}
	return v, nil
}

// Verify parses and signature-checks a component agent+jwt and returns the
// daemon-asserted identity. The token proves only key-possession; identity is
// the daemon's descriptor, never the token's own (absent) claims.
//
// A component token is bound to a single request (gibson#1246). It must carry a
// `method` claim naming the gRPC method it may be presented at, and Verify
// refuses it at any other method — the caller passes the request's method
// (Envoy's `:path`) as method. A token with no method claim is refused: that is
// the deleted unbound-token path — before this a captured token could be
// replayed against any RPC for its whole lifetime.
//
// A component token is short-lived by construction: it must carry an exp and
// an iat, and its lifetime may not exceed MaxLifetime. Absent expiry is not a
// tolerated shape — a token with no exp would authenticate forever.
//
// It is also single-use: the token's jti is remembered until its exp and a
// second presentation is refused (gibson#1246). The cache is per-process —
// see replayCache for the limits of that.
//
// Errors mirror the SDK sentinels for caller metrics:
//   - ErrMalformed       — unparseable, wrong typ, missing kid, missing iat,
//     missing jti, missing method claim, or an audience outside ExpectedAudiences
//   - ErrMethodMismatch  — the method claim does not match the request method
//   - ErrUnknownKey       — descriptor lookup failed / agent not active
//   - ErrSignature        — signature invalid
//   - ErrExpired          — exp in the past, absent, or further out than MaxLifetime
//   - ErrReplayed         — this (kid, jti) was already accepted by this process
func (v *ComponentVerifier) Verify(ctx context.Context, token, method string) (ComponentIdentity, error) {
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

	parseOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		// A component token with no exp would verify forever. Require one.
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		// ONE call, variadic: jwt.WithAudience assigns the expected set
		// rather than appending to it, so calling it per audience in a loop
		// would silently pin only the last entry and reject every other
		// configured audience. v.audiences is guaranteed non-empty by the
		// constructor, so the aud claim is always required.
		jwt.WithAudience(v.audiences...),
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("%w: unexpected alg %q", ErrSignature, t.Method.Alg())
		}
		return desc.key, nil
	}, parseOpts...)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			// Two claims are required: exp (or the token never stops being
			// valid) and aud (required implicitly, because the constructor
			// guarantees a non-empty expected set). golang-jwt reports both
			// through the same sentinel, so read the token — non-nil even on
			// a validation error — to say which one is actually absent.
			if exp, expErr := parsed.Claims.GetExpirationTime(); expErr == nil && exp != nil {
				componentRejectedTotal.WithLabelValues("audience").Inc()
				return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrMalformed, err)
			}
			componentRejectedTotal.WithLabelValues("no_expiry").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrExpired, err)
		case errors.Is(err, jwt.ErrTokenExpired):
			componentRejectedTotal.WithLabelValues("expired").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrExpired, err)
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			componentRejectedTotal.WithLabelValues("audience").Inc()
			return ComponentIdentity{}, fmt.Errorf("%w: %w", ErrMalformed, err)
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
	if err := v.checkLifetime(parsed); err != nil {
		return ComponentIdentity{}, err
	}

	// Claims are read only here, past the signature and lifetime checks —
	// never from the unverified peek above.
	sub, scope, jti, claimMethod := "", "", "", ""
	if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
		sub, _ = mc["sub"].(string)
		scope, _ = mc["component_scope"].(string)
		jti, _ = mc["jti"].(string)
		claimMethod, _ = mc["method"].(string)
	}
	// Request binding first: a token presented at the wrong method (or with no
	// method claim at all) is refused before it can consume a replay-cache slot.
	if err := v.checkMethod(claimMethod, method); err != nil {
		return ComponentIdentity{}, err
	}
	if err := v.checkReplay(kid, jti, parsed); err != nil {
		return ComponentIdentity{}, err
	}
	componentVerifiedTotal.Inc()
	return ComponentIdentity{
		Principal:      desc.principal,
		Tenant:         desc.tenant,
		Subject:        sub,
		ComponentScope: scope,
	}, nil
}

// checkMethod enforces the request binding added in gibson#1246: a component
// token names the exact gRPC method it may be presented at, and ext-authz
// refuses it at any other method. requestMethod is the request's `:path`,
// which for a gRPC call is "/<proto.package.Service>/<Method>" — the same
// shape both SDKs sign into the claim.
//
// The claim is read only after the signature check, so it is as trustworthy as
// the key that signed the token. A token with no method claim is rejected
// outright: that is the deleted unbound-token path. Accepting one would be an
// opt-out of this check that any captured token could take, since before this
// change every component token was unbound. Both SDKs set the claim on every
// call, so nothing legitimate lacks it.
func (v *ComponentVerifier) checkMethod(claimMethod, requestMethod string) error {
	if claimMethod == "" {
		componentRejectedTotal.WithLabelValues("no_method").Inc()
		return fmt.Errorf("%w: token has no method claim", ErrMalformed)
	}
	if claimMethod != requestMethod {
		componentRejectedTotal.WithLabelValues("method_mismatch").Inc()
		return fmt.Errorf("%w: token bound to method %q, presented at %q",
			ErrMethodMismatch, claimMethod, requestMethod)
	}
	return nil
}

// checkReplay enforces single use of a component token (gibson#1246).
//
// A component token is minted per RPC and carries no binding to the request
// it travels with — no method claim, no body digest — so anything that
// captures one in flight can present it again for the rest of its lifetime.
// Binding it to the request needs the SDK to mint the extra claims, which is
// cross-repo. This is the verifier-only half: the token's jti is remembered
// until its exp, and a second presentation of the same (kid, jti) is refused.
//
// It runs LAST, after signature, descriptor and lifetime all pass, so only a
// token that would otherwise have been accepted consumes a cache slot.
//
// A token with no jti is rejected outright: without it there is nothing to
// deduplicate on, so accepting one would be an opt-out of this check that
// any captured token could take. Both SDKs that mint agent+jwt set jti to a
// fresh UUID on every call, so nothing legitimate lacks it.
//
// This does NOT close the replay window — see replayCache for exactly what
// multiple ext-authz replicas leave open.
func (v *ComponentVerifier) checkReplay(kid, jti string, parsed *jwt.Token) error {
	if jti == "" {
		componentRejectedTotal.WithLabelValues("no_jti").Inc()
		return fmt.Errorf("%w: token has no jti", ErrMalformed)
	}
	exp, err := parsed.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		// checkLifetime has already established exp; belt and braces so a
		// reordering cannot turn this into an unbounded cache entry.
		componentRejectedTotal.WithLabelValues("no_expiry").Inc()
		return fmt.Errorf("%w: token has no usable exp", ErrExpired)
	}
	if !v.replay.admit(kid, jti, exp.Time, time.Now()) {
		componentRejectedTotal.WithLabelValues("replayed").Inc()
		componentReplayedTotal.Inc()
		return fmt.Errorf("%w: kid %s jti %s already used", ErrReplayed, kid, jti)
	}
	return nil
}

// checkLifetime rejects a component token that claims more life than a
// per-RPC token is allowed to have. jwt.Parse has already established that
// exp exists and has not passed; this bounds how far it may sit in the
// future, both from the token's own iat and from now, so that a component
// key cannot mint itself a durable bearer token.
func (v *ComponentVerifier) checkLifetime(parsed *jwt.Token) error {
	exp, err := parsed.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		componentRejectedTotal.WithLabelValues("no_expiry").Inc()
		return fmt.Errorf("%w: token has no usable exp", ErrExpired)
	}
	iat, err := parsed.Claims.GetIssuedAt()
	if err != nil || iat == nil {
		// Without iat the token's claimed lifetime is unknowable. Reject:
		// both SDKs that mint agent+jwt always set it.
		componentRejectedTotal.WithLabelValues("no_issued_at").Inc()
		return fmt.Errorf("%w: token has no iat", ErrMalformed)
	}
	if exp.Sub(iat.Time) > v.maxLifetime {
		componentRejectedTotal.WithLabelValues("lifetime_too_long").Inc()
		return fmt.Errorf("%w: token lifetime %s exceeds max %s",
			ErrExpired, exp.Sub(iat.Time), v.maxLifetime)
	}
	if time.Until(exp.Time) > v.maxLifetime {
		componentRejectedTotal.WithLabelValues("expiry_too_far").Inc()
		return fmt.Errorf("%w: token exp is %s away, max %s",
			ErrExpired, time.Until(exp.Time).Round(time.Second), v.maxLifetime)
	}
	return nil
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

func (v *ComponentVerifier) fetch(ctx context.Context, kid string) (cachedDescriptor, error) {
	doc, err := fetchKeyDoc(ctx, v.httpClient, v.keysBaseURL, kid)
	if err != nil {
		return cachedDescriptor{}, err
	}
	key, err := ed25519FromKeyDoc(doc, kid)
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
