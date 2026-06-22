package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
)

// circuitConfigForTest returns a CircuitConfig with the given threshold and
// timeout, suitable for fast-running unit tests.
func circuitConfigForTest(threshold uint32, timeout time.Duration) resilience.CircuitConfig {
	return resilience.CircuitConfig{
		ConsecutiveFailures: threshold,
		Interval:            10 * time.Second,
		Timeout:             timeout,
	}
}

// Valid ULIDs for the OpenFGA SDK's parameter validation. The SDK
// requires both StoreID and ModelID to parse as ULID; using opaque
// placeholders trips the validator before any test logic runs.
const (
	testStoreID = "01HX0000000000000000000001"
	testModelID = "01HX0000000000000000000002"
)

// --- FGAClient timeout ---

// TestFGAClient_TimesOutBelowEnvoyBudget proves the per-call floor:
// a slow OpenFGA must surface as ErrFGATimeout from the FGAClient
// (with the local deadline firing) BEFORE the Envoy ext_authz
// budget would have expired.
func TestFGAClient_TimesOutBelowEnvoyBudget(t *testing.T) {
	t.Parallel()

	// Fake OpenFGA that sleeps longer than the per-call timeout but
	// shorter than the test's overall ctx deadline, so we can tell
	// the difference between a local-floor trip and a global
	// ctx-cancel.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()

	c, err := NewFGAClient(FGAClientOptions{
		Endpoint:       slow.URL,
		StoreID:        testStoreID,
		ModelID:        testModelID,
		PerCallTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewFGAClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Parent ctx is generous so the test fails if the per-call
	// timeout does NOT trip.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	_, err = c.Check(ctx, CheckRequest{
		User:     "user:alice",
		Relation: "member",
		Object:   "tenant:acme",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Check: want timeout error, got nil")
	}
	if !errors.Is(err, ErrFGATimeout) {
		t.Fatalf("Check: want ErrFGATimeout, got %v", err)
	}
	// The per-call floor (100ms) must have tripped well before the
	// fake server's 2s sleep — give a small slack to account for
	// scheduling.
	if elapsed >= 1*time.Second {
		t.Fatalf("Check: elapsed=%s — per-call timeout floor did not fire below the Envoy budget", elapsed)
	}
}

// TestNewFGAClient_RejectsBudgetCeiling proves the constructor
// refuses a per-call timeout at or above the Envoy ext_authz budget.
func TestNewFGAClient_RejectsBudgetCeiling(t *testing.T) {
	t.Parallel()

	_, err := NewFGAClient(FGAClientOptions{
		Endpoint:       "http://gibson-fga:8080",
		StoreID:        testStoreID,
		ModelID:        testModelID,
		PerCallTimeout: EnvoyExtAuthzBudgetDefault,
	})
	if err == nil {
		t.Fatalf("NewFGAClient: want error for PerCallTimeout >= budget, got nil")
	}
}

// TestFGAClient_RejectsEmptyFields proves input validation runs
// before the SDK call.
func TestFGAClient_RejectsEmptyFields(t *testing.T) {
	t.Parallel()

	c, err := NewFGAClient(FGAClientOptions{
		Endpoint: "http://unused:8080",
		StoreID:  testStoreID,
		ModelID:  testModelID,
	})
	if err != nil {
		t.Fatalf("NewFGAClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	_, err = c.Check(context.Background(), CheckRequest{
		User:     "",
		Relation: "member",
		Object:   "tenant:acme",
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Check: want ErrInvalidArgument, got %v", err)
	}
}

// --- Identity-header HMAC ---

// TestValidateIdentityHeaders_RoundTrip proves a signed bundle
// validates with the same secret.
func TestValidateIdentityHeaders_RoundTrip(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-key-for-identity-headers")
	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(time.Now().Unix(), 10))

	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	id, err := ValidateIdentityHeaders(h, secret)
	if err != nil {
		t.Fatalf("ValidateIdentityHeaders: %v", err)
	}
	if id.Subject != "user:alice" || id.Tenant != "acme" || id.Issuer != "oidc" || id.CredentialType != "oidc-user" {
		t.Fatalf("ValidateIdentityHeaders: identity fields wrong: %#v", id)
	}
}

// TestValidateIdentityHeaders_RejectsTamperedSignature proves a flipped
// byte in the signature fails the HMAC check.
func TestValidateIdentityHeaders_RejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-key-for-identity-headers")
	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(time.Now().Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	// Tamper: flip the first hex digit.
	sig := h.Get(HeaderSignature)
	first := sig[0]
	switch first {
	case '0':
		sig = "1" + sig[1:]
	default:
		sig = "0" + sig[1:]
	}
	h.Set(HeaderSignature, sig)

	_, err := ValidateIdentityHeaders(h, secret)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ValidateIdentityHeaders: want ErrInvalidArgument for tampered sig, got %v", err)
	}
}

// TestValidateIdentityHeaders_RejectsTamperedField proves changing any
// signed field after signing also fails the HMAC check.
func TestValidateIdentityHeaders_RejectsTamperedField(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-key-for-identity-headers")
	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(time.Now().Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	// Tamper: change the tenant claim after signing — a classic
	// privilege-escalation attempt the HMAC must catch.
	h.Set(HeaderTenant, "victim-tenant")

	_, err := ValidateIdentityHeaders(h, secret)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ValidateIdentityHeaders: want ErrInvalidArgument for tampered tenant, got %v", err)
	}
}

// TestValidateIdentityHeaders_RejectsMissingHeaders proves the
// validator fails closed on an incomplete bundle.
func TestValidateIdentityHeaders_RejectsMissingHeaders(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-key-for-identity-headers")
	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	// HeaderTenant intentionally missing.
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderIssuedAt, strconv.FormatInt(time.Now().Unix(), 10))
	h.Set(HeaderSignature, hex.EncodeToString([]byte("not-a-real-sig")))

	_, err := ValidateIdentityHeaders(h, secret)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ValidateIdentityHeaders: want ErrInvalidArgument for missing tenant, got %v", err)
	}
}

// TestValidateIdentityHeaders_FreshnessInWindow proves a bundle whose
// IssuedAt is within the default 60-second window is accepted.
func TestValidateIdentityHeaders_FreshnessInWindow(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-freshness")
	now := time.Now().UTC()

	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	_, err := ValidateIdentityHeaders(h, secret, withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("ValidateIdentityHeaders: want nil, got %v", err)
	}
}

// TestValidateIdentityHeaders_FreshnessPastWindow proves a bundle whose
// IssuedAt is older than the freshness window is rejected with
// ErrSkewExceeded.
func TestValidateIdentityHeaders_FreshnessPastWindow(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-freshness")
	now := time.Now().UTC()

	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(now.Add(-120*time.Second).Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	_, err := ValidateIdentityHeaders(h, secret, withClock(func() time.Time { return now }))
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateIdentityHeaders: want ErrSkewExceeded for stale bundle, got %v", err)
	}
}

// TestValidateIdentityHeaders_FreshnessFutureWindow proves a bundle
// whose IssuedAt is in the future beyond the freshness window is
// rejected with ErrSkewExceeded.
func TestValidateIdentityHeaders_FreshnessFutureWindow(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-freshness")
	now := time.Now().UTC()

	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	h.Set(HeaderIssuedAt, strconv.FormatInt(now.Add(120*time.Second).Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	_, err := ValidateIdentityHeaders(h, secret, withClock(func() time.Time { return now }))
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateIdentityHeaders: want ErrSkewExceeded for future-dated bundle, got %v", err)
	}
}

// TestValidateIdentityHeaders_FreshnessCustomSkew proves
// WithFreshnessSkew overrides the default window.
func TestValidateIdentityHeaders_FreshnessCustomSkew(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-freshness")
	now := time.Now().UTC()

	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	// 30s old — within the default 60s window but outside a 10s window.
	h.Set(HeaderIssuedAt, strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	_, err := ValidateIdentityHeaders(h, secret,
		WithFreshnessSkew(10*time.Second),
		withClock(func() time.Time { return now }),
	)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateIdentityHeaders: want ErrSkewExceeded with 10s custom skew, got %v", err)
	}
}

// TestValidateIdentityHeaders_FreshnessDisabled proves WithFreshnessSkew(0)
// disables the check entirely, allowing an arbitrarily old bundle.
func TestValidateIdentityHeaders_FreshnessDisabled(t *testing.T) {
	t.Parallel()

	secret := []byte("test-hmac-secret-freshness")

	h := http.Header{}
	h.Set(HeaderSubject, "user:alice")
	h.Set(HeaderIssuer, "oidc")
	h.Set(HeaderCredentialType, "oidc-user")
	h.Set(HeaderTenant, "acme")
	// Year 2000 — far outside any reasonable skew.
	h.Set(HeaderIssuedAt, strconv.FormatInt(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 10))
	if err := SignIdentityHeaders(h, secret); err != nil {
		t.Fatalf("SignIdentityHeaders: %v", err)
	}

	_, err := ValidateIdentityHeaders(h, secret, WithFreshnessSkew(0))
	if err != nil {
		t.Fatalf("ValidateIdentityHeaders: want nil with skew disabled, got %v", err)
	}
}

// --- Capability-grant JWT ---

// jwkSetForTest constructs a JWK set + signing key pair for tests.
func jwkSetForTest(t *testing.T, kid string) (jwk.Set, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	pubKey, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("Set kid: %v", err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
		t.Fatalf("Set alg: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return set, priv
}

// signGrant builds and signs a CG-JWT for the given time window.
func signGrant(t *testing.T, kid string, priv ed25519.PrivateKey, nbf, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer("https://gibson.example/cg").
		Subject("agent:test-001").
		Audience([]string{"gibson-daemon"}).
		JwtID("grant-1").
		IssuedAt(time.Now()).
		NotBefore(nbf).
		Expiration(exp).
		Build()
	if err != nil {
		t.Fatalf("jwt.Builder: %v", err)
	}

	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("jwk.FromRaw(priv): %v", err)
	}
	if err := signKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid on signKey: %v", err)
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
		t.Fatalf("set alg on signKey: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, signKey))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

// TestVerifyCapabilityGrant_HappyPath proves a freshly-signed grant
// validates.
func TestVerifyCapabilityGrant_HappyPath(t *testing.T) {
	t.Parallel()

	set, priv := jwkSetForTest(t, "test-kid")
	tok := signGrant(t, "test-kid", priv, time.Now().Add(-1*time.Second), time.Now().Add(5*time.Minute))

	g, err := VerifyCapabilityGrant(tok, set)
	if err != nil {
		t.Fatalf("VerifyCapabilityGrant: %v", err)
	}
	if g.Subject != "agent:test-001" || g.Issuer != "https://gibson.example/cg" {
		t.Fatalf("Grant fields wrong: %#v", g)
	}
}

// TestVerifyCapabilityGrant_RejectsExpired proves an exp in the past
// produces ErrGrantExpired.
func TestVerifyCapabilityGrant_RejectsExpired(t *testing.T) {
	t.Parallel()

	set, priv := jwkSetForTest(t, "test-kid")
	tok := signGrant(t, "test-kid", priv, time.Now().Add(-1*time.Hour), time.Now().Add(-1*time.Minute))

	_, err := VerifyCapabilityGrant(tok, set)
	if !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("VerifyCapabilityGrant: want ErrGrantExpired, got %v", err)
	}
}

// TestVerifyCapabilityGrant_RejectsFutureDated proves nbf > now
// produces ErrGrantNotYetValid.
func TestVerifyCapabilityGrant_RejectsFutureDated(t *testing.T) {
	t.Parallel()

	set, priv := jwkSetForTest(t, "test-kid")
	tok := signGrant(t, "test-kid", priv, time.Now().Add(1*time.Hour), time.Now().Add(2*time.Hour))

	_, err := VerifyCapabilityGrant(tok, set)
	if !errors.Is(err, ErrGrantNotYetValid) {
		t.Fatalf("VerifyCapabilityGrant: want ErrGrantNotYetValid, got %v", err)
	}
}

// TestVerifyCapabilityGrant_RejectsBadSignature proves a token signed
// with a different key fails signature verification.
func TestVerifyCapabilityGrant_RejectsBadSignature(t *testing.T) {
	t.Parallel()

	// Verifier trusts setA's public key; the token is signed with
	// privB.
	setA, _ := jwkSetForTest(t, "kid-a")
	_, privB := jwkSetForTest(t, "kid-a")

	tok := signGrant(t, "kid-a", privB, time.Now().Add(-1*time.Second), time.Now().Add(5*time.Minute))

	_, err := VerifyCapabilityGrant(tok, setA)
	if !errors.Is(err, ErrGrantSignature) {
		t.Fatalf("VerifyCapabilityGrant: want ErrGrantSignature, got %v", err)
	}
}

// TestVerifyCapabilityGrant_RejectsEmpty proves the trivial input
// validation runs.
func TestVerifyCapabilityGrant_RejectsEmpty(t *testing.T) {
	t.Parallel()

	set, _ := jwkSetForTest(t, "kid-x")
	_, err := VerifyCapabilityGrant("", set)
	if !errors.Is(err, ErrGrantMalformed) {
		t.Fatalf("VerifyCapabilityGrant: want ErrGrantMalformed for empty token, got %v", err)
	}

	_, err = VerifyCapabilityGrant("not.a.jwt", jwk.NewSet())
	if !errors.Is(err, ErrGrantMalformed) {
		t.Fatalf("VerifyCapabilityGrant: want ErrGrantMalformed for empty key set, got %v", err)
	}
}

// --- FGAClient circuit breaker ---

// TestFGAClient_CircuitOpensOnConsecutiveFailures proves the gobreaker
// circuit opens after consecutive timeouts and returns ErrFGAUnavailable
// without hitting the backend.
func TestFGAClient_CircuitOpensOnConsecutiveFailures(t *testing.T) {
	t.Parallel()

	// Backend that stalls longer than the per-call timeout — guaranteed to
	// produce ErrFGATimeout (a genuine failure the gobreaker counts).
	// callCount is protected by a mutex because the handler and test
	// goroutines access it concurrently under -race.
	var callMu sync.Mutex
	var callCount int
	stalling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callMu.Lock()
		callCount++
		callMu.Unlock()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer stalling.Close()

	perCall := 80 * time.Millisecond
	cbTimeout := 50 * time.Millisecond
	c, err := NewFGAClient(FGAClientOptions{
		Endpoint:       stalling.URL,
		StoreID:        testStoreID,
		ModelID:        testModelID,
		PerCallTimeout: perCall,
		Circuit:        circuitConfigForTest(2, cbTimeout),
	})
	if err != nil {
		t.Fatalf("NewFGAClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	req := CheckRequest{User: "user:alice", Relation: "member", Object: "tenant:acme"}

	// Drive threshold failures (each times out at perCall).
	for range 2 {
		_, _ = c.Check(ctx, req)
	}

	// Next call must be rejected by the circuit without hitting the backend.
	callMu.Lock()
	beforeCount := callCount
	callMu.Unlock()
	_, cbErr := c.Check(ctx, req)
	if !errors.Is(cbErr, ErrFGAUnavailable) {
		t.Fatalf("want ErrFGAUnavailable from open circuit, got: %v", cbErr)
	}
	callMu.Lock()
	afterCount := callCount
	callMu.Unlock()
	if afterCount != beforeCount {
		t.Fatalf("circuit open but backend was hit (%d → %d calls)", beforeCount, afterCount)
	}
}

// TestFGAClient_CircuitClosesAfterSuccessfulProbe proves the circuit
// transitions back to closed after a successful probe request once the
// timeout elapses.
func TestFGAClient_CircuitClosesAfterSuccessfulProbe(t *testing.T) {
	t.Parallel()

	// Backend stalls (causing timeouts) until allowSuccess is closed, then
	// returns a valid FGA response.
	allowSuccess := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-allowSuccess:
			// Success path: return a valid FGA check response.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"allowed":false}`))
		case <-r.Context().Done():
			// Timeout path: the client's context deadline fired.
		}
	}))
	defer srv.Close()

	perCall := 80 * time.Millisecond
	cbTimeout := 80 * time.Millisecond
	c, err := NewFGAClient(FGAClientOptions{
		Endpoint:       srv.URL,
		StoreID:        testStoreID,
		ModelID:        testModelID,
		PerCallTimeout: perCall,
		Circuit:        circuitConfigForTest(2, cbTimeout),
	})
	if err != nil {
		t.Fatalf("NewFGAClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	req := CheckRequest{User: "user:alice", Relation: "member", Object: "tenant:acme"}

	// Trip the circuit open with 2 timeouts.
	for range 2 {
		_, _ = c.Check(ctx, req)
	}

	// Verify circuit is open.
	_, openErr := c.Check(ctx, req)
	if !errors.Is(openErr, ErrFGAUnavailable) {
		t.Fatalf("want ErrFGAUnavailable from open circuit, got: %v", openErr)
	}

	// Let the backend succeed for future calls.
	close(allowSuccess)

	// Wait for half-open.
	time.Sleep(cbTimeout + 30*time.Millisecond)

	// Successful probe — circuit closes.
	_, probeErr := c.Check(ctx, req)
	if probeErr != nil {
		t.Fatalf("probe should succeed after circuit timeout, got: %v", probeErr)
	}
}
