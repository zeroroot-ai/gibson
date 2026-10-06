// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-memory fake store (implements agentLookup)
// ---------------------------------------------------------------------------

// fakeStore is a thread-safe in-memory agentLookup for use in tests.
type fakeStore struct {
	mu     sync.RWMutex
	agents map[string]*Agent
	hosts  map[string]*Host

	// lastActiveUpdated records agent IDs passed to UpdateAgentLastActive.
	lastActiveUpdated []string
	// updateErr, if non-nil, is returned by UpdateAgentLastActive.
	updateErr error
	// getAgentErr, if non-nil, is returned by GetAgent.
	getAgentErr error
	// getHostErr, if non-nil, is returned by GetHost.
	getHostErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		agents: make(map[string]*Agent),
		hosts:  make(map[string]*Host),
	}
}

func (s *fakeStore) GetAgent(_ context.Context, agentID string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.getAgentErr != nil {
		return nil, s.getAgentErr
	}
	return s.agents[agentID], nil
}

func (s *fakeStore) GetHost(_ context.Context, hostID string) (*Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.getHostErr != nil {
		return nil, s.getHostErr
	}
	return s.hosts[hostID], nil
}

func (s *fakeStore) UpdateAgentLastActive(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActiveUpdated = append(s.lastActiveUpdated, agentID)
	return s.updateErr
}

func (s *fakeStore) addAgent(a *Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.ID] = a
}

func (s *fakeStore) addHost(h *Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts[h.ID] = h
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

// genKeyPair generates a fresh Ed25519 keypair for use in a single test.
func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// pubKeyToJWK encodes an Ed25519 public key as a minimal OKP JWK.
func pubKeyToJWK(pub ed25519.PublicKey) json.RawMessage {
	jwk := map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	b, err := json.Marshal(jwk)
	if err != nil {
		panic(fmt.Sprintf("pubKeyToJWK: marshal: %v", err))
	}
	return json.RawMessage(b)
}

// ---------------------------------------------------------------------------
// Token building helpers
// ---------------------------------------------------------------------------

// tokenParts holds the raw base64url parts of a JWT so tests can surgically
// corrupt individual sections.
type tokenParts struct {
	HeaderEncoded  string
	PayloadEncoded string
	SigEncoded     string
}

// buildAgentToken constructs and signs a minimal agent+jwt. component_scope
// defaults to "component:<agentID>" for test ergonomics; tests that need to
// exercise missing/invalid scope use buildTokenWithScope directly.
func buildAgentToken(priv ed25519.PrivateKey, agentID, hostID, aud, jti string, iat, exp time.Time) tokenParts {
	return buildTokenWithScope(priv, "agent+jwt", agentID, hostID, aud, jti, "component:"+agentID, iat, exp)
}

// buildHostToken constructs and signs a minimal host+jwt.
func buildHostToken(priv ed25519.PrivateKey, hostID, aud string, iat, exp time.Time) tokenParts {
	return buildTokenWithScope(priv, "host+jwt", hostID, hostID, aud, "", "", iat, exp)
}

// buildToken is retained for legacy call sites (host JWTs and tests that don't
// care about component_scope). It delegates to buildTokenWithScope with an
// empty scope, matching the pre-component_scope behaviour for host+jwt.
func buildToken(priv ed25519.PrivateKey, typ, sub, iss, aud, jti string, iat, exp time.Time) tokenParts {
	return buildTokenWithScope(priv, typ, sub, iss, aud, jti, "", iat, exp)
}

// buildTokenWithScope is the shared implementation for buildAgentToken,
// buildHostToken, and tests that need control over component_scope.
func buildTokenWithScope(priv ed25519.PrivateKey, typ, sub, iss, aud, jti, componentScope string, iat, exp time.Time) tokenParts {
	hdrBytes, _ := json.Marshal(map[string]string{
		"typ": typ,
		"alg": "EdDSA",
	})
	payMap := map[string]interface{}{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
	}
	if jti != "" {
		payMap["jti"] = jti
	}
	if componentScope != "" {
		payMap["component_scope"] = componentScope
	}
	payBytes, _ := json.Marshal(payMap)

	hdrEnc := base64.RawURLEncoding.EncodeToString(hdrBytes)
	payEnc := base64.RawURLEncoding.EncodeToString(payBytes)

	signingInput := hdrEnc + "." + payEnc
	sig := ed25519.Sign(priv, []byte(signingInput))
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return tokenParts{
		HeaderEncoded:  hdrEnc,
		PayloadEncoded: payEnc,
		SigEncoded:     sigEnc,
	}
}

// token returns the full "header.payload.signature" string.
func (tp tokenParts) token() string {
	return tp.HeaderEncoded + "." + tp.PayloadEncoded + "." + tp.SigEncoded
}

// ---------------------------------------------------------------------------
// VerifyAgentJWT — happy path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VerifyAgentJWT — rejection paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VerifyHostJWT — happy path
// ---------------------------------------------------------------------------

func TestVerifyHostJWT_ValidToken(t *testing.T) {
	pub, priv := genKeyPair(t)
	store := newFakeStore()
	store.addHost(&Host{
		ID:           "host-thumbprint-001",
		TenantID:     "tenant-acme",
		UserID:       "user-alice",
		Status:       "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store)
	now := time.Now()
	tp := buildHostToken(priv, "host-thumbprint-001", "gibson-daemon", now, now.Add(30*time.Second))

	claims, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.NoError(t, err)

	assert.Equal(t, "host-thumbprint-001", claims.HostID)
	assert.Equal(t, "tenant-acme", claims.TenantID)
	assert.Equal(t, "user-alice", claims.OwnerUserID)
	assert.WithinDuration(t, now, claims.IssuedAt, time.Second)
	assert.WithinDuration(t, now.Add(30*time.Second), claims.ExpiresAt, time.Second)
}

// ---------------------------------------------------------------------------
// VerifyHostJWT — rejection paths
// ---------------------------------------------------------------------------

func TestVerifyHostJWT_ExpiredToken(t *testing.T) {
	pub, priv := genKeyPair(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store)
	past := time.Now().Add(-120 * time.Second)
	tp := buildHostToken(priv, "host-001", "gibson-daemon", past, past.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyHostJWT_WrongAudience(t *testing.T) {
	pub, priv := genKeyPair(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store)
	now := time.Now()
	tp := buildHostToken(priv, "host-001", "wrong-aud", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestVerifyHostJWT_WrongSignature(t *testing.T) {
	pub, _ := genKeyPair(t)
	_, wrongPriv := genKeyPair(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store)
	now := time.Now()
	tp := buildHostToken(wrongPriv, "host-001", "gibson-daemon", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyHostJWT_UnknownHost(t *testing.T) {
	_, priv := genKeyPair(t)

	v := NewJWTVerifier(newFakeStore())
	now := time.Now()
	tp := buildHostToken(priv, "host-nobody", "gibson-daemon", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown host")
}

func TestVerifyHostJWT_NonEdDSAAlgorithm(t *testing.T) {
	hdrBytes, _ := json.Marshal(map[string]string{"typ": "host+jwt", "alg": "HS256"})
	payBytes, _ := json.Marshal(map[string]interface{}{
		"iss": "host-001", "sub": "host-001", "aud": "gibson-daemon",
		"iat": time.Now().Unix(), "exp": time.Now().Add(30 * time.Second).Unix(),
	})
	token := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payBytes) + ".fakesig"

	v := NewJWTVerifier(newFakeStore())

	_, err := v.VerifyHostJWT(context.Background(), token, "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EdDSA")
}

func TestVerifyHostJWT_WrongTyp(t *testing.T) {
	pub, priv := genKeyPair(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store)
	// Build an agent+jwt and attempt to verify it as a host+jwt.
	now := time.Now()
	tp := buildAgentToken(priv, "host-001", "host-001", "gibson-daemon", "jti-typ", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host+jwt")
}

// ---------------------------------------------------------------------------
// IsCapabilityGrantJWT tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// parseJWKEd25519 unit tests
// ---------------------------------------------------------------------------

func TestParseJWKEd25519_Valid(t *testing.T) {
	pub, _ := genKeyPair(t)
	jwk := pubKeyToJWK(pub)

	parsed, err := parseJWKEd25519(jwk)
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), []byte(parsed))
}

func TestParseJWKEd25519_WrongKty(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"RSA","crv":"Ed25519","x":"AAAA"}`)
	_, err := parseJWKEd25519(jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kty")
}

func TestParseJWKEd25519_WrongCrv(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"OKP","crv":"P-256","x":"AAAA"}`)
	_, err := parseJWKEd25519(jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "crv")
}

func TestParseJWKEd25519_MissingX(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"OKP","crv":"Ed25519"}`)
	_, err := parseJWKEd25519(jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing x")
}

func TestParseJWKEd25519_BadBase64X(t *testing.T) {
	jwk := json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"!!!not-base64!!!"}`)
	_, err := parseJWKEd25519(jwk)
	require.Error(t, err)
}

func TestParseJWKEd25519_WrongKeyLength(t *testing.T) {
	// 16 bytes instead of 32.
	short := make([]byte, 16)
	x := base64.RawURLEncoding.EncodeToString(short)
	jwk := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, x))
	_, err := parseJWKEd25519(jwk)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

// ---------------------------------------------------------------------------
// splitToken unit tests
// ---------------------------------------------------------------------------

func TestSplitToken_Valid(t *testing.T) {
	h, p, s, err := splitToken("header.payload.sig")
	require.NoError(t, err)
	assert.Equal(t, "header", h)
	assert.Equal(t, "payload", p)
	assert.Equal(t, "sig", s)
}

func TestSplitToken_TwoParts(t *testing.T) {
	_, _, _, err := splitToken("header.payload")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 parts")
}

func TestSplitToken_EmptyPart(t *testing.T) {
	_, _, _, err := splitToken("header..sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty part")
}

func TestSplitToken_FourDotsPassesAtSplitStage(t *testing.T) {
	// SplitN(n=3) puts "c.d" as the third element — the split succeeds.
	// The sig part with an embedded dot will fail later at base64 decode.
	h, p, s, err := splitToken("a.b.c.d")
	require.NoError(t, err)
	assert.Equal(t, "a", h)
	assert.Equal(t, "b", p)
	assert.Equal(t, "c.d", s)
}

// ---------------------------------------------------------------------------
// Clock injection test
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constructor test
// ---------------------------------------------------------------------------

func TestNewJWTVerifier_NotNil(t *testing.T) {
	v := NewJWTVerifier(newFakeStore())
	require.NotNil(t, v)
	require.NotNil(t, v.clock)
}

// ---------------------------------------------------------------------------
// Tampered payload — signature must fail if payload bytes are altered
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Concurrent safety smoke test
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cross-typ rejection — each method must reject the other's token type
// ---------------------------------------------------------------------------

func TestVerifyHostJWT_RejectsAgentToken(t *testing.T) {
	_, priv := genKeyPair(t)

	v := NewJWTVerifier(newFakeStore())
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-x",
		now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "host+jwt"),
		"VerifyHostJWT must reject agent+jwt tokens")
}
