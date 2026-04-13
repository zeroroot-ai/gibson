package agentauth

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

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

// buildAgentToken constructs and signs a minimal agent+jwt.
func buildAgentToken(priv ed25519.PrivateKey, agentID, hostID, aud, jti string, iat, exp time.Time) tokenParts {
	return buildToken(priv, "agent+jwt", agentID, hostID, aud, jti, iat, exp)
}

// buildHostToken constructs and signs a minimal host+jwt.
func buildHostToken(priv ed25519.PrivateKey, hostID, aud string, iat, exp time.Time) tokenParts {
	return buildToken(priv, "host+jwt", hostID, hostID, aud, "", iat, exp)
}

// buildToken is the shared implementation for buildAgentToken and buildHostToken.
func buildToken(priv ed25519.PrivateKey, typ, sub, iss, aud, jti string, iat, exp time.Time) tokenParts {
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
// miniredis fixture
// ---------------------------------------------------------------------------

// setupRedis starts a miniredis instance and returns a redis.Client backed by it.
// The instance and client are cleaned up when the test finishes.
func setupRedis(t *testing.T) (*miniredis.Miniredis, redis.Cmdable) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

// ---------------------------------------------------------------------------
// VerifyAgentJWT — happy path
// ---------------------------------------------------------------------------

func TestVerifyAgentJWT_ValidToken(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "tenant-acme",
		UserID: "user-bob", Status: "active", PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-abc", now, now.Add(30*time.Second))

	claims, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.NoError(t, err)

	assert.Equal(t, "agent-001", claims.AgentID)
	assert.Equal(t, "host-001", claims.HostID)
	assert.Equal(t, "tenant-acme", claims.TenantID)
	assert.Equal(t, "user-bob", claims.OwnerUserID)
	assert.Equal(t, "jti-abc", claims.JTI)
	assert.WithinDuration(t, now, claims.IssuedAt, time.Second)
	assert.WithinDuration(t, now.Add(30*time.Second), claims.ExpiresAt, time.Second)

	// UpdateAgentLastActive must have been called.
	assert.Contains(t, store.lastActiveUpdated, "agent-001")
}

// ---------------------------------------------------------------------------
// VerifyAgentJWT — rejection paths
// ---------------------------------------------------------------------------

func TestVerifyAgentJWT_ExpiredToken(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	past := time.Now().Add(-120 * time.Second)
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-exp", past, past.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyAgentJWT_WrongAudience(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "wrong-aud", "jti-aud", now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestVerifyAgentJWT_WrongSignature(t *testing.T) {
	pub, _ := genKeyPair(t)
	_, wrongPriv := genKeyPair(t) // sign with a different key
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub), // registered key differs from signing key
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(wrongPriv, "agent-001", "host-001", "gibson-daemon", "jti-sig", now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyAgentJWT_ReplayedJTI(t *testing.T) {
	pub, priv := genKeyPair(t)
	mr, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()

	// First presentation must succeed.
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-replay", now, now.Add(30*time.Second))
	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.NoError(t, err, "first presentation should succeed")

	// Advance miniredis clock by 1 second (token still valid for ~29 more seconds).
	mr.FastForward(time.Second)

	// Second presentation of the same jti must be rejected even with a freshly
	// signed token using the same jti value.
	tp2 := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-replay", now, now.Add(30*time.Second))
	_, err = v.VerifyAgentJWT(context.Background(), tp2.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay")
}

func TestVerifyAgentJWT_MalformedToken_TwoParts(t *testing.T) {
	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	_, err := v.VerifyAgentJWT(context.Background(), "header.payload", "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3 parts")
}

func TestVerifyAgentJWT_MalformedToken_EmptyString(t *testing.T) {
	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	_, err := v.VerifyAgentJWT(context.Background(), "", "gibson-daemon")
	require.Error(t, err)
}

func TestVerifyAgentJWT_MalformedToken_BadBase64Header(t *testing.T) {
	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	_, err := v.VerifyAgentJWT(context.Background(), "!!!.payload.sig", "gibson-daemon")
	require.Error(t, err)
}

func TestVerifyAgentJWT_MalformedToken_BadJSONHeader(t *testing.T) {
	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	badHdr := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	_, err := v.VerifyAgentJWT(context.Background(), badHdr+".payload.sig", "gibson-daemon")
	require.Error(t, err)
}

func TestVerifyAgentJWT_NonEdDSAAlgorithm(t *testing.T) {
	// Construct a token with alg=RS256 — must be rejected.
	hdrBytes, _ := json.Marshal(map[string]string{"typ": "agent+jwt", "alg": "RS256"})
	payBytes, _ := json.Marshal(map[string]interface{}{
		"iss": "host-001", "sub": "agent-001", "aud": "gibson-daemon",
		"iat": time.Now().Unix(), "exp": time.Now().Add(30 * time.Second).Unix(),
		"jti": "jti-alg",
	})
	token := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payBytes) + ".fakesig"

	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	_, err := v.VerifyAgentJWT(context.Background(), token, "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EdDSA")
}

func TestVerifyAgentJWT_FutureTooFar(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	// exp is 200 seconds in the future — exceeds the 65-second maxTokenFuture cap.
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-future",
		now, now.Add(200*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestVerifyAgentJWT_UnknownAgent(t *testing.T) {
	_, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	// Empty store — no agents registered.
	v := NewJWTVerifier(newFakeStore(), rdb)

	now := time.Now()
	tp := buildAgentToken(priv, "agent-nobody", "host-001", "gibson-daemon", "jti-unk",
		now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown agent")
}

func TestVerifyAgentJWT_InactiveAgent(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-revoked", HostID: "host-001", TenantID: "t", Status: "revoked",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-revoked", "host-001", "gibson-daemon", "jti-rev",
		now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status")
}

func TestVerifyAgentJWT_MissingJTI(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	// buildToken with an empty jti omits the field from the payload JSON.
	tp := buildToken(priv, "agent+jwt", "agent-001", "host-001", "gibson-daemon", "", now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti")
}

func TestVerifyAgentJWT_StoreError(t *testing.T) {
	_, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.getAgentErr = fmt.Errorf("database is down")

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-err",
		now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store lookup")
}

// TestVerifyAgentJWT_UpdateLastActiveErrorIgnored verifies that a best-effort
// update failure does not propagate as an error from VerifyAgentJWT.
func TestVerifyAgentJWT_UpdateLastActiveErrorIgnored(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})
	store.updateErr = fmt.Errorf("transient DB error")

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-upd",
		now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.NoError(t, err, "UpdateAgentLastActive errors must not propagate")
}

// ---------------------------------------------------------------------------
// VerifyHostJWT — happy path
// ---------------------------------------------------------------------------

func TestVerifyHostJWT_ValidToken(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addHost(&Host{
		ID:           "host-thumbprint-001",
		TenantID:     "tenant-acme",
		UserID:       "user-alice",
		Status:       "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
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
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store, rdb)
	past := time.Now().Add(-120 * time.Second)
	tp := buildHostToken(priv, "host-001", "gibson-daemon", past, past.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyHostJWT_WrongAudience(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildHostToken(priv, "host-001", "wrong-aud", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestVerifyHostJWT_WrongSignature(t *testing.T) {
	pub, _ := genKeyPair(t)
	_, wrongPriv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildHostToken(wrongPriv, "host-001", "gibson-daemon", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyHostJWT_UnknownHost(t *testing.T) {
	_, priv := genKeyPair(t)
	_, rdb := setupRedis(t)

	v := NewJWTVerifier(newFakeStore(), rdb)
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

	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)

	_, err := v.VerifyHostJWT(context.Background(), token, "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EdDSA")
}

func TestVerifyHostJWT_WrongTyp(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addHost(&Host{ID: "host-001", TenantID: "t", Status: "active", PublicKeyJWK: pubKeyToJWK(pub)})

	v := NewJWTVerifier(store, rdb)
	// Build an agent+jwt and attempt to verify it as a host+jwt.
	now := time.Now()
	tp := buildAgentToken(priv, "host-001", "host-001", "gibson-daemon", "jti-typ", now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host+jwt")
}

// ---------------------------------------------------------------------------
// IsAgentAuthJWT tests
// ---------------------------------------------------------------------------

func TestIsAgentAuthJWT_AgentJWT(t *testing.T) {
	_, priv := genKeyPair(t)
	now := time.Now()
	tp := buildAgentToken(priv, "a", "h", "aud", "jti", now, now.Add(30*time.Second))
	assert.True(t, IsAgentAuthJWT(tp.token()), "agent+jwt must be recognised")
}

func TestIsAgentAuthJWT_HostJWT(t *testing.T) {
	_, priv := genKeyPair(t)
	now := time.Now()
	tp := buildHostToken(priv, "h", "aud", now, now.Add(30*time.Second))
	assert.True(t, IsAgentAuthJWT(tp.token()), "host+jwt must be recognised")
}

func TestIsAgentAuthJWT_RegularJWT(t *testing.T) {
	// A standard JWT with typ=JWT and alg=RS256 should not be recognised.
	hdrBytes, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256"})
	payBytes, _ := json.Marshal(map[string]string{"sub": "user"})
	token := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payBytes) + ".sig"

	assert.False(t, IsAgentAuthJWT(token), "standard JWT must not be recognised as Agent Auth JWT")
}

func TestIsAgentAuthJWT_TwoPartsOnly(t *testing.T) {
	// Simulate a Better Auth session token with only one dot.
	assert.False(t, IsAgentAuthJWT("payload.signature"))
}

func TestIsAgentAuthJWT_EmptyString(t *testing.T) {
	assert.False(t, IsAgentAuthJWT(""))
}

func TestIsAgentAuthJWT_MalformedBase64Header(t *testing.T) {
	assert.False(t, IsAgentAuthJWT("!!!.payload.sig"))
}

func TestIsAgentAuthJWT_EdDSARequired(t *testing.T) {
	// agent+jwt typ but wrong alg — must return false.
	hdrBytes, _ := json.Marshal(map[string]string{"typ": "agent+jwt", "alg": "RS256"})
	payBytes, _ := json.Marshal(map[string]string{"sub": "a"})
	token := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payBytes) + ".sig"

	assert.False(t, IsAgentAuthJWT(token), "agent+jwt with RS256 must not be recognised")
}

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

func TestVerifyAgentJWT_ClockInjection(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	// Freeze the verifier's clock at t0.
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	v := &JWTVerifier{store: store, redis: rdb, clock: func() time.Time { return t0 }}

	// Token issued at t0, expires at t0+30s — valid from the frozen perspective.
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-clk",
		t0, t0.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.NoError(t, err)

	// Advance the frozen clock past expiry, use a fresh jti to bypass replay.
	v.clock = func() time.Time { return t0.Add(60 * time.Second) }
	tp2 := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-clk2",
		t0, t0.Add(30*time.Second))

	_, err = v.VerifyAgentJWT(context.Background(), tp2.token(), "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// ---------------------------------------------------------------------------
// Constructor test
// ---------------------------------------------------------------------------

func TestNewJWTVerifier_NotNil(t *testing.T) {
	_, rdb := setupRedis(t)
	v := NewJWTVerifier(newFakeStore(), rdb)
	require.NotNil(t, v)
	require.NotNil(t, v.clock)
}

// ---------------------------------------------------------------------------
// Tampered payload — signature must fail if payload bytes are altered
// ---------------------------------------------------------------------------

func TestVerifyAgentJWT_TamperedPayload(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-tamp",
		now, now.Add(30*time.Second))

	// Swap in a different payload (different iss / host claim) while keeping the
	// original signature. The sub is unchanged so the store lookup succeeds, but
	// the signing input no longer matches the registered signature.
	evilPayBytes, _ := json.Marshal(map[string]interface{}{
		"iss": "host-attacker", "sub": "agent-001", "aud": "gibson-daemon",
		"iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(),
		"jti": "jti-tamp",
	})
	evilPayEnc := base64.RawURLEncoding.EncodeToString(evilPayBytes)
	tamperedToken := tp.HeaderEncoded + "." + evilPayEnc + "." + tp.SigEncoded

	_, err := v.VerifyAgentJWT(context.Background(), tamperedToken, "gibson-daemon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

// ---------------------------------------------------------------------------
// Concurrent safety smoke test
// ---------------------------------------------------------------------------

func TestVerifyAgentJWT_ConcurrentSafety(t *testing.T) {
	pub, priv := genKeyPair(t)
	_, rdb := setupRedis(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "t", Status: "active",
		PublicKeyJWK: pubKeyToJWK(pub),
	})

	v := NewJWTVerifier(store, rdb)
	now := time.Now()

	const goroutines = 20
	results := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			jti := fmt.Sprintf("jti-concurrent-%d", idx)
			tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", jti, now, now.Add(30*time.Second))
			_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
			results[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range results {
		assert.NoError(t, err, "goroutine %d failed: %v", i, err)
	}
}

// ---------------------------------------------------------------------------
// Cross-typ rejection — each method must reject the other's token type
// ---------------------------------------------------------------------------

func TestVerifyHostJWT_RejectsAgentToken(t *testing.T) {
	_, priv := genKeyPair(t)
	_, rdb := setupRedis(t)

	v := NewJWTVerifier(newFakeStore(), rdb)
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-x",
		now, now.Add(30*time.Second))

	_, err := v.VerifyHostJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "host+jwt"),
		"VerifyHostJWT must reject agent+jwt tokens")
}

func TestVerifyAgentJWT_RejectsHostToken(t *testing.T) {
	_, priv := genKeyPair(t)
	_, rdb := setupRedis(t)

	v := NewJWTVerifier(newFakeStore(), rdb)
	now := time.Now()
	tp := buildHostToken(priv, "host-001", "gibson-daemon", now, now.Add(30*time.Second))

	_, err := v.VerifyAgentJWT(context.Background(), tp.token(), "gibson-daemon")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "agent+jwt"),
		"VerifyAgentJWT must reject host+jwt tokens")
}
