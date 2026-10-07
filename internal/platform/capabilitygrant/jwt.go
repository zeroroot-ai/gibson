// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capabilitygrant — jwt.go
//
// JWTVerifier validates Ed25519-signed JWTs produced by the Capability Grant Protocol.
//
// Two token types are supported:
//
//   - agent+jwt  — issued by agents; verified against the agent's stored public key
//   - host+jwt   — issued by hosts during registration; verified against the host's
//     stored public key
//
// No third-party JWT library is used. Verification is performed using stdlib
// crypto/ed25519, encoding/base64, and encoding/json only.
//
// Security notes:
//
//   - Token expiry is checked BEFORE signature verification to prevent timing
//     oracles from leaking information about signature validity.
//   - The JTI field is included in the JWT payload for uniqueness and audit
//     logging but is NOT enforced server-side (no Redis replay check).
//     The 55-second token lifetime combined with TLS transport security is
//     sufficient to prevent replay attacks.
//   - ed25519.Verify uses constant-time comparison internally.
package capabilitygrant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxTokenFuture is the maximum amount of time a token's exp can be in the
// future relative to the local clock. It accounts for clock skew between the
// token issuer and the verifier, plus the maximum token lifetime of 60 seconds.
const maxTokenFuture = 65 * time.Second

// HostTokenType is the JWS `typ` on a host+jwt (SignHostJWT), presented for
// RE-registration. The register endpoint dispatches on it: host+jwt →
// VerifyHostJWT; otherwise → bootstrap token (gibson#648).
const HostTokenType = "host+jwt"

// ---------------------------------------------------------------------------
// Store interface — narrow contract used by JWTVerifier
// ---------------------------------------------------------------------------

// agentLookup is the narrow interface JWTVerifier requires for agent/host
// resolution. The concrete *CapabilityGrantStore satisfies this interface, and the
// fakeStore in tests does too — keeping the verifier unit-testable without a
// real database.
type agentLookup interface {
	// GetAgent retrieves an agent record by its ID.
	// Returns (nil, nil) when no agent with the given ID exists.
	GetAgent(ctx context.Context, agentID string) (*Agent, error)

	// GetHost retrieves a host record by its ID.
	// Returns (nil, nil) when no host with the given ID exists.
	GetHost(ctx context.Context, hostID string) (*Host, error)

	// UpdateAgentLastActive sets last_active_at = now() for the given agent.
	// This is best-effort; callers must not rely on it succeeding.
	UpdateAgentLastActive(ctx context.Context, agentID string) error
}

// ---------------------------------------------------------------------------
// Claim types returned by the verifier
// ---------------------------------------------------------------------------

// HostClaims contains the verified claims extracted from a host+jwt.
type HostClaims struct {
	// HostID is the JWK thumbprint of the host's public key (JWT iss).
	HostID string

	// TenantID is sourced from the host's store record (not the JWT).
	TenantID string

	// OwnerUserID is sourced from the host's store record (not the JWT).
	OwnerUserID string

	// PrincipalRef is the typed FGA principal stored on the host record, so a
	// re-registration (host+jwt) can re-issue a Capability Grant under the
	// existing identity (gibson#648). Sourced from the store, not the JWT.
	PrincipalRef string

	// AgentName and CapabilityCeiling are the bounds of the credential that
	// enrolled the host. Sourced from the store: a re-registration keeps them.
	AgentName         string
	CapabilityCeiling []string

	// IssuedAt is when the token was created (JWT iat).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (JWT exp).
	ExpiresAt time.Time
}

// ---------------------------------------------------------------------------
// Raw JWT envelope types (unexported)
// ---------------------------------------------------------------------------

// rawHeader is the decoded JOSE header of an Agent Auth JWT.
type rawHeader struct {
	// Typ is the token type. Must be "agent+jwt" or "host+jwt".
	Typ string `json:"typ"`

	// Alg is the signing algorithm. Must be "EdDSA".
	Alg string `json:"alg"`
}

// rawPayload is the decoded JWT payload for Agent Auth tokens.
// Numeric dates use int64 (Unix seconds) as per RFC 7519 §2.
type rawPayload struct {
	// Iss is the issuer. For agent tokens this is the host ID; for host tokens
	// it is the JWK thumbprint of the host's public key.
	Iss string `json:"iss"`

	// Sub is the subject. For agent tokens this is the agent ID.
	Sub string `json:"sub"`

	// Aud is the intended audience. Must match the expectedAud parameter.
	Aud string `json:"aud"`

	// Exp is the expiry time as a Unix timestamp (seconds).
	Exp int64 `json:"exp"`

	// Iat is the issued-at time as a Unix timestamp (seconds).
	Iat int64 `json:"iat"`

	// JTI is the JWT ID used for replay prevention.
	JTI string `json:"jti"`

	// ComponentScope is the FGA component identifier bound to the agent at
	// registration time (spec R2). Required on agent+jwt tokens; absent on
	// host+jwt.
	ComponentScope string `json:"component_scope,omitempty"`
}

// ---------------------------------------------------------------------------
// JWTVerifier
// ---------------------------------------------------------------------------

// JWTVerifier validates Agent Auth JWTs.
//
// It performs:
//   - Header validation (typ, alg)
//   - Audience matching
//   - Expiry and future-skew checks
//   - Ed25519 signature verification against stored public keys
//
// The JTI field is present in verified tokens for audit purposes but is not
// enforced server-side. No Redis round-trip is performed during verification.
//
// JWTVerifier is safe for concurrent use.
type JWTVerifier struct {
	store agentLookup
	clock func() time.Time // injectable for tests
}

// NewJWTVerifier constructs a JWTVerifier backed by the given store.
func NewJWTVerifier(store agentLookup) *JWTVerifier {
	return &JWTVerifier{
		store: store,
		clock: time.Now,
	}
}

// VerifyHostJWT validates a host+jwt token string and returns its verified
// claims on success.
//
// The flow is identical to VerifyAgentJWT except:
//   - The header typ must be "host+jwt".
//   - The issuer (iss) is the JWK thumbprint of the host's public key and
//     serves as the host ID for the store lookup.
//   - No jti replay check is performed — host JWTs are only used for
//     registration, where idempotency is handled at the RPC layer.
func (v *JWTVerifier) VerifyHostJWT(ctx context.Context, tokenStr, expectedAud string) (*HostClaims, error) {
	headerPart, payloadPart, sigPart, err := splitToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: %w", err)
	}

	hdr, err := decodeHeader(headerPart)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: %w", err)
	}
	if hdr.Typ != "host+jwt" {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: unexpected typ %q, want \"host+jwt\"", hdr.Typ)
	}
	if hdr.Alg != "EdDSA" {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: unsupported alg %q, only EdDSA is accepted", hdr.Alg)
	}

	payload, err := decodePayload(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: %w", err)
	}

	if payload.Aud != expectedAud {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: audience mismatch: got %q, want %q", payload.Aud, expectedAud)
	}

	// Check expiry BEFORE signature verification.
	now := v.clock()
	expiresAt := time.Unix(payload.Exp, 0)
	issuedAt := time.Unix(payload.Iat, 0)

	if now.After(expiresAt) {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: token expired at %s", expiresAt.Format(time.RFC3339))
	}
	if expiresAt.After(now.Add(maxTokenFuture)) {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: token exp is too far in the future (%s)", expiresAt.Format(time.RFC3339))
	}

	// Host ID is the iss claim (JWK thumbprint of the host's public key).
	hostID := payload.Iss

	host, err := v.store.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: store lookup: %w", err)
	}
	if host == nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: unknown host %q", hostID)
	}
	if host.Status != "active" {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: host %q has status %q, must be active", hostID, host.Status)
	}

	pubKey, err := parseJWKEd25519(host.PublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: parse host public key: %w", err)
	}

	signingInput := []byte(headerPart + "." + payloadPart)
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: decode signature: %w", err)
	}
	if !ed25519.Verify(pubKey, signingInput, sig) {
		return nil, fmt.Errorf("capabilitygrant: VerifyHostJWT: signature verification failed")
	}

	return &HostClaims{
		HostID:            hostID,
		TenantID:          host.TenantID,
		OwnerUserID:       host.UserID,
		PrincipalRef:      host.PrincipalRef,
		AgentName:         host.AgentName,
		CapabilityCeiling: host.CapabilityCeiling,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// agentCredentialLapsed reports whether the agent's registered lifetime has run
// out at now.
//
// expires_at is written at registration and, until this check existed, was
// never read by anything: both credential paths — VerifyAgentJWT and
// AgentKeyDescriptor — tested only status == "active". An agent therefore kept
// verifying, and kept having its public key served to ext-authz, for as long as
// nobody revoked it by hand. The bounded lifetime the registration recorded was
// unbounded in practice, and keys.go's own doc comment claimed the opposite
// ("a revoked/expired agent's key is withheld").
//
// A nil ExpiresAt means the registration set no expiry, which is not the same
// as an expiry that has passed: such an agent does not lapse.
func agentCredentialLapsed(a *Agent, now time.Time) bool {
	return a != nil && a.ExpiresAt != nil && now.After(*a.ExpiresAt)
}

// splitToken splits a JWT string into its three base64url-encoded parts.
// Returns an error if the token does not have exactly 3 "." separated parts or
// if any part is empty.
func splitToken(token string) (header, payload, signature string, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("malformed token: expected 3 parts, got %d", len(parts))
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("malformed token: empty part")
	}
	return parts[0], parts[1], parts[2], nil
}

// decodeHeader base64url-decodes a JWT header part and parses the JSON.
func decodeHeader(encoded string) (*rawHeader, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var hdr rawHeader
	if err := json.Unmarshal(b, &hdr); err != nil {
		return nil, fmt.Errorf("parse header JSON: %w", err)
	}
	return &hdr, nil
}

// decodePayload base64url-decodes a JWT payload part and parses the JSON.
func decodePayload(encoded string) (*rawPayload, error) {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var p rawPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse payload JSON: %w", err)
	}
	return &p, nil
}

// parseJWKEd25519 parses a JWK containing an Ed25519 public key.
//
// Expected format:
//
//	{"kty":"OKP","crv":"Ed25519","x":"<base64url-encoded-32-byte-public-key>"}
//
// Returns an error if any required field is missing, has an unexpected value,
// or if the decoded key is not exactly 32 bytes.
func parseJWKEd25519(jwk json.RawMessage) (ed25519.PublicKey, error) {
	var key struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(jwk, &key); err != nil {
		return nil, fmt.Errorf("parseJWKEd25519: unmarshal: %w", err)
	}
	if key.Kty != "OKP" {
		return nil, fmt.Errorf("parseJWKEd25519: unsupported kty %q, want \"OKP\"", key.Kty)
	}
	if key.Crv != "Ed25519" {
		return nil, fmt.Errorf("parseJWKEd25519: unsupported crv %q, want \"Ed25519\"", key.Crv)
	}
	if key.X == "" {
		return nil, fmt.Errorf("parseJWKEd25519: missing x parameter")
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("parseJWKEd25519: decode x: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("parseJWKEd25519: x must be %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}
