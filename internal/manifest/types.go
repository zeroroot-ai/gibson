package manifest

import (
	"time"
)

// SubjectType enumerates the principals a manifest may be issued to.
// The zero value is invalid; callers must set it explicitly.
type SubjectType string

const (
	// SubjectTypeUser indicates the manifest is issued to a human/service
	// user principal (better-auth or OIDC-resolved).
	SubjectTypeUser SubjectType = "user"

	// SubjectTypeAgentPrincipal indicates the manifest is issued to an
	// Agent Auth Protocol agent_principal, optionally scoped by the
	// owner-user's grants (set-intersection handled by the Builder).
	SubjectTypeAgentPrincipal SubjectType = "agent_principal"
)

// ManifestSubject identifies whose capabilities a manifest resolves.
// ImpersonatedAgentPrincipalID is only meaningful when the requesting
// caller is a tenant admin performing a scaffold-time preview.
type ManifestSubject struct {
	// Type is the subject's principal class. Required.
	Type SubjectType

	// ID is the principal's opaque identifier (UUID for users,
	// ULID/opaque for agent_principals). Required.
	ID string

	// TenantID is the resolved tenant; the Builder fills this in during
	// Build() via TenantFromContext and surfaces any divergence with the
	// caller's claim as an error. Optional at input time.
	TenantID string

	// OwnerUserID is the user that owns this agent_principal. Only set
	// when Type == SubjectTypeAgentPrincipal. Used by the Builder to
	// intersect agent_principal grants with the owner-user's grants so
	// the manifest never surfaces a component the owner cannot reach.
	OwnerUserID string

	// ImpersonatedAgentPrincipalID is non-empty only when a tenant admin
	// is requesting a preview of another agent_principal's manifest
	// (scaffold-time debugging). The handler gates this on admin role.
	ImpersonatedAgentPrincipalID string
}

// FGARef formats the subject into the FGA "<type>:<id>" reference the
// Authorizer expects. Returns empty string for a zero-value subject so
// call sites can guard on `if s.FGARef() == "" { ... }`.
func (s ManifestSubject) FGARef() string {
	if s.ID == "" || s.Type == "" {
		return ""
	}
	return string(s.Type) + ":" + s.ID
}

// BuilderConfig carries static Builder configuration. All fields are
// optional and sensible defaults are applied in NewBuilder.
type BuilderConfig struct {
	// TTL is the lifetime stamped onto each issued manifest. SDKs refresh
	// at expires_at; operators can tune this to balance staleness against
	// daemon load. Default: 5 minutes.
	TTL time.Duration

	// CrossComponentRuleHardCap bounds the number of cross-component
	// rules emitted per manifest. If exceeded, the Builder sets
	// CapabilityManifest.CrossComponentRulesTruncated and logs WARN.
	// Default: 50_000 (matches design.md error scenario 6).
	CrossComponentRuleHardCap int

	// CrossComponentBatchCheckThreshold is the component-count squared
	// above which the Builder prefers BatchCheck over sequential Check.
	// Default: 10_000 (i.e. ~100 components).
	CrossComponentBatchCheckThreshold int
}

// defaults returns a BuilderConfig with zero fields populated.
func (c BuilderConfig) defaults() BuilderConfig {
	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}
	if c.CrossComponentRuleHardCap == 0 {
		c.CrossComponentRuleHardCap = 50000
	}
	if c.CrossComponentBatchCheckThreshold == 0 {
		c.CrossComponentBatchCheckThreshold = 10000
	}
	return c
}

// SigningKeyJWK is the public half of a manifest signing key, shaped for
// the /.well-known/agent-configuration response. Consumers (SDK, ADK) use
// it to verify manifest signatures without a separate key-fetch round-trip.
type SigningKeyJWK struct {
	// Kid is the key identifier stamped into CapabilityManifest.signing_key_id.
	Kid string `json:"kid"`

	// Kty is the key type. Always "OKP" for Ed25519.
	Kty string `json:"kty"`

	// Crv is the curve name. Always "Ed25519" for this package.
	Crv string `json:"crv"`

	// Alg is the signing algorithm identifier. Always "EdDSA".
	Alg string `json:"alg"`

	// X is the base64url-encoded public key (no padding).
	X string `json:"x"`
}

// ComponentRef is a stable FGA-addressable reference to a registered
// component. It mirrors the "component:<name>" object format used
// throughout the FGA model. Prefer agentauth.ComponentRef at the
// FGABridge boundary; this local alias exists to keep the Builder's
// public types anchored in the manifest package.
type ComponentRef struct {
	Name string
	Kind string
}

// FGARef returns the "component:<name>" reference used in FGA tuples.
func (c ComponentRef) FGARef() string {
	if c.Name == "" {
		return ""
	}
	return "component:" + c.Name
}
