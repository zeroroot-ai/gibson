package manifest

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/agentauth"
	"github.com/zero-day-ai/gibson/internal/component"
	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
)

// Builder resolves a principal's full capability set into a signed
// CapabilityManifest proto. See builder.go for the concrete
// implementation; dependencies are injected via BuilderDeps.
type Builder interface {
	Build(ctx context.Context, subject ManifestSubject) (*manifestpb.CapabilityManifest, error)
}

// Signer is the Ed25519 signing facade used by the Builder and by tests.
// Implementations must never expose private key material.
type Signer interface {
	Sign(m *manifestpb.CapabilityManifest) error
	Verify(m *manifestpb.CapabilityManifest) error
	PublishedKeys() []SigningKeyJWK
}

// VersionStore maintains the atomic per-tenant manifest version counter
// backed by Redis with a bounded in-memory cache on Current.
type VersionStore interface {
	Bump(ctx context.Context, tenantID string) (uint64, error)
	Current(ctx context.Context, tenantID string) (uint64, error)
}

// Invalidator fans out a best-effort invalidation event when a tenant's
// manifest has become stale. Implementations publish to Redis pubsub
// and MUST NOT block or error the originating write.
type Invalidator interface {
	Publish(ctx context.Context, tenantID string, reason string)
}

// ManifestNotifier is the small combined facade used by write-path call
// sites (FGA, registry, tier limits). A single Notify covers both Bump
// and Publish so cross-cutting wiring remains trivial.
type ManifestNotifier interface {
	Notify(ctx context.Context, tenantID string, reason string)
}

// FGAResolver is the narrow Builder-facing view of the agentauth.FGABridge.
// *agentauth.FGABridge satisfies it natively. Declared here so unit
// tests mock one small surface rather than the full bridge.
type FGAResolver interface {
	ResolveCapabilities(ctx context.Context, userID, tenantID string) ([]agentauth.Capability, error)
	ResolveCrossComponentRules(ctx context.Context, subjectFGA string, components []agentauth.ComponentRef) ([]agentauth.CrossRule, error)
	ResolveAgentPrincipalIntersection(ctx context.Context, agentPrincipalID, ownerUserID, tenantID string) ([]agentauth.ComponentRef, error)
}

// RegistrySource is the narrow Builder-facing view of the component
// registry. *component.RedisComponentRegistry satisfies this via
// DiscoverAll (tenant-scoped + _system merged).
type RegistrySource interface {
	DiscoverAll(ctx context.Context, tenantID string, kind string) ([]component.ComponentInfo, error)
}

// TierLimitsSource supplies per-tenant resource limits (tokens, rate,
// spend) that the Builder projects into CapabilityManifest.limits.
// Nil pointer from Limits is acceptable and renders empty limits.
type TierLimitsSource interface {
	LimitsFor(ctx context.Context, tenantID string) (*manifestpb.LimitsAndQuotas, error)
}

// MemoryPolicySource returns the per-subject memory-tier access policy.
// Nil pointer from MemoryPolicy is acceptable and renders empty memory.
type MemoryPolicySource interface {
	MemoryPolicy(ctx context.Context, tenantID string, subject ManifestSubject) (*manifestpb.MemoryPermissions, error)
}

// LLMSlotSource returns the LLM slot names the subject is permitted to
// request. Empty slice indicates no LLM access.
type LLMSlotSource interface {
	AvailableSlots(ctx context.Context, tenantID string, subject ManifestSubject) ([]string, error)
}

// AuditWriter records manifest issuances for the 7-day audit retention
// window. Failures are logged but do not fail the Build.
type AuditWriter interface {
	RecordIssuance(ctx context.Context, m *manifestpb.CapabilityManifest, bodySHA256 []byte) error
}
