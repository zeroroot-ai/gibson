// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"

	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
)

// Builder resolves a principal's full capability set into a signed
// CapabilityManifest proto. See builder.go for the concrete
// implementation; dependencies are injected via BuilderDeps.
type Builder interface {
	Build(ctx context.Context, subject ManifestSubject) (*manifestpb.CapabilityManifest, error)
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

// MemoryPolicySource returns the per-subject memory-tier access policy.
// Nil pointer from MemoryPolicy is acceptable and renders empty memory.
type MemoryPolicySource interface {
	MemoryPolicy(ctx context.Context, tenantID string, subject ManifestSubject) (*manifestpb.MemoryPermissions, error)
}

// Issuance is the attributable record of one manifest being handed out: who
// asked, on whose behalf, and — when an admin is previewing someone else's
// manifest — which principal was impersonated.
//
// The acting subject is carried explicitly because it is not recoverable
// from the manifest. CapabilityManifest.subject names the principal the
// manifest is about, which under impersonation is the impersonated
// principal, not the admin who requested it.
type Issuance struct {

	// Subject is the principal the manifest resolves capabilities for, as
	// the FGA "<type>:<id>" reference.
	Subject string

	// TenantID is the tenant the manifest was issued in.
	TenantID string
}

// AuditWriter records manifest issuances for the 7-day audit retention
// window. Failures are logged but do not fail the Build.
type AuditWriter interface {
	RecordIssuance(ctx context.Context, m *manifestpb.CapabilityManifest, issuance Issuance, bodySHA256 []byte) error
}
