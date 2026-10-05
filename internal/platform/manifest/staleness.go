// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"
	"log/slog"
)

// ManifestVersionHeader is the gRPC metadata key SDKs attach to every
// Harness call so the daemon can refuse stale-manifest calls early.
// Lower-case so it matches grpc-go metadata normalization.
const ManifestVersionHeader = "x-gibson-manifest-version"

// DefaultStalenessTolerance is the window (in version deltas) the
// interceptor tolerates before rejecting. K=2 matches design.md — a
// single unpaired invalidation during propagation is survivable.
const DefaultStalenessTolerance uint64 = 2

// StalenessOptions configures the interceptor behavior.
type StalenessOptions struct {
	// Tolerance is the number of versions by which the supplied header
	// may lag current before the interceptor rejects. Default 2.
	Tolerance uint64

	// SkipMethods is the set of fully-qualified gRPC methods that must
	// never be checked — the manifest RPCs themselves and any
	// unauthenticated bootstrap calls.
	SkipMethods map[string]struct{}

	// RequireHeaderForAgentPrincipal forces rejection when an identified
	// agent_principal caller omits the header. Human users and CLI
	// clients are exempt because they do not hold a manifest.
	RequireHeaderForAgentPrincipal bool

	// TenantResolver supplies the tenant for the caller when the
	// interceptor needs to read VersionStore.Current. The daemon passes
	// its existing auth.TenantFromContext here.
	TenantResolver func(ctx context.Context) string

	// SubjectIsAgentPrincipal reports whether the caller is an
	// agent_principal (used by RequireHeaderForAgentPrincipal).
	SubjectIsAgentPrincipal func(ctx context.Context) bool

	// Logger is optional; defaults to slog.Default.
	Logger *slog.Logger
}
