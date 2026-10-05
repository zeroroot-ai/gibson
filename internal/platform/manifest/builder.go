// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"log/slog"
	"time"
)

// BuilderDeps bundles the collaborators a Builder requires. Every field
// is exported so daemon wiring can populate them one-by-one; Builder
// validates presence at construction time.
type BuilderDeps struct {
	FGA      FGAResolver
	Registry RegistrySource
	Signer   Signer
	Versions VersionStore

	// Optional: nil-safe. Builder substitutes empty defaults when absent.
	Tiers  TierLimitsSource
	Memory MemoryPolicySource
	LLM    LLMSlotSource
	Audit  AuditWriter

	// Logger is optional; defaults to slog.Default().
	Logger *slog.Logger

	// Clock is optional; defaults to time.Now. Tests inject a fake.
	Clock func() time.Time
}

// manifestBuilder implements Builder.
type manifestBuilder struct {
	deps BuilderDeps
	cfg  BuilderConfig
}
