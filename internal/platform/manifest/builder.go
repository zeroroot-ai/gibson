// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"log/slog"
)

// BuilderDeps bundles the collaborators a Builder requires. Every field
// is exported so daemon wiring can populate them one-by-one; Builder
// validates presence at construction time.
type BuilderDeps struct {
	Memory MemoryPolicySource

	// Logger is optional; defaults to slog.Default().
	Logger *slog.Logger
}

// manifestBuilder implements Builder.
type manifestBuilder struct {
	cfg BuilderConfig
}
