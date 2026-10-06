// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import "context"

// sandboxSuspender suspends and resumes a session sandbox through setec. The
// bank reconciler suspends an idle member and resumes it when jobs wait
// (ADR-0119, gibson#809).
type sandboxSuspender interface {
	Suspend(ctx context.Context, tenant, sandboxID string) error
	Resume(ctx context.Context, tenant, sandboxID string) error
}
