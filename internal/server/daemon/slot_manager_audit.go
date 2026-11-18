// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/sdk/auth"
)

// modelResolvedCallback returns the callback that emits a model_resolved audit
// event for every slot resolution, allowed or denied. It returns nil when the
// daemon has no audit writer. Spec: llm-user-attribution-governance
// (Requirement 4.7).
func (d *daemonImpl) modelResolvedCallback() func(ctx context.Context, picked modelgate.Candidate, allowed bool) {
	if d.auditWriter == nil {
		return nil
	}
	emitter := d.auditWriter
	logger := d.logger.Slog()
	return func(ctx context.Context, picked modelgate.Candidate, allowed bool) {
		tenantID := auth.TenantStringFromContext(ctx)
		userID := ""
		if uid, ok := auth.ActingUserFromContext(ctx); ok {
			userID = uid
		} else if uid, ok := auth.InitiatorUserFromContext(ctx); ok {
			userID = uid
		}
		audit.EmitModelResolved(ctx, emitter, logger, audit.ModelResolutionEvent{
			TenantID:       tenantID,
			UserID:         userID,
			ChosenProvider: picked.Provider,
			ChosenModel:    picked.Model,
			Considered: []audit.CandidateOutcome{{
				Provider: picked.Provider,
				Model:    picked.Model,
				Allowed:  allowed,
				Reason: func() string {
					if allowed {
						return "allowed"
					}
					return "fga_denied"
				}(),
			}},
		})
	}
}
