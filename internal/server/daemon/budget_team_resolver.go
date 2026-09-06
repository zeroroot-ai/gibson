// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
)

// newBudgetTeamResolver builds the budget enforcer's team-membership lookup on
// top of FGA. `team#member@user` tuples are the source of truth.
//
// Team FGA object ids are tenant-namespaced (authz.TeamObject) while budget
// keys are already
// tenant-scoped by their own prefix (`budget:tenant:<tenant>:team:<id>`), so
// the tenant segment is stripped here rather than doubled into the key. A
// resolver that returned the raw object id would produce `…:team:acme/eng` and
// silently miss every budget an admin configured for team `eng` — budgets do
// not fail loudly, they just stop applying.
//
// Anything outside the caller's namespace is dropped with a WARN: another
// tenant's team, or a legacy un-namespaced object, must not be charged to this
// tenant's budget. That is the same cross-tenant mixing the namespace exists to
// prevent, and here it would land as someone else's spend.
//
// Failures degrade rather than deny — the enforcer falls back to tenant+user
// scopes when the resolver returns nil, which is the pre-existing contract.
func newBudgetTeamResolver(authorizer authz.Authorizer, logger *slog.Logger) budget.TeamMembershipResolver {
	if authorizer == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, tenantID, userID string) ([]string, error) {
		if userID == "" || tenantID == "" {
			return nil, nil
		}
		teams, err := authorizer.ListObjects(ctx, "user:"+userID, "member", "team")
		if err != nil {
			logger.WarnContext(ctx, "budget: team membership lookup failed; falling back to tenant+user scopes only",
				slog.String("user_id", userID),
				slog.String("error", err.Error()),
			)
			return nil, nil
		}
		tenantSlug := strings.TrimPrefix(tenantID, "tenant:")
		ids := make([]string, 0, len(teams))
		for _, t := range teams {
			id, ok := authz.TeamIDFromObject(tenantSlug, t)
			if !ok {
				logger.WarnContext(ctx, "budget: skipping team object outside the caller's namespace",
					slog.String("tenant_id", tenantID),
					slog.String("team_object", t),
				)
				continue
			}
			ids = append(ids, id)
		}
		return ids, nil
	}
}
