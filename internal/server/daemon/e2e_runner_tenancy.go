// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// seedE2ERunnerTenancy makes the exit-test runner a member and an admin of the
// platform tenant at boot, when the fixture build names one
// (e2eRunnerTenancy). A production build names none, so this writes nothing
// there. A failed seed is logged: the runner then stops at the dispatch gate,
// and the daemon log says why (gibson#14).
func seedE2ERunnerTenancy(ctx context.Context, authorizer authz.Authorizer, logger *slog.Logger, td spiffeid.TrustDomain) {
	if user, tenant, ok := e2eRunnerTenancy(logger, td); ok && authorizer != nil {
		seedTenantMembership(ctx, authorizer, user, tenant, logger)
	}
}

// runnerTenantRelations are the roles the exit-test runner holds on its
// tenant. member lets the dispatch gate judge its runs the way it judges a
// member's (gibson#14). admin lets it call the Model Access RPCs, which check
// the admin relation in the handler: the model-gate exit test revokes and
// grants the tenant's model access through them, as an administrator does on
// the dashboard page (hosted#358). Neither role holds a model grant or a
// catalog enablement, so each gate under test still decides.
var runnerTenantRelations = []string{"member", "admin"}

// seedTenantMembership is the seed's write and its report: a role that cannot
// be written is logged, and the caller keeps booting.
func seedTenantMembership(ctx context.Context, authorizer authz.Authorizer, user, tenant string, logger *slog.Logger) {
	for _, relation := range runnerTenantRelations {
		if err := ensureTenantRole(ctx, authorizer, user, relation, tenant, logger); err != nil {
			logger.Warn("test fixtures: e2e runner tenancy seed failed; every run it starts stops at the dispatch gate",
				"tenant", tenant, "relation", relation, "error", err)
		}
	}
}

// ensureTenantRole writes the (user, relation, tenant:<tenant>) tuple when it
// is absent. It is the idempotent check-then-write every FGA seed in the
// daemon does (SetCatalogEnabled, the catalog gate seed): a present tuple is
// left alone, a failed check or write is reported to the caller.
func ensureTenantRole(ctx context.Context, authorizer authz.Authorizer, user, relation, tenant string, logger *slog.Logger) error {
	tuple := authz.Tuple{User: user, Relation: relation, Object: "tenant:" + tenant}
	present, err := authorizer.Check(ctx, tuple.User, tuple.Relation, tuple.Object)
	if err != nil {
		return fmt.Errorf("check %s %s of %s: %w", user, relation, tuple.Object, err)
	}
	if present {
		return nil
	}
	if err := authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return fmt.Errorf("write %s %s of %s: %w", user, relation, tuple.Object, err)
	}
	logger.Info("tenant role written", "user", user, "relation", relation, "tenant", tenant)
	return nil
}
