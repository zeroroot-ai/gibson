// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// ensureTenantMember writes the (user, member, tenant:<tenant>) tuple when it
// is absent. It is the idempotent check-then-write every FGA seed in the
// daemon does (SetCatalogEnabled, the catalog gate seed): a present tuple is
// left alone, a failed check or write is reported to the caller.
func ensureTenantMember(ctx context.Context, authorizer authz.Authorizer, user, tenant string, logger *slog.Logger) error {
	tuple := authz.Tuple{User: user, Relation: "member", Object: "tenant:" + tenant}
	present, err := authorizer.Check(ctx, tuple.User, tuple.Relation, tuple.Object)
	if err != nil {
		return fmt.Errorf("check %s member of %s: %w", user, tuple.Object, err)
	}
	if present {
		return nil
	}
	if err := authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return fmt.Errorf("write %s member of %s: %w", user, tuple.Object, err)
	}
	logger.Info("tenant membership written", "user", user, "tenant", tenant)
	return nil
}
