// Package provisioner — rollback.go
//
// Rollback provides idempotent reverse-order cleanup of partial signup state.
// It is called by SignupHandler whenever any step in the 11-step signup flow
// fails, passing whatever state was created before the failure.
//
// Rollback order (reverse of creation):
//  1. Delete FGA tuple      (authz.Delete)
//  2. Remove org membership (kc.RemoveOrganizationMember)
//  3. Delete organization   (kc.DeleteOrganization)
//  4. Delete user           (kc.DeleteUser)
//
// Behaviour:
//   - Any ID that is empty is silently skipped (partial state is expected).
//   - ErrNotFound from any step is logged at DEBUG and not included in the
//     returned error (the resource simply does not exist — idempotent).
//   - Any other error is logged at ERROR, accumulated, and returned as a
//     combined errors.Join error at the end. All steps are always attempted
//     regardless of earlier failures.
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// Rollback holds the dependencies needed to reverse a partial signup.
//
// Construct with NewRollback; then call UndoSignup from any failure path in
// SignupHandler.
type Rollback struct {
	kc     KeycloakAdmin
	authz  authz.Authorizer
	logger *slog.Logger
}

// NewRollback constructs a Rollback helper.
//
// kc and az must be non-nil. logger may be nil; slog.Default() is used when nil.
func NewRollback(kc KeycloakAdmin, az authz.Authorizer, logger *slog.Logger) *Rollback {
	if logger == nil {
		logger = slog.Default()
	}
	return &Rollback{
		kc:     kc,
		authz:  az,
		logger: logger.With("component", "provisioner.rollback"),
	}
}

// UndoSignup reverses the signup flow in reverse creation order.
//
// Any combination of IDs may be empty — empty IDs cause the corresponding step
// to be skipped. ErrNotFound is tolerated and logged at DEBUG. All other errors
// are accumulated and returned as a combined error via errors.Join.
//
// The function always runs all steps regardless of individual failures so that
// as much state as possible is cleaned up even when some steps fail.
func (r *Rollback) UndoSignup(ctx context.Context, userID, orgID, tenantID string) error {
	var errs []error

	// Step 1: delete the FGA admin tuple.
	if userID != "" && tenantID != "" {
		tuple := authz.Tuple{
			User:     fmt.Sprintf("user:%s", userID),
			Relation: "admin",
			Object:   fmt.Sprintf("tenant:%s", tenantID),
		}
		if err := r.authz.Delete(ctx, []authz.Tuple{tuple}); err != nil {
			if errors.Is(err, ErrNotFound) {
				r.logger.DebugContext(ctx, "rollback: FGA tuple not found, skipping",
					slog.String("user_id", userID),
					slog.String("tenant_id", tenantID),
				)
			} else {
				r.logger.ErrorContext(ctx, "rollback: failed to delete FGA tuple",
					slog.String("user_id", userID),
					slog.String("tenant_id", tenantID),
					slog.String("error", err.Error()),
				)
				errs = append(errs, fmt.Errorf("rollback delete FGA tuple: %w", err))
			}
		} else {
			r.logger.InfoContext(ctx, "rollback: deleted FGA tuple",
				slog.String("user_id", userID),
				slog.String("tenant_id", tenantID),
			)
		}
	}

	// Step 2: remove org membership.
	if orgID != "" && userID != "" {
		if err := r.kc.RemoveOrganizationMember(ctx, orgID, userID); err != nil {
			if errors.Is(err, ErrNotFound) {
				r.logger.DebugContext(ctx, "rollback: org membership not found, skipping",
					slog.String("org_id", orgID),
					slog.String("user_id", userID),
				)
			} else {
				r.logger.ErrorContext(ctx, "rollback: failed to remove org membership",
					slog.String("org_id", orgID),
					slog.String("user_id", userID),
					slog.String("error", err.Error()),
				)
				errs = append(errs, fmt.Errorf("rollback remove org member: %w", err))
			}
		} else {
			r.logger.InfoContext(ctx, "rollback: removed org membership",
				slog.String("org_id", orgID),
				slog.String("user_id", userID),
			)
		}
	}

	// Step 3: delete the organization.
	if orgID != "" {
		if err := r.kc.DeleteOrganization(ctx, orgID); err != nil {
			if errors.Is(err, ErrNotFound) {
				r.logger.DebugContext(ctx, "rollback: organization not found, skipping",
					slog.String("org_id", orgID),
				)
			} else {
				r.logger.ErrorContext(ctx, "rollback: failed to delete organization",
					slog.String("org_id", orgID),
					slog.String("error", err.Error()),
				)
				errs = append(errs, fmt.Errorf("rollback delete org: %w", err))
			}
		} else {
			r.logger.InfoContext(ctx, "rollback: deleted organization",
				slog.String("org_id", orgID),
			)
		}
	}

	// Step 4: delete the Keycloak user.
	if userID != "" {
		if err := r.kc.DeleteUser(ctx, userID); err != nil {
			if errors.Is(err, ErrNotFound) {
				r.logger.DebugContext(ctx, "rollback: user not found, skipping",
					slog.String("user_id", userID),
				)
			} else {
				r.logger.ErrorContext(ctx, "rollback: failed to delete user",
					slog.String("user_id", userID),
					slog.String("error", err.Error()),
				)
				errs = append(errs, fmt.Errorf("rollback delete user: %w", err))
			}
		} else {
			r.logger.InfoContext(ctx, "rollback: deleted user",
				slog.String("user_id", userID),
			)
		}
	}

	return errors.Join(errs...)
}
