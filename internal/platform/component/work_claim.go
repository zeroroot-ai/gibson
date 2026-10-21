// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// workClaimKeyPrefix is the Redis key prefix for the work-item → claimant
// binding.
//
//	gibson:work:claim:{work_id}
//
// PollWork writes it from the authenticated identity of the component that
// claimed the item, never from anything in the request.
const workClaimKeyPrefix = "gibson:work:claim:"

func workClaimKey(workID string) string { return workClaimKeyPrefix + workID }

// ErrWorkClaimUnknown reports that no claimant is on record for a work id.
var ErrWorkClaimUnknown = errors.New("work-context registry: no claimant recorded for work id")

// WorkClaimRegistry records which principal claimed a work item. The owning
// tenant alone is not enough to act on a work item: two components of one
// tenant must not act on the work of each other.
type WorkClaimRegistry interface {
	// BindWorkClaim records subject as the claimant of workID.
	BindWorkClaim(ctx context.Context, workID, subject string) error
	// WorkClaimant returns the claimant of workID, or ErrWorkClaimUnknown.
	WorkClaimant(ctx context.Context, workID string) (string, error)
}

var _ WorkClaimRegistry = (*RedisWorkContextRegistry)(nil)

// BindWorkClaim writes the claimant of a work item with the same lifetime as
// the owner binding.
func (r *RedisWorkContextRegistry) BindWorkClaim(ctx context.Context, workID, subject string) error {
	if workID == "" || subject == "" {
		return errors.New("work-context registry: bind work claim: work id and subject are required")
	}
	if err := r.stateClient.Client().Set(ctx, workClaimKey(workID), subject, workOwnerTTL).Err(); err != nil {
		return fmt.Errorf("work-context registry: bind claimant of work %q: %w", workID, err)
	}
	return nil
}

// WorkClaimant reads the claimant of a work item.
func (r *RedisWorkContextRegistry) WorkClaimant(ctx context.Context, workID string) (string, error) {
	if workID == "" {
		return "", ErrWorkClaimUnknown
	}
	subject, err := r.stateClient.Client().Get(ctx, workClaimKey(workID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrWorkClaimUnknown
		}
		return "", fmt.Errorf("work-context registry: look up claimant of work %q: %w", workID, err)
	}
	if subject == "" {
		return "", ErrWorkClaimUnknown
	}
	return subject, nil
}

// bindWorkClaim records the caller as the claimant of a work item it has just
// claimed. A failure is logged: the item is still returned, and the claim check
// then refuses each work-scoped call of the claimant, so the failure is safe.
func (s *ComponentServiceServer) bindWorkClaim(ctx context.Context, workID string) {
	reg, ok := s.workContext.(WorkClaimRegistry)
	if !ok || workID == "" {
		return
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		s.logger.WarnContext(ctx, "poll work: no caller identity to record as the claimant", slog.String("work_id", workID))
		return
	}
	if err := reg.BindWorkClaim(ctx, workID, id.Subject); err != nil {
		s.logger.ErrorContext(ctx, "poll work: the claimant of the work item was not recorded",
			slog.String("work_id", workID), slog.String("error", err.Error()))
	}
}

// resolveClaimedWork is resolveWorkOwner plus the claim check: the caller must
// be the principal that claimed the work item, not only a principal of the
// tenant that owns it. Each RPC that lets a component act on a work item that
// it names uses it. It returns the owning tenant.
//
// An unknown claim and a foreign claim are refused with the same message as an
// unknown work id, so the answer does not say whether the id exists.
func (s *ComponentServiceServer) resolveClaimedWork(ctx context.Context, tenant, workID string) (string, error) {
	const denied = "work_id %q is not an outstanding work item for this caller"
	owner, err := s.resolveWorkOwner(ctx, tenant, workID)
	if err != nil {
		return "", err
	}
	reg, ok := s.workContext.(WorkClaimRegistry)
	if !ok {
		s.logger.ErrorContext(ctx, "work claim: registry cannot record claims; refusing work-scoped request",
			slog.String("work_id", workID))
		return "", status.Error(codes.FailedPrecondition, "work-context registry is not configured for claims")
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return "", status.Errorf(codes.PermissionDenied, denied, workID)
	}
	claimant, err := reg.WorkClaimant(ctx, workID)
	if err != nil {
		if errors.Is(err, ErrWorkClaimUnknown) {
			s.logger.WarnContext(ctx, "work claim: no claimant on record for work id",
				slog.String("tenant", tenant), slog.String("work_id", workID))
			return "", status.Errorf(codes.PermissionDenied, denied, workID)
		}
		s.logger.ErrorContext(ctx, "work claim: claimant lookup failed",
			slog.String("work_id", workID), slog.String("error", err.Error()))
		return "", status.Errorf(codes.Internal, "failed to resolve claimant of work %q", workID)
	}
	if claimant != id.Subject {
		s.logger.WarnContext(ctx, "work claim: the caller did not claim this work item",
			slog.String("tenant", tenant), slog.String("work_id", workID))
		return "", status.Errorf(codes.PermissionDenied, denied, workID)
	}
	return owner, nil
}
