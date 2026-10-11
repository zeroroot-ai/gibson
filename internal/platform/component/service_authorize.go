// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"log/slog"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RunAuthorizer decides whether a mission run may do an action on a resource.
// *harness.HarnessCallbackService satisfies it, so the pull transport and the
// callback transport run one decision (D86).
type RunAuthorizer interface {
	// AuthorizeRun returns allowed only on an explicit allow. The error is a
	// gRPC status: NotFound for an unknown run, FailedPrecondition for a run
	// that is no longer active, Unavailable when the decision cannot be made.
	AuthorizeRun(ctx context.Context, runID, action, resource string) (allowed bool, reason string, err error)
}

// WithRunAuthorizer wires the decision that Authorize runs. Without it,
// Authorize refuses every request (Unavailable); it never allows.
func (s *ComponentServiceServer) WithRunAuthorizer(a RunAuthorizer) *ComponentServiceServer {
	s.runAuthorizer = a
	return s
}

// Authorize answers whether the work item of the caller may do an action on a
// resource. It is the pull-transport twin of HarnessCallbackService.Authorize.
//
// Flow:
//  1. Confirm the caller owns the work item (resolveWorkOwner).
//  2. Read the mission run bound to the work item at enqueue. The request names
//     no run, so a caller cannot ask about a run that is not its own.
//  3. Run the decision of the callback path on that run.
//
// Every failure is an error, and the answer is allowed only on an explicit allow.
func (s *ComponentServiceServer) Authorize(
	ctx context.Context,
	req *componentpb.AuthorizeRequest,
) (*componentpb.AuthorizeResponse, error) {
	if req.GetWorkId() == "" || req.GetAction() == "" || req.GetResource() == "" {
		return nil, status.Error(codes.InvalidArgument, "authorize: work_id, action and resource are required")
	}
	tenant := auth.TenantStringFromContext(ctx)
	if _, err := s.resolveWorkOwner(ctx, tenant, req.GetWorkId()); err != nil {
		return nil, err
	}
	if s.runAuthorizer == nil {
		s.logger.ErrorContext(ctx, "authorize: no run authorizer is wired; refusing",
			slog.String("work_id", req.GetWorkId()))
		return nil, status.Error(codes.Unavailable, "authorize: the authorization service is not configured")
	}

	runID, err := s.workContext.WorkRun(ctx, req.GetWorkId())
	if err != nil {
		if errors.Is(err, ErrWorkRunUnknown) {
			return nil, status.Errorf(codes.FailedPrecondition, "authorize: work item %q has no mission run", req.GetWorkId())
		}
		s.logger.ErrorContext(ctx, "authorize: run lookup failed",
			slog.String("work_id", req.GetWorkId()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Unavailable, "authorize: cannot resolve the mission run")
	}

	allowed, reason, err := s.runAuthorizer.AuthorizeRun(ctx, runID, req.GetAction(), req.GetResource())
	if err != nil {
		return nil, err //nolint:wrapcheck // the decision returns a gRPC status that the client maps by code
	}
	return &componentpb.AuthorizeResponse{Allowed: allowed, Reason: reason}, nil
}
