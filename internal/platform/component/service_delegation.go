// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// bindSourceWork binds the work item that the caller names to the mission of
// the caller. It returns the mission and the mission run of that work item.
//
// The work id arrives from the caller, so the caller must have claimed the
// work item, and a same-tenant agent cannot name the work item of another
// agent. The task grant that the caller presents, verified by the daemon,
// names its mission and its run. A work item of another mission, or of another
// run, is refused. A delegation that names a work item without a verified task
// grant is refused. So is one whose mission or run cannot be resolved. A
// delegation with no work item is not bound.
func (s *ComponentServiceServer) bindSourceWork(ctx context.Context, tenant, sourceWorkID string) (mission, run string, err error) {
	if sourceWorkID == "" {
		return "", "", nil
	}
	if _, err := s.resolveClaimedWork(ctx, tenant, sourceWorkID); err != nil {
		return "", "", err
	}
	grantMission, grantRun, err := s.callerTaskGrant(ctx, tenant)
	if err != nil {
		return "", "", err
	}
	// The work item must belong to the mission and the run of the grant. A
	// lookup that fails, or that finds no mission, cannot prove it, so the
	// delegation is refused (fail closed).
	if s.missionCtx == nil {
		return "", "", status.Error(codes.PermissionDenied, "the mission of the work item cannot be resolved")
	}
	mission, resolveErr := s.missionCtx.ResolveMissionForWork(ctx, sourceWorkID, tenant)
	if resolveErr != nil {
		s.logger.WarnContext(ctx, "delegate to agent: mission of the work item not resolved",
			"work_id", sourceWorkID, "error", resolveErr)
		return "", "", status.Error(codes.PermissionDenied, "the mission of the work item cannot be resolved")
	}
	if mission == "" || mission != grantMission {
		return "", "", status.Error(codes.PermissionDenied, "the work item does not belong to the mission of the grant")
	}
	run = s.sourceWorkRun(ctx, tenant, sourceWorkID)
	if run == "" || run != grantRun {
		return "", "", status.Error(codes.PermissionDenied, "the work item does not belong to the run of the grant")
	}
	return mission, run, nil
}

// sourceWorkRun returns the mission run of the work item that the caller names
// as its own, when the owner recorded at enqueue is the caller tenant. It
// returns an empty string when the work item is not the caller's or has no run.
func (s *ComponentServiceServer) sourceWorkRun(ctx context.Context, tenant, sourceWorkID string) string {
	// resolveClaimedWork refuses when no work-context registry is wired.
	if _, err := s.resolveClaimedWork(ctx, tenant, sourceWorkID); err != nil {
		return ""
	}
	runID, err := s.workContext.WorkRun(ctx, sourceWorkID)
	if err != nil {
		if !errors.Is(err, ErrWorkRunUnknown) {
			s.logger.WarnContext(ctx, "delegate to agent: cannot read the run of the source work item",
				slog.String("work_id", sourceWorkID), slog.String("error", err.Error()))
		}
		return ""
	}
	return runID
}

// authzContextEntry is the work item context entry for a run. When the caller
// has no run, the entry is absent and the delegated agent has no run, so its
// Authorize is refused (fail closed). Delegation itself is not blocked.
func authzContextEntry(runID string) map[string]string {
	if runID == "" {
		return nil
	}
	ac, err := json.Marshal(map[string]any{"run_id": runID, "issued_at": time.Now().Unix(), "ttl_seconds": authz.DefaultWorkTTLSeconds})
	if err != nil {
		return nil
	}
	return map[string]string{authz.AuthzContextWorkKey: string(ac)}
}
