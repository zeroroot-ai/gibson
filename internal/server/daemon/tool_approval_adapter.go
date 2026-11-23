// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// tenantRoutedToolApproval implements metatool.ApprovalGate over the approval
// queue of ADR-0132 (gibson#1474). One value serves every tenant. It resolves
// the engine of the tenant that the call names, so a call never reaches the
// queue of another tenant.
type tenantRoutedToolApproval struct {
	registry *brain.Registry
	// betweenReadAndRecord is a seam for a test. It runs after the first read of
	// the slot and before the call is recorded, where a release can come first.
	betweenReadAndRecord func(eng *brain.Engine)
	// recordCall records an allowed call in the World and waits for its fold. It
	// is eng.SubmitAndWait, and a test replaces it to make the record fail.
	recordCall func(ctx context.Context, eng *brain.Engine, ev brain.Event) error
}

var _ metatool.ApprovalGate = (*tenantRoutedToolApproval)(nil)

func newTenantRoutedToolApproval(registry *brain.Registry) *tenantRoutedToolApproval {
	return &tenantRoutedToolApproval{registry: registry}
}

// Acquire implements metatool.ApprovalGate.
//
// gibsoncheck:allow tenant-from-request. req is no request body: metatool
// builds it from Call.Caller, which the dispatch path resolved from the
// verified identity of the caller. The tenant only routes to the queue of
// that tenant.
func (a *tenantRoutedToolApproval) Acquire(
	ctx context.Context, req metatool.ApprovalRequest,
) (metatool.ApprovalState, string, error) {
	if req.Tenant == "" {
		return 0, "", errors.New("tool approval: the call has no tenant")
	}
	eng, ok := api.TenantEngine(a.registry, req.Tenant)
	if !ok {
		return 0, "", api.ErrWorldUnavailable
	}
	rev := brain.ReversibilityIrreversible
	if req.Reversible {
		rev = brain.ReversibilityReversible
	}
	state, id, err := eng.DestructiveAuthorizationQueue().AuthorizeToolCall(ctx, req.Tenant, brain.ToolCallRequest{
		MissionID:     req.MissionID,
		RunID:         req.RunID,
		WorkID:        req.WorkID,
		Agent:         req.Agent,
		Connector:     req.Connector,
		Tool:          req.Tool,
		ArgsHash:      req.ArgsHash,
		BlastRadius:   req.BlastRadius,
		Reversibility: rev,
	})
	if err != nil {
		return 0, "", fmt.Errorf("tool approval: %w", err)
	}
	switch state {
	case brain.ToolCallApproved:
		return metatool.ApprovalStateApproved, id, nil
	case brain.ToolCallDenied:
		return metatool.ApprovalStateDenied, id, nil
	case brain.ToolCallPending:
		return metatool.ApprovalStatePending, id, nil
	default:
		return 0, "", fmt.Errorf("tool approval: unknown state %d", state)
	}
}

// mergeCallRecordTimeout bounds the wait for the fold of an allowed merge call.
const mergeCallRecordTimeout = 5 * time.Second

// MayMerge implements metatool.ApprovalGate. It reads the merge slot of the
// merge request from the World of the tenant (gibson#1458, gibson#1466). The slot
// is bound to the merge request and the tenant, and not to a mission.
//
// The gate answers yes only after the World holds the call. It records the call
// (MergeCallAllowed) with SubmitAndWait, reads the World again, and answers yes
// only when the slot is still granted and holds that call time or a later one.
// The reducer keeps the latest time, so a later call that was folded first does
// not refuse this call. A release that the
// intake queue folded before the call gives a refusal. A release that comes after
// the call is held back by the reducer, which checks the call bound. The queue
// orders the two events, so the call cannot slip past a release (gibson#1609).
func (a *tenantRoutedToolApproval) MayMerge(ctx context.Context, tenant, mergeRequest string) (bool, error) {
	if tenant == "" {
		return false, errors.New("merge gate: the call has no tenant")
	}
	eng, ok := api.TenantEngine(a.registry, tenant)
	if !ok {
		// The agent retries a call that the daemon cannot decide now, and it takes
		// a refusal as final. The two errors of this gate say "unavailable".
		return false, fmt.Errorf("%w: %w", metatool.ErrApprovalUnavailable, api.ErrWorldUnavailable)
	}
	var granted bool
	eng.ReadWorld(func(w *brain.World) { granted = w.MayMerge(mergeRequest) })
	if !granted {
		return false, nil
	}
	if a.betweenReadAndRecord != nil {
		a.betweenReadAndRecord(eng)
	}
	callAt := time.Now().UTC()
	wctx, cancel := context.WithTimeout(ctx, mergeCallRecordTimeout)
	defer cancel()
	record := a.recordCall
	if record == nil {
		record = func(ctx context.Context, e *brain.Engine, ev brain.Event) error { return e.SubmitAndWait(ctx, ev) }
	}
	if err := record(wctx, eng, brain.MergeCallAllowed{MergeRequest: mergeRequest, At: callAt}); err != nil {
		return false, fmt.Errorf("%w: merge gate: the allowed call was not recorded: %w", metatool.ErrApprovalUnavailable, err)
	}
	var held bool
	eng.ReadWorld(func(w *brain.World) {
		for _, sl := range w.MergeSlots() {
			if sl.MergeRequest == mergeRequest && sl.Granted && !sl.LastAllowedAt.Before(callAt) {
				held = true
			}
		}
	})
	return held, nil
}
