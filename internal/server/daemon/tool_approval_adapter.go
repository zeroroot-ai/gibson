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

// MayMerge implements metatool.ApprovalGate. It reads the merge slot of the
// merge request from the World of the tenant (gibson#1458, gibson#1466). The slot
// is bound to the merge request and the tenant, and not to a mission. When it
// allows a call, it records the call, so the fix loop watcher frees no slot that a
// call is still using (gibson#1609).
func (a *tenantRoutedToolApproval) MayMerge(_ context.Context, tenant, mergeRequest string) (bool, error) {
	if tenant == "" {
		return false, errors.New("merge gate: the call has no tenant")
	}
	eng, ok := api.TenantEngine(a.registry, tenant)
	if !ok {
		return false, api.ErrWorldUnavailable
	}
	var granted bool
	eng.ReadWorld(func(w *brain.World) { granted = w.MayMerge(mergeRequest) })
	if granted {
		eng.Submit(brain.MergeCallAllowed{MergeRequest: mergeRequest, At: time.Now().UTC()})
	}
	return granted, nil
}
