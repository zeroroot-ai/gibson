// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// slotModelResolver backs harness.TenantModelResolver with the SAME per-tenant
// slot resolution a mission uses (newSlotManagerForTenant). A dispatched agent
// and a mission therefore agree on what "the tenant's model" is; resolving it a
// second way here would let the two drift, and the drift would only ever show
// up as an agent running on a model the tenant did not expect.
//
// It is consulted only for an agent whose manifest declares a minimum context
// window (gibson#1692). Everything else dispatches without touching it.
type slotModelResolver struct {
	// forTenant is the daemon's per-tenant slot-manager factory. It is a
	// function rather than a resolved manager because the provider store is
	// built lazily on first use, after the harness factory exists.
	forTenant func(ctx context.Context, tenantID string) (llm.SlotManager, llm.LLMRegistry, error)
}

var _ harness.TenantModelResolver = (*slotModelResolver)(nil)

// agentFloorSlotName is the slot a dispatched agent's model is resolved under.
// It matches the orchestrator's reasoning slot so an agent and a mission node
// resolve against the same tenant policy and the same FGA model-access gate.
const agentFloorSlotName = "primary"

// ResolveAgentModel resolves the tenant's model for a dispatched agent and
// reports its context window.
//
// The floor is expressed as the slot's own MinContextWindow, so the existing
// constraint search does the work: a tenant with no model large enough fails
// here with ErrNoMatchingProvider rather than resolving something smaller. That
// matters because the caller cannot detect the difference afterwards — a model
// under the floor truncates silently and returns a short answer that reads as a
// successful run.
//
// A manifest that pins a model is honoured as an explicit override, and is
// still measured against the floor by the caller: pinning names WHICH model,
// never whether it is big enough.
func (r *slotModelResolver) ResolveAgentModel(
	ctx context.Context, tenant, pinned string, minContextWindow int,
) (model string, contextWindow int, err error) {
	if r == nil || r.forTenant == nil {
		return "", 0, errors.New("per-tenant model resolution is not wired")
	}
	manager, _, err := r.forTenant(ctx, tenant)
	if err != nil {
		return "", 0, fmt.Errorf("resolve providers for tenant %q: %w", tenant, err)
	}
	slot := agent.SlotDefinition{
		Name:     agentFloorSlotName,
		Required: true,
		Constraints: agent.SlotConstraints{
			MinContextWindow: minContextWindow,
		},
	}
	var override *agent.SlotConfig
	if pinned != "" {
		override = &agent.SlotConfig{Model: pinned}
	}
	// Wrapped, not returned bare: the constraint search's own reason ("no
	// matching provider") does not say what was being resolved, and this is the
	// only frame that knows it was an agent's declared floor rather than a
	// mission node's slot. errors.Is still reaches the cause.
	_, info, err := manager.ResolveSlot(ctx, slot, override)
	if err != nil {
		return "", 0, fmt.Errorf("resolve a model with at least %d tokens of context for tenant %q: %w",
			minContextWindow, tenant, err)
	}
	return info.Name, info.ContextWindow, nil
}
