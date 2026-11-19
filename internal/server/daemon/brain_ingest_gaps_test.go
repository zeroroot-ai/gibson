// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

func TestIngestHarnessFinding_FoldsAFindingIntoTheTenantWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	sink := ingestHarnessFinding(reg)

	sink(ctx, harness.FindingRaised{
		Tenant: "acme", ID: "f-1", Title: "RCE", Description: "unauth RCE", Severity: "critical",
		MissionID: "m1", AgentName: "scout",
	})
	// A finding with no tenant is dropped.
	sink(ctx, harness.FindingRaised{ID: "f-2", Title: "lost"})
	reg.For("acme").Tick()

	findings := reg.For("acme").Findings()
	require.Len(t, findings, 1)
	assert.Equal(t, "RCE", findings[0].Title)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, "scout", findings[0].AgentName)
	assert.Empty(t, reg.For("other").Findings(), "no finding reaches another tenant")
}

func TestIngestHarnessFinding_ANilRegistryIsANoOp(t *testing.T) {
	assert.NotPanics(t, func() {
		ingestHarnessFinding(nil)(context.Background(), harness.FindingRaised{Tenant: "acme", ID: "f"})
	})
}

// A tool call still succeeds when the World cannot fold its record. The sink
// logs the error and returns.
func TestIngestToolCall_AStoppedEngineDoesNotFailTheCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, func(context.Context, string) (brain.TimelineStore, error) {
		return nil, errors.New("the timeline store is down")
	})
	assert.NotPanics(t, func() {
		ingestToolCall(reg)(ctx, "acme", harness.ToolCallRecord{ToolCallID: "tc1", ToolName: "nmap"})
	})
	assert.Empty(t, reg.For("acme").AgentToolCalls())
}
