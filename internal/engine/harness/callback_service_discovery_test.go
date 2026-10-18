// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The discovery of a tool call is scoped to the tenant of the callback call,
// so the World of that tenant gets it.
func TestCallToolDiscoveryScopeCarriesTheCallerTenant(t *testing.T) {
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	info := &harnesspb.ContextInfo{MissionId: "m", MissionRunId: "r", AgentName: "recon", AgentRunId: "a", ToolExecutionId: "x"}

	ec := callToolDiscoveryScope(ctx, info)

	assert.Equal(t, "acme", ec.TenantID.String())
	assert.Equal(t, "m", ec.MissionID)
	assert.Equal(t, "r", ec.MissionRunID)
	assert.Equal(t, "recon", ec.AgentName)
	assert.Equal(t, "a", ec.AgentRunID)
	assert.Equal(t, "x", ec.ToolExecutionID)
}

// A call with no tenant in its context gives a scope with no tenant. The
// discovery processor then drops the discovery.
func TestCallToolDiscoveryScopeWithNoTenantHasNoTenant(t *testing.T) {
	ec := callToolDiscoveryScope(context.Background(), &harnesspb.ContextInfo{MissionId: "m"})
	assert.True(t, ec.TenantID.IsZero())
}
