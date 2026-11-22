// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// A finding keeps the tags on the way in, and it does not take the agent name
// from the payload (incident-agent#8).
func TestProtoFindingToFinding_KeepsTheTagsAndIgnoresTheAgentNameOfThePayload(t *testing.T) {
	got := protoFindingToFinding(&typespb.Finding{
		Title: "open redirect", AgentName: "incident-agent", Tags: []string{"release:1.4", "pci"},
	})
	assert.Empty(t, got.AgentName, "the payload must not name the agent")
	assert.Equal(t, []string{"release:1.4", "pci"}, got.Tags)

	none := protoFindingToFinding(&typespb.Finding{Title: "open redirect"})
	assert.Empty(t, none.AgentName)
	assert.Empty(t, none.Tags)
}

// A finding keeps the agent name and the tags on the way out.
func TestAgentFindingToProto_KeepsTheAgentNameAndTheTags(t *testing.T) {
	pf := agentFindingToProto(&agent.Finding{Title: "open redirect", AgentName: "incident-agent", Tags: []string{"release:1.4", "pci"}})
	assert.Equal(t, "incident-agent", pf.GetAgentName())
	assert.Equal(t, []string{"release:1.4", "pci"}, pf.GetTags())
}

// The two directions agree, and a change of the copy does not change the source.
func TestFindingTags_SurviveARoundTripWithoutSharingTheSlice(t *testing.T) {
	in := &typespb.Finding{Title: "t", Tags: []string{"x", "y"}}
	f := protoFindingToFinding(in)
	out := agentFindingToProto(&f)
	assert.Equal(t, in.GetTags(), out.GetTags())

	f.Tags[0] = "changed"
	assert.Equal(t, []string{"x", "y"}, in.GetTags(), "the finding must not share the slice of the request")
}

// The harness stamps the agent name from the verified mission context. A payload
// that names another agent changes nothing.
func TestSubmitFinding_StampsTheVerifiedAgentName(t *testing.T) {
	store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
	h := boundedHarness(store)
	h.missionCtx.CurrentAgent = "incident-agent"

	f := protoFindingToFinding(&typespb.Finding{Title: "t", AgentName: "someone-else", Tags: []string{"pci"}})
	f.AgentName = "someone-else" // even a caller that sets the field itself
	require.NoError(t, h.SubmitFinding(context.Background(), f))
	require.Len(t, store.stored, 1)
	assert.Equal(t, "incident-agent", store.stored[0].AgentName)
	assert.Equal(t, []string{"pci"}, store.stored[0].Tags)
}

// The store keeps the verified agent name and the tags through its JSON
// document. The embedded finding loses its agent name in JSON, so the name rides
// on EnhancedFinding and comes back to the base finding.
func TestFindingStoreDocument_KeepsTheAgentNameAndTheTags(t *testing.T) {
	f := agent.NewFinding("t", "d", agent.SeverityHigh)
	f.AgentName = "incident-agent"
	f.Tags = []string{"release:1.4", "pci"}

	doc, err := json.Marshal(enhancedForStore(f, types.NewID()))
	require.NoError(t, err)
	var stored finding.EnhancedFinding
	require.NoError(t, json.Unmarshal(doc, &stored))

	got := findingFromStore(stored)
	assert.Equal(t, "incident-agent", got.AgentName)
	assert.Equal(t, []string{"release:1.4", "pci"}, got.Tags)
}
