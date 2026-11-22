// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// A finding keeps the agent name and the tags on the way in. An incident release
// reads both (incident-agent#8).
func TestProtoFindingToFinding_KeepsTheAgentNameAndTheTags(t *testing.T) {
	got := protoFindingToFinding(&typespb.Finding{
		Title: "open redirect", AgentName: "incident-agent", Tags: []string{"release:1.4", "pci"},
	})
	assert.Equal(t, "incident-agent", got.AgentName)
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
func TestFindingAgentNameAndTags_SurviveARoundTripWithoutSharingTheSlice(t *testing.T) {
	in := &typespb.Finding{Title: "t", AgentName: "a", Tags: []string{"x", "y"}}
	f := protoFindingToFinding(in)
	out := agentFindingToProto(&f)
	assert.Equal(t, in.GetAgentName(), out.GetAgentName())
	assert.Equal(t, in.GetTags(), out.GetTags())

	f.Tags[0] = "changed"
	assert.Equal(t, []string{"x", "y"}, in.GetTags(), "the finding must not share the slice of the request")
}
