package harness

import (
	"context"

	"github.com/zeroroot-ai/sdk/agent/compliance"
)

// AgentMetadataProvider is the precedence-3 MetadataProvider that reads
// call-time metadata stamped onto the context by the agent via the
// github.com/zeroroot-ai/sdk/agent/compliance package. It is registered on
// the ComplianceMiddleware at daemon startup (audit-metadata-riders task 10).
type AgentMetadataProvider struct{}

// NewAgentMetadataProvider constructs an AgentMetadataProvider.
func NewAgentMetadataProvider() *AgentMetadataProvider {
	return &AgentMetadataProvider{}
}

// Precedence returns PrecedenceAgent (3).
func (*AgentMetadataProvider) Precedence() int { return PrecedenceAgent }

// Provide reads the call settings from the context and returns a TagSet.
// When no settings are present (agent didn't call compliance.WithCustom),
// the returned TagSet is empty — that's not an error, just absence of
// opt-in metadata.
func (*AgentMetadataProvider) Provide(ctx context.Context, method HarnessMethod, request any) TagSet {
	s := compliance.CallSettingsFromContext(ctx)
	if s == nil {
		return NewTagSet()
	}
	out := NewTagSet()
	for k, v := range s.Custom {
		out.Custom[k] = v
	}
	for k, v := range s.ResourceTags {
		out.ResourceTags[k] = v
	}
	return out
}

// Compile-time assertion.
var _ MetadataProvider = (*AgentMetadataProvider)(nil)
