// per_call_cap implements the max_tokens_per_call cascade
// declared by mission-schema-canonicalization Requirement 5
// and mission-verb-noun-registry Requirement 10.
//
// Resolution order for the effective per-call cap:
//
//   1. Per-noun *NodeConfig.max_tokens_per_call when set
//      (Proto3 explicit-presence: not nil).
//   2. Mission-level MissionConstraints.max_tokens_per_call
//      when non-zero.
//   3. 0 — no cap from this mechanism.
//
// Spec: mission-schema-canonicalization Requirement 5 ACs 3-5.

package harness

import (
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// EffectivePerCallCap returns the per-LLM-call token cap that
// applies to the given mission node, considering both the
// per-noun override and the mission-level default. Returns 0
// when no cap applies.
//
// `node` may be nil; in that case only the mission-level cap is
// considered.
//
// `constraints` may be nil; in that case only the per-noun
// override is considered.
func EffectivePerCallCap(node *missionv1.MissionNode, constraints *missionv1.MissionConstraints) int32 {
	if cap, ok := perNounCap(node); ok {
		return cap
	}
	if constraints != nil && constraints.MaxTokensPerCall > 0 {
		return constraints.MaxTokensPerCall
	}
	return 0
}

// perNounCap reads the *NodeConfig.max_tokens_per_call field
// for whichever oneof variant the node carries. Returns the cap
// and a present flag.
//
// Proto3 `optional` semantics: a nil pointer means absent; any
// non-nil value (including 0) means explicit. 0 explicitly set
// is treated as "unlimited from this mechanism" but it still
// shadows the mission-level cap (the author chose to disable
// the cap for this node).
func perNounCap(node *missionv1.MissionNode) (int32, bool) {
	if node == nil {
		return 0, false
	}
	switch cfg := node.Config.(type) {
	case *missionv1.MissionNode_AgentConfig:
		if cfg != nil && cfg.AgentConfig != nil && cfg.AgentConfig.MaxTokensPerCall != nil {
			return *cfg.AgentConfig.MaxTokensPerCall, true
		}
	case *missionv1.MissionNode_ToolConfig:
		if cfg != nil && cfg.ToolConfig != nil && cfg.ToolConfig.MaxTokensPerCall != nil {
			return *cfg.ToolConfig.MaxTokensPerCall, true
		}
	case *missionv1.MissionNode_PluginConfig:
		if cfg != nil && cfg.PluginConfig != nil && cfg.PluginConfig.MaxTokensPerCall != nil {
			return *cfg.PluginConfig.MaxTokensPerCall, true
		}
	}
	return 0, false
}
