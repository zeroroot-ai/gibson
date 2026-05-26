package component

import "github.com/zeroroot-ai/gibson/internal/types"

// TargetType is an alias for types.TargetType.
// It is defined in internal/types to avoid import cycles with the agent package.
type TargetType = types.TargetType

const (
	TargetTypeLLMChat    = types.TargetTypeLLMChat
	TargetTypeLLMAPI     = types.TargetTypeLLMAPI
	TargetTypeRAG        = types.TargetTypeRAG
	TargetTypeAgent      = types.TargetTypeAgent
	TargetTypeEmbedding  = types.TargetTypeEmbedding
	TargetTypeMultimodal = types.TargetTypeMultimodal
	TargetTypeCustom     = types.TargetTypeCustom
)

// AllTargetTypes returns all valid TargetType values.
func AllTargetTypes() []TargetType {
	return types.AllTargetTypes()
}

// ParseTargetType parses a string into a TargetType.
func ParseTargetType(s string) (TargetType, error) {
	return types.ParseTargetType(s)
}
