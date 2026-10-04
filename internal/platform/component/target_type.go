// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import "github.com/zeroroot-ai/gibson/internal/infra/types"

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
