// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agent

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// TargetSchema is an alias for SDK's TargetSchema type
type TargetSchema = sdktypes.TargetSchema

// AgentConfig holds agent initialization configuration.
// This is provided when creating or initializing an agent instance.
type AgentConfig struct {
	Name          string                `json:"name"`
	Settings      map[string]any        `json:"settings"`       // Agent-specific settings
	SlotOverrides map[string]SlotConfig `json:"slot_overrides"` // Override default slot configs
	Timeout       time.Duration         `json:"timeout"`        // Default task timeout
}

// AgentRuntime tracks a running agent instance.
// This is used for monitoring and management of executing agents.
type AgentRuntime struct {
	ID        types.ID  `json:"id"`
	AgentName string    `json:"agent_name"`
	TaskID    types.ID  `json:"task_id"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
}

// Complete marks the runtime as completed
func (r *AgentRuntime) Complete() {
	r.Status = "completed"
}

// Fail marks the runtime as failed
func (r *AgentRuntime) Fail() {
	r.Status = "failed"
}

// Cancel marks the runtime as cancelled
func (r *AgentRuntime) Cancel() {
	r.Status = "cancelled"
}
