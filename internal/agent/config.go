package agent

import (
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
	sdktypes "github.com/zero-day-ai/sdk/types"
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

// NewAgentConfig creates a new agent configuration
func NewAgentConfig(name string) AgentConfig {
	return AgentConfig{
		Name:          name,
		Settings:      make(map[string]any),
		SlotOverrides: make(map[string]SlotConfig),
		Timeout:       30 * time.Minute,
	}
}

// WithSetting adds a setting to the configuration
func (c AgentConfig) WithSetting(key string, value any) AgentConfig {
	c.Settings[key] = value
	return c
}

// WithSlotOverride adds a slot override to the configuration
func (c AgentConfig) WithSlotOverride(slotName string, config SlotConfig) AgentConfig {
	c.SlotOverrides[slotName] = config
	return c
}

// WithTimeout sets the default timeout
func (c AgentConfig) WithTimeout(timeout time.Duration) AgentConfig {
	c.Timeout = timeout
	return c
}

// GetSetting retrieves a setting with a default value
func (c AgentConfig) GetSetting(key string, defaultValue any) any {
	if val, ok := c.Settings[key]; ok {
		return val
	}
	return defaultValue
}

// GetStringSetting retrieves a string setting
func (c AgentConfig) GetStringSetting(key string, defaultValue string) string {
	if val, ok := c.Settings[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetIntSetting retrieves an int setting
func (c AgentConfig) GetIntSetting(key string, defaultValue int) int {
	if val, ok := c.Settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return defaultValue
}

// GetBoolSetting retrieves a bool setting
func (c AgentConfig) GetBoolSetting(key string, defaultValue bool) bool {
	if val, ok := c.Settings[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// AgentDescriptor contains agent metadata.
// This describes an agent's capabilities and requirements without instantiating it.
type AgentDescriptor struct {
	Name           string                    `json:"name"`
	Version        string                    `json:"version"`
	Description    string                    `json:"description"`
	Capabilities   []string                  `json:"capabilities"`
	TargetTypes    []types.TargetType    `json:"target_types"`   // Deprecated: use TargetSchemas
	TargetSchemas  []TargetSchema            `json:"target_schemas"` // New: schema-based target definitions
	TechniqueTypes []types.TechniqueType `json:"technique_types"`
	Slots          []SlotDefinition          `json:"slots"`
	IsExternal     bool                      `json:"is_external"` // True if agent runs via gRPC
}

// NewAgentDescriptor creates a descriptor from an agent instance
func NewAgentDescriptor(a Agent) AgentDescriptor {
	return AgentDescriptor{
		Name:           a.Name(),
		Version:        a.Version(),
		Description:    a.Description(),
		Capabilities:   a.Capabilities(),
		TargetTypes:    a.TargetTypes(),
		TechniqueTypes: a.TechniqueTypes(),
		Slots:          a.LLMSlots(),
		IsExternal:     false,
	}
}

// NewExternalAgentDescriptor creates a descriptor for an external agent
func NewExternalAgentDescriptor(name, version, description string) AgentDescriptor {
	return AgentDescriptor{
		Name:           name,
		Version:        version,
		Description:    description,
		Capabilities:   []string{},
		TargetTypes:    []types.TargetType{},
		TechniqueTypes: []types.TechniqueType{},
		Slots:          []SlotDefinition{},
		IsExternal:     true,
	}
}

// RequiresSlot checks if the agent requires a specific slot
func (d AgentDescriptor) RequiresSlot(slotName string) bool {
	for _, slot := range d.Slots {
		if slot.Name == slotName {
			return slot.Required
		}
	}
	return false
}

// SupportsTargetType checks if the agent supports a given target type.
// It first checks the new TargetSchemas field. If that's empty (for backward
// compatibility), it falls back to checking the deprecated TargetTypes field.
// An empty TargetSchemas list means the agent accepts any target type.
func (d AgentDescriptor) SupportsTargetType(targetType string) bool {
	// If TargetSchemas is populated, use it for validation
	if len(d.TargetSchemas) > 0 {
		for _, schema := range d.TargetSchemas {
			if schema.Type == targetType {
				return true
			}
		}
		return false
	}

	// Fall back to deprecated TargetTypes for backward compatibility
	if len(d.TargetTypes) > 0 {
		for _, tt := range d.TargetTypes {
			if string(tt) == targetType {
				return true
			}
		}
		return false
	}

	// Empty lists mean the agent accepts any target type
	return true
}

// GetTargetSchema returns the schema for a given target type, or nil if not found
func (d AgentDescriptor) GetTargetSchema(targetType string) *TargetSchema {
	for i := range d.TargetSchemas {
		if d.TargetSchemas[i].Type == targetType {
			return &d.TargetSchemas[i]
		}
	}
	return nil
}

// GetSlot retrieves a slot definition by name
func (d AgentDescriptor) GetSlot(slotName string) *SlotDefinition {
	for i, slot := range d.Slots {
		if slot.Name == slotName {
			return &d.Slots[i]
		}
	}
	return nil
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

// NewAgentRuntime creates a new runtime tracker
func NewAgentRuntime(agentName string, taskID types.ID) *AgentRuntime {
	return &AgentRuntime{
		ID:        types.NewID(),
		AgentName: agentName,
		TaskID:    taskID,
		StartedAt: time.Now(),
		Status:    "running",
	}
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

// Duration returns how long the agent has been running
func (r *AgentRuntime) Duration() time.Duration {
	return time.Since(r.StartedAt)
}
