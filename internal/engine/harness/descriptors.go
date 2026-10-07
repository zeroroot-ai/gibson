// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/schema"
)

// PluginMethodDescriptor describes a plugin method at the harness/discovery
// layer. It is the harness-local equivalent of the SDK's plugin.MethodDescriptor
// but is defined here so the harness has no dependency on the deleted
// internal/plugin package or on the SDK's evolving plugin types.
type PluginMethodDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PluginStatus represents plugin lifecycle status at the harness/descriptor
// layer. The new component-service-backed plugin runtime tracks status in Redis
// per install; the descriptor returned to agents only conveys a coarse string
// for compatibility with the legacy ListPlugins() shape.
type PluginStatus string

const (
	PluginStatusUninitialized PluginStatus = "uninitialized"
)

// ToolDescriptor provides lightweight metadata about a tool without requiring
// the full tool interface. Used for discovery, filtering, and capability queries.
type ToolDescriptor struct {
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Version         string            `json:"version"`
	Tags            []string          `json:"tags"`
	InputSchema     schema.JSON       `json:"input_schema"`
	OutputSchema    schema.JSON       `json:"output_schema"`
	InputProtoType  string            `json:"input_proto_type,omitempty"`  // Proto message type name for input (e.g., "tool.v1.Request")
	OutputProtoType string            `json:"output_proto_type,omitempty"` // Proto message type name for output (e.g., "tool.v1.Response")
	Metadata        map[string]string `json:"metadata,omitempty"`          // Additional metadata (e.g., FileDescriptorSet for proto resolution)
}

// toolDescriptorFromInfo builds a ToolDescriptor from the registry entry of a
// tool. Every field comes from what the tool registered, so the daemon dials
// no component to describe it (gibson#813).
func toolDescriptorFromInfo(info component.ComponentInfo) ToolDescriptor {
	return ToolDescriptor{
		Name:            info.Name,
		Description:     info.Metadata["description"],
		Version:         info.Version,
		Tags:            splitTags(info.Metadata["tags"]),
		InputProtoType:  info.Metadata["input_message_type"],
		OutputProtoType: info.Metadata["output_message_type"],
		Metadata:        info.Metadata,
	}
}

// splitTags parses the comma-separated tags metadata value.
func splitTags(value string) []string {
	var tags []string
	for _, t := range strings.Split(value, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// PluginDescriptor provides lightweight metadata about a plugin.
// Used for discovery and capability queries without requiring plugin initialization.
type PluginDescriptor struct {
	Name       string                   `json:"name"`
	Version    string                   `json:"version"`
	Methods    []PluginMethodDescriptor `json:"methods"`
	IsExternal bool                     `json:"is_external"`
	Status     PluginStatus             `json:"status"`
}

// AgentDescriptor provides lightweight metadata about an agent.
// Used for discovery, filtering, and delegation without instantiating the agent.
type AgentDescriptor struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Capabilities []string               `json:"capabilities"`
	Slots        []agent.SlotDefinition `json:"slots"`
	IsExternal   bool                   `json:"is_external"`
}

// HasMethod checks if a plugin descriptor supports a specific method
func (p PluginDescriptor) HasMethod(methodName string) bool {
	for _, method := range p.Methods {
		if method.Name == methodName {
			return true
		}
	}
	return false
}

// GetMethod retrieves a method descriptor by name
func (p PluginDescriptor) GetMethod(methodName string) *PluginMethodDescriptor {
	for i, method := range p.Methods {
		if method.Name == methodName {
			return &p.Methods[i]
		}
	}
	return nil
}

// HasTag checks if a tool descriptor has a specific tag
func (t ToolDescriptor) HasTag(tag string) bool {
	for _, t := range t.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// HasCapability checks if an agent descriptor has a specific capability
func (a AgentDescriptor) HasCapability(capability string) bool {
	for _, c := range a.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// RequiresSlot checks if the agent requires a specific slot
func (a AgentDescriptor) RequiresSlot(slotName string) bool {
	for _, slot := range a.Slots {
		if slot.Name == slotName {
			return slot.Required
		}
	}
	return false
}

// GetSlot retrieves a slot definition by name
func (a AgentDescriptor) GetSlot(slotName string) *agent.SlotDefinition {
	for i, slot := range a.Slots {
		if slot.Name == slotName {
			return &a.Slots[i]
		}
	}
	return nil
}
