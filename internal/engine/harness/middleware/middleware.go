// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package middleware

import (
	"context"
)

// Middleware intercepts harness operations for cross-cutting concerns like
// tracing, logging, event emission, and planning context management.
// Middleware wraps an Operation and returns a new Operation, allowing
// composition of multiple middleware through chaining.
type Middleware func(Operation) Operation

// Operation represents a harness method invocation.
// It takes a context and request payload, returning a response and error.
// Operations are the target of middleware interception.
type Operation func(ctx context.Context, req any) (any, error)

// Chain composes multiple middleware functions into a single middleware.
// Middleware are applied in the order provided, with the first middleware
// being the outermost wrapper (executed first on the way in, last on the way out).
//
// Example:
//
//	middleware := Chain(
//	    TracingMiddleware(tracer),
//	    LoggingMiddleware(logger),
//	    EventMiddleware(bus),
//	)
func Chain(middlewares ...Middleware) Middleware {
	return func(next Operation) Operation {
		// Apply middleware in reverse order so the first middleware
		// in the list becomes the outermost wrapper
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// OperationType identifies which harness method is being invoked.
// This allows middleware to behave differently based on the operation type.
type OperationType string

const (
	// LLM Operations
	OpComplete          OperationType = "complete"
	OpCompleteWithTools OperationType = "complete_with_tools"
	OpStream            OperationType = "stream"

	OpQueryPlugin     OperationType = "query_plugin"
	OpDelegateToAgent OperationType = "delegate_to_agent"

	// Finding Operations
	OpSubmitFinding OperationType = "submit_finding"
)

// Context keys for middleware communication
type ctxKey string

const (
	// CtxOperationType stores the OperationType being executed
	CtxOperationType ctxKey = "op_type"

	// CtxMissionID stores the current mission identifier
	CtxMissionID ctxKey = "mission_id"

	// CtxAgentName stores the current agent name
	CtxAgentName ctxKey = "agent_name"

	// CtxSlotName stores the LLM slot name for LLM operations
	CtxSlotName ctxKey = "slot_name"

	// CtxProvider stores the LLM provider name for LLM operations
	CtxProvider ctxKey = "provider"

	// CtxToolName stores the tool name for tool operations
	CtxToolName ctxKey = "tool_name"

	// CtxPluginName stores the plugin name for plugin operations
	CtxPluginName ctxKey = "plugin_name"

	// CtxPluginMethod stores the plugin method name for plugin operations
	CtxPluginMethod ctxKey = "plugin_method"

	// CtxAgentTargetName stores the target agent name for delegation operations
	CtxAgentTargetName ctxKey = "agent_target_name"

	// CtxMessages stores the LLM messages for LLM operations
	CtxMessages ctxKey = "messages"
)

// WithOperationType returns a new context with the operation type set.
func WithOperationType(ctx context.Context, op OperationType) context.Context {
	return context.WithValue(ctx, CtxOperationType, op)
}

// WithMissionContext returns a new context with mission ID and agent name set.
func WithMissionContext(ctx context.Context, missionID, agentName string) context.Context {
	ctx = context.WithValue(ctx, CtxMissionID, missionID)
	ctx = context.WithValue(ctx, CtxAgentName, agentName)
	return ctx
}

// GetMissionContext retrieves mission ID and agent name from the context.
// Returns empty strings if not set.
func GetMissionContext(ctx context.Context) (missionID, agentName string) {
	if id, ok := ctx.Value(CtxMissionID).(string); ok {
		missionID = id
	}
	if name, ok := ctx.Value(CtxAgentName).(string); ok {
		agentName = name
	}
	return missionID, agentName
}

// Request and response wrapper types for type-safe operation payloads.

// WithSlotName returns a new context with the LLM slot name set.
func WithSlotName(ctx context.Context, slot string) context.Context {
	return context.WithValue(ctx, CtxSlotName, slot)
}

// GetProvider retrieves the LLM provider name from the context.
// Returns empty string if not set.
func GetProvider(ctx context.Context) string {
	if provider, ok := ctx.Value(CtxProvider).(string); ok {
		return provider
	}
	return ""
}

// WithProvider returns a new context with the LLM provider name set.
func WithProvider(ctx context.Context, provider string) context.Context {
	return context.WithValue(ctx, CtxProvider, provider)
}

// GetToolName retrieves the tool name from the context.
// Returns empty string if not set.
func GetToolName(ctx context.Context) string {
	if name, ok := ctx.Value(CtxToolName).(string); ok {
		return name
	}
	return ""
}

// WithPluginInfo returns a new context with plugin name and method set.
func WithPluginInfo(ctx context.Context, name, method string) context.Context {
	ctx = context.WithValue(ctx, CtxPluginName, name)
	ctx = context.WithValue(ctx, CtxPluginMethod, method)
	return ctx
}

// WithAgentTargetName returns a new context with the target agent name set.
func WithAgentTargetName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, CtxAgentTargetName, name)
}

// WithMessages returns a new context with the LLM messages set.
func WithMessages(ctx context.Context, msgs []Message) context.Context {
	return context.WithValue(ctx, CtxMessages, msgs)
}

// Message is a simplified message type for context storage.
// This avoids importing llm package in middleware to prevent cycles.
type Message struct {
	Role    string
	Content string
}
