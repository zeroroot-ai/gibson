// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// llm_adapter.go implements the LLMCompleter and LLMToolCompleter interfaces
// as thin adapters over the CALLING TENANT's llm.LLMRegistry and
// llm.SlotManager.
//
// The adapters bridge the narrow component-callback interfaces (which accept
// slot names as plain strings) to the provider resolution chain, which requires
// SlotDefinition structs.  At call time, a synthetic SlotDefinition is built
// from the slot name string; slot constraints are intentionally left at
// defaults so that any of the tenant's own provider/model combinations can
// satisfy the request — strict constraint checking belongs to the agent
// descriptor layer, not the callback proxy.
//
// TENANT SCOPING: every completion resolves the provider set belonging to the
// tenant named in the call, through the resolver installed by
// WithTenantResolver — the same per-tenant resolution the mission path uses.
// The daemon's process-global, startup-built registry holds the operator's
// credentials and is never used to serve component traffic. Until a resolver
// is installed the adapter fails closed: it serves nothing rather than falling
// back to a shared credential.

import (
	"context"
	"encoding/json"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TenantLLMResolver resolves a tenant's own slot manager and provider registry,
// built from that tenant's stored provider configuration and that tenant's
// credentials. The daemon satisfies it with the same per-tenant provider
// resolver the mission path uses.
//
// An empty tenant, an unknown tenant, or a tenant with no usable providers is
// an error — never a fall back to a shared provider set.
type TenantLLMResolver func(ctx context.Context, tenantID string) (llm.SlotManager, llm.LLMRegistry, error)

// LLMRegistryAdapter implements both LLMCompleter and LLMToolCompleter by
// resolving the calling tenant's provider set and delegating to that tenant's
// SlotManager (slot-to-provider mapping) and LLMRegistry (provider lookup).
//
// Construct via NewLLMRegistryAdapter, install the resolver with
// WithTenantResolver, then wire into ComponentServiceServer via
// WithLLMCompleter and WithLLMToolCompleter.
type LLMRegistryAdapter struct {
	resolveTenant TenantLLMResolver
	logger        *slog.Logger
}

// NewLLMRegistryAdapter creates an adapter for component LLM callbacks.
//
// The registry and slots arguments are the daemon's process-global,
// startup-built LLM stack. They carry the operator's own credentials, so they
// are deliberately dropped here rather than used to serve tenant traffic; they
// remain in the signature only because the daemon's construction site still
// passes them. The adapter serves nothing until WithTenantResolver installs a
// per-tenant resolver.
//
// TODO(gibson): drop both leading parameters once the daemon construction site
// passes the per-tenant resolver directly.
func NewLLMRegistryAdapter(_ llm.LLMRegistry, _ llm.SlotManager, logger *slog.Logger) *LLMRegistryAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LLMRegistryAdapter{logger: logger}
}

// WithTenantResolver installs the per-tenant provider resolver and returns the
// adapter so construction can be chained. Without it every completion fails
// closed.
func (a *LLMRegistryAdapter) WithTenantResolver(resolve TenantLLMResolver) *LLMRegistryAdapter {
	a.resolveTenant = resolve
	return a
}

// resolveProvider resolves a slot name to an LLMProvider and ModelInfo within
// the named tenant's own provider set.
//
// A synthetic SlotDefinition is built from the slot name with no hard
// constraints, so any of the tenant's provider/model combinations can satisfy
// it. When the slot name is itself one of the tenant's provider names it is
// pinned explicitly (the single-provider convention); otherwise the slot is
// left unpinned and the tenant's slot manager applies the tenant's configured
// default. There is no fall back to "whichever provider happens to be first",
// and no fall back past a slot-resolution failure.
func (a *LLMRegistryAdapter) resolveProvider(ctx context.Context, tenant, slotName string) (llm.LLMProvider, llm.ModelInfo, error) {
	if tenant == "" {
		return nil, llm.ModelInfo{}, status.Errorf(codes.PermissionDenied,
			"slot %q: component LLM calls require a tenant", slotName)
	}
	if a.resolveTenant == nil {
		a.logger.ErrorContext(ctx, "llm_adapter: no per-tenant provider resolver installed; refusing completion",
			slog.String("slot", slotName),
		)
		return nil, llm.ModelInfo{}, status.Errorf(codes.FailedPrecondition,
			"slot %q: per-tenant LLM provider resolution is not configured", slotName)
	}

	slots, registry, err := a.resolveTenant(ctx, tenant)
	if err != nil {
		return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
			"slot %q: resolving the tenant's LLM providers failed: %v", slotName, err)
	}
	if slots == nil || registry == nil {
		return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
			"slot %q: the tenant has no resolved LLM provider set", slotName)
	}
	if len(registry.ListProviders()) == 0 {
		return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
			"slot %q: no LLM provider is configured for this tenant", slotName)
	}

	slotDef := agent.NewSlotDefinition(slotName, "component runtime slot", true)

	// Pin explicitly only when the slot names one of THIS tenant's providers.
	if pinned, getErr := registry.GetProvider(slotName); getErr == nil && pinned != nil {
		models, modelsErr := pinned.Models(ctx)
		if modelsErr != nil {
			return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
				"slot %q: listing models from provider %q failed: %v", slotName, slotName, modelsErr)
		}
		if len(models) > 0 {
			slotDef = slotDef.WithDefault(agent.SlotConfig{
				Provider:    slotName,
				Model:       models[0].Name,
				Temperature: 0.7,
				MaxTokens:   4096,
			})
		}
	}

	resolvedProvider, resolvedModel, resolveErr := slots.ResolveSlot(ctx, slotDef, nil)
	if resolveErr != nil {
		return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
			"slot %q: no provider in this tenant's configured set can serve the slot: %v", slotName, resolveErr)
	}
	if resolvedProvider == nil {
		return nil, llm.ModelInfo{}, status.Errorf(codes.Unavailable,
			"slot %q: the tenant's slot manager returned no provider", slotName)
	}

	return resolvedProvider, resolvedModel, nil
}

// Complete implements LLMCompleter. It resolves the slot, unmarshals messages,
// calls the provider, and returns content + usage metrics.
func (a *LLMRegistryAdapter) Complete(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON string,
	maxTokens int32,
	temperature float32,
) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, err error) {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, tenant, slot)
	if resolveErr != nil {
		return "", "", "", 0, 0, resolveErr
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return "", "", "", 0, 0, status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   effectiveMaxTokens(maxTokens),
		Temperature: float64(temperature),
	}

	resp, callErr := provider.Complete(ctx, req)
	if callErr != nil {
		return "", "", "", 0, 0, status.Errorf(codes.Internal, "slot %q: completion failed: %v", slot, callErr)
	}

	return resp.Message.Content,
		string(resp.FinishReason),
		resp.Model,
		int32(resp.Usage.PromptTokens),
		int32(resp.Usage.CompletionTokens),
		nil
}

// Stream implements LLMCompleter for server-streaming completions.
// Each chunk produced by the provider is forwarded to the send callback.
func (a *LLMRegistryAdapter) Stream(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON string,
	maxTokens int32,
	temperature float32,
	send func(delta, finishReason string) error,
) error {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, tenant, slot)
	if resolveErr != nil {
		return resolveErr
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   effectiveMaxTokens(maxTokens),
		Temperature: float64(temperature),
		Stream:      true,
	}

	chunkCh, streamErr := provider.Stream(ctx, req)
	if streamErr != nil {
		return status.Errorf(codes.Internal, "slot %q: stream failed: %v", slot, streamErr)
	}

	for chunk := range chunkCh {
		if chunk.Error != nil {
			return status.Errorf(codes.Internal, "slot %q: stream error: %v", slot, chunk.Error)
		}
		if sendErr := send(chunk.Delta.Content, string(chunk.FinishReason)); sendErr != nil {
			return sendErr
		}
	}

	return nil
}

// toolCallWire is the JSON shape the component seam carries tool calls in:
// one `gibson.component.v1.ToolCallResult`, by its protobuf JSON field names.
//
// This mapping is load-bearing, not cosmetic. `llm.ToolCall` names the same
// field `arguments` while the proto names it `arguments_json`, so marshalling
// `llm.ToolCall` straight into the seam left every tool call arriving at the
// component with an EMPTY `arguments_json` — the tool-calling loop looked
// alive while every call it made carried no arguments (zerocool-plugins#6).
type toolCallWire struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ArgumentsJSON string `json:"arguments_json"`
}

// structuredOutputSchemaName names the schema in the provider request.
// OpenAI's `response_format.json_schema` requires a name and the component
// RPC carries none, so the seam supplies a stable one.
const structuredOutputSchemaName = "component_structured_output"

// CompleteWithTools implements LLMToolCompleter.
func (a *LLMRegistryAdapter) CompleteWithTools(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON, toolsJSON string,
	maxTokens int32,
	temperature float32,
) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, toolCallsJSON string, err error) {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, tenant, slot)
	if resolveErr != nil {
		return "", "", "", 0, 0, "", resolveErr
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return "", "", "", 0, 0, "", status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	var tools []llm.ToolDef
	if toolsJSON != "" {
		if jsonErr := json.Unmarshal([]byte(toolsJSON), &tools); jsonErr != nil {
			return "", "", "", 0, 0, "", status.Errorf(codes.InvalidArgument, "failed to unmarshal tools: %v", jsonErr)
		}
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   effectiveMaxTokens(maxTokens),
		Temperature: float64(temperature),
	}

	resp, callErr := provider.CompleteWithTools(ctx, req, tools)
	if callErr != nil {
		return "", "", "", 0, 0, "", status.Errorf(codes.Internal, "slot %q: tool completion failed: %v", slot, callErr)
	}

	// Marshal any tool calls in the response back to JSON for the proto layer.
	var tcJSON string
	if len(resp.Message.ToolCalls) > 0 {
		wire := make([]toolCallWire, 0, len(resp.Message.ToolCalls))
		for _, tc := range resp.Message.ToolCalls {
			wire = append(wire, toolCallWire{ID: tc.ID, Name: tc.Name, ArgumentsJSON: tc.Arguments})
		}
		tcBytes, marshalErr := json.Marshal(wire)
		if marshalErr != nil {
			a.logger.WarnContext(ctx, "llm_adapter: failed to marshal tool calls in response",
				slog.String("slot", slot),
				slog.String("error", marshalErr.Error()),
			)
		} else {
			tcJSON = string(tcBytes)
		}
	}

	return resp.Message.Content,
		string(resp.FinishReason),
		resp.Model,
		int32(resp.Usage.PromptTokens),
		int32(resp.Usage.CompletionTokens),
		tcJSON,
		nil
}

// CompleteStructured implements LLMToolCompleter for structured JSON output.
//
// The caller's JSON Schema is enforced by the provider through
// llm.StructuredOutputProvider. A provider with no native structured-output
// support is an error, never a silent downgrade to a free-text completion:
// the caller would treat prose as schema-conforming JSON.
func (a *LLMRegistryAdapter) CompleteStructured(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON, schemaJSON string,
	maxTokens int32,
	temperature float32,
) (resultJSON string, promptTokens, completionTokens int32, err error) {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, tenant, slot)
	if resolveErr != nil {
		return "", 0, 0, resolveErr
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return "", 0, 0, status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	if schemaJSON == "" {
		return "", 0, 0, status.Error(codes.InvalidArgument, "schema_json is required")
	}
	var schema types.JSONSchema
	if jsonErr := json.Unmarshal([]byte(schemaJSON), &schema); jsonErr != nil {
		return "", 0, 0, status.Errorf(codes.InvalidArgument, "failed to unmarshal schema: %v", jsonErr)
	}

	structured, ok := provider.(llm.StructuredOutputProvider)
	if !ok || !structured.SupportsStructuredOutput(types.ResponseFormatJSONSchema) {
		return "", 0, 0, status.Errorf(codes.Unimplemented,
			"slot %q: provider %q cannot enforce a JSON schema", slot, provider.Name())
	}

	format := types.NewJSONSchemaFormat(structuredOutputSchemaName, &schema, false)
	req := llm.CompletionRequest{
		Model:          modelInfo.Name,
		Messages:       messages,
		MaxTokens:      int(maxTokens),
		Temperature:    float64(temperature),
		ResponseFormat: &format,
	}

	resp, callErr := structured.CompleteStructured(ctx, req)
	if callErr != nil {
		return "", 0, 0, status.Errorf(codes.Internal, "slot %q: structured completion failed: %v", slot, callErr)
	}

	return resp.Message.Content,
		int32(resp.Usage.PromptTokens),
		int32(resp.Usage.CompletionTokens),
		nil
}

// defaultComponentMaxTokens is the output-token ceiling applied to a component
// completion when the resolved slot supplies none. It matches the fallback
// slot definition's MaxTokens in resolveProvider.
const defaultComponentMaxTokens = 4096

// effectiveMaxTokens floors the server-resolved max output tokens to a usable
// value. The component RPCs carry NO client max-tokens field — the ceiling is
// entirely server-side, from the slot definition — and a slot that omits it
// resolves to 0. Passing 0 to the provider makes it generate an EMPTY
// completion (Anthropic returned completion_tokens=0), which the calling agent
// SDK then chokes on. So an unset/zero ceiling means "use the default", never
// "generate nothing".
func effectiveMaxTokens(maxTokens int32) int {
	if maxTokens <= 0 {
		return defaultComponentMaxTokens
	}
	return int(maxTokens)
}
