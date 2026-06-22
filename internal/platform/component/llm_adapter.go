package component

// llm_adapter.go implements the LLMCompleter and LLMToolCompleter interfaces
// as thin adapters over the daemon's llm.LLMRegistry and llm.SlotManager.
//
// The adapters bridge the narrow component-callback interfaces (which accept
// slot names as plain strings) to the daemon's provider resolution chain,
// which requires SlotDefinition structs.  At call time, a synthetic
// SlotDefinition is built from the slot name string; slot constraints are
// intentionally left at defaults so that any registered provider/model can
// satisfy the request — strict constraint checking belongs to the agent
// descriptor layer, not the callback proxy.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// LLMRegistryAdapter implements both LLMCompleter and LLMToolCompleter by
// delegating to the daemon's LLMRegistry (provider resolution) and
// SlotManager (slot-to-provider mapping).
//
// Construct via NewLLMRegistryAdapter; wire into ComponentServiceServer via
// WithLLMCompleter and WithLLMToolCompleter.
type LLMRegistryAdapter struct {
	registry llm.LLMRegistry
	slots    llm.SlotManager
	logger   *slog.Logger
}

// NewLLMRegistryAdapter creates an adapter that wraps the given registry and
// slot manager.  Both arguments must be non-nil; the constructor panics
// otherwise to surface misconfiguration early during daemon startup.
func NewLLMRegistryAdapter(registry llm.LLMRegistry, slots llm.SlotManager, logger *slog.Logger) *LLMRegistryAdapter {
	if registry == nil {
		panic("component: NewLLMRegistryAdapter: registry must not be nil")
	}
	if slots == nil {
		panic("component: NewLLMRegistryAdapter: slots must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &LLMRegistryAdapter{registry: registry, slots: slots, logger: logger}
}

// resolveProvider resolves a slot name string to an LLMProvider and ModelInfo.
// A synthetic SlotDefinition is built from the slot name, with no hard constraints
// so that any available provider/model combination is acceptable.
func (a *LLMRegistryAdapter) resolveProvider(ctx context.Context, slotName string) (llm.LLMProvider, llm.ModelInfo, error) {
	// Build a minimal SlotDefinition from just the name.
	// Provider and model within Default are intentionally empty so that
	// SlotManager.ResolveSlot's MergeConfig returns empty strings — that
	// causes ErrInvalidSlotConfig from the default slot manager.
	//
	// To work around this, if the slotName matches a known provider pattern
	// we pass it as the provider name, otherwise we ask the registry directly
	// for the first healthy provider and its first model.
	providers := a.registry.ListProviders()
	if len(providers) == 0 {
		return nil, llm.ModelInfo{}, fmt.Errorf("no LLM providers registered")
	}

	// Try to find a provider whose name matches the slot name exactly (common
	// convention: slot name == provider name when there is only one provider).
	// Otherwise fall back to the first registered provider.
	providerName := providers[0]
	for _, p := range providers {
		if p == slotName {
			providerName = p
			break
		}
	}

	provider, err := a.registry.GetProvider(providerName)
	if err != nil {
		return nil, llm.ModelInfo{}, fmt.Errorf("slot %q: provider %q not found: %w", slotName, providerName, err)
	}

	models, err := provider.Models(ctx)
	if err != nil {
		return nil, llm.ModelInfo{}, fmt.Errorf("slot %q: failed to list models from provider %q: %w", slotName, providerName, err)
	}
	if len(models) == 0 {
		return nil, llm.ModelInfo{}, fmt.Errorf("slot %q: provider %q has no models", slotName, providerName)
	}

	// If the registry has a SlotManager with a config for this slot name, use it.
	// Construct a SlotDefinition with the provider and first-model defaults.
	slotDef := agent.NewSlotDefinition(slotName, "runtime slot", true).
		WithDefault(agent.SlotConfig{
			Provider:    providerName,
			Model:       models[0].Name,
			Temperature: 0.7,
			MaxTokens:   4096,
		})

	// ResolveSlot validates constraints and returns the final provider+model.
	resolvedProvider, resolvedModel, resolveErr := a.slots.ResolveSlot(ctx, slotDef, nil)
	if resolveErr != nil {
		// Fallback: use the first provider and model directly without slot manager validation.
		a.logger.WarnContext(ctx, "llm_adapter: slot resolution failed, using first provider/model directly",
			slog.String("slot", slotName),
			slog.String("provider", providerName),
			slog.String("error", resolveErr.Error()),
		)
		return provider, models[0], nil
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
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, slot)
	if resolveErr != nil {
		return "", "", "", 0, 0, status.Errorf(codes.Unavailable, "slot %q: %v", slot, resolveErr)
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return "", "", "", 0, 0, status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   int(maxTokens),
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
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, slot)
	if resolveErr != nil {
		return status.Errorf(codes.Unavailable, "slot %q: %v", slot, resolveErr)
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   int(maxTokens),
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

// CompleteWithTools implements LLMToolCompleter.
func (a *LLMRegistryAdapter) CompleteWithTools(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON, toolsJSON string,
	maxTokens int32,
	temperature float32,
) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, toolCallsJSON string, err error) {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, slot)
	if resolveErr != nil {
		return "", "", "", 0, 0, "", status.Errorf(codes.Unavailable, "slot %q: %v", slot, resolveErr)
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
		MaxTokens:   int(maxTokens),
		Temperature: float64(temperature),
	}

	resp, callErr := provider.CompleteWithTools(ctx, req, tools)
	if callErr != nil {
		return "", "", "", 0, 0, "", status.Errorf(codes.Internal, "slot %q: tool completion failed: %v", slot, callErr)
	}

	// Marshal any tool calls in the response back to JSON for the proto layer.
	var tcJSON string
	if len(resp.Message.ToolCalls) > 0 {
		tcBytes, marshalErr := json.Marshal(resp.Message.ToolCalls)
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
func (a *LLMRegistryAdapter) CompleteStructured(
	ctx context.Context,
	tenant, missionID, slot, messagesJSON, schemaJSON string,
	maxTokens int32,
	temperature float32,
) (resultJSON string, promptTokens, completionTokens int32, err error) {
	provider, modelInfo, resolveErr := a.resolveProvider(ctx, slot)
	if resolveErr != nil {
		return "", 0, 0, status.Errorf(codes.Unavailable, "slot %q: %v", slot, resolveErr)
	}

	var messages []llm.Message
	if jsonErr := json.Unmarshal([]byte(messagesJSON), &messages); jsonErr != nil {
		return "", 0, 0, status.Errorf(codes.InvalidArgument, "failed to unmarshal messages: %v", jsonErr)
	}

	req := llm.CompletionRequest{
		Model:       modelInfo.Name,
		Messages:    messages,
		MaxTokens:   int(maxTokens),
		Temperature: float64(temperature),
	}

	resp, callErr := provider.Complete(ctx, req)
	if callErr != nil {
		return "", 0, 0, status.Errorf(codes.Internal, "slot %q: structured completion failed: %v", slot, callErr)
	}

	return resp.Message.Content,
		int32(resp.Usage.PromptTokens),
		int32(resp.Usage.CompletionTokens),
		nil
}
