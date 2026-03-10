package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// Config holds configuration for creating a mission orchestrator.
type Config struct {
	// GraphRAGClient is the Neo4j client for state tracking (required)
	GraphRAGClient graph.GraphClient

	// HarnessFactory creates harnesses for agent execution (required)
	HarnessFactory harness.HarnessFactoryInterface

	// Logger for orchestrator operations (optional, defaults to slog.Default())
	// Accepts either orchestrator.Logger interface or *slog.Logger
	Logger Logger

	// Tracer for distributed tracing (optional, defaults to noop tracer)
	Tracer trace.Tracer

	// EventBus for emitting orchestration events (optional)
	EventBus EventBus

	// MaxIterations is the maximum number of observe-think-act cycles (default: 100)
	MaxIterations int

	// MaxConcurrent is the maximum number of concurrent node executions (default: 10)
	MaxConcurrent int

	// Budget is the token budget for LLM operations (0 = unlimited)
	Budget int

	// Timeout is the overall orchestration timeout (0 = no timeout)
	Timeout time.Duration

	// ThinkerMaxRetries is the maximum number of LLM retry attempts (default: 3)
	ThinkerMaxRetries int

	// ThinkerTemperature is the LLM temperature for decisions (default: 0.2)
	ThinkerTemperature float64

	// DecisionLogWriter for external observability (optional)
	DecisionLogWriter DecisionLogWriter

	// GraphLoader for storing mission definitions in Neo4j (optional)
	GraphLoader MissionGraphLoader

	// Registry for component discovery and validation (optional)
	Registry registry.ComponentDiscovery

	// MissionGraphManager manages Mission and MissionRun nodes in Neo4j (optional)
	// When set, enables automatic mission graph node creation and status tracking
	// for GraphRAG mission-scoped storage.
	MissionGraphManager MissionGraphManager

	// DiscoveryProcessor processes DiscoveryResult from agent outputs (optional)
	// When set, enables automatic storage of discovered hosts, ports, services, etc.
	// from agent outputs to Neo4j for use by downstream agents.
	DiscoveryProcessor DiscoveryProcessor
}

// NewMissionAdapter creates a new mission orchestrator adapter.
// The adapter will create the Observer, Thinker, and Actor components per-mission
// using the provided configuration.
func NewMissionAdapter(cfg Config) (*MissionAdapter, error) {
	// Validate required dependencies
	if cfg.GraphRAGClient == nil {
		return nil, fmt.Errorf("GraphRAGClient is required")
	}
	if cfg.HarnessFactory == nil {
		return nil, fmt.Errorf("HarnessFactory is required")
	}

	// Set defaults
	if cfg.Logger == nil {
		cfg.Logger = &slogAdapter{slog: slog.Default()}
	}
	if cfg.Tracer == nil {
		cfg.Tracer = trace.NewNoopTracerProvider().Tracer("orchestrator")
	}
	if cfg.MaxIterations == 0 {
		cfg.MaxIterations = 100
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 10
	}
	if cfg.ThinkerMaxRetries == 0 {
		cfg.ThinkerMaxRetries = 3
	}
	if cfg.ThinkerTemperature == 0 {
		cfg.ThinkerTemperature = 0.2
	}

	// Create the adapter with configuration
	// The adapter will create the actual orchestrator per-mission
	adapter := &MissionAdapter{
		config:         cfg,
		pauseRequested: make(map[types.ID]bool),
	}

	return adapter, nil
}

// llmClientAdapter adapts an AgentHarness to the orchestrator.LLMClient interface.
// This allows the orchestrator's Thinker to use the harness for LLM operations.
type llmClientAdapter struct {
	harness harness.AgentHarness
}

// Complete performs a synchronous LLM completion using the harness.
func (a *llmClientAdapter) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	return a.harness.Complete(ctx, slot, messages, harnessOpts...)
}

// CompleteStructuredAny performs a completion with provider-native structured output.
func (a *llmClientAdapter) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	return a.harness.CompleteStructuredAny(ctx, slot, messages, schemaType, harnessOpts...)
}

// CompleteStructuredAnyWithUsage performs structured completion and returns token usage.
func (a *llmClientAdapter) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	harnessResult, err := a.harness.CompleteStructuredAnyWithUsage(ctx, slot, messages, schemaType, harnessOpts...)
	if err != nil {
		return nil, err
	}

	// Convert harness.StructuredCompletionResult to orchestrator.StructuredCompletionResult
	return &StructuredCompletionResult{
		Result:           harnessResult.Result,
		Model:            harnessResult.Model,
		RawJSON:          harnessResult.RawJSON,
		PromptTokens:     harnessResult.PromptTokens,
		CompletionTokens: harnessResult.CompletionTokens,
		TotalTokens:      harnessResult.TotalTokens,
	}, nil
}

// orchestratorHarnessAdapter adapts an AgentHarness to the orchestrator.Harness interface.
// This allows the orchestrator's Actor to delegate to agents.
type orchestratorHarnessAdapter struct {
	harness harness.AgentHarness
}

// DelegateToAgent delegates a task to another agent via the harness.
func (a *orchestratorHarnessAdapter) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return a.harness.DelegateToAgent(ctx, agentName, task)
}
