package middleware

import (
	"context"
	"errors"
	"testing"

	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestBuildLLMResponsePayload(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		result   any
		wantNil  bool
		validate func(*testing.T, any)
	}{
		{
			name:    "nil result",
			ctx:     context.Background(),
			result:  nil,
			wantNil: true,
		},
		{
			name:    "invalid result type",
			ctx:     context.Background(),
			result:  "not a completion response",
			wantNil: true,
		},
		{
			name: "valid response with context",
			ctx: func() context.Context {
				ctx := context.Background()
				ctx = context.WithValue(ctx, CtxProvider, "anthropic")
				ctx = context.WithValue(ctx, CtxSlotName, "default")
				return ctx
			}(),
			result: &llm.CompletionResponse{
				Model: "claude-3-5-sonnet-20241022",
				Message: llm.Message{
					Content: "Hello, world!",
				},
				Usage: llm.CompletionTokenUsage{
					PromptTokens:     10,
					CompletionTokens: 5,
				},
				FinishReason: llm.FinishReasonStop,
			},
			wantNil: false,
			validate: func(t *testing.T, payload any) {
				p, ok := payload.(events.LLMRequestCompletedPayload)
				if !ok {
					t.Fatalf("expected LLMRequestCompletedPayload, got %T", payload)
				}
				if p.Provider != "anthropic" {
					t.Errorf("expected provider 'anthropic', got '%s'", p.Provider)
				}
				if p.SlotName != "default" {
					t.Errorf("expected slot 'default', got '%s'", p.SlotName)
				}
				if p.Model != "claude-3-5-sonnet-20241022" {
					t.Errorf("expected model 'claude-3-5-sonnet-20241022', got '%s'", p.Model)
				}
				if p.InputTokens != 10 {
					t.Errorf("expected input tokens 10, got %d", p.InputTokens)
				}
				if p.OutputTokens != 5 {
					t.Errorf("expected output tokens 5, got %d", p.OutputTokens)
				}
			},
		},
		{
			name:   "valid response without context",
			ctx:    context.Background(),
			result: &llm.CompletionResponse{Model: "test"},
			validate: func(t *testing.T, payload any) {
				p := payload.(events.LLMRequestCompletedPayload)
				if p.Provider != "unknown" {
					t.Errorf("expected provider 'unknown', got '%s'", p.Provider)
				}
				if p.SlotName != "unknown" {
					t.Errorf("expected slot 'unknown', got '%s'", p.SlotName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildLLMResponsePayload(tt.ctx, tt.result)
			if tt.wantNil {
				if payload != nil {
					t.Errorf("expected nil payload, got %v", payload)
				}
				return
			}
			if tt.validate != nil {
				tt.validate(t, payload)
			}
		})
	}
}

func TestBuildFindingPayload(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		req      any
		validate func(*testing.T, any)
	}{
		{
			name: "finding pointer with context",
			ctx: func() context.Context {
				ctx := context.Background()
				ctx = context.WithValue(ctx, CtxAgentName, "test-agent")
				return ctx
			}(),
			req: &agent.Finding{
				ID:       types.NewID(),
				Title:    "Test Finding",
				Severity: agent.SeverityHigh,
				CWE:      []string{"CWE-79", "CWE-89"},
			},
			validate: func(t *testing.T, payload any) {
				p, ok := payload.(events.FindingSubmittedPayload)
				if !ok {
					t.Fatalf("expected FindingSubmittedPayload, got %T", payload)
				}
				if p.Title != "Test Finding" {
					t.Errorf("expected title 'Test Finding', got '%s'", p.Title)
				}
				if p.Severity != "high" {
					t.Errorf("expected severity 'high', got '%s'", p.Severity)
				}
				if p.AgentName != "test-agent" {
					t.Errorf("expected agent 'test-agent', got '%s'", p.AgentName)
				}
				if len(p.TechniqueIDs) != 2 {
					t.Errorf("expected 2 technique IDs, got %d", len(p.TechniqueIDs))
				}
			},
		},
		{
			name: "finding without context",
			ctx:  context.Background(),
			req: &agent.Finding{
				Title:    "Test",
				Severity: agent.SeverityLow,
			},
			validate: func(t *testing.T, payload any) {
				p := payload.(events.FindingSubmittedPayload)
				if p.AgentName != "unknown" {
					t.Errorf("expected agent 'unknown', got '%s'", p.AgentName)
				}
			},
		},
		{
			name: "map type",
			ctx:  context.Background(),
			req: map[string]any{
				"title":         "Map Finding",
				"severity":      "critical",
				"technique_ids": []string{"T1234"},
			},
			validate: func(t *testing.T, payload any) {
				p := payload.(events.FindingSubmittedPayload)
				if p.Title != "Map Finding" {
					t.Errorf("expected title 'Map Finding', got '%s'", p.Title)
				}
				if p.Severity != "critical" {
					t.Errorf("expected severity 'critical', got '%s'", p.Severity)
				}
				if len(p.TechniqueIDs) != 1 || p.TechniqueIDs[0] != "T1234" {
					t.Errorf("expected technique_ids ['T1234'], got %v", p.TechniqueIDs)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildFindingPayload(tt.ctx, tt.req)
			if tt.validate != nil {
				tt.validate(t, payload)
			}
		})
	}
}

func TestBuildAgentDelegatedPayload(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		req      any
		validate func(*testing.T, any)
	}{
		{
			name: "agent request with context",
			ctx: func() context.Context {
				ctx := context.Background()
				ctx = context.WithValue(ctx, CtxAgentName, "orchestrator")
				ctx = context.WithValue(ctx, CtxAgentTargetName, "scanner")
				ctx = context.WithValue(ctx, CtxTraceID, "trace123")
				ctx = context.WithValue(ctx, CtxSpanID, "span456")
				return ctx
			}(),
			req: AgentRequest{
				Name: "scanner",
				Task: agent.Task{
					Description: "Scan target for vulnerabilities",
				},
			},
			validate: func(t *testing.T, payload any) {
				p, ok := payload.(events.AgentDelegatedPayload)
				if !ok {
					t.Fatalf("expected AgentDelegatedPayload, got %T", payload)
				}
				if p.FromAgent != "orchestrator" {
					t.Errorf("expected from_agent 'orchestrator', got '%s'", p.FromAgent)
				}
				if p.ToAgent != "scanner" {
					t.Errorf("expected to_agent 'scanner', got '%s'", p.ToAgent)
				}
				if p.TaskDescription != "Scan target for vulnerabilities" {
					t.Errorf("expected task description, got '%s'", p.TaskDescription)
				}
				if p.FromTraceID != "trace123" {
					t.Errorf("expected trace ID 'trace123', got '%s'", p.FromTraceID)
				}
				if p.FromSpanID != "span456" {
					t.Errorf("expected span ID 'span456', got '%s'", p.FromSpanID)
				}
			},
		},
		{
			name: "map type",
			ctx:  context.Background(),
			req: map[string]any{
				"from_agent":       "agent1",
				"to_agent":         "agent2",
				"task_description": "Do something",
			},
			validate: func(t *testing.T, payload any) {
				p := payload.(events.AgentDelegatedPayload)
				if p.FromAgent != "agent1" {
					t.Errorf("expected from_agent 'agent1', got '%s'", p.FromAgent)
				}
				if p.ToAgent != "agent2" {
					t.Errorf("expected to_agent 'agent2', got '%s'", p.ToAgent)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildAgentDelegatedPayload(tt.ctx, tt.req)
			if tt.validate != nil {
				tt.validate(t, payload)
			}
		})
	}
}

func TestBuildLLMRequestFailedPayload(t *testing.T) {
	testErr := errors.New("test error")

	tests := []struct {
		name     string
		ctx      context.Context
		req      any
		err      error
		validate func(*testing.T, any)
	}{
		{
			name: "with context",
			ctx: func() context.Context {
				ctx := context.Background()
				ctx = context.WithValue(ctx, CtxProvider, "openai")
				ctx = context.WithValue(ctx, CtxSlotName, "gpt4")
				return ctx
			}(),
			req: nil,
			err: testErr,
			validate: func(t *testing.T, payload any) {
				p, ok := payload.(events.LLMRequestFailedPayload)
				if !ok {
					t.Fatalf("expected LLMRequestFailedPayload, got %T", payload)
				}
				if p.Provider != "openai" {
					t.Errorf("expected provider 'openai', got '%s'", p.Provider)
				}
				if p.SlotName != "gpt4" {
					t.Errorf("expected slot 'gpt4', got '%s'", p.SlotName)
				}
				if p.Error != "test error" {
					t.Errorf("expected error 'test error', got '%s'", p.Error)
				}
			},
		},
		{
			name: "without context",
			ctx:  context.Background(),
			req:  nil,
			err:  testErr,
			validate: func(t *testing.T, payload any) {
				p := payload.(events.LLMRequestFailedPayload)
				if p.Provider != "unknown" {
					t.Errorf("expected provider 'unknown', got '%s'", p.Provider)
				}
				if p.SlotName != "unknown" {
					t.Errorf("expected slot 'unknown', got '%s'", p.SlotName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildLLMRequestFailedPayload(tt.ctx, tt.req, tt.err)
			if tt.validate != nil {
				tt.validate(t, payload)
			}
		})
	}
}

func TestGetStringOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]any
		key      string
		defaultV string
		want     string
	}{
		{
			name:     "key exists",
			m:        map[string]any{"foo": "bar"},
			key:      "foo",
			defaultV: "default",
			want:     "bar",
		},
		{
			name:     "key missing",
			m:        map[string]any{},
			key:      "missing",
			defaultV: "default",
			want:     "default",
		},
		{
			name:     "key wrong type",
			m:        map[string]any{"num": 123},
			key:      "num",
			defaultV: "default",
			want:     "default",
		},
		{
			name:     "nil map",
			m:        nil,
			key:      "foo",
			defaultV: "default",
			want:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringOrDefault(tt.m, tt.key, tt.defaultV)
			if got != tt.want {
				t.Errorf("getStringOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// extractToolName tests
// --------------------------------------------------------------------------

func TestExtractToolName_CallToolProtoRequest(t *testing.T) {
	req := &harnesspb.CallToolProtoRequest{Name: "nmap"}
	got := extractToolName(req)
	if got != "nmap" {
		t.Errorf("extractToolName(CallToolProtoRequest) = %q, want %q", got, "nmap")
	}
}

func TestExtractToolName_QueueToolWorkRequest(t *testing.T) {
	req := &harnesspb.QueueToolWorkRequest{ToolName: "nuclei"}
	got := extractToolName(req)
	if got != "nuclei" {
		t.Errorf("extractToolName(QueueToolWorkRequest) = %q, want %q", got, "nuclei")
	}
}

func TestExtractToolName_MapFallback_ToolName(t *testing.T) {
	req := map[string]any{"tool_name": "httpx"}
	got := extractToolName(req)
	if got != "httpx" {
		t.Errorf("extractToolName(map tool_name) = %q, want %q", got, "httpx")
	}
}

func TestExtractToolName_MapFallback_Name(t *testing.T) {
	req := map[string]any{"name": "dnsx"}
	got := extractToolName(req)
	if got != "dnsx" {
		t.Errorf("extractToolName(map name) = %q, want %q", got, "dnsx")
	}
}

func TestExtractToolName_Unknown_ReturnsEmpty(t *testing.T) {
	got := extractToolName("unknown-type")
	if got != "" {
		t.Errorf("extractToolName(unknown) = %q, want empty string", got)
	}
}

// --------------------------------------------------------------------------
// extractPluginInfo tests
// --------------------------------------------------------------------------

func TestExtractPluginInfo_QueryPluginRequest(t *testing.T) {
	req := &harnesspb.QueryPluginRequest{Name: "gitlab", Method: "list_merge_requests"}
	name, method := extractPluginInfo(req)
	if name != "gitlab" {
		t.Errorf("extractPluginInfo name = %q, want %q", name, "gitlab")
	}
	if method != "list_merge_requests" {
		t.Errorf("extractPluginInfo method = %q, want %q", method, "list_merge_requests")
	}
}

func TestExtractPluginInfo_MapFallback(t *testing.T) {
	req := map[string]any{"plugin_name": "scope", "method": "get_scope"}
	name, method := extractPluginInfo(req)
	if name != "scope" {
		t.Errorf("extractPluginInfo name = %q, want %q", name, "scope")
	}
	if method != "get_scope" {
		t.Errorf("extractPluginInfo method = %q, want %q", method, "get_scope")
	}
}

func TestExtractPluginInfo_Unknown_ReturnsEmpty(t *testing.T) {
	name, method := extractPluginInfo(42)
	if name != "" || method != "" {
		t.Errorf("extractPluginInfo(unknown) = (%q, %q), want (\"\", \"\")", name, method)
	}
}
