package integration_test

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/prompt"
	"github.com/zeroroot-ai/gibson/internal/prompt/transformers"
)

// TestRelay_Integration_FullPipeline tests a complete relay transformation pipeline
func TestRelay_Integration_FullPipeline(t *testing.T) {
	relay := prompt.NewPromptRelay()

	// Setup: Create a parent agent with multiple prompts
	originalPrompts := []prompt.Prompt{
		{
			ID:       "system_main",
			Position: prompt.PositionSystem,
			Content:  "You are a helpful security assistant.",
			Priority: 10,
		},
		{
			ID:       "context_info",
			Position: prompt.PositionContext,
			Content:  "Handle security protocols carefully.",
			Priority: 5,
		},
		{
			ID:       "tools_list",
			Position: prompt.PositionTools,
			Content:  "Available tools: scanner, analyzer, logger",
			Priority: 3,
		},
		{
			ID:       "user_task",
			Position: prompt.PositionUser,
			Content:  "Analyze the security of the system.",
			Priority: 1,
		},
		{
			ID:       "excluded_prompt",
			Position: prompt.PositionPlugins,
			Content:  "This should be excluded",
			Priority: 1,
		},
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "SecurityCoordinator",
		TargetAgent: "VulnerabilityScanner",
		Task:        "Scan for vulnerabilities in the authentication module",
		Memory: map[string]any{
			"scan_depth": "deep",
			"target":     "auth_module",
		},
		Constraints: []string{
			"Do not modify any files",
			"Report all findings",
			"Use safe mode only",
		},
		Prompts: originalPrompts,
	}

	// Create transformers
	contextInjector := transformers.NewContextInjector()
	contextInjector.IncludeMemory = true
	contextInjector.IncludeConstraints = true

	scopeNarrower := transformers.NewScopeNarrower()
	scopeNarrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystemPrefix, // For injected context
		prompt.PositionSystem,
		prompt.PositionContext,
		prompt.PositionUser,
	}
	scopeNarrower.ExcludeIDs = []string{"excluded_prompt"}
	scopeNarrower.KeywordFilter = []string{"security", "assistant", "task"}

	// Execute relay transformation
	result, err := relay.Relay(ctx, contextInjector, scopeNarrower)
	if err != nil {
		t.Fatalf("Relay transformation failed: %v", err)
	}

	// Verify results
	t.Logf("Original prompts: %d", len(originalPrompts))
	t.Logf("Transformed prompts: %d", len(result))

	// Should have: context prompt + filtered prompts
	// Expected: context + system_main + context_info + user_task (4 total)
	// tools_list excluded by keyword filter, excluded_prompt by ID and position
	expectedCount := 4
	if len(result) != expectedCount {
		t.Errorf("Expected %d prompts after transformation, got %d", expectedCount, len(result))
		for i, p := range result {
			t.Logf("  [%d] ID=%s, Position=%s", i, p.ID, p.Position)
		}
	}

	// Verify context prompt was added first
	if len(result) > 0 {
		contextPrompt := result[0]
		if contextPrompt.Position != prompt.PositionSystemPrefix {
			t.Errorf("Expected first prompt to be at system_prefix, got %s", contextPrompt.Position)
		}

		if !strings.Contains(contextPrompt.Content, "SecurityCoordinator") {
			t.Errorf("Context should mention source agent")
		}

		if !strings.Contains(contextPrompt.Content, "Scan for vulnerabilities") {
			t.Errorf("Context should mention task")
		}

		if !strings.Contains(contextPrompt.Content, "Do not modify any files") {
			t.Errorf("Context should include constraints")
		}

		if !strings.Contains(contextPrompt.Content, "Shared Context: 2 items") {
			t.Errorf("Context should mention memory items")
		}
	}

	// Verify original prompts are unchanged (immutability)
	if len(originalPrompts) != 5 {
		t.Errorf("Original prompts slice was modified!")
	}

	if originalPrompts[0].ID != "system_main" {
		t.Errorf("Original prompts were modified!")
	}

	// Verify filtered prompts
	foundIDs := make(map[string]bool)
	for _, p := range result {
		foundIDs[p.ID] = true
	}

	// Should have context + these IDs
	expectedIDs := []string{"system_main", "context_info", "user_task"}
	for _, expectedID := range expectedIDs {
		if !foundIDs[expectedID] {
			t.Errorf("Expected prompt %s to be included", expectedID)
		}
	}

	// Should NOT have these
	excludedIDs := []string{"tools_list", "excluded_prompt"}
	for _, excludedID := range excludedIDs {
		if foundIDs[excludedID] {
			t.Errorf("Expected prompt %s to be excluded", excludedID)
		}
	}
}

// TestRelay_Integration_ContextOnly tests relay with only context injection
func TestRelay_Integration_ContextOnly(t *testing.T) {
	relay := prompt.NewPromptRelay()

	originalPrompts := []prompt.Prompt{
		{
			ID:       "main",
			Position: prompt.PositionSystem,
			Content:  "Main prompt",
			Priority: 1,
		},
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "Parent",
		TargetAgent: "Child",
		Task:        "Delegated task",
		Prompts:     originalPrompts,
	}

	contextInjector := transformers.NewContextInjector()

	result, err := relay.Relay(ctx, contextInjector)
	if err != nil {
		t.Fatalf("Relay failed: %v", err)
	}

	// Should have context + original prompt
	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	if result[0].Position != prompt.PositionSystemPrefix {
		t.Errorf("Expected context at system_prefix")
	}

	if result[1].ID != "main" {
		t.Errorf("Expected original prompt preserved")
	}
}

// TestRelay_Integration_ScopeOnly tests relay with only scope narrowing
func TestRelay_Integration_ScopeOnly(t *testing.T) {
	relay := prompt.NewPromptRelay()

	originalPrompts := []prompt.Prompt{
		{ID: "p1", Position: prompt.PositionSystem, Content: "security info"},
		{ID: "p2", Position: prompt.PositionUser, Content: "other info"},
		{ID: "p3", Position: prompt.PositionContext, Content: "security context"},
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "Parent",
		TargetAgent: "Child",
		Task:        "Delegated task",
		Prompts:     originalPrompts,
	}

	scopeNarrower := transformers.NewScopeNarrower()
	scopeNarrower.KeywordFilter = []string{"security"}

	result, err := relay.Relay(ctx, scopeNarrower)
	if err != nil {
		t.Fatalf("Relay failed: %v", err)
	}

	// Should only have prompts with "security" keyword
	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	for _, p := range result {
		if !strings.Contains(strings.ToLower(p.Content), "security") {
			t.Errorf("Prompt %s should contain 'security'", p.ID)
		}
	}
}

// TestRelay_Integration_ComplexScenario tests a complex multi-agent scenario
func TestRelay_Integration_ComplexScenario(t *testing.T) {
	relay := prompt.NewPromptRelay()

	// Scenario: Main orchestrator delegates to specialized sub-agents
	originalPrompts := []prompt.Prompt{
		{
			ID:       "orchestrator_system",
			Position: prompt.PositionSystem,
			Content:  "You are a security orchestrator managing multiple scanning agents.",
			Priority: 10,
		},
		{
			ID:       "target_context",
			Position: prompt.PositionContext,
			Content:  "Target: Production authentication service. Contains user credentials and session management.",
			Priority: 8,
		},
		{
			ID:       "available_tools",
			Position: prompt.PositionTools,
			Content:  "Tools: static_analyzer, dynamic_scanner, vulnerability_db, report_generator",
			Priority: 5,
		},
		{
			ID:       "constraints",
			Position: prompt.PositionConstraints,
			Content:  "Constraints: Read-only access, No invasive testing, Report severity >= MEDIUM",
			Priority: 4,
		},
		{
			ID:       "user_request",
			Position: prompt.PositionUser,
			Content:  "Perform comprehensive security audit of authentication module",
			Priority: 1,
		},
	}

	// First relay: Orchestrator -> Static Analyzer
	staticAnalyzerCtx := &prompt.RelayContext{
		SourceAgent: "SecurityOrchestrator",
		TargetAgent: "StaticAnalyzer",
		Task:        "Perform static code analysis on authentication module",
		Memory: map[string]any{
			"module":        "authentication",
			"language":      "go",
			"analysis_type": "security",
		},
		Constraints: []string{
			"Focus on authentication vulnerabilities",
			"Check for common OWASP issues",
			"Generate detailed report",
		},
		Prompts: originalPrompts,
	}

	contextInjector := transformers.NewContextInjector()
	scopeNarrower := transformers.NewScopeNarrower()
	scopeNarrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystemPrefix,
		prompt.PositionSystem,
		prompt.PositionContext,
		prompt.PositionTools,
		prompt.PositionUser,
	}
	scopeNarrower.KeywordFilter = []string{"security", "authentication", "tools", "audit"}

	staticAnalyzerPrompts, err := relay.Relay(staticAnalyzerCtx, contextInjector, scopeNarrower)
	if err != nil {
		t.Fatalf("Static analyzer relay failed: %v", err)
	}

	t.Logf("Static analyzer prompts: %d", len(staticAnalyzerPrompts))

	// Verify static analyzer got relevant prompts
	hasContext := false
	hasSystemPrompt := false
	hasUserRequest := false

	for _, p := range staticAnalyzerPrompts {
		if p.Position == prompt.PositionSystemPrefix {
			hasContext = true
			if !strings.Contains(p.Content, "SecurityOrchestrator") {
				t.Errorf("Context should mention source agent, got: %s", p.Content)
			}
			if !strings.Contains(p.Content, "Perform static code analysis") {
				t.Errorf("Context should mention task, got: %s", p.Content)
			}
		}
		if p.ID == "orchestrator_system" {
			hasSystemPrompt = true
		}
		if p.ID == "user_request" {
			hasUserRequest = true
		}
	}

	if !hasContext {
		t.Error("Static analyzer should have delegation context")
	}
	if !hasSystemPrompt {
		t.Error("Static analyzer should have system prompt")
	}
	if !hasUserRequest {
		t.Error("Static analyzer should have user request")
	}

	// Second relay: Orchestrator -> Dynamic Scanner (different scope)
	dynamicScannerCtx := &prompt.RelayContext{
		SourceAgent: "SecurityOrchestrator",
		TargetAgent: "DynamicScanner",
		Task:        "Perform runtime security testing on authentication endpoints",
		Memory: map[string]any{
			"endpoints":    []string{"/login", "/logout", "/refresh"},
			"test_level":   "safe",
			"max_requests": 1000,
		},
		Constraints: []string{
			"Use only safe testing methods",
			"Monitor for DoS patterns",
			"Respect rate limits",
		},
		Prompts: originalPrompts,
	}

	// Different scope for dynamic scanner
	dynamicScopeNarrower := transformers.NewScopeNarrower()
	dynamicScopeNarrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystemPrefix,
		prompt.PositionContext,
		prompt.PositionConstraints,
		prompt.PositionUser,
	}

	dynamicScannerPrompts, err := relay.Relay(dynamicScannerCtx, contextInjector, dynamicScopeNarrower)
	if err != nil {
		t.Fatalf("Dynamic scanner relay failed: %v", err)
	}

	t.Logf("Dynamic scanner prompts: %d", len(dynamicScannerPrompts))

	// Verify dynamic scanner got different filtered set
	if len(staticAnalyzerPrompts) == len(dynamicScannerPrompts) {
		t.Log("Warning: Different agents got same number of prompts (might be expected)")
	}

	// Verify original prompts unchanged after multiple relays
	if len(originalPrompts) != 5 {
		t.Error("Original prompts were modified during relays!")
	}
}

// TestRelay_Integration_CustomTemplateScenario tests custom context templates
func TestRelay_Integration_CustomTemplateScenario(t *testing.T) {
	relay := prompt.NewPromptRelay()

	originalPrompts := []prompt.Prompt{
		{ID: "main", Position: prompt.PositionSystem, Content: "Main system prompt"},
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "Master",
		TargetAgent: "Worker",
		Task:        "Process data batch #42",
		Constraints: []string{"max_memory: 1GB", "timeout: 5m"},
		Prompts:     originalPrompts,
	}

	// Custom template for specific use case
	contextInjector := transformers.NewContextInjector()
	contextInjector.ContextTemplate = `===== SUB-AGENT DELEGATION =====
Parent: {SourceAgent}
Agent: {TargetAgent}
Mission: {Task}
Limits: {Constraints}
================================`

	result, err := relay.Relay(ctx, contextInjector)
	if err != nil {
		t.Fatalf("Relay failed: %v", err)
	}

	if len(result) < 1 {
		t.Fatal("No prompts returned")
	}

	contextContent := result[0].Content

	if !strings.Contains(contextContent, "SUB-AGENT DELEGATION") {
		t.Error("Custom template not applied")
	}

	if !strings.Contains(contextContent, "Parent: Master") {
		t.Error("Template variables not substituted correctly")
	}

	if !strings.Contains(contextContent, "Agent: Worker") {
		t.Error("Template variables not substituted correctly")
	}

	if !strings.Contains(contextContent, "Mission: Process data batch #42") {
		t.Error("Template variables not substituted correctly")
	}
}

// TestRelay_Integration_EmptyPromptsWithContext tests behavior with no original prompts
func TestRelay_Integration_EmptyPromptsWithContext(t *testing.T) {
	relay := prompt.NewPromptRelay()

	ctx := &prompt.RelayContext{
		SourceAgent: "Parent",
		TargetAgent: "Child",
		Task:        "Standalone task",
		Prompts:     []prompt.Prompt{}, // Empty
		Constraints: []string{"constraint1"},
	}

	contextInjector := transformers.NewContextInjector()

	result, err := relay.Relay(ctx, contextInjector)
	if err != nil {
		t.Fatalf("Relay failed: %v", err)
	}

	// Should still add context even with no original prompts
	if len(result) != 1 {
		t.Errorf("Expected 1 context prompt, got %d", len(result))
	}

	if result[0].Position != prompt.PositionSystemPrefix {
		t.Error("Expected context at system_prefix")
	}

	if !strings.Contains(result[0].Content, "Standalone task") {
		t.Error("Context should contain task description")
	}
}
