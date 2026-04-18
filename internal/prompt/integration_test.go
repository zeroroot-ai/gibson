package prompt

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_FullAssemblyMission tests the complete prompt assembly mission
// from registry creation through final message generation.
func TestIntegration_FullAssemblyMission(t *testing.T) {
	// Step 1: Create a registry
	registry := NewPromptRegistry()

	// Step 2: Register built-in prompts
	err := RegisterBuiltins(registry)
	require.NoError(t, err, "Failed to register built-in prompts")

	// Verify built-ins were registered
	builtinPrompts := registry.List()
	assert.NotEmpty(t, builtinPrompts, "Built-in prompts should be registered")
	t.Logf("Registered %d built-in prompts", len(builtinPrompts))

	// Step 3: Load custom prompts from YAML
	testdataDir := filepath.Join("testdata")
	multiplePromptsFile := filepath.Join(testdataDir, "multiple_prompts.yaml")

	customPrompts, err := LoadPromptsFromFile(multiplePromptsFile)
	require.NoError(t, err, "Failed to load custom prompts from YAML")
	require.Len(t, customPrompts, 4, "Expected 4 prompts from multiple_prompts.yaml")

	// Register custom prompts
	for _, p := range customPrompts {
		err := registry.Register(p)
		require.NoError(t, err, "Failed to register custom prompt: %s", p.ID)
	}

	// Verify registration
	registeredPrompt, err := registry.Get("multi-system")
	require.NoError(t, err, "Custom prompt should be retrievable")
	assert.Equal(t, "System Prompt", registeredPrompt.Name)

	// Step 4: Create RenderContext with mission/target/agent data
	renderCtx := NewRenderContext()
	renderCtx.Mission = map[string]any{
		"name":      "Operation Security Audit",
		"objective": "Assess security posture of target system",
		"active":    true,
		"type":      "security_audit",
		"constraints": []string{
			"Non-invasive only",
			"Document all findings",
			"Follow ethical guidelines",
		},
	}
	renderCtx.Target = map[string]any{
		"url":  "https://target.example.com",
		"type": "web_application",
	}
	renderCtx.Agent = map[string]any{
		"name":      "SecurityBot",
		"expertise": "vulnerability assessment",
		"version":   "2.0",
	}

	// Step 5: Create assembler and assemble with various options
	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	// Test basic assembly
	opts := AssembleOptions{
		Registry:       registry,
		RenderContext:  renderCtx,
		IncludeTools:   true,
		IncludePlugins: false,
		IncludeAgents:  false,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err, "Assembly should succeed")

	// Step 6: Verify the AssembleResult
	assert.NotEmpty(t, result.System, "System message should not be empty")
	assert.NotEmpty(t, result.User, "User message should not be empty")
	assert.NotEmpty(t, result.Messages, "Messages array should not be empty")

	// Verify messages structure
	assert.Len(t, result.Messages, 2, "Should have system and user messages")
	assert.Equal(t, "system", result.Messages[0].Role)
	assert.Equal(t, "user", result.Messages[1].Role)

	// Verify content includes our custom prompts
	assert.Contains(t, result.System, "security testing assistant",
		"System should contain multi-system prompt content")
	assert.Contains(t, result.System, "security assessment",
		"System should contain multi-context prompt content")
	assert.Contains(t, result.System, "port_scanner",
		"System should contain tools prompt (IncludeTools=true)")

	assert.Contains(t, result.User, "comprehensive security assessment",
		"User should contain multi-user prompt content")

	// Verify prompts were processed
	assert.NotEmpty(t, result.Prompts, "Processed prompts should be included")
	t.Logf("Assembly produced %d processed prompts", len(result.Prompts))
}

// TestIntegration_AssemblyWithVariables tests assembly with variable substitution
func TestIntegration_AssemblyWithVariables(t *testing.T) {
	// Create registry and load prompts with variables
	registry := NewPromptRegistry()
	testdataDir := filepath.Join("testdata")
	varPromptsFile := filepath.Join(testdataDir, "prompts_with_variables.yaml")

	varPrompts, err := LoadPromptsFromFile(varPromptsFile)
	require.NoError(t, err, "Failed to load variable prompts")

	for _, p := range varPrompts {
		err := registry.Register(p)
		require.NoError(t, err, "Failed to register variable prompt")
	}

	// Create render context with all required variables
	renderCtx := NewRenderContext()
	renderCtx.Agent = map[string]any{
		"name":      "VulnScanner",
		"expertise": "vulnerability detection",
	}
	renderCtx.Target = map[string]any{
		"url":  "https://api.target.com",
		"type": "rest_api",
	}
	renderCtx.Mission = map[string]any{
		"name":      "API Security Audit",
		"objective": "Identify API vulnerabilities",
		"active":    true,
		"type":      "security_audit",
		"constraints": []string{
			"Rate limit: 10 req/sec",
			"No destructive operations",
		},
	}
	renderCtx.Custom = map[string]any{
		"tool_count": 5,
		"tools": []map[string]string{
			{"name": "nmap", "description": "Network scanner"},
			{"name": "burp", "description": "Web vulnerability scanner"},
		},
	}

	// Assemble with variables
	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	opts := AssembleOptions{
		Registry:      registry,
		RenderContext: renderCtx,
		IncludeTools:  true,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err, "Assembly with variables should succeed")

	t.Logf("System message:\n%s", result.System)
	t.Logf("User message:\n%s", result.User)
	t.Logf("Processed prompts: %d", len(result.Prompts))

	// Verify variable substitution in system message
	assert.Contains(t, result.System, "VulnScanner",
		"Agent name should be substituted")
	assert.Contains(t, result.System, "vulnerability detection",
		"Agent expertise should be substituted")
	assert.Contains(t, result.System, "https://api.target.com",
		"Target URL should be substituted")

	// Verify conditional prompt inclusion
	assert.Contains(t, result.User, "API Security Audit",
		"Mission name should be in user message")
	assert.Contains(t, result.User, "Rate limit: 10 req/sec",
		"Constraints should be rendered")

	// Verify tool metadata was rendered
	assert.Contains(t, result.System, "Tool Count: 5",
		"Tool count variable should be substituted")
	assert.Contains(t, result.System, "nmap",
		"Tool list should be rendered")
}

// TestIntegration_AssemblyWithConditions tests conditional prompt filtering
func TestIntegration_AssemblyWithConditions(t *testing.T) {
	registry := NewPromptRegistry()
	testdataDir := filepath.Join("testdata")
	varPromptsFile := filepath.Join(testdataDir, "prompts_with_variables.yaml")

	varPrompts, err := LoadPromptsFromFile(varPromptsFile)
	require.NoError(t, err)

	for _, p := range varPrompts {
		err := registry.Register(p)
		require.NoError(t, err)
	}

	// Test 1: Mission active = true, should include conditional prompts
	t.Run("conditions_pass", func(t *testing.T) {
		renderCtx := NewRenderContext()
		renderCtx.Mission = map[string]any{
			"active":    true,
			"type":      "security_audit",
			"name":      "Test Mission",
			"objective": "Test objective",
		}
		renderCtx.Target = map[string]any{
			"url": "https://example.com",
		}
		renderCtx.Agent = map[string]any{
			"name": "TestAgent",
		}

		renderer := NewTemplateRenderer()
		assembler := NewAssembler(renderer)

		opts := AssembleOptions{
			Registry:      registry,
			RenderContext: renderCtx,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		// Should include conditional context prompt
		assert.Contains(t, result.System, "https://example.com",
			"Conditional context prompt should be included")
		// Should include conditional user prompt
		assert.Contains(t, result.User, "Test Mission",
			"Conditional user prompt should be included")
	})

	// Test 2: Mission active = false, should exclude conditional prompts
	t.Run("conditions_fail", func(t *testing.T) {
		renderCtx := NewRenderContext()
		renderCtx.Mission = map[string]any{
			"active":    false, // Changed to false
			"type":      "reconnaissance",
			"name":      "Test Mission",
			"objective": "Test objective",
		}
		renderCtx.Target = map[string]any{
			"url": "https://example.com",
		}
		renderCtx.Agent = map[string]any{
			"name": "TestAgent",
		}

		renderer := NewTemplateRenderer()
		assembler := NewAssembler(renderer)

		opts := AssembleOptions{
			Registry:      registry,
			RenderContext: renderCtx,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		// Context prompt has condition mission.active == true, should be excluded
		// (might still have other content, so we check for specific conditional content)

		// User prompt has condition mission.type == "security_audit", should be excluded
		assert.NotContains(t, result.User, "Test Mission",
			"Conditional user prompt should be excluded when type != security_audit")
	})
}

// TestIntegration_AssemblyWithSystemOverride tests SystemOverride option
func TestIntegration_AssemblyWithSystemOverride(t *testing.T) {
	registry := NewPromptRegistry()
	testdataDir := filepath.Join("testdata")
	multiplePromptsFile := filepath.Join(testdataDir, "multiple_prompts.yaml")

	prompts, err := LoadPromptsFromFile(multiplePromptsFile)
	require.NoError(t, err)

	for _, p := range prompts {
		err := registry.Register(p)
		require.NoError(t, err)
	}

	renderCtx := NewRenderContext()
	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	customSystemPrompt := "This is a completely custom system prompt that overrides all others."

	opts := AssembleOptions{
		Registry:       registry,
		RenderContext:  renderCtx,
		SystemOverride: customSystemPrompt,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	// System message should be exactly the override
	assert.Equal(t, customSystemPrompt, result.System,
		"SystemOverride should replace all system content")

	// Should not contain any original system prompts
	assert.NotContains(t, result.System, "security testing assistant",
		"Original system prompts should be excluded")
	assert.NotContains(t, result.System, "port_scanner",
		"Tools should be excluded when SystemOverride is set")

	// User message should still work normally
	assert.Contains(t, result.User, "comprehensive security assessment",
		"User prompts should not be affected by SystemOverride")
}

// TestIntegration_AssemblyWithPersona tests persona selection
func TestIntegration_AssemblyWithPersona(t *testing.T) {
	// Test with expert persona
	t.Run("expert_persona", func(t *testing.T) {
		registry := NewPromptRegistry()

		// Register some persona prompts
		personaExpert := Prompt{
			ID:       "persona:expert",
			Name:     "Expert Persona",
			Position: PositionSystem,
			Priority: 200,
			Content:  "You are an expert security analyst with 10+ years of experience.",
		}

		baseSystemPrompt := Prompt{
			ID:       "base-system",
			Name:     "Base System",
			Position: PositionSystem,
			Priority: 100,
			Content:  "You are a security assistant.",
		}

		err := registry.Register(personaExpert)
		require.NoError(t, err)
		err = registry.Register(baseSystemPrompt)
		require.NoError(t, err)

		renderer := NewTemplateRenderer()
		assembler := NewAssembler(renderer)

		opts := AssembleOptions{
			Registry: registry,
			Persona:  "expert",
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Contains(t, result.System, "expert security analyst",
			"Expert persona should be included")
		assert.NotContains(t, result.System, "beginner-friendly",
			"Beginner persona should not be included")
	})

	// Test with beginner persona
	t.Run("beginner_persona", func(t *testing.T) {
		registry := NewPromptRegistry()

		personaBeginner := Prompt{
			ID:       "persona:beginner",
			Name:     "Beginner Persona",
			Position: PositionSystem,
			Priority: 200,
			Content:  "You are a beginner-friendly security assistant. Explain concepts clearly.",
		}

		baseSystemPrompt := Prompt{
			ID:       "base-system",
			Name:     "Base System",
			Position: PositionSystem,
			Priority: 100,
			Content:  "You are a security assistant.",
		}

		err := registry.Register(personaBeginner)
		require.NoError(t, err)
		err = registry.Register(baseSystemPrompt)
		require.NoError(t, err)

		renderer := NewTemplateRenderer()
		assembler := NewAssembler(renderer)

		opts := AssembleOptions{
			Registry: registry,
			Persona:  "beginner",
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Contains(t, result.System, "beginner-friendly",
			"Beginner persona should be included")
		assert.NotContains(t, result.System, "expert security analyst",
			"Expert persona should not be included")
	})
}

// TestIntegration_AssemblyWithExtraPrompts tests ExtraPrompts option
func TestIntegration_AssemblyWithExtraPrompts(t *testing.T) {
	registry := NewPromptRegistry()

	basePrompt := Prompt{
		ID:       "base",
		Name:     "Base Prompt",
		Position: PositionSystem,
		Priority: 100,
		Content:  "This is the base system prompt.",
	}

	err := registry.Register(basePrompt)
	require.NoError(t, err)

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	// Add extra prompts at runtime
	extraPrompts := []Prompt{
		{
			ID:       "extra-context",
			Name:     "Extra Context",
			Position: PositionContext,
			Priority: 50,
			Content:  "This is additional runtime context.",
		},
		{
			ID:       "extra-user",
			Name:     "Extra User",
			Position: PositionUser,
			Priority: 10,
			Content:  "Additional user instruction.",
		},
	}

	opts := AssembleOptions{
		Registry:     registry,
		ExtraPrompts: extraPrompts,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	assert.Contains(t, result.System, "base system prompt",
		"Registry prompts should be included")
	assert.Contains(t, result.System, "additional runtime context",
		"Extra context prompt should be included")
	assert.Contains(t, result.User, "Additional user instruction",
		"Extra user prompt should be included")
}

// TestIntegration_AssemblyWithExtraPromptsOverride tests that ExtraPrompts override registry
func TestIntegration_AssemblyWithExtraPromptsOverride(t *testing.T) {
	registry := NewPromptRegistry()

	originalPrompt := Prompt{
		ID:       "test-prompt",
		Name:     "Original",
		Position: PositionSystem,
		Priority: 100,
		Content:  "Original content",
	}

	err := registry.Register(originalPrompt)
	require.NoError(t, err)

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	// Override with same ID
	overridePrompts := []Prompt{
		{
			ID:       "test-prompt", // Same ID
			Name:     "Override",
			Position: PositionSystem,
			Priority: 100,
			Content:  "Overridden content",
		},
	}

	opts := AssembleOptions{
		Registry:     registry,
		ExtraPrompts: overridePrompts,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	assert.Contains(t, result.System, "Overridden content",
		"ExtraPrompts should override registry prompts")
	assert.NotContains(t, result.System, "Original content",
		"Original prompt should be replaced")
}

// TestIntegration_AssemblyPositionOrdering tests prompt position ordering
func TestIntegration_AssemblyPositionOrdering(t *testing.T) {
	registry := NewPromptRegistry()

	// Create prompts in different positions
	testPrompts := []Prompt{
		{ID: "system-prefix", Position: PositionSystemPrefix, Priority: 10, Content: "PREFIX"},
		{ID: "system", Position: PositionSystem, Priority: 10, Content: "SYSTEM"},
		{ID: "system-suffix", Position: PositionSystemSuffix, Priority: 10, Content: "SUFFIX"},
		{ID: "context", Position: PositionContext, Priority: 10, Content: "CONTEXT"},
		{ID: "constraints", Position: PositionConstraints, Priority: 10, Content: "CONSTRAINTS"},
		{ID: "examples", Position: PositionExamples, Priority: 10, Content: "EXAMPLES"},
		{ID: "user-prefix", Position: PositionUserPrefix, Priority: 10, Content: "USER-PREFIX"},
		{ID: "user", Position: PositionUser, Priority: 10, Content: "USER"},
		{ID: "user-suffix", Position: PositionUserSuffix, Priority: 10, Content: "USER-SUFFIX"},
	}

	for _, p := range testPrompts {
		err := registry.Register(p)
		require.NoError(t, err)
	}

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	opts := AssembleOptions{
		Registry: registry,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	t.Logf("System:\n%s", result.System)
	t.Logf("User:\n%s", result.User)

	// Verify system message order
	expectedSystemOrder := []string{"PREFIX", "SYSTEM", "SUFFIX", "CONTEXT", "CONSTRAINTS", "EXAMPLES"}

	// Match content in order (allowing for flexibility in exact position)
	systemContent := result.System
	lastIndex := -1
	for _, expected := range expectedSystemOrder {
		index := strings.Index(systemContent, expected)
		assert.Greater(t, index, lastIndex,
			"System positions should appear in order: %s should come after previous", expected)
		lastIndex = index
	}

	// Verify user message order - check that they appear in sequence
	userParts := strings.Split(result.User, "\n\n")
	require.GreaterOrEqual(t, len(userParts), 3, "Should have at least 3 user parts")

	// Trim whitespace and verify content in order
	assert.Equal(t, "USER-PREFIX", strings.TrimSpace(userParts[0]))
	assert.Equal(t, "USER", strings.TrimSpace(userParts[1]))
	assert.Equal(t, "USER-SUFFIX", strings.TrimSpace(userParts[2]))
}

// TestIntegration_AssemblyPriorityOrdering tests priority-based sorting
func TestIntegration_AssemblyPriorityOrdering(t *testing.T) {
	registry := NewPromptRegistry()

	// Create multiple prompts in same position with different priorities
	testPrompts := []Prompt{
		{ID: "low", Position: PositionSystem, Priority: 1, Content: "LOW_PRIORITY"},
		{ID: "high", Position: PositionSystem, Priority: 100, Content: "HIGH_PRIORITY"},
		{ID: "medium", Position: PositionSystem, Priority: 50, Content: "MEDIUM_PRIORITY"},
	}

	for _, p := range testPrompts {
		err := registry.Register(p)
		require.NoError(t, err)
	}

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	opts := AssembleOptions{
		Registry: registry,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	// Higher priority should come first
	highIndex := strings.Index(result.System, "HIGH_PRIORITY")
	mediumIndex := strings.Index(result.System, "MEDIUM_PRIORITY")
	lowIndex := strings.Index(result.System, "LOW_PRIORITY")

	assert.Less(t, highIndex, mediumIndex,
		"Higher priority should appear before medium priority")
	assert.Less(t, mediumIndex, lowIndex,
		"Medium priority should appear before low priority")
}

// TestIntegration_AssemblyIncludeOptions tests Include flags
func TestIntegration_AssemblyIncludeOptions(t *testing.T) {
	registry := NewPromptRegistry()

	testPrompts := []Prompt{
		{ID: "tools-1", Position: PositionTools, Priority: 10, Content: "TOOL_CONTENT"},
		{ID: "plugins-1", Position: PositionPlugins, Priority: 10, Content: "PLUGIN_CONTENT"},
		{ID: "agents-1", Position: PositionAgents, Priority: 10, Content: "AGENT_CONTENT"},
		{ID: "system-1", Position: PositionSystem, Priority: 10, Content: "SYSTEM_CONTENT"},
	}

	for _, p := range testPrompts {
		err := registry.Register(p)
		require.NoError(t, err)
	}

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	t.Run("include_all", func(t *testing.T) {
		opts := AssembleOptions{
			Registry:       registry,
			IncludeTools:   true,
			IncludePlugins: true,
			IncludeAgents:  true,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Contains(t, result.System, "TOOL_CONTENT")
		assert.Contains(t, result.System, "PLUGIN_CONTENT")
		assert.Contains(t, result.System, "AGENT_CONTENT")
		assert.Contains(t, result.System, "SYSTEM_CONTENT")
	})

	t.Run("exclude_tools", func(t *testing.T) {
		opts := AssembleOptions{
			Registry:       registry,
			IncludeTools:   false,
			IncludePlugins: true,
			IncludeAgents:  true,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.NotContains(t, result.System, "TOOL_CONTENT")
		assert.Contains(t, result.System, "PLUGIN_CONTENT")
		assert.Contains(t, result.System, "AGENT_CONTENT")
	})

	t.Run("exclude_plugins", func(t *testing.T) {
		opts := AssembleOptions{
			Registry:       registry,
			IncludeTools:   true,
			IncludePlugins: false,
			IncludeAgents:  true,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Contains(t, result.System, "TOOL_CONTENT")
		assert.NotContains(t, result.System, "PLUGIN_CONTENT")
		assert.Contains(t, result.System, "AGENT_CONTENT")
	})

	t.Run("exclude_agents", func(t *testing.T) {
		opts := AssembleOptions{
			Registry:       registry,
			IncludeTools:   true,
			IncludePlugins: true,
			IncludeAgents:  false,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Contains(t, result.System, "TOOL_CONTENT")
		assert.Contains(t, result.System, "PLUGIN_CONTENT")
		assert.NotContains(t, result.System, "AGENT_CONTENT")
	})

	t.Run("exclude_all", func(t *testing.T) {
		opts := AssembleOptions{
			Registry:       registry,
			IncludeTools:   false,
			IncludePlugins: false,
			IncludeAgents:  false,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.NotContains(t, result.System, "TOOL_CONTENT")
		assert.NotContains(t, result.System, "PLUGIN_CONTENT")
		assert.NotContains(t, result.System, "AGENT_CONTENT")
		assert.Contains(t, result.System, "SYSTEM_CONTENT") // System always included
	})
}

// TestIntegration_AssemblyEmptyMessages tests edge cases with empty messages
func TestIntegration_AssemblyEmptyMessages(t *testing.T) {
	registry := NewPromptRegistry()
	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	t.Run("only_system", func(t *testing.T) {
		systemPrompt := Prompt{
			ID:       "system",
			Position: PositionSystem,
			Priority: 10,
			Content:  "System content",
		}
		err := registry.Register(systemPrompt)
		require.NoError(t, err)

		opts := AssembleOptions{
			Registry: registry,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.NotEmpty(t, result.System)
		assert.Empty(t, result.User)
		assert.Len(t, result.Messages, 1, "Should only have system message")
		assert.Equal(t, "system", result.Messages[0].Role)
	})

	t.Run("only_user", func(t *testing.T) {
		registry2 := NewPromptRegistry()
		userPrompt := Prompt{
			ID:       "user",
			Position: PositionUser,
			Priority: 10,
			Content:  "User content",
		}
		err := registry2.Register(userPrompt)
		require.NoError(t, err)

		opts := AssembleOptions{
			Registry: registry2,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Empty(t, result.System)
		assert.NotEmpty(t, result.User)
		assert.Len(t, result.Messages, 1, "Should only have user message")
		assert.Equal(t, "user", result.Messages[0].Role)
	})

	t.Run("empty_registry", func(t *testing.T) {
		registry3 := NewPromptRegistry()

		opts := AssembleOptions{
			Registry: registry3,
		}

		result, err := assembler.Assemble(context.Background(), opts)
		require.NoError(t, err)

		assert.Empty(t, result.System)
		assert.Empty(t, result.User)
		assert.Empty(t, result.Messages, "Should have no messages")
	})
}

// TestIntegration_LoadFromDirectory tests loading multiple YAML files
func TestIntegration_LoadFromDirectory(t *testing.T) {
	testdataDir := filepath.Join("testdata")

	prompts, err := LoadPromptsFromDirectory(testdataDir)
	require.NoError(t, err, "Should load prompts from directory")

	// Should have prompts from all YAML files in testdata
	assert.NotEmpty(t, prompts, "Should load at least some prompts")

	// Verify we got prompts from different files
	ids := make(map[string]bool)
	for _, p := range prompts {
		ids[p.ID] = true
	}

	// Check for prompts from single_prompt.yaml
	assert.True(t, ids["test-single-prompt"], "Should have prompt from single_prompt.yaml")

	// Check for prompts from multiple_prompts.yaml
	assert.True(t, ids["multi-system"], "Should have multi-system from multiple_prompts.yaml")
	assert.True(t, ids["multi-context"], "Should have multi-context from multiple_prompts.yaml")

	// Check for prompts from prompts_with_variables.yaml
	assert.True(t, ids["var-system"], "Should have var-system from prompts_with_variables.yaml")

	t.Logf("Loaded %d prompts from directory", len(prompts))
}

// TestIntegration_ComponentPromptCollection tests collecting prompts from components
// Note: Uses mock types defined in component_test.go
func TestIntegration_ComponentPromptCollection(t *testing.T) {
	t.Run("tool_with_prompts", func(t *testing.T) {
		toolPrompts := []Prompt{
			{
				ID:       "tool-scanner",
				Position: PositionTools,
				Priority: 10,
				Content:  "Port scanner tool usage instructions",
			},
		}

		mockTool := &mockToolWithPrompt{
			prompts: toolPrompts,
		}

		// Test interface check
		assert.True(t, ToolHasPrompts(mockTool), "Tool should have prompts")

		// Test prompt retrieval
		retrievedPrompts := GetToolPrompts(mockTool)
		require.Len(t, retrievedPrompts, 1)
		assert.Equal(t, "tool-scanner", retrievedPrompts[0].ID)
		assert.Equal(t, "Port scanner tool usage instructions", retrievedPrompts[0].Content)
	})

	t.Run("tool_without_prompts", func(t *testing.T) {
		regularTool := &mockTool{}

		assert.False(t, ToolHasPrompts(regularTool), "Regular tool should not have prompts")

		prompts := GetToolPrompts(regularTool)
		assert.Empty(t, prompts, "Should return empty slice for tool without prompts")
	})

	t.Run("plugin_with_prompts", func(t *testing.T) {
		pluginPrompts := []Prompt{
			{
				ID:       "plugin-db",
				Position: PositionPlugins,
				Priority: 10,
				Content:  "Database plugin query examples",
			},
		}

		mockPlugin := &mockPluginWithPrompts{
			prompts: pluginPrompts,
		}

		assert.True(t, PluginHasPrompts(mockPlugin), "Plugin should have prompts")

		retrievedPrompts := GetPluginPrompts(mockPlugin)
		require.Len(t, retrievedPrompts, 1)
		assert.Equal(t, "plugin-db", retrievedPrompts[0].ID)
	})

	t.Run("plugin_without_prompts", func(t *testing.T) {
		regularPlugin := &mockPlugin{}

		assert.False(t, PluginHasPrompts(regularPlugin), "Regular plugin should not have prompts")

		prompts := GetPluginPrompts(regularPlugin)
		assert.Empty(t, prompts)
	})

	t.Run("agent_with_all_prompts", func(t *testing.T) {
		systemPrompt := &Prompt{
			ID:       "agent-system",
			Position: PositionSystem,
			Priority: 100,
			Content:  "Agent system instructions",
		}

		taskPrompt := &Prompt{
			ID:       "agent-task",
			Position: PositionUser,
			Priority: 10,
			Content:  "Current task instructions",
		}

		personas := []Prompt{
			{
				ID:       "persona:analyst",
				Position: PositionContext,
				Priority: 50,
				Content:  "Security analyst persona",
			},
			{
				ID:       "persona:researcher",
				Position: PositionContext,
				Priority: 50,
				Content:  "Security researcher persona",
			},
		}

		mockAgent := &mockAgentWithPrompts{
			systemPrompt: systemPrompt,
			taskPrompt:   taskPrompt,
			personas:     personas,
		}

		assert.True(t, AgentHasPrompts(mockAgent), "Agent should have prompts")

		retrievedPrompts := GetAgentPrompts(mockAgent)
		require.Len(t, retrievedPrompts, 4, "Should have system + task + 2 personas")

		// Verify order: system, task, personas
		assert.Equal(t, "agent-system", retrievedPrompts[0].ID)
		assert.Equal(t, "agent-task", retrievedPrompts[1].ID)
		assert.Equal(t, "persona:analyst", retrievedPrompts[2].ID)
		assert.Equal(t, "persona:researcher", retrievedPrompts[3].ID)
	})

	t.Run("agent_with_partial_prompts", func(t *testing.T) {
		systemPrompt := &Prompt{
			ID:       "agent-system",
			Position: PositionSystem,
			Priority: 100,
			Content:  "Agent system instructions",
		}

		mockAgent := &mockAgentWithPrompts{
			systemPrompt: systemPrompt,
			taskPrompt:   nil, // No task prompt
			personas:     nil, // No personas
		}

		retrievedPrompts := GetAgentPrompts(mockAgent)
		require.Len(t, retrievedPrompts, 1, "Should only have system prompt")
		assert.Equal(t, "agent-system", retrievedPrompts[0].ID)
	})

	t.Run("agent_without_prompts", func(t *testing.T) {
		regularAgent := &mockAgent{}

		assert.False(t, AgentHasPrompts(regularAgent), "Regular agent should not have prompts")

		prompts := GetAgentPrompts(regularAgent)
		assert.Empty(t, prompts)
	})
}

// TestIntegration_ComponentPromptsInAssembly tests integrating component prompts into assembly
func TestIntegration_ComponentPromptsInAssembly(t *testing.T) {
	registry := NewPromptRegistry()

	// Add base system prompt
	basePrompt := Prompt{
		ID:       "base-system",
		Position: PositionSystem,
		Priority: 100,
		Content:  "Base system prompt",
	}
	err := registry.Register(basePrompt)
	require.NoError(t, err)

	// Create mock components with prompts
	toolPrompts := []Prompt{
		{
			ID:       "tool-nmap",
			Position: PositionTools,
			Priority: 20,
			Content:  "nmap: Network port scanner",
		},
		{
			ID:       "tool-burp",
			Position: PositionTools,
			Priority: 15,
			Content:  "burp: Web vulnerability scanner",
		},
	}

	pluginPrompts := []Prompt{
		{
			ID:       "plugin-cve",
			Position: PositionPlugins,
			Priority: 10,
			Content:  "CVE database plugin for vulnerability lookup",
		},
	}

	agentSystemPrompt := &Prompt{
		ID:       "agent-coordinator",
		Position: PositionAgents,
		Priority: 50,
		Content:  "Coordinator agent: Manages sub-agents",
	}

	// Register component prompts as extra prompts
	extraPrompts := append(toolPrompts, pluginPrompts...)
	if agentSystemPrompt != nil {
		extraPrompts = append(extraPrompts, *agentSystemPrompt)
	}

	renderer := NewTemplateRenderer()
	assembler := NewAssembler(renderer)

	opts := AssembleOptions{
		Registry:       registry,
		ExtraPrompts:   extraPrompts,
		IncludeTools:   true,
		IncludePlugins: true,
		IncludeAgents:  true,
	}

	result, err := assembler.Assemble(context.Background(), opts)
	require.NoError(t, err)

	// Verify all component prompts are included
	assert.Contains(t, result.System, "Base system prompt")
	assert.Contains(t, result.System, "nmap: Network port scanner")
	assert.Contains(t, result.System, "burp: Web vulnerability scanner")
	assert.Contains(t, result.System, "CVE database plugin")
	assert.Contains(t, result.System, "Coordinator agent")

	// Verify priority ordering within tools section
	nmapIndex := strings.Index(result.System, "nmap:")
	burpIndex := strings.Index(result.System, "burp:")
	assert.Less(t, nmapIndex, burpIndex,
		"Higher priority tool (nmap=20) should appear before lower priority (burp=15)")
}
