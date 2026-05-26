package prompt

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestNewRenderContext verifies that NewRenderContext creates a properly initialized context
func TestNewRenderContext(t *testing.T) {
	ctx := NewRenderContext()

	if ctx == nil {
		t.Fatal("NewRenderContext returned nil")
	}

	if ctx.Mission == nil {
		t.Error("Mission map not initialized")
	}
	if ctx.Target == nil {
		t.Error("Target map not initialized")
	}
	if ctx.Agent == nil {
		t.Error("Agent map not initialized")
	}
	if ctx.Memory == nil {
		t.Error("Memory map not initialized")
	}
	if ctx.Variables == nil {
		t.Error("Variables map not initialized")
	}
	if ctx.Custom == nil {
		t.Error("Custom map not initialized")
	}
}

// TestRenderContext_GetAndSet verifies Get and Set operations on RenderContext
func TestRenderContext_GetAndSet(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*RenderContext)
		path      string
		setValue  any
		wantValue any
		wantFound bool
	}{
		{
			name:      "set and get simple value",
			path:      "mission.id",
			setValue:  "op-001",
			wantValue: "op-001",
			wantFound: true,
		},
		{
			name:      "set and get nested value",
			path:      "mission.target.url",
			setValue:  "https://example.com",
			wantValue: "https://example.com",
			wantFound: true,
		},
		{
			name:     "get whole category",
			path:     "agent",
			setValue: nil,
			setup: func(ctx *RenderContext) {
				ctx.Agent["name"] = "Gibson"
			},
			wantValue: map[string]any{"name": "Gibson"},
			wantFound: true,
		},
		{
			name:      "get nonexistent path",
			path:      "mission.nonexistent.path",
			setValue:  nil,
			wantValue: nil,
			wantFound: false,
		},
		{
			name:      "get with invalid category",
			path:      "invalid.path",
			setValue:  nil,
			wantValue: nil,
			wantFound: false,
		},
		{
			name:      "set nested creates intermediate maps",
			path:      "custom.deep.nested.value",
			setValue:  42,
			wantValue: 42,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewRenderContext()

			if tt.setup != nil {
				tt.setup(ctx)
			}

			if tt.setValue != nil {
				ctx.Set(tt.path, tt.setValue)
			}

			got, found := ctx.Get(tt.path)
			if found != tt.wantFound {
				t.Errorf("Get(%q) found = %v, want %v", tt.path, found, tt.wantFound)
			}

			if tt.wantFound && !equal(got, tt.wantValue) {
				t.Errorf("Get(%q) = %v, want %v", tt.path, got, tt.wantValue)
			}
		})
	}
}

// TestRenderContext_ToMap verifies ToMap conversion
func TestRenderContext_ToMap(t *testing.T) {
	ctx := NewRenderContext()
	ctx.Mission["id"] = "op-001"
	ctx.Agent["name"] = "Gibson"
	ctx.Variables["apiKey"] = "secret"

	m := ctx.ToMap()

	if m == nil {
		t.Fatal("ToMap returned nil")
	}

	// Check that all categories are present
	categories := []string{"Mission", "Target", "Agent", "Memory", "Variables", "Custom"}
	for _, cat := range categories {
		if _, exists := m[cat]; !exists {
			t.Errorf("ToMap missing category: %s", cat)
		}
	}

	// Verify values
	if mission, ok := m["Mission"].(map[string]any); ok {
		if mission["id"] != "op-001" {
			t.Errorf("Mission.id = %v, want op-001", mission["id"])
		}
	} else {
		t.Error("Mission is not a map[string]any")
	}
}

// TestNewTemplateRenderer verifies renderer creation
func TestNewTemplateRenderer(t *testing.T) {
	renderer := NewTemplateRenderer()

	if renderer == nil {
		t.Fatal("NewTemplateRenderer returned nil")
	}

	// Verify it implements the interface
	var _ TemplateRenderer = renderer
}

// TestTemplateRenderer_Render_SimpleVariable tests simple variable substitution
func TestTemplateRenderer_Render_SimpleVariable(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()
	ctx.Variables["name"] = "Gibson"

	prompt := &Prompt{
		ID:       "test-prompt",
		Name:     "Test Prompt",
		Content:  "Hello, {{.Variables.name}}!",
		Position: PositionSystem,
		Variables: []VariableDef{
			{
				Name:   "name",
				Source: "variables.name",
			},
		},
	}

	result, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	expected := "Hello, Gibson!"
	if result != expected {
		t.Errorf("Render = %q, want %q", result, expected)
	}
}

// TestTemplateRenderer_Render_NestedPath tests nested path access
func TestTemplateRenderer_Render_NestedPath(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()
	ctx.Mission["target"] = map[string]any{
		"url": "https://example.com",
	}

	prompt := &Prompt{
		ID:       "test-nested",
		Name:     "Test Nested",
		Content:  "Target URL: {{.Mission.target.url}}",
		Position: PositionSystem,
		Variables: []VariableDef{
			{
				Name:   "targetUrl",
				Source: "mission.target.url",
			},
		},
	}

	result, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	expected := "Target URL: https://example.com"
	if result != expected {
		t.Errorf("Render = %q, want %q", result, expected)
	}
}

// TestTemplateRenderer_Render_MissingRequiredVariable tests missing required variable error
func TestTemplateRenderer_Render_MissingRequiredVariable(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()

	prompt := &Prompt{
		ID:       "test-missing",
		Name:     "Test Missing",
		Content:  "API Key: {{.Variables.apiKey}}",
		Position: PositionSystem,
		Variables: []VariableDef{
			{
				Name:     "apiKey",
				Source:   "variables.apiKey",
				Required: true,
			},
		},
	}

	_, err := renderer.Render(prompt, ctx)
	if err == nil {
		t.Fatal("Expected error for missing required variable, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodeMissingVariable {
		t.Errorf("Error code = %s, want %s", gibsonErr.Code, ErrCodeMissingVariable)
	}

	if !strings.Contains(gibsonErr.Message, "apiKey") {
		t.Errorf("Error message should contain variable name 'apiKey', got: %s", gibsonErr.Message)
	}
}

// TestTemplateRenderer_Render_DefaultValue tests default value usage
func TestTemplateRenderer_Render_DefaultValue(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()

	prompt := &Prompt{
		ID:       "test-default",
		Name:     "Test Default",
		Content:  "Model: {{.Variables.model}}",
		Position: PositionSystem,
		Variables: []VariableDef{
			{
				Name:    "model",
				Source:  "variables.model",
				Default: "gpt-4",
			},
		},
	}

	result, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	expected := "Model: gpt-4"
	if result != expected {
		t.Errorf("Render = %q, want %q", result, expected)
	}
}

// TestTemplateRenderer_Render_TemplateSyntaxError tests template syntax errors
func TestTemplateRenderer_Render_TemplateSyntaxError(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()

	prompt := &Prompt{
		ID:       "test-syntax-error",
		Name:     "Test Syntax Error",
		Content:  "Invalid template: {{.Variables.name",
		Position: PositionSystem,
	}

	_, err := renderer.Render(prompt, ctx)
	if err == nil {
		t.Fatal("Expected error for invalid template syntax, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodeInvalidTemplate {
		t.Errorf("Error code = %s, want %s", gibsonErr.Code, ErrCodeInvalidTemplate)
	}
}

// TestTemplateRenderer_Render_ConditionalBlocks tests conditional template blocks
func TestTemplateRenderer_Render_ConditionalBlocks(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*RenderContext)
		content   string
		variables []VariableDef
		expected  string
	}{
		{
			name: "if block - condition true",
			setup: func(ctx *RenderContext) {
				ctx.Variables["enabled"] = true
			},
			content: "{{if .Variables.enabled}}Feature is enabled{{end}}",
			variables: []VariableDef{
				{Name: "enabled", Source: "variables.enabled"},
			},
			expected: "Feature is enabled",
		},
		{
			name: "if block - condition false",
			setup: func(ctx *RenderContext) {
				ctx.Variables["enabled"] = false
			},
			content: "{{if .Variables.enabled}}Feature is enabled{{end}}",
			variables: []VariableDef{
				{Name: "enabled", Source: "variables.enabled"},
			},
			expected: "",
		},
		{
			name: "if-else block",
			setup: func(ctx *RenderContext) {
				ctx.Variables["mode"] = "production"
			},
			content: "{{if eq .Variables.mode \"production\"}}Production mode{{else}}Development mode{{end}}",
			variables: []VariableDef{
				{Name: "mode", Source: "variables.mode"},
			},
			expected: "Production mode",
		},
		{
			name: "range block",
			setup: func(ctx *RenderContext) {
				ctx.Variables["items"] = []string{"a", "b", "c"}
			},
			content: "{{range .Variables.items}}{{.}} {{end}}",
			variables: []VariableDef{
				{Name: "items", Source: "variables.items"},
			},
			expected: "a b c ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renderer := NewTemplateRenderer()
			ctx := NewRenderContext()

			if tt.setup != nil {
				tt.setup(ctx)
			}

			prompt := &Prompt{
				ID:        "test-conditional",
				Name:      "Test Conditional",
				Content:   tt.content,
				Position:  PositionSystem,
				Variables: tt.variables,
			}

			result, err := renderer.Render(prompt, ctx)
			if err != nil {
				t.Fatalf("Render failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Render = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestTemplateRenderer_RegisterFunc tests custom function registration
func TestTemplateRenderer_RegisterFunc(t *testing.T) {
	renderer := NewTemplateRenderer()

	// Register a custom function
	err := renderer.RegisterFunc("upper", strings.ToUpper)
	if err != nil {
		t.Fatalf("RegisterFunc failed: %v", err)
	}

	ctx := NewRenderContext()
	ctx.Variables["text"] = "hello"

	prompt := &Prompt{
		ID:       "test-custom-func",
		Name:     "Test Custom Function",
		Content:  "{{upper .Variables.text}}",
		Position: PositionSystem,
		Variables: []VariableDef{
			{Name: "text", Source: "variables.text"},
		},
	}

	result, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	expected := "HELLO"
	if result != expected {
		t.Errorf("Render = %q, want %q", result, expected)
	}
}

// TestTemplateRenderer_RegisterFunc_EmptyName tests error on empty function name
func TestTemplateRenderer_RegisterFunc_EmptyName(t *testing.T) {
	renderer := NewTemplateRenderer()

	err := renderer.RegisterFunc("", strings.ToUpper)
	if err == nil {
		t.Fatal("Expected error for empty function name, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodeInvalidTemplate {
		t.Errorf("Error code = %s, want %s", gibsonErr.Code, ErrCodeInvalidTemplate)
	}
}

// TestTemplateRenderer_TemplateCaching tests that templates are cached
func TestTemplateRenderer_TemplateCaching(t *testing.T) {
	renderer := NewTemplateRenderer().(*DefaultTemplateRenderer)
	ctx := NewRenderContext()
	ctx.Variables["name"] = "Gibson"

	prompt := &Prompt{
		ID:       "cached-prompt",
		Name:     "Cached Prompt",
		Content:  "Hello, {{.Variables.name}}!",
		Position: PositionSystem,
		Variables: []VariableDef{
			{Name: "name", Source: "variables.name"},
		},
	}

	// First render - should compile and cache
	_, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("First render failed: %v", err)
	}

	// Verify template is cached
	renderer.mu.RLock()
	_, cached := renderer.templates[prompt.ID]
	renderer.mu.RUnlock()

	if !cached {
		t.Error("Template was not cached after first render")
	}

	// Second render - should use cached template
	_, err = renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Second render failed: %v", err)
	}

	// Verify cache wasn't cleared
	renderer.mu.RLock()
	_, stillCached := renderer.templates[prompt.ID]
	renderer.mu.RUnlock()

	if !stillCached {
		t.Error("Template cache was cleared unexpectedly")
	}
}

// TestTemplateRenderer_NilPrompt tests error on nil prompt
func TestTemplateRenderer_NilPrompt(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()

	_, err := renderer.Render(nil, ctx)
	if err == nil {
		t.Fatal("Expected error for nil prompt, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("Expected GibsonError, got %T", err)
	}

	if gibsonErr.Code != ErrCodeInvalidPrompt {
		t.Errorf("Error code = %s, want %s", gibsonErr.Code, ErrCodeInvalidPrompt)
	}
}

// TestTemplateRenderer_NilContext tests rendering with nil context
func TestTemplateRenderer_NilContext(t *testing.T) {
	renderer := NewTemplateRenderer()

	prompt := &Prompt{
		ID:       "test-nil-context",
		Name:     "Test Nil Context",
		Content:  "Simple text",
		Position: PositionSystem,
	}

	// Should create a new context automatically
	result, err := renderer.Render(prompt, nil)
	if err != nil {
		t.Fatalf("Render with nil context failed: %v", err)
	}

	expected := "Simple text"
	if result != expected {
		t.Errorf("Render = %q, want %q", result, expected)
	}
}

// TestTemplateRenderer_ComplexTemplate tests a complex realistic template
func TestTemplateRenderer_ComplexTemplate(t *testing.T) {
	renderer := NewTemplateRenderer()
	ctx := NewRenderContext()

	// Setup complex context
	ctx.Mission["id"] = "op-001"
	ctx.Mission["objective"] = "Penetration test"
	ctx.Target["url"] = "https://example.com"
	ctx.Target["type"] = "web-application"
	ctx.Agent["name"] = "Gibson"
	ctx.Agent["capabilities"] = []string{"scanning", "exploitation", "reporting"}

	prompt := &Prompt{
		ID:   "complex-prompt",
		Name: "Complex Mission Brief",
		Content: `Mission: {{.Mission.id}} - {{.Mission.objective}}
Target: {{.Target.url}} ({{.Target.type}})
Agent: {{.Agent.name}}
Capabilities:{{range .Agent.capabilities}}
- {{.}}{{end}}

{{if .Variables.priority}}Priority: {{.Variables.priority}}{{end}}`,
		Position: PositionSystem,
		Variables: []VariableDef{
			{Name: "priority", Source: "variables.priority", Default: "normal"},
		},
	}

	result, err := renderer.Render(prompt, ctx)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	// Verify key parts are present
	expectedParts := []string{
		"Mission: op-001 - Penetration test",
		"Target: https://example.com (web-application)",
		"Agent: Gibson",
		"scanning",
		"exploitation",
		"reporting",
		"Priority: normal",
	}

	for _, part := range expectedParts {
		if !strings.Contains(result, part) {
			t.Errorf("Render result missing expected part: %q", part)
		}
	}
}

// equal is a helper function to compare values deeply
func equal(a, b any) bool {
	// Simple equality check - in production you'd use reflect.DeepEqual
	// or a more sophisticated comparison
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// For maps, do a simple comparison
	aMap, aIsMap := a.(map[string]any)
	bMap, bIsMap := b.(map[string]any)

	if aIsMap && bIsMap {
		if len(aMap) != len(bMap) {
			return false
		}
		for k, v := range aMap {
			if bv, ok := bMap[k]; !ok || !equal(v, bv) {
				return false
			}
		}
		return true
	}

	return a == b
}
