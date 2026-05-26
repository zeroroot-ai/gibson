package prompt

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"text/template"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// RenderContext provides data for template rendering.
// It organizes data into logical categories for easy access in templates.
type RenderContext struct {
	Mission   map[string]any `json:"mission,omitempty"`
	Target    map[string]any `json:"target,omitempty"`
	Agent     map[string]any `json:"agent,omitempty"`
	Memory    map[string]any `json:"memory,omitempty"`
	Variables map[string]any `json:"variables,omitempty"`
	Custom    map[string]any `json:"custom,omitempty"`
}

// NewRenderContext creates a new empty render context with initialized maps.
func NewRenderContext() *RenderContext {
	return &RenderContext{
		Mission:   make(map[string]any),
		Target:    make(map[string]any),
		Agent:     make(map[string]any),
		Memory:    make(map[string]any),
		Variables: make(map[string]any),
		Custom:    make(map[string]any),
	}
}

// Get retrieves a value by dot-notation path from the context.
// The first part of the path determines the category (mission, target, agent, etc.),
// and the remaining parts navigate the nested structure.
//
// Examples:
//   - "mission.target.url" -> Mission["target"]["url"]
//   - "agent.name" -> Agent["name"]
//   - "variables.apiKey" -> Variables["apiKey"]
func (c *RenderContext) Get(path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")

	// Determine the root category
	var root map[string]any
	switch parts[0] {
	case "mission":
		root = c.Mission
	case "target":
		root = c.Target
	case "agent":
		root = c.Agent
	case "memory":
		root = c.Memory
	case "variables":
		root = c.Variables
	case "custom":
		root = c.Custom
	default:
		return nil, false
	}

	// If only the category name was provided, return the whole map
	if len(parts) == 1 {
		return root, true
	}

	// Navigate the remaining path
	return ResolvePath(root, strings.Join(parts[1:], "."))
}

// Set sets a value at the given path in the context.
// The first part of the path determines the category.
//
// Examples:
//   - Set("mission.id", "op-001") -> Mission["id"] = "op-001"
//   - Set("agent.name", "Gibson") -> Agent["name"] = "Gibson"
func (c *RenderContext) Set(path string, value any) {
	if path == "" {
		return
	}

	parts := strings.Split(path, ".")

	// Determine the root category
	var root map[string]any
	switch parts[0] {
	case "mission":
		root = c.Mission
	case "target":
		root = c.Target
	case "agent":
		root = c.Agent
	case "memory":
		root = c.Memory
	case "variables":
		root = c.Variables
	case "custom":
		root = c.Custom
	default:
		return
	}

	// If only the category name was provided, ignore (can't replace whole category)
	if len(parts) == 1 {
		return
	}

	// Navigate and set the value
	setPath(root, parts[1:], value)
}

// setPath sets a value in a nested map structure by creating intermediate maps as needed
func setPath(m map[string]any, parts []string, value any) {
	if len(parts) == 0 {
		return
	}

	if len(parts) == 1 {
		m[parts[0]] = value
		return
	}

	// Get or create the intermediate map
	next, exists := m[parts[0]]
	if !exists {
		next = make(map[string]any)
		m[parts[0]] = next
	}

	// Convert to map if possible
	nextMap, ok := next.(map[string]any)
	if !ok {
		// Can't navigate further if not a map
		return
	}

	setPath(nextMap, parts[1:], value)
}

// ToMap converts the context to a flat map for template rendering.
// This creates a single-level map with the category names as keys.
func (c *RenderContext) ToMap() map[string]any {
	return map[string]any{
		"Mission":   c.Mission,
		"Target":    c.Target,
		"Agent":     c.Agent,
		"Memory":    c.Memory,
		"Variables": c.Variables,
		"Custom":    c.Custom,
	}
}

// TemplateRenderer processes Go templates in prompt content.
// It provides variable resolution, custom functions, and template caching.
type TemplateRenderer interface {
	// Render processes the template with the given context.
	// It first resolves variables from their Source paths, then renders the template.
	Render(prompt *Prompt, ctx *RenderContext) (string, error)

	// RegisterFunc adds a custom template function that can be used in templates.
	RegisterFunc(name string, fn any) error
}

// DefaultTemplateRenderer is the default implementation of TemplateRenderer.
// It uses Go's text/template package and caches compiled templates for performance.
type DefaultTemplateRenderer struct {
	mu        sync.RWMutex
	templates map[string]*template.Template // Cache of compiled templates by prompt ID
	funcMap   template.FuncMap              // Custom template functions
}

// NewTemplateRenderer creates a new DefaultTemplateRenderer with default configuration.
func NewTemplateRenderer() TemplateRenderer {
	return &DefaultTemplateRenderer{
		templates: make(map[string]*template.Template),
		funcMap:   DefaultFuncMap(),
	}
}

// RegisterFunc adds a custom template function to the renderer.
// The function will be available to all templates rendered after registration.
func (r *DefaultTemplateRenderer) RegisterFunc(name string, fn any) error {
	if name == "" {
		return types.NewError(
			ErrCodeInvalidTemplate,
			"function name cannot be empty",
		)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.funcMap[name] = fn

	// Clear template cache to force recompilation with new functions
	r.templates = make(map[string]*template.Template)

	return nil
}

// Render processes the prompt template with the given context.
// It resolves variables from their Source paths and adds them to the context,
// then compiles and executes the template.
func (r *DefaultTemplateRenderer) Render(prompt *Prompt, ctx *RenderContext) (string, error) {
	if prompt == nil {
		return "", types.NewError(
			ErrCodeInvalidPrompt,
			"prompt cannot be nil",
		)
	}

	if ctx == nil {
		ctx = NewRenderContext()
	}

	// Resolve variables and add to context
	if err := r.resolveVariables(prompt, ctx); err != nil {
		return "", err
	}

	// Get or compile the template
	tmpl, err := r.getTemplate(prompt)
	if err != nil {
		return "", err
	}

	// Execute the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx.ToMap()); err != nil {
		return "", NewTemplateRenderError(prompt.ID, err)
	}

	return buf.String(), nil
}

// resolveVariables resolves all variables defined in the prompt and adds them to the context.
// It checks for missing required variables and returns appropriate errors.
func (r *DefaultTemplateRenderer) resolveVariables(prompt *Prompt, ctx *RenderContext) error {
	// Convert context to flat map for variable resolution
	flatCtx := r.flattenContext(ctx)

	for _, varDef := range prompt.Variables {
		value, err := varDef.Resolve(flatCtx)
		if err != nil {
			// Check if it's a missing required variable error
			var gibsonErr *types.GibsonError
			if errors.As(err, &gibsonErr) && gibsonErr.Code == PROMPT_VAR_REQUIRED {
				return NewMissingVariableError(prompt.ID, varDef.Name)
			}
			return err
		}

		// Add resolved value to Variables section of context
		if ctx.Variables == nil {
			ctx.Variables = make(map[string]any)
		}
		ctx.Variables[varDef.Name] = value
	}

	return nil
}

// flattenContext converts the RenderContext to a flat map for variable resolution.
// This allows ResolvePath to work with the nested structure.
func (r *DefaultTemplateRenderer) flattenContext(ctx *RenderContext) map[string]any {
	return map[string]any{
		"mission":   ctx.Mission,
		"target":    ctx.Target,
		"agent":     ctx.Agent,
		"memory":    ctx.Memory,
		"variables": ctx.Variables,
		"custom":    ctx.Custom,
	}
}

// getTemplate retrieves a compiled template from cache or compiles it.
func (r *DefaultTemplateRenderer) getTemplate(prompt *Prompt) (*template.Template, error) {
	// Check cache with read lock
	r.mu.RLock()
	tmpl, exists := r.templates[prompt.ID]
	r.mu.RUnlock()

	if exists {
		return tmpl, nil
	}

	// Compile template with write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check in case another goroutine compiled it
	if tmpl, exists := r.templates[prompt.ID]; exists {
		return tmpl, nil
	}

	// Create new template with custom functions
	tmpl, err := template.New(prompt.ID).Funcs(r.funcMap).Parse(prompt.Content)
	if err != nil {
		return nil, NewInvalidTemplateError(prompt.ID, err)
	}

	// Cache the compiled template
	r.templates[prompt.ID] = tmpl

	return tmpl, nil
}
