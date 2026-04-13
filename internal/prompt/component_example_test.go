package prompt_test

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/prompt"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
)

// Example tool that implements ToolWithPrompt
type PortScannerTool struct{}

func (t *PortScannerTool) Name() string              { return "port-scanner" }
func (t *PortScannerTool) Description() string       { return "Scans network ports" }
func (t *PortScannerTool) Version() string           { return "1.0.0" }
func (t *PortScannerTool) Tags() []string            { return []string{"network", "recon"} }
func (t *PortScannerTool) InputMessageType() string  { return "" }
func (t *PortScannerTool) OutputMessageType() string { return "" }
func (t *PortScannerTool) ExecuteProto(_ context.Context, _ proto.Message) (proto.Message, error) {
	return nil, nil
}
func (t *PortScannerTool) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("operational")
}

// Prompts returns usage instructions for the port scanner tool
func (t *PortScannerTool) Prompts() []prompt.Prompt {
	return []prompt.Prompt{
		{
			ID:       "port-scanner:usage",
			Name:     "Port Scanner Usage",
			Position: prompt.PositionTools,
			Content: "The port-scanner tool can scan TCP and UDP ports on target systems.\n" +
				"Use it to discover open services and their versions.\n" +
				"Always respect scope and scan only authorized targets.",
			Priority: 50,
		},
	}
}

// Example plugin that implements PluginWithPrompts
type VulnDatabasePlugin struct{}

func (p *VulnDatabasePlugin) Name() string    { return "vuln-database" }
func (p *VulnDatabasePlugin) Version() string { return "1.0.0" }
func (p *VulnDatabasePlugin) Initialize(ctx context.Context, cfg plugin.PluginConfig) error {
	return nil
}
func (p *VulnDatabasePlugin) Shutdown(ctx context.Context) error { return nil }
func (p *VulnDatabasePlugin) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	return nil, nil
}
func (p *VulnDatabasePlugin) Methods() []plugin.MethodDescriptor { return nil }
func (p *VulnDatabasePlugin) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("operational")
}

// Prompts returns information about the vulnerability database
func (p *VulnDatabasePlugin) Prompts() []prompt.Prompt {
	return []prompt.Prompt{
		{
			ID:       "vuln-db:usage",
			Name:     "Vulnerability Database Usage",
			Position: prompt.PositionPlugins,
			Content: "The vuln-database plugin provides access to CVE and exploit data.\n" +
				"Use the 'search' method to find vulnerabilities by keyword, CVE ID, or product name.\n" +
				"Use the 'get_details' method to retrieve comprehensive information about a specific CVE.",
			Priority: 50,
		},
	}
}

// Example agent that implements AgentWithPrompts
type WebAppTestAgent struct{}

func (a *WebAppTestAgent) Name() string        { return "webapp-tester" }
func (a *WebAppTestAgent) Version() string     { return "1.0.0" }
func (a *WebAppTestAgent) Description() string { return "Web application security testing agent" }
func (a *WebAppTestAgent) Capabilities() []string {
	return []string{"web", "owasp-top-10"}
}
func (a *WebAppTestAgent) TargetTypes() []component.TargetType {
	return []component.TargetType{component.TargetTypeLLMAPI}
}
func (a *WebAppTestAgent) TechniqueTypes() []component.TechniqueType {
	return []component.TechniqueType{component.TechniquePromptInjection}
}
func (a *WebAppTestAgent) LLMSlots() []agent.SlotDefinition { return nil }
func (a *WebAppTestAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, nil
}
func (a *WebAppTestAgent) Initialize(ctx context.Context, cfg agent.AgentConfig) error {
	return nil
}
func (a *WebAppTestAgent) Shutdown(ctx context.Context) error { return nil }
func (a *WebAppTestAgent) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("operational")
}

// SystemPrompt returns the agent's core behavior guidance
func (a *WebAppTestAgent) SystemPrompt() *prompt.Prompt {
	return &prompt.Prompt{
		ID:       "webapp-tester:system",
		Name:     "Web App Tester System Prompt",
		Position: prompt.PositionSystem,
		Content: "You are a specialized web application security testing agent.\n" +
			"Your expertise includes OWASP Top 10 vulnerabilities, authentication bypass, " +
			"SQL injection, XSS, CSRF, and API security testing.\n" +
			"Always test systematically and document findings with evidence.",
		Priority: 100,
	}
}

// TaskPrompt returns task-specific instructions
func (a *WebAppTestAgent) TaskPrompt() *prompt.Prompt {
	return &prompt.Prompt{
		ID:       "webapp-tester:task",
		Name:     "Web App Testing Task",
		Position: prompt.PositionUser,
		Content:  "Conduct a comprehensive security assessment of the target web application.",
		Priority: 50,
	}
}

// Personas returns available testing personas
func (a *WebAppTestAgent) Personas() []prompt.Prompt {
	return []prompt.Prompt{
		{
			ID:       "webapp-tester:persona:thorough",
			Name:     "Thorough Testing Mode",
			Position: prompt.PositionContext,
			Content: "Operate in thorough mode: test every endpoint, parameter, and feature.\n" +
				"Take your time to ensure complete coverage.",
			Priority: 50,
		},
		{
			ID:       "webapp-tester:persona:stealth",
			Name:     "Stealth Testing Mode",
			Position: prompt.PositionContext,
			Content: "Operate in stealth mode: minimize requests, avoid WAF triggers, " +
				"and use subtle reconnaissance techniques.",
			Priority: 50,
		},
	}
}

// ExampleToolWithPrompt demonstrates how to use ToolWithPrompt
func Example_toolWithPrompt() {
	var t tool.Tool = &PortScannerTool{}

	// Check if tool provides prompts
	if prompt.ToolHasPrompts(t) {
		prompts := prompt.GetToolPrompts(t)
		for _, p := range prompts {
			fmt.Printf("Tool Prompt: %s\n", p.Name)
			fmt.Printf("Position: %s\n", p.Position)
		}
	}

	// Output:
	// Tool Prompt: Port Scanner Usage
	// Position: tools
}

// ExamplePluginWithPrompts demonstrates how to use PluginWithPrompts
func Example_pluginWithPrompts() {
	var p plugin.Plugin = &VulnDatabasePlugin{}

	// Check if plugin provides prompts
	if prompt.PluginHasPrompts(p) {
		prompts := prompt.GetPluginPrompts(p)
		for _, pr := range prompts {
			fmt.Printf("Plugin Prompt: %s\n", pr.Name)
			fmt.Printf("Position: %s\n", pr.Position)
		}
	}

	// Output:
	// Plugin Prompt: Vulnerability Database Usage
	// Position: plugins
}

// ExampleAgentWithPrompts demonstrates how to use AgentWithPrompts
func Example_agentWithPrompts() {
	var a agent.Agent = &WebAppTestAgent{}

	// Check if agent provides prompts
	if prompt.AgentHasPrompts(a) {
		prompts := prompt.GetAgentPrompts(a)
		fmt.Printf("Agent provides %d prompts\n", len(prompts))

		// Access specific prompt types
		awp := a.(prompt.AgentWithPrompts)
		if sys := awp.SystemPrompt(); sys != nil {
			fmt.Printf("System Prompt: %s\n", sys.Name)
		}
		if task := awp.TaskPrompt(); task != nil {
			fmt.Printf("Task Prompt: %s\n", task.Name)
		}
		personas := awp.Personas()
		fmt.Printf("Personas: %d\n", len(personas))
	}

	// Output:
	// Agent provides 4 prompts
	// System Prompt: Web App Tester System Prompt
	// Task Prompt: Web App Testing Task
	// Personas: 2
}

// ExampleCollectingComponentPrompts demonstrates collecting prompts from multiple components
func Example_collectingComponentPrompts() {
	// Create components
	tool := &PortScannerTool{}
	plugin := &VulnDatabasePlugin{}
	agent := &WebAppTestAgent{}

	// Collect all prompts from components
	var allPrompts []prompt.Prompt

	// Collect from tool
	if prompt.ToolHasPrompts(tool) {
		allPrompts = append(allPrompts, prompt.GetToolPrompts(tool)...)
	}

	// Collect from plugin
	if prompt.PluginHasPrompts(plugin) {
		allPrompts = append(allPrompts, prompt.GetPluginPrompts(plugin)...)
	}

	// Collect from agent
	if prompt.AgentHasPrompts(agent) {
		allPrompts = append(allPrompts, prompt.GetAgentPrompts(agent)...)
	}

	fmt.Printf("Collected %d prompts from all components\n", len(allPrompts))

	// Count by position in order
	positions := []prompt.Position{
		prompt.PositionSystem,
		prompt.PositionTools,
		prompt.PositionPlugins,
		prompt.PositionContext,
		prompt.PositionUser,
	}

	byPosition := make(map[prompt.Position]int)
	for _, p := range allPrompts {
		byPosition[p.Position]++
	}

	for _, pos := range positions {
		if count, ok := byPosition[pos]; ok {
			fmt.Printf("%s: %d\n", pos, count)
		}
	}

	// Output:
	// Collected 6 prompts from all components
	// system: 1
	// tools: 1
	// plugins: 1
	// context: 2
	// user: 1
}
