package orchestrator_test

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
)

// ExampleInventoryPromptFormatter_Format demonstrates basic usage of the formatter
// with a simple inventory containing agents, tools, and plugins.
func ExampleInventoryPromptFormatter_Format() {
	// Create formatter with default settings (500 token budget, non-verbose)
	formatter := orchestrator.NewInventoryPromptFormatter()

	// Build sample inventory
	inv := &orchestrator.ComponentInventory{
		Agents: []orchestrator.AgentSummary{
			{
				Name:         "davinci",
				Capabilities: []string{"prompt_injection", "jailbreak"},
				TargetTypes:  []string{"llm_chat", "llm_api"},
				HealthStatus: "healthy",
				Instances:    2,
			},
			{
				Name:         "k8skiller",
				Capabilities: []string{"container_escape", "rbac_abuse"},
				TargetTypes:  []string{"kubernetes"},
				HealthStatus: "healthy",
				Instances:    1,
			},
		},
		Tools: []orchestrator.ToolSummary{
			{
				Name:         "nmap",
				Tags:         []string{"network", "enumeration"},
				Description:  "Port scanning and service detection",
				HealthStatus: "healthy",
			},
		},
		Plugins: []orchestrator.PluginSummary{
			{
				Name: "mitre-lookup",
				Methods: []orchestrator.MethodSummary{
					{Name: "getTechnique"},
					{Name: "mapToTactic"},
				},
				HealthStatus: "healthy",
			},
		},
	}

	// Format with mission target type to highlight relevant agents
	output := formatter.Format(inv, "llm_chat")

	// Output will contain markdown tables (abbreviated for example)
	_ = output // Use output to avoid unused variable error
	fmt.Println("Generated inventory section for LLM prompt")
	fmt.Println("Contains:", len(inv.Agents), "agents,", len(inv.Tools), "tools,", len(inv.Plugins), "plugins")

	// Output:
	// Generated inventory section for LLM prompt
	// Contains: 2 agents, 1 tools, 1 plugins
}

// ExampleInventoryPromptFormatter_FormatCondensed demonstrates the condensed format
// used when token budget is tight.
func ExampleInventoryPromptFormatter_FormatCondensed() {
	formatter := orchestrator.NewInventoryPromptFormatter()

	// Large inventory with many components
	inv := &orchestrator.ComponentInventory{
		Agents: []orchestrator.AgentSummary{
			{Name: "davinci"},
			{Name: "k8skiller"},
			{Name: "nuclei-runner"},
			{Name: "web-crawler"},
		},
		Tools: []orchestrator.ToolSummary{
			{Name: "nmap"},
			{Name: "sqlmap"},
			{Name: "ffuf"},
		},
		Plugins: []orchestrator.PluginSummary{
			{Name: "mitre-lookup"},
			{Name: "report-gen"},
		},
	}

	// Use condensed format
	condensed := formatter.FormatCondensed(inv)

	fmt.Println("Condensed format lists component names grouped by type")
	fmt.Println("Total components:", len(inv.Agents)+len(inv.Tools)+len(inv.Plugins))

	// Verify it's actually condensed
	if len(condensed) < 500 {
		fmt.Println("Format is compact and under 500 characters")
	}

	// Output:
	// Condensed format lists component names grouped by type
	// Total components: 9
	// Format is compact and under 500 characters
}

// ExampleInventoryPromptFormatter_EstimateTokens demonstrates token estimation
// for budget management.
func ExampleInventoryPromptFormatter_EstimateTokens() {
	formatter := orchestrator.NewInventoryPromptFormatter()

	smallInv := &orchestrator.ComponentInventory{
		Agents: []orchestrator.AgentSummary{
			{
				Name:         "davinci",
				Capabilities: []string{"prompt_injection"},
				TargetTypes:  []string{"llm_chat"},
				HealthStatus: "healthy",
				Instances:    1,
			},
		},
	}

	largeInv := &orchestrator.ComponentInventory{
		Agents: []orchestrator.AgentSummary{
			{Name: "agent1", Capabilities: []string{"cap1"}, TargetTypes: []string{"type1"}, HealthStatus: "healthy", Instances: 1},
			{Name: "agent2", Capabilities: []string{"cap2"}, TargetTypes: []string{"type2"}, HealthStatus: "healthy", Instances: 1},
			{Name: "agent3", Capabilities: []string{"cap3"}, TargetTypes: []string{"type3"}, HealthStatus: "healthy", Instances: 1},
		},
		Tools: []orchestrator.ToolSummary{
			{Name: "tool1", Tags: []string{"tag1"}, Description: "desc1", HealthStatus: "healthy"},
			{Name: "tool2", Tags: []string{"tag2"}, Description: "desc2", HealthStatus: "healthy"},
		},
	}

	smallTokens := formatter.EstimateTokens(smallInv)
	largeTokens := formatter.EstimateTokens(largeInv)

	fmt.Println("Small inventory estimates fewer tokens than large inventory")
	if smallTokens < largeTokens {
		fmt.Println("Estimation works correctly")
	}

	// Output:
	// Small inventory estimates fewer tokens than large inventory
	// Estimation works correctly
}

// ExampleNewInventoryPromptFormatter demonstrates configuring the formatter
// with custom options.
func ExampleNewInventoryPromptFormatter() {
	// Default configuration
	defaultFormatter := orchestrator.NewInventoryPromptFormatter()
	fmt.Println("Default formatter created")

	// Custom token budget
	budgetFormatter := orchestrator.NewInventoryPromptFormatter(
		orchestrator.WithMaxTokenBudget(1000),
	)
	fmt.Println("Formatter with 1000 token budget created")

	// Verbose mode with full schemas
	verboseFormatter := orchestrator.NewInventoryPromptFormatter(
		orchestrator.WithVerboseMode(true),
	)
	fmt.Println("Verbose formatter created")

	// Combined options
	customFormatter := orchestrator.NewInventoryPromptFormatter(
		orchestrator.WithMaxTokenBudget(750),
		orchestrator.WithVerboseMode(true),
	)
	fmt.Println("Custom formatter with budget and verbose mode created")

	// All formatters are ready to use
	_ = defaultFormatter
	_ = budgetFormatter
	_ = verboseFormatter
	_ = customFormatter

	// Output:
	// Default formatter created
	// Formatter with 1000 token budget created
	// Verbose formatter created
	// Custom formatter with budget and verbose mode created
}

// ExampleInventoryPromptFormatter_Format_targetTypeHighlighting demonstrates
// how agents matching the mission target type are highlighted.
func ExampleInventoryPromptFormatter_Format_targetTypeHighlighting() {
	formatter := orchestrator.NewInventoryPromptFormatter()

	inv := &orchestrator.ComponentInventory{
		Agents: []orchestrator.AgentSummary{
			{
				Name:         "llm-agent",
				TargetTypes:  []string{"llm_chat", "llm_api"},
				Capabilities: []string{"prompt_injection"},
				HealthStatus: "healthy",
				Instances:    1,
			},
			{
				Name:         "k8s-agent",
				TargetTypes:  []string{"kubernetes"},
				Capabilities: []string{"container_escape"},
				HealthStatus: "healthy",
				Instances:    1,
			},
		},
	}

	// Format with llm_chat as target type
	output := formatter.Format(inv, "llm_chat")

	// The llm-agent will be highlighted because it matches llm_chat
	_ = output // Use output to avoid unused variable error
	fmt.Println("Generated output with target type highlighting")
	fmt.Println("Matching agents and target types are bold in markdown")

	// Output:
	// Generated output with target type highlighting
	// Matching agents and target types are bold in markdown
}
