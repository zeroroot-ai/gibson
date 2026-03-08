package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/component"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
)

var logsCmd = &cobra.Command{
	Use:   "logs [component]",
	Short: "Stream component logs",
	Long: `Stream log output from a component (agent, tool, or plugin).

Similar to 'kubectl logs', this command retrieves log entries from
a running or stopped component. Use -f to follow log output in real-time.

Examples:
  # Show last 100 lines from an agent
  gibson logs my-agent

  # Follow log output in real-time
  gibson logs my-agent -f

  # Show last 50 lines
  gibson logs my-tool --tail 50

  # Specify component type explicitly
  gibson logs --kind agent my-agent

  # Show logs from all components
  gibson logs --all -f

  # Show logs from specific components
  gibson logs --component my-agent --component my-tool -f`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLogs,
}

func init() {
	logsCmd.Flags().BoolP("follow", "f", false, "Follow log output (stream continuously)")
	logsCmd.Flags().Int("tail", 100, "Number of lines to show from the end of the logs")
	logsCmd.Flags().String("kind", "", "Component kind (agent, tool, plugin). Auto-detected if not specified.")
	logsCmd.Flags().Bool("all", false, "Show logs from all components")
	logsCmd.Flags().StringSlice("component", nil, "Specific components to include (can be specified multiple times)")
}

func runLogs(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse flags
	follow, _ := cmd.Flags().GetBool("follow")
	tailLines, _ := cmd.Flags().GetInt("tail")
	kind, _ := cmd.Flags().GetString("kind")
	showAll, _ := cmd.Flags().GetBool("all")
	components, _ := cmd.Flags().GetStringSlice("component")

	// Validate arguments
	if len(args) == 0 && !showAll && len(components) == 0 {
		return fmt.Errorf("component name required, or use --all or --component flags")
	}

	if len(args) > 0 && (showAll || len(components) > 0) {
		return fmt.Errorf("cannot specify component name with --all or --component flags")
	}

	if showAll && len(components) > 0 {
		return fmt.Errorf("cannot use --all and --component flags together")
	}

	// Validate kind if specified
	if kind != "" && kind != "agent" && kind != "tool" && kind != "plugin" {
		return fmt.Errorf("invalid component kind %q: must be agent, tool, or plugin", kind)
	}

	// Get daemon client from context
	client := component.GetDaemonClient(ctx)
	if client == nil {
		return fmt.Errorf("daemon not available - please ensure the daemon is running")
	}

	daemonClient, ok := client.(*daemonclient.Client)
	if !ok {
		return fmt.Errorf("invalid daemon client type")
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create cancellable context
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle signals in background
	go func() {
		<-sigChan
		cancel()
	}()

	// Configure log options
	opts := daemonclient.LogsOptions{
		Follow: follow,
		Lines:  tailLines,
	}

	// Handle multi-component mode
	if showAll || len(components) > 0 {
		return runMultiComponentLogs(streamCtx, daemonClient, components, showAll, opts)
	}

	// Single component mode
	componentName := args[0]
	return runSingleComponentLogs(streamCtx, daemonClient, componentName, kind, opts)
}

// runSingleComponentLogs streams logs from a single component
func runSingleComponentLogs(ctx context.Context, client *daemonclient.Client, componentName, kind string, opts daemonclient.LogsOptions) error {
	var logChan <-chan daemonclient.LogEntry
	var err error

	if kind != "" {
		// Kind explicitly specified
		switch kind {
		case "agent":
			logChan, err = client.GetAgentLogs(ctx, componentName, opts)
		case "tool":
			logChan, err = client.GetToolLogs(ctx, componentName, opts)
		case "plugin":
			logChan, err = client.GetPluginLogs(ctx, componentName, opts)
		}
	} else {
		// Try to auto-detect component kind by trying each type
		// Start with agent as most common
		logChan, err = client.GetAgentLogs(ctx, componentName, opts)
		if err != nil && strings.Contains(err.Error(), "not found") {
			logChan, err = client.GetToolLogs(ctx, componentName, opts)
			if err != nil && strings.Contains(err.Error(), "not found") {
				logChan, err = client.GetPluginLogs(ctx, componentName, opts)
			}
		}
	}

	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}

	// Stream logs to stdout
	for entry := range logChan {
		printLogEntry("", entry)
	}

	return nil
}

// runMultiComponentLogs streams logs from multiple components
func runMultiComponentLogs(ctx context.Context, client *daemonclient.Client, componentNames []string, showAll bool, opts daemonclient.LogsOptions) error {
	// Build list of components to stream
	type componentSpec struct {
		kind string
		name string
	}
	var specs []componentSpec

	if showAll {
		// Get all components from daemon
		agents, err := client.ListAgents(ctx)
		if err == nil {
			for _, a := range agents {
				specs = append(specs, componentSpec{kind: "agent", name: a.Name})
			}
		}

		tools, err := client.ListTools(ctx)
		if err == nil {
			for _, t := range tools {
				specs = append(specs, componentSpec{kind: "tool", name: t.Name})
			}
		}

		plugins, err := client.ListPlugins(ctx)
		if err == nil {
			for _, p := range plugins {
				specs = append(specs, componentSpec{kind: "plugin", name: p.Name})
			}
		}

		if len(specs) == 0 {
			return fmt.Errorf("no components found")
		}
	} else {
		// Use specified components - try to auto-detect kind for each
		for _, name := range componentNames {
			// Try agent first
			_, err := client.GetAgentLogs(ctx, name, daemonclient.LogsOptions{Lines: 1})
			if err == nil || !strings.Contains(err.Error(), "not found") {
				specs = append(specs, componentSpec{kind: "agent", name: name})
				continue
			}

			// Try tool
			_, err = client.GetToolLogs(ctx, name, daemonclient.LogsOptions{Lines: 1})
			if err == nil || !strings.Contains(err.Error(), "not found") {
				specs = append(specs, componentSpec{kind: "tool", name: name})
				continue
			}

			// Try plugin
			_, err = client.GetPluginLogs(ctx, name, daemonclient.LogsOptions{Lines: 1})
			if err == nil || !strings.Contains(err.Error(), "not found") {
				specs = append(specs, componentSpec{kind: "plugin", name: name})
				continue
			}

			// Not found anywhere
			fmt.Fprintf(os.Stderr, "Warning: component %q not found\n", name)
		}

		if len(specs) == 0 {
			return fmt.Errorf("no valid components found")
		}
	}

	// Create merged channel for all log entries
	merged := make(chan struct {
		component string
		entry     daemonclient.LogEntry
	}, 100)

	var wg sync.WaitGroup

	// Start streaming from each component
	for _, spec := range specs {
		wg.Add(1)
		go func(kind, name string) {
			defer wg.Done()

			var logChan <-chan daemonclient.LogEntry
			var err error

			switch kind {
			case "agent":
				logChan, err = client.GetAgentLogs(ctx, name, opts)
			case "tool":
				logChan, err = client.GetToolLogs(ctx, name, opts)
			case "plugin":
				logChan, err = client.GetPluginLogs(ctx, name, opts)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get logs for %s: %v\n", name, err)
				return
			}

			for entry := range logChan {
				select {
				case merged <- struct {
					component string
					entry     daemonclient.LogEntry
				}{component: name, entry: entry}:
				case <-ctx.Done():
					return
				}
			}
		}(spec.kind, spec.name)
	}

	// Close merged channel when all streams complete
	go func() {
		wg.Wait()
		close(merged)
	}()

	// Print merged logs with component prefix
	for item := range merged {
		printLogEntry(item.component, item.entry)
	}

	return nil
}

// printLogEntry formats and prints a single log entry
func printLogEntry(componentName string, entry daemonclient.LogEntry) {
	// Format timestamp
	ts := entry.Timestamp.Format("2006-01-02 15:04:05.000")

	// Format level with color codes (if terminal supports it)
	level := formatLevel(entry.Level)

	// Print main log line with optional component prefix
	if componentName != "" {
		fmt.Printf("%s %s [%s] %s\n", ts, level, componentName, entry.Message)
	} else {
		fmt.Printf("%s %s %s\n", ts, level, entry.Message)
	}

	// Print any extra fields on separate lines if present
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			// Skip common fields that are already shown
			if k == "timestamp" || k == "level" || k == "msg" || k == "message" {
				continue
			}
			fmt.Printf("  %s=%s\n", k, v)
		}
	}
}

// formatLevel returns a formatted log level string
func formatLevel(level string) string {
	level = strings.ToUpper(level)
	switch level {
	case "ERROR", "ERR":
		return "[ERROR]"
	case "WARN", "WARNING":
		return "[WARN] "
	case "INFO":
		return "[INFO] "
	case "DEBUG":
		return "[DEBUG]"
	case "TRACE":
		return "[TRACE]"
	default:
		if level == "" {
			return "[INFO] "
		}
		return fmt.Sprintf("[%-5s]", level)
	}
}
