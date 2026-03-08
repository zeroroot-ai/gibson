package component

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	dclient "github.com/zero-day-ai/gibson/internal/daemon/client"
)

// newStatusCommand creates a status command for the specified component type.
func newStatusCommand(cfg Config, flags *StatusFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [NAME]",
		Short: "Show component status from registry",
		Long: fmt.Sprintf(`Display status of registered %ss from the service registry.

Without arguments, shows all registered %ss with instance counts.
With a component name, shows detailed information about all instances of that %s.

The registry is the source of truth for all component discovery.
Components automatically register when started and deregister when stopped.`,
			cfg.DisplayName, cfg.DisplayName, cfg.DisplayName),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args, cfg, flags)
		},
	}

	// Register flags
	cmd.Flags().BoolVar(&flags.JSON, "json", false, "Output in JSON format")

	return cmd
}

// runStatus executes the status command for a component.
func runStatus(cmd *cobra.Command, args []string, cfg Config, flags *StatusFlags) error {
	var componentName string
	if len(args) > 0 {
		componentName = args[0]
	}

	// Check for daemon client - status command requires daemon for accurate component status
	ctx := cmd.Context()
	daemonClient := GetDaemonClient(ctx)
	if daemonClient == nil {
		return fmt.Errorf("daemon is not running - component status requires the daemon to be running\n\nPlease start the daemon first:\n  gibson daemon start")
	}

	return queryComponentStatusViaDaemon(cmd, daemonClient, cfg, componentName, flags)
}

// formatDuration formats a duration in a human-readable format (e.g., "2h 15m 30s").
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		if seconds > 0 {
			return fmt.Sprintf("%dm %ds", minutes, seconds)
		}
		return fmt.Sprintf("%dm", minutes)
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if seconds > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dh", hours)
}

// queryComponentStatusViaDaemon queries component status from the daemon registry.
func queryComponentStatusViaDaemon(cmd *cobra.Command, daemonClient interface{}, cfg Config, componentName string, flags *StatusFlags) error {
	// Type assert to daemon client
	client, ok := daemonClient.(*dclient.Client)
	if !ok {
		return fmt.Errorf("invalid daemon client type")
	}

	ctx := cmd.Context()

	// Query appropriate component type from daemon
	switch cfg.Kind {
	case "agent":
		agents, err := client.ListAgents(ctx)
		if err != nil {
			return fmt.Errorf("failed to list agents from daemon: %w", err)
		}
		return displayDaemonComponents(cmd, "AGENTS", agents, componentName)

	case "tool":
		tools, err := client.ListTools(ctx)
		if err != nil {
			return fmt.Errorf("failed to list tools from daemon: %w", err)
		}
		return displayDaemonTools(cmd, tools, componentName)

	case "plugin":
		plugins, err := client.ListPlugins(ctx)
		if err != nil {
			return fmt.Errorf("failed to list plugins from daemon: %w", err)
		}
		return displayDaemonPlugins(cmd, plugins, componentName)

	default:
		return fmt.Errorf("unknown component kind: %s", cfg.Kind)
	}
}

// displayDaemonComponents displays agent components from daemon.
func displayDaemonComponents(cmd *cobra.Command, title string, agents []dclient.AgentInfo, filter string) error {
	if len(agents) == 0 {
		fmt.Println("No components registered")
		return nil
	}

	// Filter if needed
	if filter != "" {
		filtered := make([]dclient.AgentInfo, 0)
		for _, a := range agents {
			if strings.Contains(a.Name, filter) {
				filtered = append(filtered, a)
			}
		}
		agents = filtered
	}

	// Display table
	fmt.Printf("\n%s (%d registered)\n\n", title, len(agents))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tSTATUS\tADDRESS")
	for _, a := range agents {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.Name, a.Version, a.Status, a.Address)
	}
	w.Flush()

	return nil
}

// displayDaemonTools displays tool components from daemon.
func displayDaemonTools(cmd *cobra.Command, tools []dclient.ToolInfo, filter string) error {
	if len(tools) == 0 {
		fmt.Println("No tools registered")
		return nil
	}

	// Filter if needed
	if filter != "" {
		filtered := make([]dclient.ToolInfo, 0)
		for _, t := range tools {
			if strings.Contains(t.Name, filter) {
				filtered = append(filtered, t)
			}
		}
		tools = filtered
	}

	// If filter is set (showing single tool detail), display detailed view with capabilities
	if filter != "" && len(tools) > 0 {
		return displayToolsDetailed(cmd, tools)
	}

	// Display summary table
	fmt.Printf("\nTOOLS (%d registered)\n\n", len(tools))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tSTATUS\tPRIVILEGES\tADDRESS")
	for _, t := range tools {
		privileges := formatPrivileges(t.Capabilities)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Version, t.Status, privileges, t.Address)
	}
	w.Flush()

	return nil
}

// displayToolsDetailed displays detailed information about tools including capabilities.
func displayToolsDetailed(cmd *cobra.Command, tools []dclient.ToolInfo) error {
	for i, t := range tools {
		if i > 0 {
			fmt.Println()
		}

		fmt.Printf("Tool: %s\n", t.Name)
		fmt.Printf("Version: %s\n", t.Version)
		fmt.Printf("Description: %s\n", t.Description)
		fmt.Printf("Status: %s\n", t.Status)
		fmt.Printf("Address: %s\n", t.Address)

		if t.Capabilities != nil {
			fmt.Printf("\nCapabilities:\n")

			// Privilege level
			if t.Capabilities.HasRoot {
				fmt.Printf("  Privileges: root (full access)\n")
			} else if t.Capabilities.HasSudo {
				fmt.Printf("  Privileges: sudo (passwordless escalation available)\n")
			} else if t.Capabilities.CanRawSocket {
				fmt.Printf("  Privileges: unprivileged with raw socket capability\n")
			} else {
				fmt.Printf("  Privileges: unprivileged (no root, no sudo, no raw socket)\n")
			}

			// Blocked arguments
			if len(t.Capabilities.BlockedArgs) > 0 {
				fmt.Printf("  Blocked flags: %s\n", strings.Join(t.Capabilities.BlockedArgs, ", "))
			}

			// Argument alternatives
			if len(t.Capabilities.ArgAlternatives) > 0 {
				fmt.Printf("  Available alternatives:\n")
				for blocked, alternative := range t.Capabilities.ArgAlternatives {
					fmt.Printf("    - Use %s instead of %s\n", alternative, blocked)
				}
			}

			// Features
			if len(t.Capabilities.Features) > 0 {
				var enabledFeatures []string
				var disabledFeatures []string
				for feature, enabled := range t.Capabilities.Features {
					if enabled {
						enabledFeatures = append(enabledFeatures, feature)
					} else {
						disabledFeatures = append(disabledFeatures, feature)
					}
				}
				if len(enabledFeatures) > 0 {
					fmt.Printf("  Available features: %s\n", strings.Join(enabledFeatures, ", "))
				}
				if len(disabledFeatures) > 0 {
					fmt.Printf("  Unavailable features: %s\n", strings.Join(disabledFeatures, ", "))
				}
			}
		} else {
			fmt.Printf("\nCapabilities: not reported\n")
		}
	}

	return nil
}

// formatPrivileges returns a short string summarizing tool privileges.
func formatPrivileges(caps *dclient.Capabilities) string {
	if caps == nil {
		return "unknown"
	}

	if caps.HasRoot {
		return "root"
	}
	if caps.HasSudo {
		return "sudo"
	}
	if caps.CanRawSocket {
		return "rawsock"
	}
	return "unprivileged"
}

// displayDaemonPlugins displays plugin components from daemon.
func displayDaemonPlugins(cmd *cobra.Command, plugins []dclient.PluginInfo, filter string) error {
	if len(plugins) == 0 {
		fmt.Println("No plugins registered")
		return nil
	}

	// Filter if needed
	if filter != "" {
		filtered := make([]dclient.PluginInfo, 0)
		for _, p := range plugins {
			if strings.Contains(p.Name, filter) {
				filtered = append(filtered, p)
			}
		}
		plugins = filtered
	}

	// Display table
	fmt.Printf("\nPLUGINS (%d registered)\n\n", len(plugins))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tSTATUS\tADDRESS")
	for _, p := range plugins {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Status, p.Address)
	}
	w.Flush()

	return nil
}
