package component

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
)

// newLogsCommand creates a logs command for the specified component type.
func newLogsCommand(cfg Config, flags *LogsFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs [name]",
		Short: fmt.Sprintf("View %s logs", cfg.DisplayName),
		Long: fmt.Sprintf(`Display logs for a %s or multiple %s.

Logs are stored in ~/.gibson/logs/%s/<name>.log

Use --follow (-f) to stream logs in real-time.
Use --lines (-n) to specify the number of lines to show.
Use --all to view logs from all %s.
Use --component to view logs from specific %s (can be specified multiple times).`,
			cfg.DisplayName, cfg.DisplayPlural, cfg.DisplayName, cfg.DisplayPlural, cfg.DisplayPlural),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogs(cmd, args, cfg, flags)
		},
	}

	// Register flags
	cmd.Flags().BoolVarP(&flags.Follow, "follow", "f", false, "Follow log output (like tail -f)")
	cmd.Flags().IntVarP(&flags.Lines, "lines", "n", 50, "Number of lines to show")
	cmd.Flags().BoolVar(&flags.All, "all", false, fmt.Sprintf("View logs from all %s", cfg.DisplayPlural))
	cmd.Flags().StringSliceVar(&flags.Components, "component", nil, "View logs from specific components (can be specified multiple times)")

	return cmd
}

// runLogs executes the logs command for a component.
func runLogs(cmd *cobra.Command, args []string, cfg Config, flags *LogsFlags) error {
	componentName := args[0]
	ctx := cmd.Context()

	// Check for daemon client in context
	clientIface := GetDaemonClient(ctx)
	if clientIface == nil {
		return fmt.Errorf("daemon not running. Start with: gibson daemon start --foreground")
	}

	// Type assert to daemon client
	client, ok := clientIface.(*daemonclient.Client)
	if !ok {
		return fmt.Errorf("invalid daemon client type")
	}

	// Build logs options
	opts := daemonclient.LogsOptions{
		Follow: flags.Follow,
		Lines:  flags.Lines,
	}

	// Call appropriate method based on component kind
	var logChan <-chan daemonclient.LogEntry
	var err error

	switch cfg.Kind.String() {
	case "agent":
		logChan, err = client.GetAgentLogs(ctx, componentName, opts)
	case "tool":
		logChan, err = client.GetToolLogs(ctx, componentName, opts)
	case "plugin":
		logChan, err = client.GetPluginLogs(ctx, componentName, opts)
	default:
		return fmt.Errorf("unsupported component kind: %s", cfg.Kind)
	}

	if err != nil {
		// Check if it's a connection error
		if strings.Contains(err.Error(), "daemon not responding") {
			return fmt.Errorf("daemon not running. Start with: gibson daemon start --foreground")
		}
		return err
	}

	// Stream logs from channel
	if flags.Follow {
		cmd.Printf("Following logs for %s '%s' (Ctrl+C to stop)...\n\n", cfg.DisplayName, componentName)
	}

	for entry := range logChan {
		// Format log entry
		timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
		if entry.Level != "" {
			cmd.Printf("[%s] %s: %s\n", timestamp, strings.ToUpper(entry.Level), entry.Message)
		} else {
			cmd.Printf("[%s] %s\n", timestamp, entry.Message)
		}
	}

	return nil
}
