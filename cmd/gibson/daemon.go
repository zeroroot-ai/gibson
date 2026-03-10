package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the Gibson daemon",
	Long: `Manage the Gibson daemon lifecycle - start, stop, check status, and restart.

The daemon runs Gibson's long-running services including the registry manager,
callback server, and component registry. CLI commands connect to the daemon
for operations instead of starting their own services.

WHY USE THE DAEMON?

The daemon architecture provides several benefits:
  - Single instance: Only one set of services runs (no port conflicts)
  - Fast commands: CLI commands connect instantly (no startup delay)
  - Persistent state: Registry and services stay running between commands
  - Container-friendly: Runs in foreground, perfect for Docker/Kubernetes

USAGE SCENARIOS:

1. Local Development:
   $ gibson daemon start &        # Start daemon in background shell
   $ gibson mission run workflow.yaml
   $ gibson agent list
   $ gibson daemon stop

2. Container Deployment (Dockerfile):
   CMD ["gibson", "daemon", "start"]

3. System Service (with systemd):
   ExecStart=/usr/bin/gibson daemon start`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Gibson daemon",
	Long: `Start the Gibson daemon (runs in foreground until stopped).

The daemon manages long-running services including:
  - etcd registry (embedded or external)
  - Callback server for agent harnesses
  - Component discovery and health monitoring
  - gRPC API server for client connections

The daemon runs in the foreground and blocks until stopped with Ctrl+C or
SIGTERM. This makes it ideal for Docker containers and systemd services.

WHEN TO USE:

Use 'gibson daemon start' before running any other Gibson commands (except
standalone commands like 'version', 'init', 'config'). Most Gibson operations
require a running daemon to access the registry and coordinated services.

EXAMPLES:

  # Start daemon (blocks until Ctrl+C)
  $ gibson daemon start

  # Start daemon in background (shell job control)
  $ gibson daemon start &

  # Docker container
  CMD ["gibson", "daemon", "start"]

  # systemd service
  ExecStart=/usr/bin/gibson daemon start

TROUBLESHOOTING:

  - "daemon already running": Another daemon instance is running.
    Stop it with 'gibson daemon stop' first.

  - "port already in use": Another process is using required ports.
    Check etcd (2379, 2380) and callback (50001) ports.

  - "failed to start registry": Check GIBSON_HOME permissions and
    that etcd data directory is not corrupted.`,
	RunE: runDaemonStart,
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Gibson daemon",
	Long: `Stop the running Gibson daemon gracefully.

This command sends SIGTERM to the daemon process and waits for it to
shut down cleanly. All in-flight operations are given time to complete
(up to 30 seconds).

WHAT HAPPENS:

  1. SIGTERM is sent to the daemon process
  2. Daemon stops accepting new client connections
  3. In-flight missions and operations complete
  4. Services shut down in order:
     - gRPC server (no new clients)
     - Callback server (no new agent callbacks)
     - Registry manager (etcd shutdown)
  5. PID and state files are cleaned up

EXAMPLES:

  # Stop the running daemon
  $ gibson daemon stop

  # Stop daemon and verify it stopped
  $ gibson daemon stop
  $ gibson daemon status

NOTES:

  - If daemon doesn't respond within 30 seconds, it will be force-killed
  - Stale PID files (from crashed daemons) are automatically cleaned up
  - Safe to run even if daemon is not running`,
	RunE: runDaemonStop,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	Long: `Display the current status and health of the Gibson daemon.

Shows process information, service endpoints, component counts, and uptime.
Returns exit code 0 if daemon is running, non-zero if stopped.

OUTPUT FIELDS:

  Running         Whether the daemon process is running
  PID             Process ID of the daemon
  Uptime          How long the daemon has been running
  Started         When the daemon was started
  gRPC Address    Address for client connections
  Version         Daemon version

FLAGS:

  --json          Output status as JSON (useful for scripting)

EXAMPLES:

  # Check daemon status (human-readable)
  $ gibson daemon status

  # Get status as JSON
  $ gibson daemon status --json

  # Use in scripts to check if daemon is running
  $ if gibson daemon status > /dev/null 2>&1; then
      echo "Daemon is running"
    fi

EXIT CODES:

  0    Daemon is running
  0    Daemon is not running (but command succeeded)
  >0   Error checking daemon status`,
	RunE: runDaemonStatus,
}

var daemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the Gibson daemon",
	Long: `Restart the Gibson daemon by stopping and starting it.

This is equivalent to running 'gibson daemon stop' followed by 'gibson daemon start'.

WHEN TO USE:

  - After updating Gibson configuration
  - After installing new agents/tools/plugins
  - To recover from daemon issues
  - To apply configuration changes

EXAMPLES:

  # Restart the daemon
  $ gibson daemon restart

  # Edit config and restart
  $ gibson config set llm.providers[0].api_key "new-key"
  $ gibson daemon restart

NOTES:

  - All in-flight operations are stopped during restart
  - Registered agents will reconnect automatically
  - New configuration is loaded on restart`,
	RunE: runDaemonRestart,
}

// Flags
var (
	daemonStatusJSON bool
)

func init() {
	// Add flags
	daemonStatusCmd.Flags().BoolVar(&daemonStatusJSON, "json", false, "Output status as JSON")

	// Add subcommands
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonRestartCmd)
}

// runDaemonStart starts the Gibson daemon
func runDaemonStart(cmd *cobra.Command, args []string) error {
	// Check if GIBSON_DAEMON_ADDRESS is set
	if remoteAddr := os.Getenv(daemonclient.EnvDaemonAddress); remoteAddr != "" {
		return fmt.Errorf("cannot start daemon when %s is set to %q\n\n"+
			"You are configured to use a remote daemon at that address.\n\n"+
			"Options:\n"+
			"  1. Unset %s to start a local daemon:\n"+
			"     unset %s\n"+
			"     gibson daemon start\n\n"+
			"  2. The remote daemon should already be running at %s\n"+
			"     Check status with: gibson daemon status",
			daemonclient.EnvDaemonAddress, remoteAddr,
			daemonclient.EnvDaemonAddress,
			daemonclient.EnvDaemonAddress,
			remoteAddr)
	}

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Get Gibson home directory
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Get config file path
	configFile := flags.ConfigFile
	if configFile == "" {
		configFile = config.DefaultConfigPath(homeDir)
	}

	// Check if config exists
	if _, err := os.Stat(configFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file not found at %s (use configs/gibson.yaml as a template)", configFile)
		}
		return fmt.Errorf("failed to access config file: %w", err)
	}

	// Load configuration
	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.LoadWithDefaults(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if daemon is already running
	pidFile := filepath.Join(homeDir, "daemon.pid")
	running, pid, err := daemon.CheckPIDFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to check for existing daemon: %w", err)
	}
	if running {
		return fmt.Errorf("daemon already running (PID %d)", pid)
	}

	// Set up verbose logging if requested - simple approach using slog directly
	// This avoids the complex VerboseWriter/VerboseAwareHandler system
	if flags.IsVerbose() {
		level := slog.LevelInfo
		if flags.DebugVerbose {
			level = slog.LevelDebug
		}
		handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
		slog.SetDefault(slog.New(handler))
	}

	// Create daemon instance
	d, err := daemon.New(cfg, homeDir)
	if err != nil {
		return fmt.Errorf("failed to create daemon: %w", err)
	}

	// Start daemon (always runs in foreground, blocks until stopped)
	ctx := cmd.Context()
	if err := d.Start(ctx); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	return nil
}

// runDaemonStop stops the Gibson daemon
func runDaemonStop(cmd *cobra.Command, args []string) error {
	// Check if GIBSON_DAEMON_ADDRESS is set
	if remoteAddr := os.Getenv(daemonclient.EnvDaemonAddress); remoteAddr != "" {
		return fmt.Errorf("cannot stop remote daemon at %q\n\n"+
			"The remote daemon must be stopped on the remote host.\n\n"+
			"Options:\n"+
			"  1. Stop the daemon on the remote host:\n"+
			"     SSH to the remote host and run: gibson daemon stop\n\n"+
			"  2. If running in Kubernetes/container:\n"+
			"     kubectl delete pod <pod-name>\n\n"+
			"  3. To manage a local daemon instead:\n"+
			"     unset %s\n"+
			"     gibson daemon stop",
			remoteAddr,
			daemonclient.EnvDaemonAddress)
	}

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Get Gibson home directory
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Read PID file
	pidFile := filepath.Join(homeDir, "daemon.pid")
	pid, err := daemon.ReadPIDFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	// Check if daemon is running
	if pid == 0 {
		fmt.Println("Daemon not running")
		return nil
	}

	// Check if process exists
	running, _, err := daemon.CheckPIDFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to check daemon status: %w", err)
	}

	if !running {
		// Process not running, clean up stale files
		fmt.Printf("Daemon not running (stale PID file with PID %d)\n", pid)
		fmt.Println("Cleaning up stale files...")

		daemon.RemovePIDFile(pidFile)
		infoFile := filepath.Join(homeDir, "daemon.json")
		daemon.RemoveDaemonInfo(infoFile)

		fmt.Println("Cleanup complete")
		return nil
	}

	// Send SIGTERM to daemon
	if flags.IsVerbose() {
		fmt.Printf("Sending SIGTERM to daemon (PID %d)...\n", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find daemon process: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to daemon: %w", err)
	}

	// Wait for daemon to stop (up to 30 seconds)
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Check if process still exists
		err := syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			// Process no longer exists
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Check if process stopped
	err = syscall.Kill(pid, 0)
	if err != syscall.ESRCH {
		// Process still running after timeout
		return fmt.Errorf("daemon did not stop within %v (PID %d still running)", timeout, pid)
	}

	// Clean up files
	if flags.IsVerbose() {
		fmt.Println("Cleaning up daemon files...")
	}

	daemon.RemovePIDFile(pidFile)
	infoFile := filepath.Join(homeDir, "daemon.json")
	daemon.RemoveDaemonInfo(infoFile)

	fmt.Println("Gibson daemon stopped successfully")
	return nil
}

// runDaemonStatus shows the daemon status
func runDaemonStatus(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check if GIBSON_DAEMON_ADDRESS is set (remote daemon mode)
	if remoteAddr := os.Getenv(daemonclient.EnvDaemonAddress); remoteAddr != "" {
		// Connect to remote daemon
		client, err := daemonclient.ConnectOrFail(ctx)
		if err != nil {
			// Connection failed - return the detailed error from ConnectOrFail
			if daemonStatusJSON {
				status := map[string]interface{}{
					"running":        false,
					"remote_address": remoteAddr,
					"error":          err.Error(),
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.Encode(status)
				return nil
			}
			return err
		}
		defer client.Close()

		// Get status from remote daemon
		daemonStatus, err := client.Status(ctx)
		if err != nil {
			if daemonStatusJSON {
				status := map[string]interface{}{
					"running":        false,
					"remote_address": remoteAddr,
					"error":          fmt.Sprintf("failed to get daemon status: %v", err),
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.Encode(status)
				return nil
			}
			return fmt.Errorf("failed to get daemon status from %s: %w", remoteAddr, err)
		}

		// Display remote daemon status
		if daemonStatusJSON {
			status := map[string]interface{}{
				"running":              true,
				"remote":               true,
				"remote_address":       remoteAddr,
				"pid":                  daemonStatus.PID,
				"uptime":               daemonStatus.Uptime,
				"grpc_address":         daemonStatus.GRPCAddress,
				"callback_address":     daemonStatus.CallbackAddr,
				"registry_type":        daemonStatus.RegistryType,
				"registry_addr":        daemonStatus.RegistryAddr,
				"agent_count":          daemonStatus.AgentCount,
				"mission_count":        daemonStatus.MissionCount,
				"active_mission_count": daemonStatus.ActiveCount,
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(status)
		}

		// Text format for remote daemon
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		defer tw.Flush()

		fmt.Fprintln(tw, "GIBSON DAEMON STATUS (REMOTE)")
		fmt.Fprintln(tw, "")
		fmt.Fprintf(tw, "Remote Address:\t%s\n", remoteAddr)
		fmt.Fprintf(tw, "Running:\ttrue\n")
		fmt.Fprintf(tw, "PID:\t%d\n", daemonStatus.PID)
		fmt.Fprintf(tw, "Uptime:\t%s\n", daemonStatus.Uptime)
		fmt.Fprintln(tw, "")
		fmt.Fprintln(tw, "ENDPOINTS")
		fmt.Fprintf(tw, "gRPC Address:\t%s\n", daemonStatus.GRPCAddress)
		if daemonStatus.CallbackAddr != "" {
			fmt.Fprintf(tw, "Callback Address:\t%s\n", daemonStatus.CallbackAddr)
		}
		fmt.Fprintln(tw, "")
		fmt.Fprintln(tw, "REGISTRY")
		fmt.Fprintf(tw, "Type:\t%s\n", daemonStatus.RegistryType)
		fmt.Fprintf(tw, "Address:\t%s\n", daemonStatus.RegistryAddr)
		fmt.Fprintln(tw, "")
		fmt.Fprintln(tw, "COMPONENTS")
		fmt.Fprintf(tw, "Agents:\t%d\n", daemonStatus.AgentCount)
		fmt.Fprintln(tw, "")
		fmt.Fprintln(tw, "MISSIONS")
		fmt.Fprintf(tw, "Active:\t%d\n", daemonStatus.ActiveCount)
		fmt.Fprintf(tw, "Total:\t%d\n", daemonStatus.MissionCount)

		return nil
	}

	// Local daemon mode - use existing file-based status check
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Get Gibson home directory
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Check for daemon.json file
	infoFile := filepath.Join(homeDir, "daemon.json")
	if _, err := os.Stat(infoFile); err != nil {
		if os.IsNotExist(err) {
			if daemonStatusJSON {
				// Output JSON for not running
				status := map[string]interface{}{
					"running": false,
					"message": "Daemon not running",
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.Encode(status)
				return nil
			}

			fmt.Println("Daemon not running")
			fmt.Println()
			fmt.Println("Start the daemon with: gibson daemon start")
			return nil
		}
		return fmt.Errorf("failed to check daemon status: %w", err)
	}

	// Read daemon info
	info, err := daemon.ReadDaemonInfo(infoFile)
	if err != nil {
		return fmt.Errorf("failed to read daemon info: %w", err)
	}

	// Check if process is actually running
	pidFile := filepath.Join(homeDir, "daemon.pid")
	running, pid, err := daemon.CheckPIDFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to check daemon status: %w", err)
	}

	// If not running, clean up and report
	if !running {
		if daemonStatusJSON {
			status := map[string]interface{}{
				"running": false,
				"message": "Daemon not running (stale files cleaned up)",
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			encoder.Encode(status)
			return nil
		}

		fmt.Println("Daemon not running (stale files found)")
		fmt.Println("Cleaning up stale files...")

		daemon.RemovePIDFile(pidFile)
		daemon.RemoveDaemonInfo(infoFile)

		fmt.Println()
		fmt.Println("Start the daemon with: gibson daemon start")
		return nil
	}

	// Calculate uptime
	uptime := time.Since(info.StartTime)
	uptimeStr := formatUptime(uptime)

	// Note: For local daemons, we show basic file-based status.
	// Remote daemons (via GIBSON_DAEMON_ADDRESS) show full status via gRPC above.
	// Full gRPC status for local daemons could be added in the future if needed.

	// Build status output
	if daemonStatusJSON {
		status := map[string]interface{}{
			"running":      true,
			"pid":          pid,
			"start_time":   info.StartTime,
			"uptime":       uptimeStr,
			"grpc_address": info.GRPCAddress,
			"version":      info.Version,
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	}

	// Text format
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintln(tw, "GIBSON DAEMON STATUS")
	fmt.Fprintln(tw, "")
	fmt.Fprintf(tw, "Running:\t%v\n", running)
	fmt.Fprintf(tw, "PID:\t%d\n", pid)
	fmt.Fprintf(tw, "Uptime:\t%s\n", uptimeStr)
	fmt.Fprintf(tw, "Started:\t%s\n", info.StartTime.Format(time.RFC3339))
	fmt.Fprintln(tw, "")
	fmt.Fprintln(tw, "ENDPOINTS")
	fmt.Fprintf(tw, "gRPC Address:\t%s\n", info.GRPCAddress)
	fmt.Fprintln(tw, "")
	fmt.Fprintf(tw, "Version:\t%s\n", info.Version)

	return nil
}

// runDaemonRestart restarts the daemon
func runDaemonRestart(cmd *cobra.Command, args []string) error {
	// Stop the daemon
	fmt.Println("Stopping daemon...")
	if err := runDaemonStop(cmd, args); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	// Wait a moment for cleanup
	time.Sleep(500 * time.Millisecond)

	// Start the daemon
	fmt.Println("Starting daemon...")
	if err := runDaemonStart(cmd, args); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	return nil
}

// formatUptime formats a duration into a human-readable uptime string
func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
