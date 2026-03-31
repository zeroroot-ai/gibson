package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/component"
	"github.com/zero-day-ai/gibson/cmd/gibson/mode"
	"github.com/zero-day-ai/gibson/internal/config"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
	"github.com/zero-day-ai/gibson/internal/harness"
)

// Global callback manager for cleanup (legacy - only used if daemon owns callback)
var globalCallbackManager *harness.CallbackManager

var rootCmd = &cobra.Command{
	Use:   "gibson",
	Short: "Gibson - Autonomous LLM Red-Teaming Framework",
	Long: `Gibson is an autonomous AI security testing platform for
red-teaming LLM systems, RAG pipelines, and AI agents.`,
	PersistentPreRunE:  loadConfig,
	PersistentPostRunE: shutdown,
	SilenceUsage:       true,
	SilenceErrors:      true,
	// No RunE - shows help by default when no subcommand is given
}

// Execute runs the root command with signal handling
func Execute(ctx context.Context) error {
	// Create context with signal handling
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return rootCmd.ExecuteContext(ctx)
}

// loadConfig is called before any command runs to load configuration and initialize the registry
func loadConfig(cmd *cobra.Command, args []string) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return err
	}

	// Determine home directory
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Determine config file path
	configFile := flags.ConfigFile
	if configFile == "" {
		configFile = config.DefaultConfigPath(homeDir)
	}

	// Get command mode to determine initialization strategy
	cmdMode := mode.GetMode(cmd.CommandPath())

	// Standalone mode: just load config file, no services
	if cmdMode == mode.Standalone {
		// For standalone commands, we may not even need the config
		// But load it if it exists for consistency
		if _, err := os.Stat(configFile); err == nil {
			loader := config.NewConfigLoader(config.NewValidator())
			if _, err := loader.LoadWithDefaults(configFile); err != nil {
				// Don't fail for standalone commands
				if flags.IsVerbose() {
					cmd.PrintErrf("Warning: failed to load config: %v\n", err)
				}
			}
		}
		return nil
	}

	// Daemon mode: daemon commands handle their own initialization
	// Don't start any services here - let daemon.go handle it
	if cmdMode == mode.Daemon {
		return nil
	}

	// Client mode: connect to existing daemon
	if cmdMode == mode.Client {
		// Connect to daemon using the client library
		client, err := daemonclient.ConnectOrFail(cmd.Context())
		if err != nil {
			return err
		}

		// Store client in context for subcommands
		ctx := component.WithDaemonClient(cmd.Context(), client)
		cmd.SetContext(ctx)

		if flags.IsVerbose() {
			cmd.PrintErrf("Connected to daemon\n")
		}

		return nil
	}

	// This should never happen (all modes should be handled above)
	return fmt.Errorf("unknown command mode: %v", cmdMode)
}

// shutdown gracefully shuts down resources when Gibson exits.
// The shutdown behavior depends on the command mode:
// - Daemon mode: stop registry and callback manager (owned by daemon)
// - Client mode: close daemon client connection
// - Standalone mode: no cleanup needed
func shutdown(cmd *cobra.Command, args []string) error {
	// Get command mode to determine cleanup strategy
	cmdMode := mode.GetMode(cmd.CommandPath())

	// For daemon mode, shut down services
	if cmdMode == mode.Daemon {
		// Stop callback manager if we own it
		if globalCallbackManager != nil {
			if globalFlags.IsVerbose() {
				cmd.PrintErrf("Stopping callback server...\n")
			}
			globalCallbackManager.Stop()
			globalCallbackManager = nil
		}
	}

	// For client mode, close daemon client connection
	if cmdMode == mode.Client {
		if client := component.GetDaemonClient(cmd.Context()); client != nil {
			// Type assert to *daemonclient.Client
			if dc, ok := client.(*daemonclient.Client); ok {
				if err := dc.Close(); err != nil {
					// Log error but don't fail - we're shutting down anyway
					if globalFlags.IsVerbose() {
						cmd.PrintErrf("Warning: failed to close daemon client: %v\n", err)
					}
				}
			}
		}
	}

	// Standalone mode: no cleanup needed

	return nil
}

func init() {
	// Register global flags
	RegisterGlobalFlags(rootCmd)

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(targetCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(toolCmd)
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(missionCmd)
	rootCmd.AddCommand(findingCmd)
	rootCmd.AddCommand(attackCmd)
	rootCmd.AddCommand(payloadCmd)
	rootCmd.AddCommand(knowledgeCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(checkpointCmd)
	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(daemonCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("Gibson v0.1.0")
	},
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for Gibson.

To load completions:

Bash:

  $ source <(gibson completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ gibson completion bash > /etc/bash_completion.d/gibson
  # macOS:
  $ gibson completion bash > $(brew --prefix)/etc/bash_completion.d/gibson

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ gibson completion zsh > "${fpath[1]}/_gibson"

  # You will need to start a new shell for this setup to take effect.

Fish:

  $ gibson completion fish | source

  # To load completions for each session, execute once:
  $ gibson completion fish > ~/.config/fish/completions/gibson.fish

PowerShell:

  PS> gibson completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> gibson completion powershell > gibson.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			_ = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}
