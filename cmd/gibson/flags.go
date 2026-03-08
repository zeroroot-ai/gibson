package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/config"
)

// OutputFormat represents the output format for CLI commands
type OutputFormat string

const (
	// FormatText is human-readable text output
	FormatText OutputFormat = "text"
	// FormatJSON is structured JSON output
	FormatJSON OutputFormat = "json"
)

// GlobalFlags holds global flags available to all commands
type GlobalFlags struct {
	Verbose      bool
	VeryVerbose  bool
	DebugVerbose bool
	Quiet        bool
	OutputFormat string
	ConfigFile   string
	HomeDir      string
}

var globalFlags = &GlobalFlags{}

// RegisterGlobalFlags registers persistent flags on the root command
func RegisterGlobalFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&globalFlags.Verbose, "verbose", "v", false, "Enable verbose output (-v): shows major operations (LLM requests, tool calls, agent lifecycle)")
	cmd.PersistentFlags().BoolVarP(&globalFlags.VeryVerbose, "very-verbose", "", false, "Enable very verbose output (-vv): adds detailed operation data (token counts, durations, parameters)")
	cmd.PersistentFlags().BoolVarP(&globalFlags.DebugVerbose, "debug-verbose", "", false, "Enable debug output (-vvv): shows all internal events (memory operations, component health, system events)")
	cmd.PersistentFlags().BoolVarP(&globalFlags.Quiet, "quiet", "q", false, "Suppress non-essential output")
	cmd.PersistentFlags().StringVarP(&globalFlags.OutputFormat, "output", "o", "text", "Output format (text|json)")
	cmd.PersistentFlags().StringVar(&globalFlags.ConfigFile, "config", "", "Path to config file (default: $GIBSON_HOME/config.yaml)")
	cmd.PersistentFlags().StringVar(&globalFlags.HomeDir, "home", "", "Gibson home directory (default: ~/.gibson)")
}

// ParseGlobalFlags parses and validates global flags from the command
func ParseGlobalFlags(cmd *cobra.Command) (*GlobalFlags, error) {
	// Validate output format
	format := globalFlags.OutputFormat
	if format != string(FormatText) && format != string(FormatJSON) {
		return nil, cmd.Help()
	}

	// Validate that verbose and quiet are not both set
	if globalFlags.Verbose && globalFlags.Quiet {
		cmd.PrintErrln("Error: --verbose and --quiet cannot be used together")
		return nil, cmd.Help()
	}

	return globalFlags, nil
}

// IsVerbose returns true if verbose mode is enabled
func (f *GlobalFlags) IsVerbose() bool {
	return f.Verbose && !f.Quiet
}

// IsQuiet returns true if quiet mode is enabled
func (f *GlobalFlags) IsQuiet() bool {
	return f.Quiet
}

// VerbosityLevel returns the appropriate VerboseLevel based on the flags.
// The hierarchy is:
//   - Quiet mode: LevelNone
//   - Debug (-vvv or --debug-verbose): LevelDebug (3)
//   - Very verbose (-vv or --very-verbose): LevelVerbose (2)
//   - Verbose (-v or --verbose): LevelBasic (1)
//   - Default: LevelNone (0)
func (f *GlobalFlags) VerbosityLevel() internal.VerboseLevel {
	// Quiet mode disables all verbose output
	if f.Quiet {
		return internal.LevelNone
	}

	// Debug takes highest precedence
	if f.DebugVerbose {
		return internal.LevelDebug
	}

	// Very verbose is next
	if f.VeryVerbose {
		return internal.LevelVerbose
	}

	// Regular verbose
	if f.Verbose {
		return internal.LevelBasic
	}

	// Default: no verbose output
	return internal.LevelNone
}

// loadGlobalConfig loads the Gibson configuration using global flags.
// This is a convenience function for commands that need config access.
func loadGlobalConfig() (*config.Config, error) {
	homeDir := globalFlags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	configFile := globalFlags.ConfigFile
	if configFile == "" {
		configFile = config.DefaultConfigPath(homeDir)
	}

	loader := config.NewConfigLoader(config.NewValidator())
	return loader.LoadWithDefaults(configFile)
}
