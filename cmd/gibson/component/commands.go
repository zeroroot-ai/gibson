package component

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/component"
)

// Config holds configuration for command generation.
type Config struct {
	Kind          component.ComponentKind
	DisplayName   string // "tool", "agent", "plugin"
	DisplayPlural string // "tools", "agents", "plugins"
}

// InstallFlags holds flags for install and install-all commands.
type InstallFlags struct {
	Branch       string
	Tag          string
	Force        bool
	SkipBuild    bool
	SkipRegister bool
	Verbose      bool
}

// UpdateFlags holds flags for update commands.
type UpdateFlags struct {
	Restart   bool
	SkipBuild bool
	Verbose   bool
}

// UninstallFlags holds flags for uninstall commands.
type UninstallFlags struct {
	Force bool
}

// StatusFlags holds flags for status commands.
type StatusFlags struct {
	Watch      bool          // Enable continuous monitoring
	Interval   time.Duration // Refresh interval for watch mode (default 2s, min 1s)
	ErrorCount int           // Number of errors to display (default 5)
	JSON       bool          // Output in JSON format
}

// LogsFlags holds flags for logs commands.
type LogsFlags struct {
	Follow     bool     // Follow log output (like tail -f)
	Lines      int      // Number of lines to show (default 50)
	All        bool     // View logs from all components
	Components []string // View logs from specific components
}

// ListFlags holds flags for list commands.
type ListFlags struct {
	Local  bool // Show only local components
	Remote bool // Show only remote components
}

// ComponentCommands holds all the generated subcommands for a component type.
type ComponentCommands struct {
	List       *cobra.Command
	Install    *cobra.Command
	InstallAll *cobra.Command
	Uninstall  *cobra.Command
	Update     *cobra.Command
	Show       *cobra.Command
	Build      *cobra.Command
	Start      *cobra.Command
	Stop       *cobra.Command
	Status     *cobra.Command
	Logs       *cobra.Command
}

// RegisterCommands creates and registers all common subcommands to the parent command.
// Returns ComponentCommands so callers can access individual commands if needed.
func RegisterCommands(parent *cobra.Command, cfg Config) *ComponentCommands {
	// Create all commands
	commands := NewCommands(cfg)

	// Register all commands to parent
	parent.AddCommand(commands.List)
	parent.AddCommand(commands.Install)
	parent.AddCommand(commands.InstallAll)
	parent.AddCommand(commands.Uninstall)
	parent.AddCommand(commands.Update)
	parent.AddCommand(commands.Show)
	parent.AddCommand(commands.Build)
	parent.AddCommand(commands.Start)
	parent.AddCommand(commands.Stop)
	parent.AddCommand(commands.Status)
	parent.AddCommand(commands.Logs)

	return commands
}

// NewCommands creates ComponentCommands without registering them.
// Useful for testing or custom registration.
func NewCommands(cfg Config) *ComponentCommands {
	// Create flag structs
	installFlags := &InstallFlags{}
	updateFlags := &UpdateFlags{}
	uninstallFlags := &UninstallFlags{}
	statusFlags := &StatusFlags{}
	listFlags := &ListFlags{}
	logsFlags := &LogsFlags{}

	// Create all commands
	return &ComponentCommands{
		List:       newListCommand(cfg, listFlags),
		Install:    newInstallCommand(cfg, installFlags),
		InstallAll: newInstallAllCommand(cfg, installFlags),
		Uninstall:  newUninstallCommand(cfg, uninstallFlags),
		Update:     newUpdateCommand(cfg, updateFlags),
		Show:       newShowCommand(cfg),
		Build:      newBuildCommand(cfg),
		Start:      newStartCommand(cfg),
		Stop:       newStopCommand(cfg),
		Status:     newStatusCommand(cfg, statusFlags),
		Logs:       newLogsCommand(cfg, logsFlags),
	}
}
