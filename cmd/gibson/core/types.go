package core

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/state"
)

// CommandContext holds all dependencies and context needed for command execution.
// This provides a unified context for both CLI and TUI command handlers.
type CommandContext struct {
	// Ctx is the context for cancellation and timeouts
	Ctx context.Context

	// StateClient provides access to Redis for data persistence
	StateClient *state.StateClient

	// ComponentStore provides access to component data from etcd
	ComponentStore component.ComponentStore

	// TargetDAO provides access to target data from Redis
	TargetDAO database.TargetDAO

	// HomeDir is the Gibson home directory path (e.g., ~/.gibson)
	HomeDir string

	// Installer provides component installation functionality
	Installer component.Installer

	// MissionStore provides access to mission data (optional, may be nil)
	MissionStore mission.MissionStore

	// MissionRunStore provides access to mission run data (optional, may be nil)
	MissionRunStore mission.MissionRunStore

	// RegManager provides access to the component registry for service discovery
	RegManager *registry.Manager

	// ConfigFile is the path to the Gibson configuration file
	ConfigFile string
}

// Close cleans up resources held by the CommandContext.
// It should be called when the context is no longer needed.
func (cc *CommandContext) Close() error {
	if cc.StateClient != nil {
		return cc.StateClient.Close()
	}
	return nil
}

// CommandResult represents the result of a command execution.
// It provides both structured data and human-readable output.
type CommandResult struct {
	// Success indicates whether the operation succeeded
	Success bool

	// Data contains structured output that can be used programmatically
	Data interface{}

	// Message contains a human-readable message describing the result
	Message string

	// Error contains any error that occurred during execution
	Error error

	// Duration tracks how long the operation took
	Duration time.Duration
}

// InstallOptions holds options for component installation commands.
type InstallOptions struct {
	// Branch specifies the Git branch to install from
	Branch string

	// Tag specifies the Git tag to install from
	Tag string

	// Commit specifies the Git commit to install from
	Commit string

	// Force allows reinstallation even if component exists
	Force bool

	// SkipBuild skips the build step during installation
	SkipBuild bool

	// SkipRegister skips registering the component after installation
	SkipRegister bool

	// Verbose enables verbose output during installation
	Verbose bool
}

// UpdateOptions holds options for component update commands.
type UpdateOptions struct {
	// Restart automatically restarts the component after update
	Restart bool

	// SkipBuild skips the build step during update
	SkipBuild bool

	// Verbose enables verbose output during update
	Verbose bool
}

// UninstallOptions holds options for component uninstall commands.
type UninstallOptions struct {
	// Force allows uninstallation even if component is running
	Force bool
}

// StatusOptions holds options for component status commands.
type StatusOptions struct {
	// Watch enables continuous monitoring mode
	Watch bool

	// Interval specifies the refresh interval for watch mode (default 2s, min 1s)
	Interval time.Duration

	// ErrorCount specifies the number of errors to display (default 5)
	ErrorCount int

	// JSON enables JSON output format
	JSON bool
}

// LogsOptions holds options for component logs commands.
type LogsOptions struct {
	// Follow enables continuous log output (like tail -f)
	Follow bool

	// Lines specifies the number of lines to show (default 50)
	Lines int
}

// ListOptions holds options for component list commands.
type ListOptions struct {
	// Local shows only local components
	Local bool

	// Remote shows only remote components
	Remote bool
}
