package main

import (
	"github.com/spf13/cobra"

	"github.com/zero-day-ai/gibson/internal/config"
	initpkg "github.com/zero-day-ai/gibson/internal/init"
)

var (
	initNonInteractive bool
	initForce          bool
	initHomeDir        string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Gibson configuration and database",
	Long: `Initialize the Gibson framework by creating:
- Configuration directory structure
- Default configuration file
- Encryption key for credential storage
- Redis connection validation`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initNonInteractive, "non-interactive", false, "Run without prompts (for CI/CD)")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing configuration")
	initCmd.Flags().StringVar(&initHomeDir, "home", "", "Custom home directory (default: ~/.gibson)")
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Determine home directory
	homeDir := initHomeDir
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	cmd.Printf("Initializing Gibson in %s...\n", homeDir)

	// Create initializer with default dependencies
	initializer := initpkg.NewDefaultInitializer()

	// Run initialization
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: initNonInteractive,
		Force:          initForce,
	}

	result, err := initializer.Initialize(ctx, opts)
	if err != nil {
		cmd.PrintErrln("Initialization failed:", err)
		return err
	}

	// Display results
	displayInitResult(cmd, result)

	return nil
}

func displayInitResult(cmd *cobra.Command, result *initpkg.InitResult) {
	cmd.Println("\nGibson initialized successfully!")
	cmd.Printf("  Home directory: %s\n", result.HomeDir)
	cmd.Printf("  Directories created: %d\n", len(result.DirsCreated))
	cmd.Printf("  Config created: %v\n", result.ConfigCreated)
	cmd.Printf("  Encryption key created: %v\n", result.KeyCreated)

	if len(result.Warnings) > 0 {
		cmd.Println("\nWarnings:")
		for _, w := range result.Warnings {
			cmd.Printf("  - %s\n", w)
		}
	}
}
