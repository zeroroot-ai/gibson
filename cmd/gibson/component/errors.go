package component

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/component"
)

// FormatInstallError formats a component error with full build context.
// Extracts stdout, stderr, build command, and work dir from ComponentError.Context.
// Returns a simplified error for the final return.
func FormatInstallError(cmd *cobra.Command, err error) error {
	// Check if we can extract more details from the error
	var compErr *component.ComponentError
	if errors.As(err, &compErr) {
		// Always show basic error info
		cmd.PrintErrf("Error: %s\n", err)

		// Provide helpful suggestions based on error code
		if compErr.Code == component.ErrCodeManifestNotFound {
			cmd.PrintErrf("\nHint: If this is a mono-repo with multiple components, use 'install-all' instead:\n")
			cmd.PrintErrf("  gibson <type> install-all <repo-url>\n")
			cmd.PrintErrf("\nOr specify a subdirectory with a # fragment:\n")
			cmd.PrintErrf("  gibson <type> install <repo-url>#path/to/component\n")
		}

		// Show build context if available
		if compErr.Context != nil {
			if buildCmd, ok := compErr.Context["build_command"].(string); ok {
				cmd.PrintErrf("\nBuild command: %s\n", buildCmd)
			}
			if workDir, ok := compErr.Context["work_dir"].(string); ok {
				cmd.PrintErrf("Working directory: %s\n", workDir)
			}

			// Always show stdout/stderr on failure - this is the key diagnostic info
			if stdout, ok := compErr.Context["stdout"].(string); ok && stdout != "" {
				cmd.PrintErrf("\n--- Build stdout ---\n%s\n", stdout)
			}
			if stderr, ok := compErr.Context["stderr"].(string); ok && stderr != "" {
				cmd.PrintErrf("\n--- Build stderr ---\n%s\n", stderr)
			}
		}
		return fmt.Errorf("installation failed")
	}
	return fmt.Errorf("installation failed: %w", err)
}

