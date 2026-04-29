// Package pluginlegacyclean is an analysistest fixture for the pluginlegacy
// analyzer (plugin-runtime Requirement 11.6).
//
// This package imports the new sdk/plugin package and uses only the new
// Serve() entry point — none of the deleted symbol names. It should produce
// NO diagnostic from the pluginlegacy analyzer.
package pluginlegacyclean

import (
	"context"

	"github.com/zero-day-ai/sdk/plugin"
)

// RunPlugin demonstrates use of the new plugin.Serve entry point, which is
// NOT in the deleted symbol list and must not be flagged.
func RunPlugin(ctx context.Context) error {
	return plugin.Serve(ctx)
}
