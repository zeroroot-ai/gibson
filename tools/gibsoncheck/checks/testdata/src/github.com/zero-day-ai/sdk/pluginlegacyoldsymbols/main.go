// Package pluginlegacyoldsymbols is an analysistest fixture for the
// pluginlegacy analyzer (plugin-runtime Requirement 11.6).
//
// This package imports sdk/plugin and references the old deleted symbol
// names (New, NewConfig, ToDescriptor), which triggers rule #3.
package pluginlegacyoldsymbols

import (
	"context"

	"github.com/zeroroot-ai/sdk/plugin"
)

// badUsage references the deleted Plugin interface symbol names via the
// plugin package qualifier. Each should produce a diagnostic.
func badUsage(ctx context.Context) {
	_ = plugin.New        // want `reference to deleted symbol "plugin.New"`
	_ = plugin.NewConfig  // want `reference to deleted symbol "plugin.NewConfig"`
	_ = plugin.ToDescriptor // want `reference to deleted symbol "plugin.ToDescriptor"`
}
