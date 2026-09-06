// Package pluginkit is a stub for analysistest fixtures used by the
// pluginlegacy analyzer test. The real pluginkit package was deleted by the
// plugin-runtime spec (Spec 2, Phase 1).
package pluginkit

import "context"

// ContextWithConfig is a stub for the deleted pluginkit.ContextWithConfig.
func ContextWithConfig(ctx context.Context, cfg map[string]any) context.Context {
	return ctx
}
