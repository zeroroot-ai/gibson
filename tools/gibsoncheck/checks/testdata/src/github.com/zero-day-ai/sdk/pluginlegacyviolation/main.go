// Package pluginlegacyviolation is an analysistest fixture for the
// pluginlegacy analyzer (plugin-runtime Requirement 11.6).
//
// This package imports the deleted sdk/pluginkit package, which triggers
// rule #1 of the pluginlegacy analyzer.
package pluginlegacyviolation

import (
	_ "github.com/zeroroot-ai/sdk/pluginkit" // want `forbidden import "github.com/zeroroot-ai/sdk/pluginkit"`
)
