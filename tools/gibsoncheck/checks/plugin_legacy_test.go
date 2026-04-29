package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zero-day-ai/gibson/tools/gibsoncheck/checks"
)

// TestPluginLegacy_PluginkitViolation verifies that a package within the
// sdk scope that imports the deleted sdk/pluginkit path is flagged.
func TestPluginLegacy_PluginkitViolation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.PluginLegacyAnalyzer,
		"github.com/zero-day-ai/sdk/pluginlegacyviolation")
}

// TestPluginLegacy_NewSDKPluginClean verifies that a package importing the
// new sdk/plugin package and using only the Serve() entry point produces NO
// diagnostic from the pluginlegacy analyzer.
func TestPluginLegacy_NewSDKPluginClean(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments in the fixture — zero diagnostics expected.
	analysistest.Run(t, testdata, checks.PluginLegacyAnalyzer,
		"github.com/zero-day-ai/sdk/pluginlegacyclean")
}

// TestPluginLegacy_OldSymbolsViolation verifies that a package importing
// sdk/plugin and referencing deleted symbol names (New, NewConfig,
// ToDescriptor) is flagged by rule #3.
func TestPluginLegacy_OldSymbolsViolation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.PluginLegacyAnalyzer,
		"github.com/zero-day-ai/sdk/pluginlegacyoldsymbols")
}
