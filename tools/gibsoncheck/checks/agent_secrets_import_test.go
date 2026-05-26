package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestAgentSecretsImport_AgentViolation verifies that a package under
// github.com/zeroroot-ai/sdk/agent/ that imports sdk/secrets is flagged.
func TestAgentSecretsImport_AgentViolation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.AgentSecretsImportAnalyzer,
		"github.com/zeroroot-ai/sdk/agent/agentsecretsviolation")
}

// TestAgentSecretsImport_ToolViolation verifies that a package under
// github.com/zeroroot-ai/sdk/tool/ that imports sdk/secrets is flagged.
func TestAgentSecretsImport_ToolViolation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.AgentSecretsImportAnalyzer,
		"github.com/zeroroot-ai/sdk/tool/toolsecretsviolation")
}

// TestAgentSecretsImport_AgentClean verifies that a package under
// github.com/zeroroot-ai/sdk/agent/ that does NOT import sdk/secrets
// produces no diagnostic.
func TestAgentSecretsImport_AgentClean(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments in the fixture — zero diagnostics expected.
	analysistest.Run(t, testdata, checks.AgentSecretsImportAnalyzer,
		"github.com/zeroroot-ai/sdk/agent/agentsecretsclean")
}

// TestAgentSecretsImport_PluginExempt verifies that a package under
// github.com/zeroroot-ai/sdk/plugin/ that imports sdk/secrets is NOT
// flagged — plugins legitimately consume the broker.
func TestAgentSecretsImport_PluginExempt(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments — plugins are exempt; zero diagnostics expected.
	analysistest.Run(t, testdata, checks.AgentSecretsImportAnalyzer,
		"github.com/zeroroot-ai/sdk/plugin/pluginsecretsclean")
}
