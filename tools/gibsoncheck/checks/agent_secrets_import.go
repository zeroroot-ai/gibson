package checks

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// AgentSecretsImportAnalyzer flags any file in the agent or tool SDK packages
// that imports github.com/zero-day-ai/sdk/secrets or any of its subpackages.
//
// Enforced package-path prefixes (scope):
//
//   - github.com/zero-day-ai/sdk/agent
//   - github.com/zero-day-ai/sdk/tool
//   - github.com/zero-day-ai/sdk/toolerr
//   - github.com/zero-day-ai/sdk/toolrunner
//
// Exemptions:
//
//   - github.com/zero-day-ai/sdk/plugin/ — plugins legitimately consume the
//     broker (per Spec 2: plugin-runtime).
//   - Any package whose path contains "/testdata/" — analysistest fixtures may
//     import the secrets stub to act as a controlled violation for other tests.
//   - Any package whose path contains "/cmd/gibsoncheck/" — the checker itself
//     and its test infrastructure are not subject to the rule.
//
// The failure message steers the developer to the correct pattern:
//
//	agent and tool SDKs cannot import the broker; dispatch a tool that uses a plugin.
//
// Spec: non-plugin-secret-isolation Requirement 2.
var AgentSecretsImportAnalyzer = &analysis.Analyzer{
	Name: "agentsecretsimport",
	Doc:  "flag imports of github.com/zero-day-ai/sdk/secrets from agent or tool SDK packages (non-plugin-secret-isolation Req 2)",
	Run:  runAgentSecretsImport,
}

// agentToolScopePrefixes lists the package-path prefixes that bring a file
// into scope for the agentsecretsimport check.
var agentToolScopePrefixes = []string{
	"github.com/zero-day-ai/sdk/agent",
	"github.com/zero-day-ai/sdk/tool",
	"github.com/zero-day-ai/sdk/toolerr",
	"github.com/zero-day-ai/sdk/toolrunner",
}

// agentSecretsImportExemptSubstrings lists package-path substrings that
// remove a package from scope even if a scope prefix matched.
var agentSecretsImportExemptSubstrings = []string{
	"github.com/zero-day-ai/sdk/plugin/",  // plugins legitimately use the broker
	"/testdata/",                           // analysistest fixtures
	"/cmd/gibsoncheck/",                    // the checker itself
}

// brokerImportPrefix is the import path prefix that is disallowed.
const brokerImportPrefix = "github.com/zero-day-ai/sdk/secrets"

func runAgentSecretsImport(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// Only analyze packages in the defined scope.
	inScope := false
	for _, prefix := range agentToolScopePrefixes {
		if strings.HasPrefix(pkgPath, prefix) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil, nil
	}

	// Apply exemptions.
	for _, exempt := range agentSecretsImportExemptSubstrings {
		if strings.Contains(pkgPath, exempt) {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			// Flag any import of sdk/secrets or a subpackage of it.
			if path == brokerImportPrefix || strings.HasPrefix(path, brokerImportPrefix+"/") {
				pass.Reportf(imp.Pos(),
					"forbidden import %q in %q: agent and tool SDKs cannot import the broker; dispatch a tool that uses a plugin (non-plugin-secret-isolation Req 2)",
					path, pkgPath)
			}
		}
	}

	return nil, nil
}
