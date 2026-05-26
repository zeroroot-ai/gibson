// Package agentsecretsviolation is an analysistest fixture for the
// agentsecretsimport analyzer (non-plugin-secret-isolation Requirement 2).
//
// This package lives under github.com/zeroroot-ai/sdk/agent/ and imports
// github.com/zeroroot-ai/sdk/secrets, which triggers the rule. Agents must
// not import the broker; they dispatch a tool that uses a plugin instead.
package agentsecretsviolation

import (
	_ "github.com/zeroroot-ai/sdk/secrets" // want `forbidden import "github.com/zeroroot-ai/sdk/secrets"`
)
