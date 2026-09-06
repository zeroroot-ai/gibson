// Package toolsecretsviolation is an analysistest fixture for the
// agentsecretsimport analyzer (non-plugin-secret-isolation Requirement 2).
//
// This package lives under github.com/zeroroot-ai/sdk/tool/ and imports
// github.com/zeroroot-ai/sdk/secrets, which triggers the rule. Tool SDK
// packages must not import the broker.
package toolsecretsviolation

import (
	_ "github.com/zeroroot-ai/sdk/secrets" // want `forbidden import "github.com/zeroroot-ai/sdk/secrets"`
)
