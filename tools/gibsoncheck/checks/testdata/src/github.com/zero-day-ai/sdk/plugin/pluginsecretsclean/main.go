// Package pluginsecretsclean is an analysistest fixture for the
// agentsecretsimport analyzer (non-plugin-secret-isolation Requirement 2).
//
// This package lives under github.com/zero-day-ai/sdk/plugin/, which is
// exempt from the rule — plugins legitimately consume the secrets broker
// (per Spec 2: plugin-runtime). No diagnostic should be produced here.
package pluginsecretsclean

import (
	// Plugins may import the broker. No diagnostic expected.
	_ "github.com/zero-day-ai/sdk/secrets"
)
