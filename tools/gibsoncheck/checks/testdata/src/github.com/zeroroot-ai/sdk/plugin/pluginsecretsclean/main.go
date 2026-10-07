// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pluginsecretsclean is an analysistest fixture for the
// agentsecretsimport analyzer (non-plugin-secret-isolation Requirement 2).
//
// This package lives under github.com/zeroroot-ai/sdk/plugin/, which is
// exempt from the rule — plugins legitimately consume the secrets broker
// (per Spec 2: plugin-runtime). No diagnostic should be produced here.
package pluginsecretsclean

import (
	// Plugins may import the broker. No diagnostic expected.
	_ "github.com/zeroroot-ai/sdk/secrets"
)
