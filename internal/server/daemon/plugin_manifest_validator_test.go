// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// Tests for pluginManifestValidator after the legacy connector-runtime removal
// (ADR-0065): spec.runtime is process | pod | setec only, there is no connector
// branch, and a valid plugin manifest round-trips into a ValidatedManifest
// carrying its RuntimeMode. Covers the runtime and methods validation paths.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/server/admin"
)

const validProcessPluginYAML = `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: scanner
  version: 1.0.0
spec:
  runtime: process
  methods:
    - name: run
`

func TestPluginManifestValidator_ValidProcessManifest(t *testing.T) {
	v := &pluginManifestValidator{}
	m, errs := v.Validate([]byte(validProcessPluginYAML))
	require.Empty(t, errs)
	assert.Equal(t, "scanner", m.Name)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, "process", m.RuntimeMode)
	assert.Equal(t, []string{"run"}, m.DeclaredMethods)
}

func TestPluginManifestValidator_AcceptsPodAndSetecRuntimes(t *testing.T) {
	v := &pluginManifestValidator{}
	for _, rt := range []string{"pod", "setec"} {
		yaml := `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: scanner
  version: 1.0.0
spec:
  runtime: ` + rt + `
  methods:
    - name: run
`
		m, errs := v.Validate([]byte(yaml))
		require.Empty(t, errs, "runtime %q should be valid", rt)
		assert.Equal(t, rt, m.RuntimeMode)
	}
}

func TestPluginManifestValidator_MissingRuntime_Rejected(t *testing.T) {
	v := &pluginManifestValidator{}
	yaml := `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: scanner
  version: 1.0.0
spec:
  methods:
    - name: run
`
	_, errs := v.Validate([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.Contains(t, fieldCodes(errs), "spec.runtime:required")
}

func TestPluginManifestValidator_UnknownRuntime_Rejected(t *testing.T) {
	v := &pluginManifestValidator{}
	yaml := `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: scanner
  version: 1.0.0
spec:
  runtime: bogus-runtime
  methods:
    - name: run
`
	_, errs := v.Validate([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.Contains(t, fieldCodes(errs), "spec.runtime:invalid_value")
}

func TestPluginManifestValidator_NoMethods_Rejected(t *testing.T) {
	v := &pluginManifestValidator{}
	yaml := `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: scanner
  version: 1.0.0
spec:
  runtime: process
`
	_, errs := v.Validate([]byte(yaml))
	require.NotEmpty(t, errs)
	assert.Contains(t, fieldCodes(errs), "spec.methods:required")
}

// fieldCodes renders validation errors as "field:code" for order-independent
// assertions.
func fieldCodes(errs []admin.ManifestValidationError) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Field+":"+e.Code)
	}
	return out
}
