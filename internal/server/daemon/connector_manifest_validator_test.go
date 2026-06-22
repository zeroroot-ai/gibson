package daemon

// Tests for the mcp-bridge branch of pluginManifestValidator (gibson#732,
// ADR-0049): a connector is one plugin manifest with runtime: mcp-bridge —
// there is no separate connector.gibson.zeroroot.ai/v1 schema or apiVersion
// sniff. The validator marks such a manifest IsConnector=true, requires no
// static methods (discovered at bridge startup), and surfaces the vendor
// credentials from spec.mcp_bridge.secrets.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validMCPBridgeYAML = `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: github
  version: 0.1.0
spec:
  workload_class: plugin
  runtime: mcp-bridge
  mcp_bridge:
    transport: stdio
    vendor:
      command: npx
      args: ["-y", "@modelcontextprotocol/server-github"]
    secrets:
      - name: cred:github_token
        env: GITHUB_PERSONAL_ACCESS_TOKEN
  egress:
    - host: api.github.com
      protocol: https
      port: 443
`

func TestValidate_MCPBridgeManifest_Accepted(t *testing.T) {
	v := &pluginManifestValidator{}
	m, errs := v.Validate([]byte(validMCPBridgeYAML))
	require.Empty(t, errs, "violations: %+v", errs)

	assert.True(t, m.IsConnector, "runtime: mcp-bridge marks the component as a connector")
	assert.Equal(t, "github", m.Name)
	assert.Equal(t, "0.1.0", m.Version)
	assert.Empty(t, m.DeclaredMethods, "mcp-bridge methods are discovered at bridge startup")
	assert.Equal(t, []string{"cred:github_token"}, m.DeclaredSecrets, "vendor creds come from spec.mcp_bridge.secrets")
	assert.Equal(t, "mcp-bridge", m.RuntimeMode)
	assert.True(t, m.SetecRequired)
	assert.NotEmpty(t, m.ManifestHash)
}

func TestValidate_MCPBridgeManifest_RuntimeWithoutBlock_Rejected(t *testing.T) {
	v := &pluginManifestValidator{}
	_, errs := v.Validate([]byte(`apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: github
  version: 0.1.0
spec:
  workload_class: plugin
  runtime: mcp-bridge
`))
	require.NotEmpty(t, errs)
	joined := ""
	for _, e := range errs {
		joined += e.Message + "\n"
	}
	assert.Contains(t, joined, "spec.mcp_bridge")
}

func TestValidate_BadRuntime_Rejected(t *testing.T) {
	v := &pluginManifestValidator{}
	_, errs := v.Validate([]byte(`apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: github
  version: 0.1.0
spec:
  workload_class: plugin
  runtime: carrier-pigeon
`))
	require.NotEmpty(t, errs)
	joined := ""
	for _, e := range errs {
		joined += e.Message + "\n"
	}
	assert.Contains(t, joined, "spec.runtime")
}

func TestValidate_PluginManifest_StillWorks(t *testing.T) {
	v := &pluginManifestValidator{}
	m, errs := v.Validate([]byte(`apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: plain
  version: 1.0.0
spec:
  runtime: process
  methods:
    - name: Echo
`))
	require.Empty(t, errs, "violations: %+v", errs)
	assert.False(t, m.IsConnector)
	assert.Equal(t, []string{"Echo"}, m.DeclaredMethods)
}
