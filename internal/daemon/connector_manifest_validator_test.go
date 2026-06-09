package daemon

// Tests for the connector branch of pluginManifestValidator (gibson#684):
// connector.gibson.zeroroot.ai/v1 manifests route to the SDK connector
// validator and map onto ValidatedManifest with IsConnector=true.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validConnectorYAML = `apiVersion: connector.gibson.zeroroot.ai/v1
kind: Connector
metadata:
  name: github
  version: 0.1.0
spec:
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

func TestValidate_ConnectorManifest_Accepted(t *testing.T) {
	v := &pluginManifestValidator{}
	m, errs := v.Validate([]byte(validConnectorYAML))
	require.Empty(t, errs, "violations: %+v", errs)

	assert.True(t, m.IsConnector)
	assert.Equal(t, "github", m.Name)
	assert.Equal(t, "0.1.0", m.Version)
	assert.Empty(t, m.DeclaredMethods, "connector methods are discovered at bridge startup")
	assert.Equal(t, []string{"cred:github_token"}, m.DeclaredSecrets)
	assert.Equal(t, "setec", m.RuntimeMode)
	assert.True(t, m.SetecRequired)
	assert.NotEmpty(t, m.ManifestHash)
}

func TestValidate_ConnectorManifest_InvalidReportsViolations(t *testing.T) {
	v := &pluginManifestValidator{}
	_, errs := v.Validate([]byte(`apiVersion: connector.gibson.zeroroot.ai/v1
kind: Connector
metadata:
  name: BAD NAME
  version: 0.1.0
spec:
  transport: carrier-pigeon
`))
	require.NotEmpty(t, errs)
	joined := ""
	for _, e := range errs {
		joined += e.Message + "\n"
	}
	assert.Contains(t, joined, "metadata.name")
	assert.Contains(t, joined, "spec.transport")
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
