package connector

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeSandboxClient records Launch calls.
type fakeSandboxClient struct {
	launched  []sandboxed.LaunchRequest
	launchErr error
}

func (f *fakeSandboxClient) Launch(_ context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	f.launched = append(f.launched, req)
	if f.launchErr != nil {
		return sandboxed.LaunchResponse{}, f.launchErr
	}
	return sandboxed.LaunchResponse{SandboxID: "ns/sbx-1/uid-1"}, nil
}

func (f *fakeSandboxClient) StreamLogs(context.Context, string) (sandboxed.LogStream, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeSandboxClient) Wait(context.Context, string) (sandboxed.WaitResponse, error) {
	return sandboxed.WaitResponse{}, fmt.Errorf("not implemented")
}

func (f *fakeSandboxClient) Kill(context.Context, string) error { return nil }

const connectorYAML = `apiVersion: connector.gibson.zeroroot.ai/v1
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

const httpConnectorYAML = `apiVersion: connector.gibson.zeroroot.ai/v1
kind: Connector
metadata:
  name: gitlab
  version: 0.1.0
spec:
  transport: http
  endpoint: https://mcp.example.com/mcp
`

var platformEgress = []sandboxed.EgressRule{
	{Host: "gibson.gibson-prod.svc.cluster.local", Port: 50051},
	{Host: "registry.npmjs.org", Port: 443},
}

func newTestLauncher(t *testing.T, client sandboxed.SandboxClient) *Launcher {
	t.Helper()
	l, err := New(Config{
		Client:         client,
		RunnerImage:    "ghcr.io/zeroroot-ai/gibson-mcp-bridge-runner:dev",
		PlatformURL:    "http://gibson.gibson-prod.svc.cluster.local:8080",
		PlatformEgress: platformEgress,
	})
	require.NoError(t, err)
	return l
}

func TestNew_Validation(t *testing.T) {
	client := &fakeSandboxClient{}
	base := Config{
		Client:         client,
		RunnerImage:    "img",
		PlatformURL:    "http://gibson:8080",
		PlatformEgress: platformEgress,
	}

	for _, tt := range []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"missing client", func(c *Config) { c.Client = nil }, "Client is required"},
		{"missing image", func(c *Config) { c.RunnerImage = "" }, "RunnerImage is required"},
		{"missing platform URL", func(c *Config) { c.PlatformURL = "" }, "PlatformURL is required"},
		{"missing platform egress", func(c *Config) { c.PlatformEgress = nil }, "PlatformEgress is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			_, err := New(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLaunch_BuildsSandboxRequest(t *testing.T) {
	client := &fakeSandboxClient{}
	l := newTestLauncher(t, client)
	tenant := auth.MustNewTenantID("acme")

	id, err := l.Launch(context.Background(), tenant, []byte(connectorYAML), "tok-once")
	require.NoError(t, err)
	assert.Equal(t, "ns/sbx-1/uid-1", id)

	require.Len(t, client.launched, 1)
	req := client.launched[0]

	assert.Equal(t, "ghcr.io/zeroroot-ai/gibson-mcp-bridge-runner:dev", req.Image)
	assert.Empty(t, req.Command, "image ENTRYPOINT is the runner; no override")
	assert.Equal(t, "acme", req.Tenant)
	assert.Equal(t, int32(defaultVCPU), req.VCPU)
	assert.Equal(t, defaultMemory, req.Memory)
	assert.Equal(t, defaultTimeout, req.Timeout)

	// Manifest delivered inline, decodable back to the original YAML.
	decoded, err := base64.StdEncoding.DecodeString(req.Env["GIBSON_CONNECTOR_MANIFEST_B64"])
	require.NoError(t, err)
	assert.Equal(t, connectorYAML, string(decoded))
	assert.Equal(t, "http://gibson.gibson-prod.svc.cluster.local:8080", req.Env["GIBSON_URL"])
	assert.Equal(t, "tok-once", req.Env["GIBSON_BOOTSTRAP_TOKEN"])

	// Egress = platform endpoints + manifest-declared vendor targets.
	assert.Equal(t, []sandboxed.EgressRule{
		{Host: "gibson.gibson-prod.svc.cluster.local", Port: 50051},
		{Host: "registry.npmjs.org", Port: 443},
		{Host: "api.github.com", Port: 443},
	}, req.Egress)
}

func TestLaunch_HTTPTransport_Rejected(t *testing.T) {
	client := &fakeSandboxClient{}
	l := newTestLauncher(t, client)

	_, err := l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(httpConnectorYAML), "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdio transport only")
	assert.Empty(t, client.launched)
}

func TestLaunch_InvalidManifest_Rejected(t *testing.T) {
	client := &fakeSandboxClient{}
	l := newTestLauncher(t, client)

	_, err := l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte("kind: Nope"), "tok")
	require.Error(t, err)
	assert.Empty(t, client.launched)
}

func TestLaunch_MissingBootstrapToken_Rejected(t *testing.T) {
	client := &fakeSandboxClient{}
	l := newTestLauncher(t, client)

	_, err := l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(connectorYAML), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap token")
	assert.Empty(t, client.launched)
}

// When Admit denies (plan-tier connector budget exceeded), Launch surfaces the
// capacity error and never creates a sandbox.
func TestLaunch_AdmitDenied_NoSandbox(t *testing.T) {
	client := &fakeSandboxClient{}
	l, err := New(Config{
		Client:         client,
		RunnerImage:    "img",
		PlatformURL:    "http://gibson:8080",
		PlatformEgress: platformEgress,
		Admit: func(context.Context, auth.TenantID) error {
			return status.Error(codes.ResourceExhausted, "concurrent_connectors quota exceeded (2/2)")
		},
	})
	require.NoError(t, err)

	_, err = l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(connectorYAML), "tok")
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "capacity error must propagate")
	assert.Empty(t, client.launched, "over-budget tenant must not launch a sandbox")
}

// When Admit allows, the launch proceeds normally.
func TestLaunch_AdmitAllows_Launches(t *testing.T) {
	client := &fakeSandboxClient{}
	admitted := false
	l, err := New(Config{
		Client:         client,
		RunnerImage:    "img",
		PlatformURL:    "http://gibson:8080",
		PlatformEgress: platformEgress,
		Admit: func(context.Context, auth.TenantID) error {
			admitted = true
			return nil
		},
	})
	require.NoError(t, err)

	_, err = l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(connectorYAML), "tok")
	require.NoError(t, err)
	assert.True(t, admitted, "Admit must be consulted")
	require.Len(t, client.launched, 1)
}

func TestLaunch_SandboxFailure_Propagates(t *testing.T) {
	client := &fakeSandboxClient{launchErr: fmt.Errorf("no capacity")}
	l := newTestLauncher(t, client)

	_, err := l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(connectorYAML), "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no capacity")
	// The token must not leak into the error string.
	assert.False(t, strings.Contains(err.Error(), "tok-once"))
}

func TestLaunch_DefaultsOverridable(t *testing.T) {
	client := &fakeSandboxClient{}
	l, err := New(Config{
		Client:         client,
		RunnerImage:    "img",
		PlatformURL:    "http://gibson:8080",
		PlatformEgress: platformEgress,
		VCPU:           2,
		Memory:         "1Gi",
		Timeout:        time.Hour,
	})
	require.NoError(t, err)

	_, err = l.Launch(context.Background(), auth.MustNewTenantID("acme"), []byte(connectorYAML), "tok")
	require.NoError(t, err)
	req := client.launched[0]
	assert.Equal(t, int32(2), req.VCPU)
	assert.Equal(t, "1Gi", req.Memory)
	assert.Equal(t, time.Hour, req.Timeout)
}
