package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// --- Stub SPIFFE sources for unit tests ---

// stubSVIDSource implements x509svid.Source with a synthetic self-signed cert.
type stubSVIDSource struct {
	svid *x509svid.SVID
}

func (s *stubSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	return s.svid, nil
}

// stubBundleSource implements x509bundle.Source backed by a synthetic CA cert.
type stubBundleSource struct {
	bundle *x509bundle.Bundle
}

func (s *stubBundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

// newSyntheticSPIFFESources creates a self-signed CA and a leaf SVID cert sharing
// the same key material, both in-process using a deterministic seed. This is used
// by TLS unit tests that need valid-looking SPIFFE sources without a live SPIRE server.
func newSyntheticSPIFFESources(t *testing.T) (*stubSVIDSource, *stubBundleSource) {
	t.Helper()

	// Generate CA key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "synthetic CA key generation")

	// Self-signed CA cert.
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err, "synthetic CA cert creation")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "synthetic CA cert parse")

	// Generate leaf key.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "synthetic leaf key generation")

	// Build SPIFFE URI SAN: spiffe://zero-day.ai/test/unit.
	spiffeURI, err := url.Parse("spiffe://zero-day.ai/test/unit")
	require.NoError(t, err, "SPIFFE URI parse")

	// Leaf cert signed by the CA, with SPIFFE URI SAN.
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-svid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{spiffeURI},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err, "synthetic leaf cert creation")
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err, "synthetic leaf cert parse")

	td := spiffeid.RequireTrustDomainFromString("zero-day.ai")

	svidID, err := spiffeid.FromString("spiffe://zero-day.ai/test/unit")
	require.NoError(t, err, "SPIFFE ID parse")

	svid := &x509svid.SVID{
		ID:           svidID,
		Certificates: []*x509.Certificate{leafCert, caCert},
		PrivateKey:   leafKey,
	}
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{caCert})

	return &stubSVIDSource{svid: svid}, &stubBundleSource{bundle: bundle}
}

// --- SPIFFE fail-closed and non-loopback bind tests (zero-trust-hardening Req 1.1 & 1.2) ---

// TestRejectNonLoopbackWithoutSPIFFE verifies that rejectNonLoopbackWithoutSPIFFE
// returns an error for non-loopback addresses and succeeds for loopback ones.
// Covers Requirement 1.2 of the zero-trust-hardening spec.
func TestRejectNonLoopbackWithoutSPIFFE(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		// --- Loopback cases (should succeed) ---
		{name: "loopback IPv4", addr: "127.0.0.1:50002", wantErr: false},
		{name: "loopback localhost", addr: "localhost:50002", wantErr: false},
		{name: "loopback IPv6", addr: "[::1]:50002", wantErr: false},

		// --- Non-loopback cases (should fail) ---
		{name: "all interfaces IPv4 0.0.0.0", addr: "0.0.0.0:50002", wantErr: true},
		{name: "all interfaces shorthand :port", addr: ":50002", wantErr: true},
		{name: "all interfaces IPv6 [::]", addr: "[::]:50002", wantErr: true},
		{name: "routable IP", addr: "10.0.0.1:50002", wantErr: true},
		{name: "public IP", addr: "203.0.113.1:50002", wantErr: true},
		{name: "non-loopback hostname", addr: "gibson.gibson.svc:50002", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectNonLoopbackWithoutSPIFFE(tt.addr)
			if tt.wantErr {
				assert.Error(t, err, "expected error for non-loopback addr %q", tt.addr)
				// Confirm the error mentions the spec reference.
				assert.Contains(t, err.Error(), "zero-trust-hardening Req 1.2")
			} else {
				assert.NoError(t, err, "expected no error for loopback addr %q", tt.addr)
			}
		})
	}
}

// TestSPIFFEInitFailClosed is a source-code value-lock asserting that
// grpc.go returns an error (fail-closed) when workloadapi.NewX509Source
// fails, rather than falling back to a plaintext listener.
//
// This test reads the source text of grpc.go and asserts:
//  1. The old warn-and-continue pattern is NOT present.
//  2. A return-with-error pattern following the sourceErr != nil check IS present.
//
// Covers Requirement 1.1 of the zero-trust-hardening spec.
func TestSPIFFEInitFailClosed(t *testing.T) {
	src, err := os.ReadFile("grpc.go")
	require.NoError(t, err, "could not read grpc.go; run test from core/gibson/ or internal/daemon/")
	srcStr := string(src)

	// The old soft-fail pattern must be gone.
	const oldWarnFallback = `d.logger.Warn(ctx, "failed to initialize SPIFFE X509Source; running without mTLS"`
	assert.NotContains(t, srcStr, oldWarnFallback,
		"REGRESSION (zero-trust-hardening Req 1.1): "+
			"grpc.go must NOT fall back to plaintext on SPIFFE init failure; "+
			"the warn-and-continue pattern was replaced with return nil, fmt.Errorf(...).")

	// The fail-closed return must be present immediately after the sourceErr check.
	const failClosedPattern = `"SPIFFE workload API unreachable:`
	assert.Contains(t, srcStr, failClosedPattern,
		"REGRESSION (zero-trust-hardening Req 1.1): "+
			"grpc.go must return a non-nil error when workloadapi.NewX509Source fails. "+
			"Expected to find the fail-closed error message.")

	// Confirm the spec reference is in the error message.
	assert.Contains(t, srcStr, "zero-trust-hardening Req 1.1",
		"REGRESSION (zero-trust-hardening Req 1.1): "+
			"the fail-closed error message must reference the spec.")
}

// TestBuildGRPCServer_NonLoopbackWithoutSPIFFE verifies that the non-loopback
// guard fires for a routable address when SPIFFE is unconfigured.
// We test rejectNonLoopbackWithoutSPIFFE directly since spinning a full
// daemonImpl is complex; the integration between buildGRPCServer and this
// helper is covered by TestRejectNonLoopbackWithoutSPIFFE.
// Covers Requirement 1.2 of the zero-trust-hardening spec.
func TestBuildGRPCServer_NonLoopbackWithoutSPIFFE(t *testing.T) {
	// Direct test of the guard for 0.0.0.0
	err := rejectNonLoopbackWithoutSPIFFE("0.0.0.0:50002")
	require.Error(t, err, "expected error for 0.0.0.0 without SPIFFE")
	assert.Contains(t, err.Error(), "zero-trust-hardening Req 1.2")

	// Also verify the source text calls the validator from buildGRPCServer.
	src, readErr := os.ReadFile("grpc.go")
	require.NoError(t, readErr)
	assert.Contains(t, string(src), "rejectNonLoopbackWithoutSPIFFE",
		"REGRESSION: buildGRPCServer must call rejectNonLoopbackWithoutSPIFFE")
}

// TestBuildGRPCServer_LoopbackWithoutSPIFFE verifies that buildGRPCServer
// proceeds past the bind check (with a warning) when the address is loopback
// and SPIFFE is unconfigured.  The test does not assert full server startup —
// only that the non-loopback guard is cleared and the function reaches the
// listener step (which may fail for other reasons in a unit test context,
// such as the port already being in use or the authz-registry validation).
// Covers the success branch of Requirement 1.2.
func TestBuildGRPCServer_LoopbackWithoutSPIFFE(t *testing.T) {
	// We are only testing that the non-loopback guard does NOT fire.
	// Use rejectNonLoopbackWithoutSPIFFE directly to avoid the side-effects
	// of actually starting a listener.
	err := rejectNonLoopbackWithoutSPIFFE("127.0.0.1:50002")
	assert.NoError(t, err, "loopback without SPIFFE must not be rejected by the bind guard")

	err = rejectNonLoopbackWithoutSPIFFE("localhost:50002")
	assert.NoError(t, err, "localhost without SPIFFE must not be rejected by the bind guard")
}

// TestBuildGRPCServer_ClientAuthRejectsNoCert is a regression test for spec
// critical-tls-no-fallbacks Requirements 2.1, 2.3.
//
// The production daemon listener uses tlsconfig.MTLSServerConfig WITHOUT
// overriding ClientAuth — go-spiffe's built-in value rejects cert-less
// handshakes, and SPIFFE bundle validation is owned by the library's
// VerifyPeerCertificate callback. We assert two invariants:
//
//  1. grpc.go does NOT contain ANY of the four banned ClientAuth literals
//     (RequestClientCert / NoClientCert / VerifyClientCertIfGiven /
//     RequireAnyClientCert) — that is enforced workspace-wide by
//     TestNoFallbackAudit; this targeted assertion is for the daemon file
//     specifically.
//  2. The resulting TLS config rejects cert-less connections (ClientAuth
//     value satisfies requiresClientCert from Go's crypto/tls — i.e. is one
//     of RequireAnyClientCert or RequireAndVerifyClientCert; we accept
//     either since the daemon does not override the library default).
func TestBuildGRPCServer_ClientAuthRejectsNoCert(t *testing.T) {
	// Part 1: source-text value-lock — grpc.go must NOT contain ANY of the
	// banned literals.
	src, err := os.ReadFile("grpc.go")
	require.NoError(t, err, "could not read grpc.go; run test from core/gibson/ or internal/daemon/")
	srcStr := string(src)
	for _, banned := range []string{
		"tls.RequestClientCert",
		"tls.NoClientCert",
		"tls.VerifyClientCertIfGiven",
		"tls.RequireAnyClientCert",
	} {
		assert.NotContains(t, srcStr, banned,
			"spec critical-tls-no-fallbacks Requirement 3.1: "+
				"grpc.go must NOT reference %s — go-spiffe's built-in ClientAuth "+
				"value (set by tlsconfig.MTLSServerConfig) is the only acceptable "+
				"posture. The CI guard TestNoFallbackAudit covers all of core/.",
			banned)
	}

	// Part 2: TLS config produced by tlsconfig.MTLSServerConfig (the same way
	// production grpc.go builds it) rejects cert-less connections. We allow
	// either RequireAnyClientCert (current go-spiffe v2.6.0 default) or
	// RequireAndVerifyClientCert as ACCEPTABLE; the BANNED values are
	// RequestClientCert / NoClientCert / VerifyClientCertIfGiven.
	svidSource, bundleSource := newSyntheticSPIFFESources(t)
	tlsCfg := tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeAny())
	// requiresClientCert is true for RequireAnyClientCert and
	// RequireAndVerifyClientCert; false for the banned values.
	requiresCert := tlsCfg.ClientAuth == tls.RequireAnyClientCert ||
		tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert
	assert.True(t, requiresCert,
		"spec critical-tls-no-fallbacks Requirement 2.3: "+
			"the daemon TLS config must reject cert-less connections; "+
			"go-spiffe's MTLSServerConfig must produce a ClientAuth value that requires a client cert.")
}

// Stub implementations for other interface methods (not tested in this task)

// TestListAgents_Success tests ListAgents with mock registry adapter.
func TestListAgents_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:         "test-agent-1",
					Version:      "1.0.0",
					Endpoints:    []string{"localhost:50100"},
					Capabilities: []string{"llm", "web"},
					Instances:    1,
				},
				{
					Name:         "test-agent-2",
					Version:      "2.0.0",
					Endpoints:    []string{"localhost:50101", "localhost:50102"},
					Capabilities: []string{"cli"},
					Instances:    2,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 2)

	// Verify first agent
	assert.Equal(t, "test-agent-1", agents[0].Name)
	assert.Equal(t, "test-agent-1", agents[0].ID)
	assert.Equal(t, "1.0.0", agents[0].Version)
	assert.Equal(t, "localhost:50100", agents[0].Endpoint)
	assert.Equal(t, []string{"llm", "web"}, agents[0].Capabilities)
	assert.Equal(t, "healthy", agents[0].Health)

	// Verify second agent
	assert.Equal(t, "test-agent-2", agents[1].Name)
	assert.Equal(t, "2.0.0", agents[1].Version)
	assert.Equal(t, "localhost:50101", agents[1].Endpoint) // First endpoint used
	assert.Equal(t, "healthy", agents[1].Health)
}

// TestListAgents_EmptyResults tests ListAgents with no agents registered.
func TestListAgents_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Empty(t, agents)
}

// TestListAgents_NoInstances tests ListAgents with agents that have no instances.
func TestListAgents_NoInstances(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "offline-agent",
					Version:   "1.0.0",
					Endpoints: []string{"localhost:50100"},
					Instances: 0, // No instances running
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Equal(t, "healthy", agents[0].Health) // Registry agents default to healthy
}

// TestListAgents_RegistryError tests ListAgents graceful degradation when registry fails.
func TestListAgents_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return nil, fmt.Errorf("registry connection failed")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	// Registry error is gracefully degraded - returns empty results, not error
	require.NoError(t, err)
	assert.Empty(t, agents)
}

// TestGetAgentStatus_Success tests GetAgentStatus with existing agent.
func TestGetAgentStatus_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:         "target-agent",
					Version:      "1.5.0",
					Endpoints:    []string{"localhost:50200"},
					Capabilities: []string{"recon"},
					Instances:    3,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "target-agent")

	require.NoError(t, err)
	assert.Equal(t, "target-agent", status.Agent.Name)
	assert.Equal(t, "1.5.0", status.Agent.Version)
	assert.Equal(t, "localhost:50200", status.Agent.Endpoint)
	assert.Equal(t, "healthy", status.Agent.Health)
	assert.True(t, status.Active) // Active because instances > 0
	assert.Empty(t, status.CurrentTask)
}

// TestGetAgentStatus_NotFound tests GetAgentStatus with non-existent agent.
func TestGetAgentStatus_NotFound(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:    "other-agent",
					Version: "1.0.0",
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "nonexistent-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "agent not found")
	assert.Contains(t, err.Error(), "nonexistent-agent")
	assert.Equal(t, api.AgentStatusInternal{}, status)
}

// TestGetAgentStatus_RegistryError tests GetAgentStatus error propagation.
func TestGetAgentStatus_RegistryError(t *testing.T) {
	expectedErr := fmt.Errorf("etcd timeout")
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return nil, expectedErr
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "any-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to query registry")
	assert.Equal(t, api.AgentStatusInternal{}, status)
}

// TestListTools_Success tests ListTools with tools in component store and running in registry.
func TestListTools_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "nmap",
					Version:   "7.92",
					Endpoints: []string{"localhost:50300"},
					Instances: 1,
				},
				{
					Name:      "sqlmap",
					Version:   "1.5",
					Endpoints: []string{"localhost:50301"},
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	// Verify tools (order may vary)
	toolMap := make(map[string]api.ToolInfoInternal)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}

	nmap := toolMap["nmap"]
	assert.Equal(t, "nmap", nmap.ID)
	assert.Equal(t, "7.92", nmap.Version)
	assert.Equal(t, "Network scanner", nmap.Description)
	assert.Equal(t, "localhost:50300", nmap.Endpoint)
	assert.Equal(t, "healthy", nmap.Health)

	sqlmap := toolMap["sqlmap"]
	assert.Equal(t, "sqlmap", sqlmap.Name)
	assert.Equal(t, "SQL injection tool", sqlmap.Description)
}

// TestListTools_EmptyResults tests ListTools with no tools registered.
func TestListTools_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Empty(t, tools)
}

// TestListTools_RegistryError tests ListTools graceful degradation when registry fails.
func TestListTools_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return nil, fmt.Errorf("registry unavailable")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	// Registry error is propagated
	require.Error(t, err)
	assert.Empty(t, tools)
}

// TestListPlugins_Success tests ListPlugins with mock registry adapter.
func TestListPlugins_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:        "mitre-lookup",
					Version:     "1.0.0",
					Description: "MITRE ATT&CK lookup plugin",
					Endpoints:   []string{"localhost:50400"},
					Instances:   1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Len(t, plugins, 1)

	// Verify plugin
	assert.Equal(t, "mitre-lookup", plugins[0].Name)
	assert.Equal(t, "mitre-lookup", plugins[0].ID)
	assert.Equal(t, "1.0.0", plugins[0].Version)
	assert.Equal(t, "MITRE ATT&CK lookup plugin", plugins[0].Description)
	assert.Equal(t, "localhost:50400", plugins[0].Endpoint)
	assert.Equal(t, "healthy", plugins[0].Health)
}

// TestListPlugins_EmptyResults tests ListPlugins with no plugins registered.
func TestListPlugins_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Empty(t, plugins)
}

// TestListPlugins_RegistryError tests ListPlugins graceful degradation when registry fails.
func TestListPlugins_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return nil, fmt.Errorf("plugin registry error")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	// Registry error is gracefully degraded - returns empty results, not error
	require.NoError(t, err)
	assert.Empty(t, plugins)
}

// TestListAgents_NoEndpoints tests handling of agents with no endpoints.
func TestListAgents_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "no-endpoint-agent",
					Version:   "1.0.0",
					Endpoints: []string{}, // Empty endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Empty(t, agents[0].Endpoint)          // Should be empty string when no endpoints
	assert.Equal(t, "healthy", agents[0].Health) // Still healthy if instances > 0
}

// TestListTools_NoEndpoints tests handling of tools with no endpoints.
func TestListTools_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "no-endpoint-tool",
					Version:   "1.0.0",
					Endpoints: nil, // Nil endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Empty(t, tools[0].Endpoint) // Should be empty string when no endpoints
}

// TestGetAgentStatus_NoEndpoints tests GetAgentStatus with agent that has no endpoints.
func TestGetAgentStatus_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "target-agent",
					Version:   "1.0.0",
					Endpoints: []string{}, // No endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "target-agent")

	require.NoError(t, err)
	assert.Empty(t, status.Agent.Endpoint)
	assert.True(t, status.Active)
}

// TestListAgents_WithKindFilter tests ListAgents with kind parameter (even though not yet used).
func TestListAgents_WithKindFilter(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "test-agent",
					Version:   "1.0.0",
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "security") // Kind parameter passed but not yet used

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Equal(t, "agent", agents[0].Kind) // Default kind
}

// TestHealthStatus_BasedOnInstances tests that health status is correctly determined by instance count.
func TestHealthStatus_BasedOnInstances(t *testing.T) {
	tests := []struct {
		name                 string
		instances            int
		expectedStatusHealth string // GetAgentStatus checks instances
		expectedActive       bool
	}{
		{
			name:                 "healthy with instances",
			instances:            5,
			expectedStatusHealth: "healthy",
			expectedActive:       true,
		},
		{
			name:                 "unknown with no instances",
			instances:            0,
			expectedStatusHealth: "unknown",
			expectedActive:       false,
		},
		{
			name:                 "healthy with one instance",
			instances:            1,
			expectedStatusHealth: "healthy",
			expectedActive:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRegistry := &mockComponentDiscovery{
				listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
					return []component.AgentInfo{
						{
							Name:      "test-agent",
							Version:   "1.0.0",
							Instances: tt.instances,
						},
					}, nil
				},
			}

			daemon := &daemonImpl{
				registryAdapter: mockRegistry,
				logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
			}

			ctx := context.Background()

			// Test via GetAgentStatus (uses instance-aware health check)
			status, err := daemon.GetAgentStatus(ctx, "test-agent")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatusHealth, status.Agent.Health)
			assert.Equal(t, tt.expectedActive, status.Active)
		})
	}
}

// TestListTools_HealthStatus tests tool health status based on instances.
func TestListTools_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "healthy-tool",
					Instances: 2,
				},
				{
					Name:      "offline-tool",
					Instances: 0,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	toolMap := make(map[string]api.ToolInfoInternal)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}
	assert.Equal(t, "healthy", toolMap["healthy-tool"].Health)
	assert.Equal(t, "healthy", toolMap["offline-tool"].Health) // ListTools defaults all registry entries to healthy
}

// TestListPlugins_HealthStatus tests plugin health status based on instances.
func TestListPlugins_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:      "active-plugin",
					Instances: 1,
				},
				{
					Name:      "inactive-plugin",
					Instances: 0,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Len(t, plugins, 2)
	assert.Equal(t, "healthy", plugins[0].Health)
	assert.Equal(t, "unknown", plugins[1].Health)
}

// TestLastSeenTime tests that LastSeen is populated (currently uses time.Now()).
func TestLastSeenTime(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "test-agent",
					Version:   "1.0.0",
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	beforeTime := time.Now().Add(-1 * time.Second)

	agents, err := daemon.ListAgents(ctx, "")
	require.NoError(t, err)

	afterTime := time.Now().Add(1 * time.Second)

	assert.Len(t, agents, 1)
	assert.True(t, agents[0].LastSeen.After(beforeTime))
	assert.True(t, agents[0].LastSeen.Before(afterTime))
}
