// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
)

// kindRegistry answers Discover with the instances and the error that it holds.
type kindRegistry struct {
	component.ComponentRegistry
	instances []component.ComponentInfo
	err       error
}

func (k kindRegistry) Discover(context.Context, string, string, string) ([]component.ComponentInfo, error) {
	return k.instances, k.err
}

func TestRegistryCards_Failures(t *testing.T) {
	gw := component.GatewayInfo{URL: "https://api.example/gateway/agent"}
	ctx := context.Background()

	_, err := registryCards{registry: kindRegistry{err: errors.New("redis is down")}, gateway: gw}.Card(ctx, "acme", "scout")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discover agent scout")

	_, err = registryCards{registry: kindRegistry{}, gateway: gw}.Card(ctx, "acme", "scout")
	require.ErrorIs(t, err, a2aserver.ErrNoCard, "an agent with no instance has no card")

	notAnAgent := kindRegistry{instances: []component.ComponentInfo{{Kind: "tool", Name: "scout"}}}
	_, err = registryCards{registry: notAnAgent, gateway: gw}.Card(ctx, "acme", "scout")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build the card of agent scout")
}

func serveOn(t *testing.T, handler http.Handler, drain time.Duration) (sub *httpSubsystem, addr string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	return &httpSubsystem{
		srv:                 &http.Server{Handler: handler, ReadHeaderTimeout: time.Second},
		listener:            lis,
		logger:              testObservabilityLogger(),
		gracefulStopTimeout: drain,
	}, lis.Addr().String()
}

func TestHTTPSubsystem_ServeStopsWithTheContext(t *testing.T) {
	sub, addr := serveOn(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sub.Serve(ctx) }()

	resp, err := http.Get("http://" + addr + "/") //nolint:noctx // a local test request
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	cancel()
	require.NoError(t, <-done)
}

func TestHTTPSubsystem_ServeReportsAListenerThatFails(t *testing.T) {
	sub, _ := serveOn(t, http.NotFoundHandler(), time.Second)
	require.NoError(t, sub.listener.Close())
	err := sub.Serve(context.Background())
	require.Error(t, err)
}

// A request that does not end holds the drain. The listener closes the server
// when the drain time is over, and it still returns.
func TestHTTPSubsystem_ServeClosesWhenTheDrainTimesOut(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	sub, addr := serveOn(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}), 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sub.Serve(ctx) }()

	go func() {
		resp, err := http.Get("http://" + addr + "/") //nolint:noctx // a local test request
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	cancel()
	require.NoError(t, <-done)
}

func a2aListenerDaemon(t *testing.T, mutate func(d *daemonImpl)) *daemonImpl {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Auth.SPIFFE = &config.SPIFFEConfig{TrustDomain: "example.org", WorkloadAPISocket: "unix:///tmp/none"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newMinimalDaemon(cfg)
	d.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	d.brainExecutor = newBrainExecutor(nil, nil)
	d.spiffeX509Source = &workloadapi.X509Source{}
	d.publicGateways.agent = component.GatewayInfo{URL: "https://api.example/gateway/agent"}
	if mutate != nil {
		mutate(d)
	}
	return d
}

func TestBuildA2AServer_RefusesAnIncompleteSetup(t *testing.T) {
	const svid = "spiffe://example.org/platform/agentgateway"
	tests := []struct {
		name    string
		svid    string
		addr    string
		mutate  func(d *daemonImpl)
		wantErr string
	}{
		{"no gateway identity", "  ", "127.0.0.1:0", nil, "GIBSON_A2A_GATEWAY_SVID is not set"},
		{"no address", svid, "", nil, "GIBSON_A2A_ADDR is not set"},
		{"the identity is not a SPIFFE ID", "not-an-id", "127.0.0.1:0", nil, "is not a SPIFFE ID"},
		{"no brain registry", svid, "127.0.0.1:0", func(d *daemonImpl) { d.brainRegistry = nil }, "the brain is not available"},
		{"no brain executor", svid, "127.0.0.1:0", func(d *daemonImpl) { d.brainExecutor = nil }, "the brain is not available"},
		{"no SPIFFE config", svid, "127.0.0.1:0", func(d *daemonImpl) { d.config.Auth.SPIFFE = nil }, "SPIFFE is not configured"},
		{"no workload socket", svid, "127.0.0.1:0", func(d *daemonImpl) { d.config.Auth.SPIFFE.WorkloadAPISocket = "" },
			"SPIFFE is not configured"},
		{"another trust domain", "spiffe://other.org/platform/agentgateway", "127.0.0.1:0", nil, "not in the trust domain"},
		{"the X.509 source is not open", svid, "127.0.0.1:0", func(d *daemonImpl) { d.spiffeX509Source = nil },
			"the SPIFFE X.509 source is not open"},
		{"no public gateway URL", svid, "127.0.0.1:0", func(d *daemonImpl) { d.publicGateways.agent.URL = "" },
			"the public URL of the Agent gateway is not set"},
		{"the address cannot be bound", svid, "127.0.0.1:-1", nil, "listen on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvA2AGatewaySVID, tt.svid)
			t.Setenv(EnvA2AAddr, tt.addr)
			sub, err := a2aListenerDaemon(t, tt.mutate).buildA2AServer()
			require.Error(t, err)
			assert.Nil(t, sub)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBuildA2AServer_ListensWhenTheSetupIsComplete(t *testing.T) {
	t.Setenv(EnvA2AGatewaySVID, "spiffe://example.org/platform/agentgateway")
	t.Setenv(EnvA2AAddr, "127.0.0.1:0")
	sub, err := a2aListenerDaemon(t, nil).buildA2AServer()
	require.NoError(t, err)
	require.NotNil(t, sub)
	defer func() { _ = sub.listener.Close() }()
	assert.Equal(t, 10*time.Second, sub.gracefulStopTimeout)
	assert.NotNil(t, sub.srv.Handler)
	assert.Equal(t, 64<<10, sub.srv.MaxHeaderBytes)
}

// The handler of the listener reads the job store of the executor for each
// call, since the data pool starts after the daemon builds the listener.
func TestBuildA2AServer_TheRunsReadTheJobStoreOfTheExecutorForEachCall(t *testing.T) {
	t.Setenv(EnvA2AGatewaySVID, "spiffe://example.org/platform/agentgateway")
	t.Setenv(EnvA2AAddr, "127.0.0.1:0")
	d := a2aListenerDaemon(t, nil)
	sub, err := d.buildA2AServer()
	require.NoError(t, err)
	defer func() { _ = sub.listener.Close() }()

	eng := d.brainRegistry.For("acme")
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "run-1", TenantID: "acme"})
	eng.Tick()
	d.brainExecutor.register("m1", &missionBinding{runID: "run-1", tenant: "acme"})

	const body = `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":` +
		`{"messageId":"m","role":"ROLE_USER","taskId":"job-x","parts":[{"text":"next"}]}}}`
	call := func() string {
		req, rerr := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
		require.NoError(t, rerr)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-gibson-tenant", "acme")
		req.Header.Set("x-gibson-subject", "agent:caller")
		req.Header.Set("x-gibson-mission", "m1")
		req.Header.Set("x-gibson-task", "node-task")
		req.Header.Set("x-gibson-route-agent", "scout")
		req.Header.Set("x-gibson-route-bank", "nightly")
		rec := &recordedResponse{header: http.Header{}}
		sub.srv.Handler.ServeHTTP(rec, req)
		return rec.body.String()
	}

	// No job store: the call fails and says nothing of the cause.
	assert.Contains(t, call(), `"error"`)

	// A job store with no such job: the task is not found.
	d.brainExecutor.jobs = func() (job.Store, error) { return newFakeJobStore(), nil }
	assert.Contains(t, call(), "TASK_NOT_FOUND")
}

// recordedResponse is a minimal http.ResponseWriter.
type recordedResponse struct {
	header http.Header
	body   strings.Builder
}

func (r *recordedResponse) Header() http.Header { return r.header }
func (r *recordedResponse) Write(b []byte) (int, error) {
	n, err := r.body.Write(b)
	if err != nil {
		return n, fmt.Errorf("record the body: %w", err)
	}
	return n, nil
}
func (r *recordedResponse) WriteHeader(int) {}
