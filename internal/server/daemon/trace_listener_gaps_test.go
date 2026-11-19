// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

func traceDaemon(t *testing.T, mutate func(d *daemonImpl)) *daemonImpl {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Auth.SPIFFE = &config.SPIFFEConfig{TrustDomain: "example.org", WorkloadAPISocket: "unix:///tmp/none"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	scfg := state.DefaultConfig()
	scfg.URL = "redis://" + miniredis.RunT(t).Addr()
	client, err := state.NewStateClient(scfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	d := newMinimalDaemon(cfg)
	d.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	d.spiffeX509Source = &workloadapi.X509Source{}
	d.budgetEnforcer = &recordingEnforcer{}
	d.stateClient = client
	if mutate != nil {
		mutate(d)
	}
	return d
}

func TestTraceServerOptions_SetTheLimitAndKeepAlive(t *testing.T) {
	assert.Len(t, traceServerOptions(), 4)
}

func TestBuildTraceServer_RefusesAnIncompleteSetup(t *testing.T) {
	const svid = "spiffe://example.org/platform/collector"
	tests := []struct {
		name    string
		svid    string
		addr    string
		mutate  func(d *daemonImpl)
		wantErr string
	}{
		{"no brain registry", svid, "127.0.0.1:0", func(d *daemonImpl) { d.brainRegistry = nil }, "the brain registry is not available"},
		{"no address", svid, "", nil, "GIBSON_TRACE_GRPC_ADDR is not"},
		{"the identity is not a SPIFFE ID", "nope", "127.0.0.1:0", nil, "is not a SPIFFE ID"},
		{"no SPIFFE config", svid, "127.0.0.1:0", func(d *daemonImpl) { d.config.Auth.SPIFFE = nil }, "SPIFFE is not configured"},
		{"another trust domain", "spiffe://other.org/platform/collector", "127.0.0.1:0", nil, "not in the trust domain"},
		{"the X.509 source is not open", svid, "127.0.0.1:0", func(d *daemonImpl) { d.spiffeX509Source = nil },
			"the SPIFFE X.509 source is not open"},
		{"no budget enforcer", svid, "127.0.0.1:0", func(d *daemonImpl) { d.budgetEnforcer = nil },
			"the platform budget is not wired"},
		{"no state client", svid, "127.0.0.1:0", func(d *daemonImpl) { d.stateClient = nil },
			"the platform budget is not wired"},
		{"the address cannot be bound", svid, "127.0.0.1:-1", nil, "listen on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(api.EnvTraceCollectorSVID, tt.svid)
			t.Setenv(EnvTraceGRPCAddr, tt.addr)
			sub, err := traceDaemon(t, tt.mutate).buildTraceServer(context.Background())
			require.Error(t, err)
			assert.Nil(t, sub)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestBuildTraceServer_IsOffWithoutACollectorIdentity(t *testing.T) {
	t.Setenv(api.EnvTraceCollectorSVID, " ")
	sub, err := traceDaemon(t, nil).buildTraceServer(context.Background())
	require.NoError(t, err)
	assert.Nil(t, sub)
	assert.Empty(t, traceCollectorSVIDFromEnv())
}

func TestBuildTraceServer_ListensWhenTheSetupIsComplete(t *testing.T) {
	t.Setenv(api.EnvTraceCollectorSVID, "spiffe://example.org/platform/collector")
	t.Setenv(EnvTraceGRPCAddr, "127.0.0.1:0")
	sub, err := traceDaemon(t, nil).buildTraceServer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sub)
	defer func() { _ = sub.listener.Close() }()
	assert.Equal(t, 10*time.Second, sub.gracefulStopTimeout)
	assert.Contains(t, sub.srv.GetServiceInfo(), "opentelemetry.proto.collector.trace.v1.TraceService")
}
