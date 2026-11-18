// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/agentcard"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
)

// The environment of the A2A listener (gibson#1400).
const (
	// EnvA2AAddr is the listen address of the A2A listener, for example ":8443".
	EnvA2AAddr = "GIBSON_A2A_ADDR"
	// EnvA2AGatewaySVID is the SPIFFE ID of the Agent gateway. It is the only
	// peer that the listener accepts.
	EnvA2AGatewaySVID = "GIBSON_A2A_GATEWAY_SVID"
)

// httpSubsystem owns the lifecycle of one HTTP listener.
type httpSubsystem struct {
	srv                 *http.Server
	listener            net.Listener
	logger              *observability.Logger
	gracefulStopTimeout time.Duration
}

// Serve serves until ctx ends. It then drains for a bounded time.
func (s *httpSubsystem) Serve(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		s.logger.Info(ctx, "A2A listener serving", "address", s.listener.Addr().String())
		err := s.srv.Serve(s.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), s.gracefulStopTimeout)
		defer cancel()
		if err := s.srv.Shutdown(stopCtx); err != nil {
			s.logger.Warn(ctx, "A2A listener drain timed out, closing", "error", err.Error())
			_ = s.srv.Close()
		}
		<-serveErr
		return nil
	}
}

// registryCards builds the Agent Card of an agent from the component registry.
type registryCards struct {
	registry   component.ComponentRegistry
	gatewayURL string
}

var _ a2aserver.Cards = registryCards{}

// Card returns the card of the first live instance of the agent that the tenant
// can see. A name with no instance has no card.
func (c registryCards) Card(ctx context.Context, tenant, name string) (*a2a.AgentCard, error) {
	instances, err := c.registry.Discover(ctx, tenant, "agent", name)
	if err != nil {
		return nil, fmt.Errorf("discover agent %s: %w", name, err)
	}
	if len(instances) == 0 {
		return nil, a2aserver.ErrNoCard
	}
	card, err := agentcard.Build(instances[0], c.gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("build the card of agent %s: %w", name, err)
	}
	return card, nil
}

// buildA2AServer builds the A2A listener (gibson#1400). It has its own port.
// The TLS layer accepts the one SPIFFE ID of the Agent gateway and no other
// peer. With no gateway identity configured the daemon starts no listener, and
// the result is nil.
func (d *daemonImpl) buildA2AServer(ctx context.Context) (*httpSubsystem, error) {
	svid := strings.TrimSpace(os.Getenv(EnvA2AGatewaySVID))
	if svid == "" {
		d.logger.Info(ctx, "no Agent gateway identity is configured; the A2A listener is off", "env", EnvA2AGatewaySVID)
		return nil, nil
	}
	addr := strings.TrimSpace(os.Getenv(EnvA2AAddr))
	if addr == "" {
		return nil, fmt.Errorf("A2A listener: %s is set and %s is not", EnvA2AGatewaySVID, EnvA2AAddr)
	}
	gateway, err := spiffeid.FromString(svid)
	if err != nil {
		return nil, fmt.Errorf("A2A listener: %s is not a SPIFFE ID: %w", EnvA2AGatewaySVID, err)
	}
	if d.brainRegistry == nil || d.brainExecutor == nil {
		return nil, errors.New("A2A listener: the brain is not available")
	}
	if d.config.Auth.SPIFFE == nil || d.config.Auth.SPIFFE.WorkloadAPISocket == "" {
		return nil, errors.New("A2A listener: the gateway identity needs SPIFFE mTLS, and SPIFFE is not configured")
	}
	if td := d.spiffeTrustDomain(); !gateway.MemberOf(td) {
		return nil, fmt.Errorf("A2A listener: %s is not in the trust domain %s", svid, td)
	}
	x509Source, ok := d.spiffeX509Source.(*workloadapi.X509Source)
	if !ok || x509Source == nil {
		return nil, fmt.Errorf("A2A listener: the SPIFFE X.509 source is not open (got %T)", d.spiffeX509Source)
	}
	if d.publicGateways.agent.URL == "" {
		return nil, errors.New("A2A listener: the public URL of the Agent gateway is not set")
	}

	// The executor reads the job store for each call, since the data pool starts
	// after the daemon builds the executor. The runs read it the same way.
	runs := newA2ARuns(d.brainRegistry, d.brainExecutor, func() (job.Store, error) {
		if d.brainExecutor.jobs == nil {
			return nil, errors.New("this daemon serves no jobs")
		}
		return d.brainExecutor.jobs()
	})
	handler := a2aserver.NewHandler(runs, registryCards{registry: d.compRegistry, gatewayURL: d.publicGateways.agent.URL})

	tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeID(gateway))
	tlsCfg.MinVersion = tls.VersionTLS13
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("A2A listener: listen on %s: %w", addr, err)
	}
	return &httpSubsystem{
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    64 << 10,
		},
		listener:            tls.NewListener(lis, tlsCfg),
		logger:              d.logger,
		gracefulStopTimeout: 10 * time.Second,
	}, nil
}
