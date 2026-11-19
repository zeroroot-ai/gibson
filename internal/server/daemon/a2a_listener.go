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
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/agentcard"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
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
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.gracefulStopTimeout)
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
// The interface URL of the card is the A2A endpoint on the public Agent gateway,
// the same URL that ResolveAgent gives (GatewayInfo.URLFor), so it has the prefix
// that the Edge routes.
type registryCards struct {
	registry component.ComponentRegistry
	gateway  component.GatewayInfo
}

var _ a2aserver.Cards = registryCards{}

// Card returns the card of the first live instance of the agent that the tenant
// can see. A name with no instance has no card.
func (c registryCards) Card(ctx context.Context, tenant, name string) (*a2a.AgentCard, error) {
	info, err := agentCardInfo(ctx, c.registry, tenant, name)
	if err != nil {
		return nil, err
	}
	card, err := agentcard.Build(info, c.gateway.URLFor(agentcall.RouteA2A))
	if err != nil {
		return nil, fmt.Errorf("build the card of agent %s: %w", name, err)
	}
	return card, nil
}

// agentCardInfo returns the catalog entry of the first live instance of an agent
// that the tenant can see. A name with no instance has no card, and the error
// is a2aserver.ErrNoCard. The card of a gateway call and the card of an inbound
// call come from the same entry.
func agentCardInfo(
	ctx context.Context, registry component.ComponentRegistry, tenant, name string,
) (component.ComponentInfo, error) {
	instances, err := registry.Discover(ctx, tenant, "agent", name)
	if err != nil {
		return component.ComponentInfo{}, fmt.Errorf("discover agent %s: %w", name, err)
	}
	if len(instances) == 0 {
		return component.ComponentInfo{}, a2aserver.ErrNoCard
	}
	return instances[0], nil
}

// buildA2AServer builds the A2A listener (gibson#1400). It has its own port.
// The TLS layer accepts the one SPIFFE ID of the Agent gateway and no other
// peer. The listener is required. A missing setting stops the daemon at start.
func (d *daemonImpl) buildA2AServer() (*httpSubsystem, error) {
	svid := strings.TrimSpace(os.Getenv(EnvA2AGatewaySVID))
	if svid == "" {
		return nil, fmt.Errorf("A2A listener: %s is not set. Set it to the SPIFFE ID of the Agent gateway",
			EnvA2AGatewaySVID)
	}
	addr := strings.TrimSpace(os.Getenv(EnvA2AAddr))
	if addr == "" {
		return nil, fmt.Errorf("A2A listener: %s is not set. Set it to the listen address, for example \":8443\"",
			EnvA2AAddr)
	}
	gateway, err := spiffeid.FromString(svid)
	if err != nil {
		return nil, fmt.Errorf("A2A listener: %s is not a SPIFFE ID: %w", EnvA2AGatewaySVID, err)
	}
	if d.brainRegistry == nil || d.brainExecutor == nil {
		return nil, errors.New("A2A listener: the brain is not available")
	}
	tlsCfg, err := d.peerTLSConfig("A2A listener", gateway)
	if err != nil {
		return nil, err
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
	handler := a2aserver.NewHandler(runs, registryCards{registry: d.compRegistry, gateway: d.publicGateways.agent})

	lis, err := listenTLS("A2A listener", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return d.newHTTPSubsystem(handler, lis), nil
}

// peerTLSConfig builds the TLS config of an A2A listener. The config accepts the
// one SPIFFE ID of the peer and no other. It needs SPIFFE mTLS, a peer inside the
// trust domain of the install, and an open X.509 source.
func (d *daemonImpl) peerTLSConfig(label string, peer spiffeid.ID) (*tls.Config, error) {
	if d.config.Auth.SPIFFE == nil || d.config.Auth.SPIFFE.WorkloadAPISocket == "" {
		return nil, fmt.Errorf("%s: the peer identity needs SPIFFE mTLS, and SPIFFE is not configured", label)
	}
	if td := d.spiffeTrustDomain(); !peer.MemberOf(td) {
		return nil, fmt.Errorf("%s: %s is not in the trust domain %s", label, peer, td)
	}
	x509Source, ok := d.spiffeX509Source.(x509Source)
	if !ok || x509Source == nil || isNilWorkloadSource(d.spiffeX509Source) {
		return nil, fmt.Errorf("%s: the SPIFFE X.509 source is not open (got %T)", label, d.spiffeX509Source)
	}
	cfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeID(peer))
	cfg.MinVersion = tls.VersionTLS13
	return cfg, nil
}

// x509Source is the SVID and the trust bundles that an A2A listener serves with.
// *workloadapi.X509Source is the one production value.
type x509Source interface {
	x509svid.Source
	x509bundle.Source
}

// isNilWorkloadSource reports a nil *workloadapi.X509Source inside the interface.
func isNilWorkloadSource(v any) bool {
	w, ok := v.(*workloadapi.X509Source)
	return ok && w == nil
}

// listenTLS listens on addr and serves TLS with the config.
func listenTLS(label, addr string, cfg *tls.Config) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: listen on %s: %w", label, addr, err)
	}
	return tls.NewListener(lis, cfg), nil
}

// newHTTPSubsystem wraps a handler and a listener in the lifecycle of an A2A
// listener.
func (d *daemonImpl) newHTTPSubsystem(handler http.Handler, lis net.Listener) *httpSubsystem {
	return &httpSubsystem{
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			// A request is small (the body limit of the inbound endpoint is 1 MiB), so
			// 30 seconds read it. The server has no write timeout, because a result
			// can be large. The inbound handler sets a write deadline for each
			// response (a2aserver.InboundWriteFloor, and more for a large result), and
			// the permits of the inbound runs bound the results in work.
			ReadTimeout:    30 * time.Second,
			IdleTimeout:    2 * time.Minute,
			MaxHeaderBytes: 64 << 10,
		},
		listener:            lis,
		logger:              d.logger,
		gracefulStopTimeout: 10 * time.Second,
	}
}
