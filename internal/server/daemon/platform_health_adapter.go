// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// openbaoHealthProbe asks the secret backend of the platform, the OpenBao
// server that the chart configures, to answer now. It calls the health
// endpoint of the server, with no token and no tenant. It does not read
// tenant_secrets_broker_config: no row there names the platform backend,
// and asking the broker of the system tenant made the start gate wait
// forever on a new install (gibson#1078). A problem of one tenant's broker
// shows in the health of that tenant, never in the readiness of the daemon.
type openbaoHealthProbe struct {
	address string
	client  *http.Client
}

var _ api.SecretPlaneProbe = (*openbaoHealthProbe)(nil)

// newOpenBaoHealthProbe returns the probe of the configured secret backend.
// The client trusts the system roots, which include the OpenBao CA through
// SSL_CERT_DIR. The caller bounds each call with its context.
func newOpenBaoHealthProbe(address string) *openbaoHealthProbe {
	return &openbaoHealthProbe{
		address: strings.TrimRight(address, "/"),
		client:  &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
	}
}

// Probe calls /v1/sys/health. A standby answers 200 with standbyok and
// perfstandbyok set, so only an active or standby server that is
// initialized and unsealed passes. Every other answer, and silence, fails.
func (p *openbaoHealthProbe) Probe(ctx context.Context) error {
	if p.address == "" {
		return errors.New("security.secret_source.address is not set: the daemon has no secret backend to ask")
	}
	url := p.address + "/v1/sys/health?standbyok=true&perfstandbyok=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build the health request of %s: %w", p.address, err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("ask the secret backend %s: %w", p.address, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotImplemented:
		return fmt.Errorf("the secret backend %s is not initialized (status 501)", p.address)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("the secret backend %s is sealed (status 503)", p.address)
	default:
		return fmt.Errorf("the secret backend %s answered status %d", p.address, resp.StatusCode)
	}
}

// secretSourceReadiness is the readiness check of the secret source. It is
// a start gate (hosted#174): each call probes the source with the bound of
// AdminGetPlatformHealth, and the daemon is not ready until a probe passes.
// After the first pass a failed probe does not change readiness. A short
// outage of the source must not take every daemon pod out of its Service at
// once, while the pods still serve on the secrets they loaded. That failure
// shows on AdminGetPlatformHealth and in the ExternalSecretNotReady alert.
func secretSourceReadiness(probe api.SecretPlaneProbe) func(context.Context) sdktypes.HealthStatus {
	var passed atomic.Bool
	return func(ctx context.Context) sdktypes.HealthStatus {
		probeCtx, cancel := context.WithTimeout(ctx, api.SecretPlaneProbeTimeout)
		defer cancel()
		err := probe.Probe(probeCtx)
		switch {
		case err == nil:
			passed.Store(true)
			return sdktypes.NewHealthyStatus("broker: the secret backend answered")
		case !passed.Load():
			return sdktypes.NewUnhealthyStatus("broker: the secret backend has not answered since start: "+err.Error(), nil)
		default:
			return sdktypes.NewHealthyStatus("broker: the secret source did not answer; the daemon serves on its loaded secrets, see the platform health: " + err.Error())
		}
	}
}

// secretBackendProbe returns the probe of the secret backend that the
// configuration names. The readiness check and AdminGetPlatformHealth share
// it, so both ask the same backend.
func (d *daemonImpl) secretBackendProbe() api.SecretPlaneProbe {
	return newOpenBaoHealthProbe(d.config.Security.SecretSource.Address)
}
