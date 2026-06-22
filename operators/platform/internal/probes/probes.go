// Package probes provides readiness.Probe implementations for platform-operator
// dependencies. These probes are registered with the readiness.Aggregator in
// main.go so that /readyz returns 503 when Vault or Zitadel is unreachable.
package probes

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// probeHTTPClient is the shared HTTP client for probe checks. Short timeout so
// a hung dependency doesn't block the readyz response chain.
var probeHTTPClient = &http.Client{Timeout: 5 * time.Second}

// VaultProbe implements readiness.Probe against the Vault health endpoint.
// It hits /v1/sys/health?standbyok=true (returns 200 on active, 429 on
// standby — both mean "Vault is up"). 503 or a network error means Vault is
// unreachable.
type VaultProbe struct {
	Address string // e.g. "http://gibson-vault:8200"
}

// Name implements readiness.Probe.
func (p *VaultProbe) Name() string { return "vault" }

// Check implements readiness.Probe. Returns nil when Vault responds with any
// 2xx or 429 (standby). Returns an error on network failure or other status
// codes that indicate Vault is sealed or unavailable.
func (p *VaultProbe) Check(ctx context.Context) error {
	url := p.Address + "/v1/sys/health?standbyok=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("vault probe: build request: %w", err)
	}
	resp, err := probeHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// 200 = active, 429 = standby (still healthy from our POV),
	// 472 = disaster-recovery mode — treat all < 500 as healthy.
	if resp.StatusCode >= 500 {
		return fmt.Errorf("vault health status %d", resp.StatusCode)
	}
	return nil
}

// ZitadelProbe implements readiness.Probe against Zitadel's readiness endpoint.
// It hits /debug/ready which returns 200 when Zitadel is accepting traffic.
//
// Address MUST be the IN-CLUSTER Zitadel service URL
// (e.g. "http://gibson-zitadel.gibson.svc:8080"), NOT the external OIDC issuer.
// The external origin (app.<domain>) does not resolve from inside the pod, and
// Envoy does not route /debug/ to Zitadel — so probing the issuer always 503s
// the operator (deploy#630 single-host consolidation; platform-operator#76).
// The operator already reaches Zitadel via this service for its admin client.
type ZitadelProbe struct {
	Address string // in-cluster service, e.g. "http://gibson-zitadel.gibson.svc:8080"
}

// Name implements readiness.Probe.
func (p *ZitadelProbe) Name() string { return "zitadel" }

// Check implements readiness.Probe. Returns nil when Zitadel's /debug/ready
// returns 200. Returns an error on network failure or non-200 status.
func (p *ZitadelProbe) Check(ctx context.Context) error {
	url := p.Address + "/debug/ready"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("zitadel probe: build request: %w", err)
	}
	resp, err := probeHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("zitadel /debug/ready status %d", resp.StatusCode)
	}
	return nil
}
