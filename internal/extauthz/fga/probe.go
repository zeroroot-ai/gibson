// Package fga: readiness probe.
//
// readiness.Probe implementation that does a single Check against a
// well-formed but intentionally non-existent canary tuple. This is the
// /readyz signal Kubernetes uses to pull traffic off the pod when
// OpenFGA is unreachable — distinct from /healthz (process liveness)
// which only signals the runtime is not deadlocked.
//
// Audit finding closed: ext-authz previously exposed only /healthz, so
// kubelet kept routing requests at the pod even when every FGA Check
// returned codes.Unavailable. The aggregator-wired /readyz now returns
// 503 on FGA unreachability and Kubernetes pulls the pod from
// service-endpoints within the readinessProbe period.
package fga

import (
	"context"
	"errors"
	"fmt"

	fgaclient "github.com/openfga/go-sdk/client"
)

// CanaryUser is the sentinel FGA user used by the readiness probe and
// startup self-check. Naming makes it obvious in OpenFGA audit logs.
const (
	CanaryUser     = "user:__ext_authz_readiness__"
	CanaryRelation = "owner"
	CanaryObject   = "tenant:__ext_authz_readiness__"
)

// ReadinessProbe is a readiness.Probe (Name() + Check(ctx)) that calls
// FGA Check against a non-existent canary tuple. {"allowed":false} is
// the success signal — we only care that the HTTP round-trip completed.
type ReadinessProbe struct {
	client FGAClient
	name   string
}

// NewReadinessProbe wraps client behind a Name() string for the
// readiness aggregator. name defaults to "fga" when empty.
func NewReadinessProbe(client FGAClient, name string) *ReadinessProbe {
	if name == "" {
		name = "fga"
	}
	return &ReadinessProbe{client: client, name: name}
}

// Name returns the probe identifier surfaced in /readyz JSON.
func (p *ReadinessProbe) Name() string { return p.name }

// Check runs a canary FGA Check and returns nil iff the call completed
// without a transport-class error. Deadline is taken from ctx.
func (p *ReadinessProbe) Check(ctx context.Context) error {
	if p.client == nil {
		return errors.New("fga.ReadinessProbe: client is nil")
	}
	_, err := p.client.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User:     CanaryUser,
		Relation: CanaryRelation,
		Object:   CanaryObject,
	}).Execute()
	if err == nil {
		return nil
	}
	return fmt.Errorf("fga readiness probe: %w", err)
}
