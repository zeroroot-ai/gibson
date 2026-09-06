// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
)

// brokerCandidateWarner is the narrow logging surface
// newBrokerCandidateFactories needs. An interface rather than the concrete
// *observability.Logger so the factory can be built and exercised without a
// daemon.
type brokerCandidateWarner interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// newBrokerCandidateFactories builds the provider-factory map for the
// broker-config CANDIDATE path.
//
// The map has exactly two consumers, and both probe a config the caller
// supplied: ConfigStore.Set's probe-before-persist step, and — via
// admin.NewMapProbeFactory in grpc.go — the TenantAdminServer's
// ProbeBrokerConfig / SetBrokerConfig handlers. In both, the Vault address
// arrives as a field in a tenant admin's RPC, and probing it means dialling it
// and presenting credentials to whatever answers.
//
// So the providers are constructed through sdkvault.NewGuarded: the resolved
// address is vetted before connect(2), on the first hop and on every redirect,
// and refused when it is loopback, link-local (which includes the cloud
// metadata service), private, CGNAT, multicast or reserved.
//
// The registry factory in initBrokerStack is deliberately NOT built this way.
// It constructs providers from rows already in the store, and the platform's
// own namespace-mode row — written directly to the platform database by the
// tenant-operator's provisioning saga, never through this path — points at the
// in-cluster Vault Service, an RFC1918 ClusterIP in every deployment profile.
// Guarding that would refuse every install's platform broker.
//
// allowPrivate comes from security.allow_private_broker_endpoints and is off by
// default. It exists for the one case that would otherwise regress: a
// self-hosted install whose tenants legitimately point BYO Vault at an
// in-cluster address. Turning it on is logged, because it is an operator
// widening the daemon's egress on someone else's behalf.
func newBrokerCandidateFactories(ctx context.Context, allowPrivate bool, log brokerCandidateWarner) map[string]secrets.ProviderFactory {
	if allowPrivate && log != nil {
		log.Warn(ctx, "broker stack: security.allow_private_broker_endpoints is on; "+
			"tenant-supplied broker addresses may resolve to internal destinations")
	}
	// Vault is the only broker backend (Hosted namespace mode + BYO
	// path-prefix mode); the AWS/GCP/Azure backends were removed in
	// gibson#1109.
	return map[string]secrets.ProviderFactory{
		"vault": func(blob []byte) (sdksecrets.Broker, error) {
			var cfg sdkvault.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("vault: unmarshal config: %w", err)
			}
			if allowPrivate {
				return sdkvault.New(ctx, cfg)
			}
			return sdkvault.NewGuarded(ctx, cfg)
		},
	}
}
