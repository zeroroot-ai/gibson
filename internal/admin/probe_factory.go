// Package admin — probe_factory.go
//
// MapProbeFactory adapts a map[string]secrets.ProviderFactory (the shape
// initBrokerStack already builds for ConfigStore.Set's probe step) to the
// ProviderProbeFactory interface that TenantAdminServer expects.
// initBrokerStack stores the map on daemonImpl.brokerFactories and
// internal/daemon/grpc.go wraps it via NewMapProbeFactory before calling
// admin.NewTenantAdminServer.
//
// Spec: tenant-secrets-broker-completion (Task 11).
package admin

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/secrets"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
)

// MapProbeFactory implements ProviderProbeFactory by looking up the
// provider name in a map of ProviderFactory closures.
type MapProbeFactory struct {
	factories map[string]secrets.ProviderFactory
}

// NewMapProbeFactory wraps factories so the TenantAdminServer's probe
// path can call factories by provider name.
func NewMapProbeFactory(factories map[string]secrets.ProviderFactory) *MapProbeFactory {
	return &MapProbeFactory{factories: factories}
}

// Construct looks up the named factory and invokes it with the config
// blob. Returns an error when the provider is not registered.
func (m *MapProbeFactory) Construct(provider string, configBlob []byte) (sdksecrets.Broker, error) {
	if m == nil || m.factories == nil {
		return nil, fmt.Errorf("probe factory: factories map is nil")
	}
	f, ok := m.factories[provider]
	if !ok {
		return nil, fmt.Errorf("probe factory: unknown provider %q", provider)
	}
	return f(configBlob)
}
