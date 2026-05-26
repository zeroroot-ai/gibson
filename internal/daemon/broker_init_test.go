package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/sdk/auth"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// TestDaemonStartup_BrokerStack_NoKeyProvider verifies that the daemon can be
// created (Task 29) when no key provider is configured. The broker stack is
// gracefully skipped; secretsRegistry and secretsService remain nil.
func TestDaemonStartup_BrokerStack_NoKeyProvider(t *testing.T) {
	t.Parallel()

	cfg := minimalCfg()
	cfg.Security.KeyProvider = nil // no key provider = broker stack skipped

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	impl := d.(*daemonImpl)

	// secretsRegistry is nil when no key provider is configured.
	if impl.secretsRegistry != nil {
		t.Error("secretsRegistry should be nil when no key provider is configured")
	}
	if impl.secretsService != nil {
		t.Error("secretsService should be nil when no key provider is configured")
	}
	// credentialStore and credentialHandler also remain nil until broker wired.
	if impl.credentialStore != nil {
		t.Error("credentialStore should be nil before broker stack is initialized")
	}
	if impl.credentialHandler != nil {
		t.Error("credentialHandler should be nil before broker stack is initialized")
	}
}

// TestNoopRegistryConfigGetter_GetReturnsNotFound confirms the noop getter
// returns ErrBrokerConfigNotFound so the registry defaults every tenant to
// the Postgres provider (Task 29 fallback requirement).
func TestNoopRegistryConfigGetter_GetReturnsNotFound(t *testing.T) {
	t.Parallel()

	var getter secrets.RegistryConfigGetter = &noopRegistryConfigGetter{}
	_, err := getter.Get(context.Background(), auth.SystemTenant)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !isErrBrokerConfigNotFound(err) {
		t.Errorf("expected ErrBrokerConfigNotFound; got %v", err)
	}
}

// isErrBrokerConfigNotFound checks whether err is or wraps ErrBrokerConfigNotFound.
func isErrBrokerConfigNotFound(err error) bool {
	return err != nil && err.Error() == secrets.ErrBrokerConfigNotFound.Error()
}

// TestBrokerHealthGauge_RegisteredOnce verifies the Prometheus gauge vector
// for broker health (Task 30) can be accessed without panicking.
func TestBrokerHealthGauge_RegisteredOnce(t *testing.T) {
	t.Parallel()
	// Obtain a gauge for a fake (tenant, provider) pair.
	gauge := brokerHealthGauge.WithLabelValues("test-tenant", "vault")
	if gauge == nil {
		t.Fatal("brokerHealthGauge gauge must not be nil")
	}
	// Write 0 (healthy) to confirm the metric accepts writes.
	gauge.Set(0)
}

// TestBrokerReadyzStatus_Healthy verifies that the sdktypes.NewHealthyStatus
// helper used in the /readyz broker check (Task 30) works correctly.
func TestBrokerReadyzStatus_Healthy(t *testing.T) {
	t.Parallel()

	s := sdktypes.NewHealthyStatus("broker: test healthy")
	if !s.IsHealthy() {
		t.Errorf("NewHealthyStatus should report IsHealthy=true; got %v", s)
	}
}

// TestBrokerReadyzStatus_Unhealthy verifies that the sdktypes.NewUnhealthyStatus
// helper used in the /readyz broker check (Task 30) works correctly.
func TestBrokerReadyzStatus_Unhealthy(t *testing.T) {
	t.Parallel()

	s := sdktypes.NewUnhealthyStatus("broker: test unhealthy", nil)
	if s.IsHealthy() {
		t.Errorf("NewUnhealthyStatus should report IsHealthy=false; got %v", s)
	}
}
