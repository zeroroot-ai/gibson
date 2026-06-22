package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/secrets/configstore"
)

// ErrBrokerConfigNotFound is returned by ConfigStore.Get when no
// configuration row exists for the requested tenant. Re-exported from the
// configstore sub-package so callers under internal/secrets/* don't need
// to import the sub-package directly.
var ErrBrokerConfigNotFound = configstore.ErrNotFound

// BrokerConfig is the decrypted, in-memory representation of a tenant's
// broker configuration. Provider is the short provider name ("postgres",
// "vault", "awssm", "gcpsm", "azurekv"). ConfigBlob is the raw JSON bytes
// of the provider-specific configuration (before encryption). The blob is
// never persisted in plaintext — configstore.Store.SetRaw encrypts it
// before writing.
type BrokerConfig struct {
	// Provider is one of: "vault", "awssm", "gcpsm", "azurekv".
	Provider string

	// ConfigBlob is the raw JSON of the provider-specific configuration
	// containing auth credentials and connection parameters. This field is
	// the envelope payload — callers must treat it as opaque bytes and never
	// log it.
	ConfigBlob []byte
}

// ProviderFactory is a function that constructs a SecretsBroker from a raw
// JSON config blob. It is used by ConfigStore.Set to probe the candidate
// provider before persisting its configuration.
type ProviderFactory func(configBlob []byte) (sdksecrets.Broker, error)

// ConfigStoreAuditWriter is the narrow interface ConfigStore uses to emit
// audit events. The concrete implementation is AuditWriter (audit.go);
// tests inject a fake.
type ConfigStoreAuditWriter interface {
	Audit(ctx context.Context, event AuditEvent)
}

// ConfigStore provides Get/Set/Delete operations for per-tenant broker
// configurations. Set runs a Probe against the candidate provider before
// persisting; failure aborts the write and returns a structured error.
//
// ConfigStore is safe for concurrent use.
type ConfigStore struct {
	store     *configstore.Store
	factories map[string]ProviderFactory
	auditor   ConfigStoreAuditWriter
}

// NewConfigStore constructs a ConfigStore. store is the underlying row
// store; factories maps each provider name to its constructor (used by Set
// to probe the candidate). auditor receives audit events on Set and Delete;
// it must never be nil.
func NewConfigStore(
	store *configstore.Store,
	factories map[string]ProviderFactory,
	auditor ConfigStoreAuditWriter,
) (*ConfigStore, error) {
	if store == nil {
		return nil, errors.New("config store: underlying store must not be nil")
	}
	if auditor == nil {
		return nil, errors.New("config store: auditor must not be nil")
	}
	if factories == nil {
		factories = make(map[string]ProviderFactory)
	}
	return &ConfigStore{
		store:     store,
		factories: factories,
		auditor:   auditor,
	}, nil
}

// Get retrieves the BrokerConfig for the given tenant. Returns
// ErrBrokerConfigNotFound when no configuration row exists.
func (cs *ConfigStore) Get(ctx context.Context, tenant auth.TenantID) (BrokerConfig, error) {
	provider, blob, err := cs.store.GetRaw(ctx, tenant)
	if err != nil {
		if errors.Is(err, ErrBrokerConfigNotFound) {
			return BrokerConfig{}, ErrBrokerConfigNotFound
		}
		return BrokerConfig{}, fmt.Errorf("config store: get tenant %s: %w", tenant, err)
	}
	return BrokerConfig{Provider: provider, ConfigBlob: blob}, nil
}

// Set validates, probes, and persists the given BrokerConfig for the tenant.
// The Probe step constructs a candidate provider via the registered factory
// and calls provider.Probe(ctx). Only on a successful probe is the config
// row written.
//
// actor is the operator principal ID stored in created_by / updated_by and
// included in the audit event. Pass auth.SystemTenant.String() for
// daemon-internal writes.
//
// Returns a structured error when:
//   - the provider name is not registered in the factory map
//   - the configBlob is not valid JSON
//   - provider construction fails
//   - the probe fails
//   - the database write fails
func (cs *ConfigStore) Set(ctx context.Context, tenant auth.TenantID, cfg BrokerConfig, actor string) error {
	start := time.Now()

	// Validate the config blob is parseable JSON (provider-specific
	// structure is validated inside the factory, but we catch obvious
	// malformed blobs here).
	if len(cfg.ConfigBlob) > 0 {
		var check json.RawMessage
		if err := json.Unmarshal(cfg.ConfigBlob, &check); err != nil {
			return fmt.Errorf("config store: set tenant %s: config blob is not valid JSON: %w", tenant, err)
		}
	}

	factory, ok := cs.factories[cfg.Provider]
	if !ok {
		return fmt.Errorf("config store: set tenant %s: unknown provider %q (registered: %v)", tenant, cfg.Provider, registeredProviders(cs.factories))
	}

	// Construct a candidate provider and probe it.
	candidate, err := factory(cfg.ConfigBlob)
	if err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID:        actor,
			ActorTenantID:  tenant.String(),
			Action:         ActionSecretConfigSet,
			Effect:         EffectDeny,
			ResourceType:   "secret_broker_config",
			ResourceURI:    "secret_broker_config:tenant-" + tenant.String(),
			Decision:       "deny",
			DecisionReason: "provider_construct_failed",
			Success:        false,
			ErrorCode:      "provider_construct_failed",
			LatencyMS:      time.Since(start).Milliseconds(),
			OccurredAt:     time.Now().UTC(),
		})
		return fmt.Errorf("config store: set tenant %s: construct provider %q: %w", tenant, cfg.Provider, err)
	}

	if err := candidate.Probe(ctx); err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID:        actor,
			ActorTenantID:  tenant.String(),
			Action:         ActionSecretConfigSet,
			Effect:         EffectDeny,
			ResourceType:   "secret_broker_config",
			ResourceURI:    "secret_broker_config:tenant-" + tenant.String(),
			Decision:       "deny",
			DecisionReason: "probe_failed",
			Success:        false,
			ErrorCode:      "probe_failed",
			LatencyMS:      time.Since(start).Milliseconds(),
			OccurredAt:     time.Now().UTC(),
		})
		return fmt.Errorf("config store: set tenant %s: probe provider %q: %w", tenant, cfg.Provider, err)
	}

	// Probe succeeded — persist.
	if err := cs.store.SetRaw(ctx, tenant, cfg.Provider, cfg.ConfigBlob, actor); err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID:        actor,
			ActorTenantID:  tenant.String(),
			Action:         ActionSecretConfigSet,
			Effect:         EffectDeny,
			ResourceType:   "secret_broker_config",
			ResourceURI:    "secret_broker_config:tenant-" + tenant.String(),
			Decision:       "deny",
			DecisionReason: "db_write_failed",
			Success:        false,
			ErrorCode:      "db_write_failed",
			LatencyMS:      time.Since(start).Milliseconds(),
			OccurredAt:     time.Now().UTC(),
		})
		return fmt.Errorf("config store: set tenant %s: persist: %w", tenant, err)
	}

	cs.auditor.Audit(ctx, AuditEvent{
		ActorID:       actor,
		ActorTenantID: tenant.String(),
		Action:        ActionSecretConfigSet,
		Effect:        EffectAllow,
		ResourceType:  "secret_broker_config",
		ResourceURI:   "secret_broker_config:tenant-" + tenant.String(),
		Decision:      "allow",
		Success:       true,
		LatencyMS:     time.Since(start).Milliseconds(),
		OccurredAt:    time.Now().UTC(),
	})
	return nil
}

// Delete removes the broker config for the given tenant. It is a no-op when
// no config row exists. An audit event is emitted on both success and failure.
//
// actor is the operator principal ID stored in updated_by.
func (cs *ConfigStore) Delete(ctx context.Context, tenant auth.TenantID, actor string) error {
	start := time.Now()

	if err := cs.store.DeleteRaw(ctx, tenant); err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID:        actor,
			ActorTenantID:  tenant.String(),
			Action:         ActionSecretConfigSet,
			Effect:         EffectDeny,
			ResourceType:   "secret_broker_config",
			ResourceURI:    "secret_broker_config:tenant-" + tenant.String(),
			Decision:       "deny",
			DecisionReason: "db_delete_failed",
			Success:        false,
			ErrorCode:      "db_delete_failed",
			LatencyMS:      time.Since(start).Milliseconds(),
			OccurredAt:     time.Now().UTC(),
		})
		return fmt.Errorf("config store: delete tenant %s: %w", tenant, err)
	}

	cs.auditor.Audit(ctx, AuditEvent{
		ActorID:       actor,
		ActorTenantID: tenant.String(),
		Action:        ActionSecretConfigSet,
		Effect:        EffectAllow,
		ResourceType:  "secret_broker_config",
		ResourceURI:   "secret_broker_config:tenant-" + tenant.String(),
		Decision:      "allow",
		Success:       true,
		LatencyMS:     time.Since(start).Milliseconds(),
		OccurredAt:    time.Now().UTC(),
	})
	return nil
}

// registeredProviders returns the keys of the factory map as a slice for use
// in error messages.
func registeredProviders(factories map[string]ProviderFactory) []string {
	names := make([]string, 0, len(factories))
	for k := range factories {
		names = append(names, k)
	}
	return names
}
