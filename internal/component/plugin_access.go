package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/crypto"
)

// Sentinel errors for plugin access operations.
var (
	ErrPluginNotEnabled    = errors.New("plugin not enabled for tenant")
	ErrPluginNotConfigured = errors.New("plugin enabled but not configured")
	ErrPluginAlreadyExists = errors.New("plugin access record already exists")
	ErrPluginAccessDenied  = errors.New("plugin access level not granted for tenant")
)

// PluginAccess represents a tenant's opt-in record for a plugin.
//
// ReadEnabled and WriteEnabled provide fine-grained access control within an
// enabled plugin. When both are false (legacy records where only Enabled is
// true), the effective access is read+write for backward compatibility. New
// records should always set at least one of ReadEnabled or WriteEnabled
// explicitly; callers should use EffectiveReadEnabled / EffectiveWriteEnabled
// (or CheckAccess) rather than reading these fields directly.
type PluginAccess struct {
	TenantID      string `json:"tenant_id"`
	PluginName    string `json:"plugin_name"`
	Enabled       bool   `json:"enabled"`
	ReadEnabled   bool   `json:"read_enabled"`
	WriteEnabled  bool   `json:"write_enabled"`
	Source        string `json:"source"` // "platform" or "self-hosted"
	ConfiguredAt  string `json:"configured_at,omitempty"`
	ConfiguredBy  string `json:"configured_by,omitempty"`
	HasConfig     bool   `json:"has_config"`
}

// EffectiveReadEnabled returns whether the tenant has read access to the plugin,
// applying backward-compat logic: if both ReadEnabled and WriteEnabled are false
// but Enabled is true (a legacy record), read access is implicitly granted.
func (a *PluginAccess) EffectiveReadEnabled() bool {
	if !a.Enabled {
		return false
	}
	// Legacy record: neither granular flag is set — treat as full access.
	if !a.ReadEnabled && !a.WriteEnabled {
		return true
	}
	return a.ReadEnabled
}

// EffectiveWriteEnabled returns whether the tenant has write access to the
// plugin, applying the same backward-compat logic as EffectiveReadEnabled.
func (a *PluginAccess) EffectiveWriteEnabled() bool {
	if !a.Enabled {
		return false
	}
	// Legacy record: neither granular flag is set — treat as full access.
	if !a.ReadEnabled && !a.WriteEnabled {
		return true
	}
	return a.WriteEnabled
}

// PluginCatalogEntry describes a plugin available to a tenant, combining
// registry info with access status.
type PluginCatalogEntry struct {
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Description   string   `json:"description"`
	Methods       []string `json:"methods"`
	ConfigSchema  string   `json:"config_schema,omitempty"` // JSON Schema
	Enabled       bool     `json:"enabled"`
	Configured    bool     `json:"configured"`
	HealthStatus  string   `json:"health_status"`
	Source        string   `json:"source"` // "platform" or "self-hosted"
	InstanceCount int      `json:"instance_count"`
}

// encryptedConfig holds the encrypted form of a plugin's per-tenant config.
type encryptedConfig struct {
	Ciphertext []byte `json:"ciphertext"`
	IV         []byte `json:"iv"`
	Salt       []byte `json:"salt"`
}

// PluginAccessStore manages tenant opt-in and encrypted configuration for
// platform-hosted plugins.
type PluginAccessStore interface {
	// Enable grants a tenant access to a _system plugin and stores their config.
	// ReadEnabled and writeEnabled control the granular access flags; when both
	// are false the record is stored with Enabled=true and no granular flags,
	// which is treated as full read+write access (legacy behavior).
	Enable(ctx context.Context, tenant, pluginName string, config map[string]any, configuredBy string) error

	// Disable removes access and deletes stored config.
	Disable(ctx context.Context, tenant, pluginName string) error

	// SetAccessGranularity updates the ReadEnabled/WriteEnabled toggles for an
	// already-enabled plugin without touching its configuration. Returns
	// ErrPluginNotEnabled if the plugin has not been enabled first.
	SetAccessGranularity(ctx context.Context, tenant, pluginName string, readEnabled, writeEnabled bool) error

	// CheckAccess returns nil if the tenant has the requested access level for
	// the plugin. Pass write=false for read-only operations and write=true for
	// mutations. Returns ErrPluginNotEnabled if the plugin is not enabled at all,
	// or ErrPluginAccessDenied if the requested level is not granted.
	CheckAccess(ctx context.Context, tenant, pluginName string, write bool) error

	// GetAccess returns the access record for a tenant+plugin.
	// Returns ErrPluginNotEnabled if no record exists.
	GetAccess(ctx context.Context, tenant, pluginName string) (*PluginAccess, error)

	// GetDecryptedConfig returns the decrypted config for an enabled plugin.
	// Returns ErrPluginNotEnabled if not enabled, ErrPluginNotConfigured if enabled but no config.
	GetDecryptedConfig(ctx context.Context, tenant, pluginName string) (map[string]any, error)

	// GetMaskedConfig returns the config with secret fields masked for API responses.
	GetMaskedConfig(ctx context.Context, tenant, pluginName string) (map[string]any, error)

	// UpdateConfig replaces the stored config for an already-enabled plugin.
	UpdateConfig(ctx context.Context, tenant, pluginName string, config map[string]any, configuredBy string) error

	// ListTenantPlugins returns all plugins the tenant has access to.
	ListTenantPlugins(ctx context.Context, tenant string) ([]PluginAccess, error)

	// ListAvailablePlugins returns all _system plugins with the tenant's enablement status.
	ListAvailablePlugins(ctx context.Context, tenant string) ([]PluginCatalogEntry, error)

	// EnableSelfHosted creates an access record for a self-hosted plugin.
	// Does not overwrite existing records.
	EnableSelfHosted(ctx context.Context, tenant, pluginName string) error

	// StoreConfigSchema stores a plugin's config schema (called on registration).
	StoreConfigSchema(ctx context.Context, pluginName, schemaJSON string) error

	// GetConfigSchema returns the stored config schema for a plugin.
	GetConfigSchema(ctx context.Context, pluginName string) (string, error)
}

// RedisPluginAccessStore implements PluginAccessStore using Redis for storage
// and AES-256-GCM for config encryption.
//
// An optional Casbin enforcer can be attached via SetEnforcer. When present,
// Enable and Disable sync Casbin policies for the "tenant-admin" subject so
// that the harness layer can enforce per-plugin read/write capabilities without
// additional Redis lookups.
type RedisPluginAccessStore struct {
	client      *redis.Client
	encryptor   crypto.Encryptor
	keyProvider crypto.KeyProvider
	registry    ComponentRegistry
	logger      *slog.Logger
	enforcer    *casbin.Enforcer // optional; nil disables Casbin sync
}

// SetEnforcer attaches a Casbin enforcer to the store. When non-nil, calls to
// Enable, Disable, and SetAccessGranularity will sync Casbin policies so that
// "tenant-admin" subjects gain or lose read/write capabilities for each plugin
// in real time. Passing nil disables Casbin sync (safe default).
func (s *RedisPluginAccessStore) SetEnforcer(e *casbin.Enforcer) {
	s.enforcer = e
}

// NewRedisPluginAccessStore creates a new store.
func NewRedisPluginAccessStore(
	client *redis.Client,
	encryptor crypto.Encryptor,
	keyProvider crypto.KeyProvider,
	registry ComponentRegistry,
	logger *slog.Logger,
) *RedisPluginAccessStore {
	return &RedisPluginAccessStore{
		client:      client,
		encryptor:   encryptor,
		keyProvider: keyProvider,
		registry:    registry,
		logger:      logger.With("component", "plugin_access_store"),
	}
}

func accessKey(tenant, pluginName string) string {
	return fmt.Sprintf("plugin-access:%s:%s", tenant, pluginName)
}

func configKey(tenant, pluginName string) string {
	return fmt.Sprintf("plugin-config:%s:%s", tenant, pluginName)
}

func schemaKey(pluginName string) string {
	return fmt.Sprintf("plugin-schema:%s", pluginName)
}

func accessPattern(tenant string) string {
	return fmt.Sprintf("plugin-access:%s:*", tenant)
}

// Enable implements PluginAccessStore.
//
// The access record is stored with Enabled=true. ReadEnabled and WriteEnabled
// are left as their zero values (false), so EffectiveReadEnabled and
// EffectiveWriteEnabled will both return true (legacy/full-access semantics).
// Call SetAccessGranularity after Enable to apply granular restrictions.
//
// If a Casbin enforcer is attached, Enable adds both read and write policies
// for the "tenant-admin" subject in the tenant domain.
func (s *RedisPluginAccessStore) Enable(ctx context.Context, tenant, pluginName string, config map[string]any, configuredBy string) error {
	s.logger.InfoContext(ctx, "enabling plugin for tenant",
		slog.String("tenant", tenant),
		slog.String("plugin", pluginName))

	access := PluginAccess{
		TenantID:     tenant,
		PluginName:   pluginName,
		Enabled:      true,
		Source:       "platform",
		ConfiguredAt: time.Now().UTC().Format(time.RFC3339),
		ConfiguredBy: configuredBy,
		HasConfig:    config != nil && len(config) > 0,
	}

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal access record: %w", err)
	}

	// Store access record (no TTL — persists until explicitly disabled).
	if err := s.client.Set(ctx, accessKey(tenant, pluginName), accessJSON, 0).Err(); err != nil {
		return fmt.Errorf("store access record: %w", err)
	}

	// Encrypt and store config if provided.
	if config != nil && len(config) > 0 {
		if err := s.storeEncryptedConfig(ctx, tenant, pluginName, config); err != nil {
			// Roll back access record on config storage failure.
			_ = s.client.Del(ctx, accessKey(tenant, pluginName)).Err()
			return fmt.Errorf("store encrypted config: %w", err)
		}
	}

	// Sync full read+write Casbin policies (legacy: no granular restrictions).
	s.syncCasbinEnable(ctx, tenant, pluginName, true, true)

	return nil
}

// Disable implements PluginAccessStore.
//
// Removes the access record and encrypted config from Redis. If a Casbin
// enforcer is attached, all policies for "tenant-admin" on this plugin resource
// are removed regardless of read/write state.
func (s *RedisPluginAccessStore) Disable(ctx context.Context, tenant, pluginName string) error {
	s.logger.InfoContext(ctx, "disabling plugin for tenant",
		slog.String("tenant", tenant),
		slog.String("plugin", pluginName))

	pipe := s.client.Pipeline()
	pipe.Del(ctx, accessKey(tenant, pluginName))
	pipe.Del(ctx, configKey(tenant, pluginName))
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("disable plugin: %w", err)
	}

	// Remove all Casbin policies for this plugin resource and tenant domain.
	s.syncCasbinDisable(ctx, tenant, pluginName)

	return nil
}

// GetAccess implements PluginAccessStore.
func (s *RedisPluginAccessStore) GetAccess(ctx context.Context, tenant, pluginName string) (*PluginAccess, error) {
	data, err := s.client.Get(ctx, accessKey(tenant, pluginName)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrPluginNotEnabled
		}
		return nil, fmt.Errorf("get access record: %w", err)
	}

	var access PluginAccess
	if err := json.Unmarshal(data, &access); err != nil {
		return nil, fmt.Errorf("unmarshal access record: %w", err)
	}

	return &access, nil
}

// SetAccessGranularity implements PluginAccessStore.
//
// Updates ReadEnabled and WriteEnabled on an existing access record without
// touching the configuration. Returns ErrPluginNotEnabled if the plugin has not
// been enabled first. If a Casbin enforcer is attached the policies are synced
// immediately: read/write policies are added for enabled levels and removed for
// disabled ones.
func (s *RedisPluginAccessStore) SetAccessGranularity(ctx context.Context, tenant, pluginName string, readEnabled, writeEnabled bool) error {
	access, err := s.GetAccess(ctx, tenant, pluginName)
	if err != nil {
		return err
	}

	access.ReadEnabled = readEnabled
	access.WriteEnabled = writeEnabled

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal access record: %w", err)
	}

	if err := s.client.Set(ctx, accessKey(tenant, pluginName), accessJSON, 0).Err(); err != nil {
		return fmt.Errorf("store access record: %w", err)
	}

	s.logger.InfoContext(ctx, "plugin access granularity updated",
		slog.String("tenant", tenant),
		slog.String("plugin", pluginName),
		slog.Bool("read_enabled", readEnabled),
		slog.Bool("write_enabled", writeEnabled),
	)

	// Sync Casbin policies to reflect the new access levels.
	if readEnabled || writeEnabled {
		s.syncCasbinEnable(ctx, tenant, pluginName, readEnabled, writeEnabled)
	} else {
		// Both disabled — remove all policies (equivalent to a full disable at the
		// Casbin level even though the Redis record remains for config retention).
		s.syncCasbinDisable(ctx, tenant, pluginName)
	}

	return nil
}

// CheckAccess implements PluginAccessStore.
//
// Returns nil if the tenant has the requested access level for the plugin.
// Returns ErrPluginNotEnabled if the plugin is not enabled at all.
// Returns ErrPluginAccessDenied if the plugin is enabled but the requested
// level (read or write) is not granted.
func (s *RedisPluginAccessStore) CheckAccess(ctx context.Context, tenant, pluginName string, write bool) error {
	access, err := s.GetAccess(ctx, tenant, pluginName)
	if err != nil {
		return err // propagates ErrPluginNotEnabled
	}

	if write {
		if !access.EffectiveWriteEnabled() {
			return ErrPluginAccessDenied
		}
		return nil
	}

	if !access.EffectiveReadEnabled() {
		return ErrPluginAccessDenied
	}
	return nil
}

// syncCasbinEnable adds Casbin allow policies for the "tenant-admin" role in
// the tenant domain for the given plugin resource. It is a best-effort
// operation: errors are logged but never returned to callers.
func (s *RedisPluginAccessStore) syncCasbinEnable(ctx context.Context, tenant, pluginName string, read, write bool) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("plugin:%s", pluginName)

	if read {
		if _, err := s.enforcer.AddPolicy("tenant-admin", tenant, resource, "read"); err != nil {
			s.logger.WarnContext(ctx, "casbin: failed to add read policy for plugin",
				slog.String("tenant", tenant),
				slog.String("plugin", pluginName),
				slog.String("error", err.Error()),
			)
		}
	}

	if write {
		if _, err := s.enforcer.AddPolicy("tenant-admin", tenant, resource, "write"); err != nil {
			s.logger.WarnContext(ctx, "casbin: failed to add write policy for plugin",
				slog.String("tenant", tenant),
				slog.String("plugin", pluginName),
				slog.String("error", err.Error()),
			)
		}
	}
}

// syncCasbinDisable removes all Casbin policies for "tenant-admin" on this
// plugin resource in the tenant domain. It is a best-effort operation: errors
// are logged but never returned to callers.
func (s *RedisPluginAccessStore) syncCasbinDisable(ctx context.Context, tenant, pluginName string) {
	if s.enforcer == nil {
		return
	}

	resource := fmt.Sprintf("plugin:%s", pluginName)

	// RemoveFilteredPolicy(1, ...) removes rows where field[1] (dom) == tenant
	// AND field[2] (obj) == resource, regardless of subject or action.
	if _, err := s.enforcer.RemoveFilteredPolicy(1, tenant, resource); err != nil {
		s.logger.WarnContext(ctx, "casbin: failed to remove policies for plugin",
			slog.String("tenant", tenant),
			slog.String("plugin", pluginName),
			slog.String("error", err.Error()),
		)
	}
}

// GetDecryptedConfig implements PluginAccessStore.
func (s *RedisPluginAccessStore) GetDecryptedConfig(ctx context.Context, tenant, pluginName string) (map[string]any, error) {
	// Verify access first.
	access, err := s.GetAccess(ctx, tenant, pluginName)
	if err != nil {
		return nil, err
	}
	if !access.HasConfig {
		return nil, ErrPluginNotConfigured
	}

	data, err := s.client.Get(ctx, configKey(tenant, pluginName)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrPluginNotConfigured
		}
		return nil, fmt.Errorf("get encrypted config: %w", err)
	}

	var enc encryptedConfig
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted config: %w", err)
	}

	masterKey, err := s.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("get encryption key: %w", err)
	}

	plaintext, err := s.encryptor.Decrypt(enc.Ciphertext, enc.IV, enc.Salt, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}

	var config map[string]any
	if err := json.Unmarshal(plaintext, &config); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted config: %w", err)
	}

	return config, nil
}

// GetMaskedConfig implements PluginAccessStore.
func (s *RedisPluginAccessStore) GetMaskedConfig(ctx context.Context, tenant, pluginName string) (map[string]any, error) {
	config, err := s.GetDecryptedConfig(ctx, tenant, pluginName)
	if err != nil {
		return nil, err
	}

	// Load schema to determine which fields are secret.
	schemaJSON, err := s.GetConfigSchema(ctx, pluginName)
	if err != nil || schemaJSON == "" {
		// No schema — mask all string values as a safe default.
		return maskAllStrings(config), nil
	}

	secretFields := extractSecretFields(schemaJSON)
	return maskFields(config, secretFields), nil
}

// UpdateConfig implements PluginAccessStore.
func (s *RedisPluginAccessStore) UpdateConfig(ctx context.Context, tenant, pluginName string, config map[string]any, configuredBy string) error {
	// Verify plugin is enabled.
	access, err := s.GetAccess(ctx, tenant, pluginName)
	if err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "updating plugin config",
		slog.String("tenant", tenant),
		slog.String("plugin", pluginName))

	if err := s.storeEncryptedConfig(ctx, tenant, pluginName, config); err != nil {
		return fmt.Errorf("store encrypted config: %w", err)
	}

	// Update access record timestamps.
	access.ConfiguredAt = time.Now().UTC().Format(time.RFC3339)
	access.ConfiguredBy = configuredBy
	access.HasConfig = true

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal access record: %w", err)
	}

	if err := s.client.Set(ctx, accessKey(tenant, pluginName), accessJSON, 0).Err(); err != nil {
		return fmt.Errorf("update access record: %w", err)
	}

	return nil
}

// ListTenantPlugins implements PluginAccessStore.
func (s *RedisPluginAccessStore) ListTenantPlugins(ctx context.Context, tenant string) ([]PluginAccess, error) {
	var results []PluginAccess
	var cursor uint64

	for {
		keys, next, err := s.client.Scan(ctx, cursor, accessPattern(tenant), 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan tenant plugins: %w", err)
		}

		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}
				return nil, fmt.Errorf("get access record %s: %w", key, err)
			}

			var access PluginAccess
			if err := json.Unmarshal(data, &access); err != nil {
				continue
			}
			results = append(results, access)
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	return results, nil
}

// ListAvailablePlugins implements PluginAccessStore.
func (s *RedisPluginAccessStore) ListAvailablePlugins(ctx context.Context, tenant string) ([]PluginCatalogEntry, error) {
	// Get all _system plugins from registry.
	systemPlugins, err := s.registry.DiscoverAll(ctx, systemTenant, "plugin")
	if err != nil {
		return nil, fmt.Errorf("discover system plugins: %w", err)
	}

	// Get tenant's self-hosted plugins.
	tenantPlugins, err := s.registry.DiscoverAll(ctx, tenant, "plugin")
	if err != nil {
		return nil, fmt.Errorf("discover tenant plugins: %w", err)
	}

	// Get tenant's access records for enrichment.
	accessRecords, err := s.ListTenantPlugins(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("list tenant access: %w", err)
	}

	accessMap := make(map[string]*PluginAccess, len(accessRecords))
	for i := range accessRecords {
		accessMap[accessRecords[i].PluginName] = &accessRecords[i]
	}

	var catalog []PluginCatalogEntry

	// Aggregate _system plugins by name (may have multiple instances).
	systemByName := aggregateByName(systemPlugins)
	for name, instances := range systemByName {
		entry := PluginCatalogEntry{
			Name:          name,
			Version:       instances[0].Version,
			Source:        "platform",
			InstanceCount: len(instances),
			HealthStatus:  "unknown",
		}

		// Enrich from metadata.
		if desc, ok := instances[0].Metadata["description"]; ok {
			entry.Description = desc
		}
		entry.Methods = extractMethods(instances[0].Metadata)

		// Load config schema.
		schema, _ := s.GetConfigSchema(ctx, name)
		entry.ConfigSchema = schema

		// Enrich from access record.
		if access, ok := accessMap[name]; ok {
			entry.Enabled = access.Enabled
			entry.Configured = access.HasConfig
		}

		catalog = append(catalog, entry)
	}

	// Aggregate tenant's self-hosted plugins.
	tenantByName := aggregateByName(filterTenantOnly(tenantPlugins))
	for name, instances := range tenantByName {
		// Skip if already listed as platform (shouldn't happen but be safe).
		if _, exists := systemByName[name]; exists {
			continue
		}

		entry := PluginCatalogEntry{
			Name:          name,
			Version:       instances[0].Version,
			Source:        "self-hosted",
			Enabled:       true,
			Configured:    true,
			InstanceCount: len(instances),
			HealthStatus:  "unknown",
		}

		if desc, ok := instances[0].Metadata["description"]; ok {
			entry.Description = desc
		}
		entry.Methods = extractMethods(instances[0].Metadata)

		catalog = append(catalog, entry)
	}

	return catalog, nil
}

// EnableSelfHosted implements PluginAccessStore.
func (s *RedisPluginAccessStore) EnableSelfHosted(ctx context.Context, tenant, pluginName string) error {
	// Don't overwrite existing records.
	_, err := s.GetAccess(ctx, tenant, pluginName)
	if err == nil {
		return nil // already exists
	}
	if !errors.Is(err, ErrPluginNotEnabled) {
		return err // real error
	}

	access := PluginAccess{
		TenantID:     tenant,
		PluginName:   pluginName,
		Enabled:      true,
		Source:       "self-hosted",
		ConfiguredAt: time.Now().UTC().Format(time.RFC3339),
		HasConfig:    false,
	}

	accessJSON, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("marshal access record: %w", err)
	}

	// NX ensures we don't overwrite if a concurrent registration won the race.
	set, err := s.client.SetNX(ctx, accessKey(tenant, pluginName), accessJSON, 0).Result()
	if err != nil {
		return fmt.Errorf("store self-hosted access record: %w", err)
	}
	if !set {
		return nil // another goroutine won the race, record already exists
	}

	s.logger.InfoContext(ctx, "auto-created access record for self-hosted plugin",
		slog.String("tenant", tenant),
		slog.String("plugin", pluginName))

	return nil
}

// StoreConfigSchema implements PluginAccessStore.
func (s *RedisPluginAccessStore) StoreConfigSchema(ctx context.Context, pluginName, schemaJSON string) error {
	if schemaJSON == "" {
		return nil
	}
	return s.client.Set(ctx, schemaKey(pluginName), schemaJSON, 0).Err()
}

// GetConfigSchema implements PluginAccessStore.
func (s *RedisPluginAccessStore) GetConfigSchema(ctx context.Context, pluginName string) (string, error) {
	val, err := s.client.Get(ctx, schemaKey(pluginName)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", fmt.Errorf("get config schema: %w", err)
	}
	return val, nil
}

// storeEncryptedConfig encrypts and stores plugin config.
func (s *RedisPluginAccessStore) storeEncryptedConfig(ctx context.Context, tenant, pluginName string, config map[string]any) error {
	plaintext, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	masterKey, err := s.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return fmt.Errorf("get encryption key: %w", err)
	}

	ciphertext, iv, salt, err := s.encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	enc := encryptedConfig{
		Ciphertext: ciphertext,
		IV:         iv,
		Salt:       salt,
	}

	encJSON, err := json.Marshal(enc)
	if err != nil {
		return fmt.Errorf("marshal encrypted config: %w", err)
	}

	return s.client.Set(ctx, configKey(tenant, pluginName), encJSON, 0).Err()
}

// extractSecretFields parses a JSON Schema and returns field names marked with "secret": true.
func extractSecretFields(schemaJSON string) map[string]bool {
	fields := make(map[string]bool)

	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return fields
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return fields
	}

	for name, def := range props {
		propDef, ok := def.(map[string]any)
		if !ok {
			continue
		}
		if secret, ok := propDef["secret"].(bool); ok && secret {
			fields[name] = true
		}
	}

	return fields
}

// maskFields returns a copy of config with secret fields masked.
func maskFields(config map[string]any, secretFields map[string]bool) map[string]any {
	result := make(map[string]any, len(config))
	for k, v := range config {
		if secretFields[k] {
			if s, ok := v.(string); ok {
				result[k] = maskString(s)
			} else {
				result[k] = "••••••••"
			}
		} else {
			result[k] = v
		}
	}
	return result
}

// maskAllStrings masks every string value in config (used when no schema is available).
func maskAllStrings(config map[string]any) map[string]any {
	result := make(map[string]any, len(config))
	for k, v := range config {
		if s, ok := v.(string); ok {
			result[k] = maskString(s)
		} else {
			result[k] = v
		}
	}
	return result
}

// maskString preserves a short prefix and suffix for identification.
func maskString(s string) string {
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:4] + "••••" + s[len(s)-4:]
}

// aggregateByName groups ComponentInfo instances by Name.
func aggregateByName(infos []ComponentInfo) map[string][]ComponentInfo {
	result := make(map[string][]ComponentInfo)
	for _, info := range infos {
		result[info.Name] = append(result[info.Name], info)
	}
	return result
}

// extractMethods pulls method names from ComponentInfo.Metadata.
func extractMethods(metadata map[string]string) []string {
	var methods []string
	for k, v := range metadata {
		if strings.HasPrefix(k, "method:") && v == "true" {
			methods = append(methods, strings.TrimPrefix(k, "method:"))
		}
	}
	return methods
}

// filterTenantOnly removes _system-scoped components from a slice.
func filterTenantOnly(infos []ComponentInfo) []ComponentInfo {
	var result []ComponentInfo
	for _, info := range infos {
		if info.TenantID != systemTenant {
			result = append(result, info)
		}
	}
	return result
}
