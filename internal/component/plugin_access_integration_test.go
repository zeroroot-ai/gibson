package component

// Integration tests for the full plugin access flow. These tests exercise
// end-to-end paths that cross the PluginAccessStore and a real
// RedisComponentRegistry (backed by miniredis), covering the scenarios that
// unit tests with the stubComponentRegistry cannot reach.
//
// All tests run without a real Redis daemon — miniredis provides an in-process
// server that is functionally equivalent for our purposes.

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/crypto"
)

// ---------------------------------------------------------------------------
// Test-local helpers
// ---------------------------------------------------------------------------

// richComponentRegistry is a ComponentRegistry implementation that can be
// seeded with ComponentInfo entries for specific (tenant, kind) pairs. It
// embeds stubComponentRegistry so that all methods not overridden here
// continue to return empty/nil responses.
type richComponentRegistry struct {
	stubComponentRegistry

	// entries is indexed by "tenant:kind" and holds slices of ComponentInfo.
	entries map[string][]ComponentInfo
}

func newRichRegistry() *richComponentRegistry {
	return &richComponentRegistry{
		entries: make(map[string][]ComponentInfo),
	}
}

// seed adds a ComponentInfo for the given (tenant, kind) pair.
func (r *richComponentRegistry) seed(tenant, kind string, info ComponentInfo) {
	key := tenant + ":" + kind
	r.entries[key] = append(r.entries[key], info)
}

// DiscoverAll returns seeded entries for (tenant, kind). When the caller is
// not _system it also merges in entries seeded under "_system", mirroring the
// behaviour of RedisComponentRegistry.DiscoverAll.
func (r *richComponentRegistry) DiscoverAll(_ context.Context, tenant, kind string) ([]ComponentInfo, error) {
	key := tenant + ":" + kind
	results := append([]ComponentInfo{}, r.entries[key]...)

	if tenant != systemTenant {
		sysKey := systemTenant + ":" + kind
		results = append(results, r.entries[sysKey]...)
	}

	return results, nil
}

// newIntegrationStore creates a RedisPluginAccessStore backed by a fresh
// miniredis instance with a real AES-GCM encryptor, static key provider, and
// the supplied ComponentRegistry. Cleanup is registered on t.
func newIntegrationStore(t *testing.T, registry ComponentRegistry) *RedisPluginAccessStore {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	return NewRedisPluginAccessStore(
		client,
		crypto.NewAESGCMEncryptor(),
		newStaticKeyProvider(),
		registry,
		logger,
	)
}

// catalogByName builds a map from plugin name to PluginCatalogEntry for
// deterministic assertions over ListAvailablePlugins results.
func catalogByName(entries []PluginCatalogEntry) map[string]PluginCatalogEntry {
	m := make(map[string]PluginCatalogEntry, len(entries))
	for _, e := range entries {
		m[e.Name] = e
	}
	return m
}

// catalogNames returns a sorted slice of plugin names from a catalog.
func catalogNames(entries []PluginCatalogEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// 1. Test_SystemPluginEnableQueryFlow
// ---------------------------------------------------------------------------

// Test_SystemPluginEnableQueryFlow registers a _system plugin in the registry,
// enables it for a tenant with a config containing a secret field, then
// verifies:
//   - GetDecryptedConfig returns the original config
//   - GetMaskedConfig masks the secret field and leaves non-secret fields intact
//   - ListAvailablePlugins shows the plugin as enabled and configured
func Test_SystemPluginEnableQueryFlow(t *testing.T) {
	ctx := context.Background()

	registry := newRichRegistry()
	registry.seed(systemTenant, "plugin", ComponentInfo{
		Kind:    "plugin",
		Name:    "gitlab",
		Version: "2.1.0",
		Metadata: map[string]string{
			"description":   "GitLab integration",
			"method:issues": "true",
			"method:mrs":    "true",
		},
	})

	store := newIntegrationStore(t, registry)

	// Register a schema that marks "token" as secret.
	schema := `{
		"type": "object",
		"properties": {
			"token": {"type": "string", "secret": true},
			"url":   {"type": "string"}
		}
	}`
	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", schema))

	cfg := map[string]any{
		"token": "glpat-supersecrettokenvalue",
		"url":   "https://gitlab.example.com",
	}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))

	// GetDecryptedConfig must return the original values.
	decrypted, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, cfg["token"], decrypted["token"])
	assert.Equal(t, cfg["url"], decrypted["url"])

	// GetMaskedConfig must mask the secret field only.
	masked, err := store.GetMaskedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.NotEqual(t, cfg["token"], masked["token"], "token must be masked")
	assert.Equal(t, cfg["url"], masked["url"], "url must not be masked")

	// ListAvailablePlugins must show gitlab as enabled and configured.
	catalog, err := store.ListAvailablePlugins(ctx, "tenant-a")
	require.NoError(t, err)

	byName := catalogByName(catalog)
	entry, ok := byName["gitlab"]
	require.True(t, ok, "gitlab must appear in the catalog")
	assert.True(t, entry.Enabled, "plugin must be marked enabled")
	assert.True(t, entry.Configured, "plugin must be marked configured")
	assert.Equal(t, "platform", entry.Source)
	assert.Equal(t, "2.1.0", entry.Version)
}

// ---------------------------------------------------------------------------
// 2. Test_SelfHostedPluginAutoAccess
// ---------------------------------------------------------------------------

// Test_SelfHostedPluginAutoAccess registers a tenant-scoped plugin in the
// registry, calls EnableSelfHosted, and verifies:
//   - The plugin appears in ListTenantPlugins with source="self-hosted"
//   - GetAccess returns a valid record
//   - A second EnableSelfHosted call is idempotent (no duplicate records)
func Test_SelfHostedPluginAutoAccess(t *testing.T) {
	ctx := context.Background()

	registry := newRichRegistry()
	registry.seed("tenant-a", "plugin", ComponentInfo{
		Kind:     "plugin",
		Name:     "custom-scanner",
		Version:  "0.9.0",
		TenantID: "tenant-a",
		Metadata: map[string]string{
			"description": "Tenant-owned scanning plugin",
		},
	})

	store := newIntegrationStore(t, registry)

	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "custom-scanner"))

	// Access record must have source=self-hosted.
	access, err := store.GetAccess(ctx, "tenant-a", "custom-scanner")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", access.TenantID)
	assert.Equal(t, "custom-scanner", access.PluginName)
	assert.True(t, access.Enabled)
	assert.Equal(t, "self-hosted", access.Source)
	assert.False(t, access.HasConfig)

	// ListTenantPlugins must include the self-hosted record with correct source.
	plugins, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Contains(t, pluginAccessNames(plugins), "custom-scanner")

	var found *PluginAccess
	for i := range plugins {
		if plugins[i].PluginName == "custom-scanner" {
			found = &plugins[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, "self-hosted", found.Source)

	// Second call must be idempotent — still exactly one record.
	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "custom-scanner"))
	plugins2, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)
	count := 0
	for _, p := range plugins2 {
		if p.PluginName == "custom-scanner" {
			count++
		}
	}
	assert.Equal(t, 1, count, "EnableSelfHosted must be idempotent")
}

// ---------------------------------------------------------------------------
// 3. Test_TenantIsolation_SystemPlugin
// ---------------------------------------------------------------------------

// Test_TenantIsolation_SystemPlugin enables the same _system plugin for two
// tenants with different configs and verifies:
//   - Each tenant sees only their own config
//   - Disabling for tenant-A does not affect tenant-B's access or config
func Test_TenantIsolation_SystemPlugin(t *testing.T) {
	ctx := context.Background()

	registry := newRichRegistry()
	registry.seed(systemTenant, "plugin", ComponentInfo{
		Kind:    "plugin",
		Name:    "jira",
		Version: "3.0.0",
		Metadata: map[string]string{
			"description": "Jira issue tracker integration",
		},
	})

	store := newIntegrationStore(t, registry)

	cfgA := map[string]any{
		"api_token": "tenant-a-jira-token-xxxx",
		"host":      "https://acme.atlassian.net",
	}
	cfgB := map[string]any{
		"api_token": "tenant-b-jira-token-yyyy",
		"host":      "https://beta.atlassian.net",
	}

	require.NoError(t, store.Enable(ctx, "tenant-a", "jira", cfgA, "admin-a"))
	require.NoError(t, store.Enable(ctx, "tenant-b", "jira", cfgB, "admin-b"))

	// Each tenant retrieves their own config.
	gotA, err := store.GetDecryptedConfig(ctx, "tenant-a", "jira")
	require.NoError(t, err)
	assert.Equal(t, cfgA["api_token"], gotA["api_token"])
	assert.Equal(t, cfgA["host"], gotA["host"])

	gotB, err := store.GetDecryptedConfig(ctx, "tenant-b", "jira")
	require.NoError(t, err)
	assert.Equal(t, cfgB["api_token"], gotB["api_token"])
	assert.Equal(t, cfgB["host"], gotB["host"])

	// Configs must not bleed across tenants.
	assert.NotEqual(t, gotA["api_token"], gotB["api_token"])

	// Disable jira for tenant-A.
	require.NoError(t, store.Disable(ctx, "tenant-a", "jira"))

	// Tenant-A access must be gone.
	_, err = store.GetAccess(ctx, "tenant-a", "jira")
	assert.ErrorIs(t, err, ErrPluginNotEnabled)

	// Tenant-B must be completely unaffected.
	accessB, err := store.GetAccess(ctx, "tenant-b", "jira")
	require.NoError(t, err)
	assert.True(t, accessB.Enabled)

	gotBAfter, err := store.GetDecryptedConfig(ctx, "tenant-b", "jira")
	require.NoError(t, err)
	assert.Equal(t, cfgB["api_token"], gotBAfter["api_token"])

	// ListAvailablePlugins for tenant-B must still show jira as enabled.
	catalog, err := store.ListAvailablePlugins(ctx, "tenant-b")
	require.NoError(t, err)
	byName := catalogByName(catalog)
	jiraEntry, ok := byName["jira"]
	require.True(t, ok, "jira must remain in tenant-B catalog after tenant-A disables it")
	assert.True(t, jiraEntry.Enabled)
	assert.True(t, jiraEntry.Configured)
}

// ---------------------------------------------------------------------------
// 4. Test_DisableRemovesConfig
// ---------------------------------------------------------------------------

// Test_DisableRemovesConfig verifies that Disable removes both the access
// record and the encrypted config blob — GetAccess and GetDecryptedConfig both
// return ErrPluginNotEnabled after a Disable call.
func Test_DisableRemovesConfig(t *testing.T) {
	ctx := context.Background()

	store := newIntegrationStore(t, &stubComponentRegistry{})

	cfg := map[string]any{
		"api_key": "sk-ultra-secret-api-key-value",
		"region":  "us-east-1",
	}

	require.NoError(t, store.Enable(ctx, "tenant-a", "aws-bedrock", cfg, "ops"))

	// Pre-condition: access record exists and config is retrievable.
	access, err := store.GetAccess(ctx, "tenant-a", "aws-bedrock")
	require.NoError(t, err)
	assert.True(t, access.HasConfig)

	preCfg, err := store.GetDecryptedConfig(ctx, "tenant-a", "aws-bedrock")
	require.NoError(t, err)
	assert.Equal(t, cfg["api_key"], preCfg["api_key"])

	// Disable the plugin.
	require.NoError(t, store.Disable(ctx, "tenant-a", "aws-bedrock"))

	// Access record must be gone.
	_, err = store.GetAccess(ctx, "tenant-a", "aws-bedrock")
	assert.ErrorIs(t, err, ErrPluginNotEnabled,
		"GetAccess must return ErrPluginNotEnabled after Disable")

	// Encrypted config must also be gone — GetDecryptedConfig returns
	// ErrPluginNotEnabled because the access record check fires first.
	_, err = store.GetDecryptedConfig(ctx, "tenant-a", "aws-bedrock")
	assert.ErrorIs(t, err, ErrPluginNotEnabled,
		"GetDecryptedConfig must return ErrPluginNotEnabled after Disable")

	// Disabling an already-disabled plugin must not error.
	require.NoError(t, store.Disable(ctx, "tenant-a", "aws-bedrock"),
		"Disable must be idempotent on a non-existent plugin")
}

// ---------------------------------------------------------------------------
// 5. Test_ConfigSchemaRoundTrip
// ---------------------------------------------------------------------------

// Test_ConfigSchemaRoundTrip stores a config schema for a plugin, enables the
// plugin with a matching config, and verifies that GetMaskedConfig correctly
// distinguishes secret fields (masked) from non-secret fields (left as-is)
// based on the schema's "secret": true annotations.
func Test_ConfigSchemaRoundTrip(t *testing.T) {
	ctx := context.Background()

	store := newIntegrationStore(t, &stubComponentRegistry{})

	// Schema with a mix of secret and non-secret fields.
	schema := `{
		"type": "object",
		"properties": {
			"webhook_secret": {"type": "string", "secret": true},
			"signing_key":    {"type": "string", "secret": true},
			"endpoint_url":   {"type": "string"},
			"timeout_secs":   {"type": "number"},
			"verify_ssl":     {"type": "boolean"}
		}
	}`
	require.NoError(t, store.StoreConfigSchema(ctx, "webhook-relay", schema))

	// Schema must survive a round-trip through Redis.
	storedSchema, err := store.GetConfigSchema(ctx, "webhook-relay")
	require.NoError(t, err)
	assert.Equal(t, schema, storedSchema)

	cfg := map[string]any{
		"webhook_secret": "whsec_abcdefghijklmnopqrstuvwxyz123456",
		"signing_key":    "sk_live_supersecretkey9876543210",
		"endpoint_url":   "https://relay.example.com/hook",
		"timeout_secs":   float64(30),
		"verify_ssl":     true,
	}
	require.NoError(t, store.Enable(ctx, "tenant-a", "webhook-relay", cfg, "devops"))

	// GetDecryptedConfig must return the exact original values.
	decrypted, err := store.GetDecryptedConfig(ctx, "tenant-a", "webhook-relay")
	require.NoError(t, err)
	assert.Equal(t, cfg["webhook_secret"], decrypted["webhook_secret"])
	assert.Equal(t, cfg["signing_key"], decrypted["signing_key"])
	assert.Equal(t, cfg["endpoint_url"], decrypted["endpoint_url"])
	assert.Equal(t, cfg["timeout_secs"], decrypted["timeout_secs"])
	assert.Equal(t, cfg["verify_ssl"], decrypted["verify_ssl"])

	// GetMaskedConfig must mask only the fields annotated "secret": true.
	masked, err := store.GetMaskedConfig(ctx, "tenant-a", "webhook-relay")
	require.NoError(t, err)

	// Secret string fields must be masked.
	assert.NotEqual(t, cfg["webhook_secret"], masked["webhook_secret"],
		"webhook_secret must be masked")
	assert.NotEqual(t, cfg["signing_key"], masked["signing_key"],
		"signing_key must be masked")

	// Non-secret fields must pass through unchanged.
	assert.Equal(t, cfg["endpoint_url"], masked["endpoint_url"],
		"endpoint_url must not be masked")
	assert.Equal(t, cfg["timeout_secs"], masked["timeout_secs"],
		"timeout_secs (number) must not be masked")
	assert.Equal(t, cfg["verify_ssl"], masked["verify_ssl"],
		"verify_ssl (bool) must not be masked")

	// Masked strings for long secrets must follow the maskString format:
	// first 4 chars preserved, ••••, then last 4 chars.
	webhookMasked, ok := masked["webhook_secret"].(string)
	require.True(t, ok, "masked webhook_secret must still be a string")
	original := cfg["webhook_secret"].(string)
	assert.Equal(t, original[:4], webhookMasked[:4],
		"masked value must preserve first 4 chars")
	assert.Equal(t, original[len(original)-4:], webhookMasked[len(webhookMasked)-4:],
		"masked value must preserve last 4 chars")
	assert.Contains(t, webhookMasked, "••••", "masked value must contain bullet separator")

	// Schema must still be retrievable after the plugin is enabled.
	schemaAfter, err := store.GetConfigSchema(ctx, "webhook-relay")
	require.NoError(t, err)
	assert.Equal(t, schema, schemaAfter)
}

// ---------------------------------------------------------------------------
// Additional integration: mixed _system + self-hosted catalog
// ---------------------------------------------------------------------------

// Test_ListAvailablePlugins_MixedCatalog verifies that ListAvailablePlugins
// correctly merges _system plugins (with access-record enrichment) and the
// tenant's own self-hosted plugin registrations, and that the two sets are
// reported with the correct source values.
func Test_ListAvailablePlugins_MixedCatalog(t *testing.T) {
	ctx := context.Background()

	registry := newRichRegistry()

	// Two _system plugins.
	registry.seed(systemTenant, "plugin", ComponentInfo{
		Kind: "plugin", Name: "gitlab", Version: "2.0.0",
		Metadata: map[string]string{"description": "GitLab"},
	})
	registry.seed(systemTenant, "plugin", ComponentInfo{
		Kind: "plugin", Name: "jira", Version: "3.0.0",
		Metadata: map[string]string{"description": "Jira"},
	})

	// One tenant self-hosted plugin.
	registry.seed("tenant-a", "plugin", ComponentInfo{
		Kind: "plugin", Name: "internal-scanner", Version: "1.0.0",
		TenantID: "tenant-a",
		Metadata: map[string]string{"description": "Internal"},
	})

	store := newIntegrationStore(t, registry)

	// Enable gitlab (platform) with config; leave jira disabled.
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab",
		map[string]any{"token": "glpat-xxxxxxxxxxx"}, "admin"))

	// Register self-hosted plugin access.
	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "internal-scanner"))

	catalog, err := store.ListAvailablePlugins(ctx, "tenant-a")
	require.NoError(t, err)

	byName := catalogByName(catalog)

	// gitlab: enabled + configured (platform).
	gl, ok := byName["gitlab"]
	require.True(t, ok, "gitlab must be in the catalog")
	assert.True(t, gl.Enabled)
	assert.True(t, gl.Configured)
	assert.Equal(t, "platform", gl.Source)

	// jira: present but not enabled by tenant-a.
	jira, ok := byName["jira"]
	require.True(t, ok, "jira must be in the catalog")
	assert.False(t, jira.Enabled)
	assert.False(t, jira.Configured)
	assert.Equal(t, "platform", jira.Source)

	// internal-scanner: self-hosted, enabled=true by convention.
	scanner, ok := byName["internal-scanner"]
	require.True(t, ok, "internal-scanner must be in the catalog")
	assert.True(t, scanner.Enabled)
	assert.Equal(t, "self-hosted", scanner.Source)

	// Catalog must contain exactly three entries.
	assert.Equal(t, []string{"gitlab", "internal-scanner", "jira"}, catalogNames(catalog))
}

// ---------------------------------------------------------------------------
// Additional integration: UpdateConfig reflects in GetDecryptedConfig
// ---------------------------------------------------------------------------

// Test_UpdateConfig_Integration verifies the full UpdateConfig round-trip
// through encryption and decryption, including the HasConfig + ConfiguredBy
// fields on the access record.
func Test_UpdateConfig_Integration(t *testing.T) {
	ctx := context.Background()

	store := newIntegrationStore(t, &stubComponentRegistry{})

	initial := map[string]any{
		"api_key":  "initial-key-value-here",
		"base_url": "https://v1.api.example.com",
	}
	require.NoError(t, store.Enable(ctx, "tenant-a", "platform-api", initial, "provisioner"))

	updated := map[string]any{
		"api_key":  "rotated-key-value-here",
		"base_url": "https://v2.api.example.com",
	}
	require.NoError(t, store.UpdateConfig(ctx, "tenant-a", "platform-api", updated, "operator"))

	got, err := store.GetDecryptedConfig(ctx, "tenant-a", "platform-api")
	require.NoError(t, err)
	assert.Equal(t, updated["api_key"], got["api_key"])
	assert.Equal(t, updated["base_url"], got["base_url"])

	// Access record must reflect the update.
	access, err := store.GetAccess(ctx, "tenant-a", "platform-api")
	require.NoError(t, err)
	assert.True(t, access.HasConfig)
	assert.Equal(t, "operator", access.ConfiguredBy)

	// ConfiguredAt must be a valid RFC3339 timestamp within the last minute.
	ts, err := time.Parse(time.RFC3339, access.ConfiguredAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), ts, time.Minute)
}
