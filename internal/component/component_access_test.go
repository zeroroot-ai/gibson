package component

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/crypto"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// staticKeyProvider returns a fixed 32-byte master key for testing.
type staticKeyProvider struct {
	key []byte
}

func newStaticKeyProvider() *staticKeyProvider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1) // deterministic, non-zero bytes
	}
	return &staticKeyProvider{key: key}
}

func (p *staticKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	return p.key, nil
}

func (p *staticKeyProvider) Name() string { return "static-test" }

func (p *staticKeyProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("test provider")
}

func (p *staticKeyProvider) Close() error { return nil }

// stubComponentRegistry is a minimal ComponentRegistry that returns empty
// results for all discovery calls. It is sufficient for testing
// RedisComponentAccessStore because ListAvailablePlugins calls DiscoverAll
// on the registry; all other store operations do not touch the registry.
type stubComponentRegistry struct{}

func (s *stubComponentRegistry) Register(_ context.Context, _, _, _ string, _ ComponentInfo) (string, error) {
	return "", nil
}

func (s *stubComponentRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }

func (s *stubComponentRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }

func (s *stubComponentRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

func (s *stubComponentRegistry) DiscoverAll(_ context.Context, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

func (s *stubComponentRegistry) ListTenantComponents(_ context.Context, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

func (s *stubComponentRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

func (s *stubComponentRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]ComponentInfo, error) {
	return nil, nil
}

// newTestPluginAccessStore creates a RedisComponentAccessStore backed by a fresh
// miniredis instance with a real AES-GCM encryptor and a static key provider.
// Cleanup is registered on t so callers do not need to manage it.
func newTestPluginAccessStore(t *testing.T) (*RedisComponentAccessStore, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // suppress noise in tests
	}))

	store := NewRedisPluginAccessStore(
		client,
		crypto.NewAESGCMEncryptor(),
		newStaticKeyProvider(),
		&stubComponentRegistry{},
		logger,
	)

	return store, mr
}

// pluginAccessNames returns a sorted slice of plugin names from a slice of
// ComponentAccess records — useful for deterministic assertions.
func pluginAccessNames(records []ComponentAccess) []string {
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, r.PluginName)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Enable / GetAccess / Disable lifecycle
// ---------------------------------------------------------------------------

func TestPluginAccessStore_Enable_GetAccess(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	err := store.Enable(ctx, "tenant-a", "gitlab", map[string]any{"url": "https://gitlab.example.com"}, "admin")
	require.NoError(t, err)

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.Equal(t, "tenant-a", access.TenantID)
	assert.Equal(t, "gitlab", access.PluginName)
	assert.True(t, access.Enabled)
	assert.Equal(t, "platform", access.Source)
	assert.Equal(t, "admin", access.ConfiguredBy)
	assert.True(t, access.HasConfig)
	assert.NotEmpty(t, access.ConfiguredAt)
}

func TestPluginAccessStore_Enable_WithoutConfig(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	err := store.Enable(ctx, "tenant-a", "gitlab", nil, "admin")
	require.NoError(t, err)

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.False(t, access.HasConfig)
}

func TestPluginAccessStore_Disable_RemovesRecord(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	// Confirm it exists.
	_, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	require.NoError(t, store.Disable(ctx, "tenant-a", "gitlab"))

	// Access record must be gone.
	_, err = store.GetAccess(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_Disable_RemovesConfig(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	cfg := map[string]any{"token": "super-secret-token-value"}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))

	// Config must be retrievable before disable.
	_, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	require.NoError(t, store.Disable(ctx, "tenant-a", "gitlab"))

	// After disabling, both the access record and the config must be gone.
	_, err = store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

// ---------------------------------------------------------------------------
// Config encryption round-trip
// ---------------------------------------------------------------------------

func TestPluginAccessStore_EncryptionRoundTrip(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	originalCfg := map[string]any{
		"token":   "ghp_supersecrettoken123456",
		"url":     "https://gitlab.example.com",
		"timeout": float64(30), // JSON round-trips integers as float64
	}

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", originalCfg, "admin"))

	decrypted, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.Equal(t, originalCfg["token"], decrypted["token"])
	assert.Equal(t, originalCfg["url"], decrypted["url"])
	assert.Equal(t, originalCfg["timeout"], decrypted["timeout"])
}

// Encrypting the same config twice produces different ciphertexts (random IV/salt).
func TestPluginAccessStore_EncryptionProducesUniqueCiphertexts(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	cfg := map[string]any{"token": "my-token"}

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))
	first, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	// UpdateConfig re-encrypts — the resulting plaintext must still match.
	require.NoError(t, store.UpdateConfig(ctx, "tenant-a", "gitlab", cfg, "admin"))
	second, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

// ---------------------------------------------------------------------------
// GetMaskedConfig
// ---------------------------------------------------------------------------

func TestPluginAccessStore_GetMaskedConfig_MasksSecretFields(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Register a schema that marks "token" as a secret field.
	schema := `{
		"type": "object",
		"properties": {
			"token": {"type": "string", "secret": true},
			"url":   {"type": "string"}
		}
	}`
	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", schema))

	cfg := map[string]any{
		"token": "ghp_supersecrettoken123456",
		"url":   "https://gitlab.example.com",
	}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))

	masked, err := store.GetMaskedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	// "token" must be masked; "url" must be left as-is.
	assert.NotEqual(t, cfg["token"], masked["token"], "secret field must be masked")
	assert.Equal(t, cfg["url"], masked["url"], "non-secret field must be unmasked")
}

func TestPluginAccessStore_GetMaskedConfig_NoSchema_MasksAllStrings(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Do NOT store a schema — fallback masking should apply.
	cfg := map[string]any{
		"token":   "ghp_supersecrettoken123456",
		"url":     "https://gitlab.example.com",
		"retries": float64(3), // non-string; must survive unmasked
	}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))

	masked, err := store.GetMaskedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.NotEqual(t, cfg["token"], masked["token"], "string field must be masked without schema")
	assert.NotEqual(t, cfg["url"], masked["url"], "string field must be masked without schema")
	assert.Equal(t, float64(3), masked["retries"], "non-string field must not be masked")
}

func TestPluginAccessStore_GetMaskedConfig_ShortSecret_FullyMasked(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	schema := `{
		"type": "object",
		"properties": {
			"pin": {"type": "string", "secret": true}
		}
	}`
	require.NoError(t, store.StoreConfigSchema(ctx, "vault", schema))

	cfg := map[string]any{"pin": "1234"} // <= 8 chars — should become "••••••••"
	require.NoError(t, store.Enable(ctx, "tenant-a", "vault", cfg, "admin"))

	masked, err := store.GetMaskedConfig(ctx, "tenant-a", "vault")
	require.NoError(t, err)

	assert.Equal(t, "••••••••", masked["pin"])
}

// ---------------------------------------------------------------------------
// UpdateConfig
// ---------------------------------------------------------------------------

func TestPluginAccessStore_UpdateConfig_ReplacesStoredConfig(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	initial := map[string]any{"token": "old-token", "url": "https://old.example.com"}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", initial, "admin"))

	updated := map[string]any{"token": "new-token", "url": "https://new.example.com"}
	require.NoError(t, store.UpdateConfig(ctx, "tenant-a", "gitlab", updated, "ops"))

	got, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	assert.Equal(t, "new-token", got["token"])
	assert.Equal(t, "https://new.example.com", got["url"])
}

func TestPluginAccessStore_UpdateConfig_SetsHasConfigAndConfiguredBy(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Enable without initial config.
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "provisioner"))

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.False(t, access.HasConfig)

	require.NoError(t, store.UpdateConfig(ctx, "tenant-a", "gitlab", map[string]any{"token": "tok"}, "operator"))

	access, err = store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.True(t, access.HasConfig)
	assert.Equal(t, "operator", access.ConfiguredBy)
}

func TestPluginAccessStore_UpdateConfig_FailsWhenNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	err := store.UpdateConfig(ctx, "tenant-a", "gitlab", map[string]any{"token": "tok"}, "admin")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

// ---------------------------------------------------------------------------
// ListTenantPlugins
// ---------------------------------------------------------------------------

func TestPluginAccessStore_ListTenantPlugins_ReturnsAll(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-a", "jira", nil, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-a", "pagerduty", nil, "admin"))

	records, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)

	assert.Equal(t, []string{"gitlab", "jira", "pagerduty"}, pluginAccessNames(records))
}

func TestPluginAccessStore_ListTenantPlugins_EmptyForNewTenant(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	records, err := store.ListTenantPlugins(ctx, "new-tenant")
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestPluginAccessStore_ListTenantPlugins_ReflectsDisable(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-a", "jira", nil, "admin"))
	require.NoError(t, store.Disable(ctx, "tenant-a", "gitlab"))

	records, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)

	assert.Equal(t, []string{"jira"}, pluginAccessNames(records))
}

// ---------------------------------------------------------------------------
// EnableSelfHosted
// ---------------------------------------------------------------------------

func TestPluginAccessStore_EnableSelfHosted_CreatesRecord(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "custom-plugin"))

	access, err := store.GetAccess(ctx, "tenant-a", "custom-plugin")
	require.NoError(t, err)

	assert.Equal(t, "tenant-a", access.TenantID)
	assert.Equal(t, "custom-plugin", access.PluginName)
	assert.True(t, access.Enabled)
	assert.Equal(t, "self-hosted", access.Source)
	assert.False(t, access.HasConfig)
}

func TestPluginAccessStore_EnableSelfHosted_DoesNotOverwriteExisting(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Establish an initial platform record with config.
	cfg := map[string]any{"token": "original-token"}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "original-admin"))

	// A self-hosted registration must not clobber the existing record.
	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "gitlab"))

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)

	// Original values must be preserved.
	assert.Equal(t, "platform", access.Source)
	assert.Equal(t, "original-admin", access.ConfiguredBy)
	assert.True(t, access.HasConfig)

	// Original config must still decrypt correctly.
	got, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, "original-token", got["token"])
}

func TestPluginAccessStore_EnableSelfHosted_IdempotentWhenCalledTwice(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "custom-plugin"))
	require.NoError(t, store.EnableSelfHosted(ctx, "tenant-a", "custom-plugin"))

	// Only one record should exist.
	records, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation
// ---------------------------------------------------------------------------

func TestPluginAccessStore_CrossTenantIsolation_GetAccess(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Tenant A enables gitlab.
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	// Tenant B must not see tenant A's plugin.
	_, err := store.GetAccess(ctx, "tenant-b", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_CrossTenantIsolation_Config(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	cfgA := map[string]any{"token": "tenant-a-secret"}
	cfgB := map[string]any{"token": "tenant-b-secret"}

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfgA, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-b", "gitlab", cfgB, "admin"))

	gotA, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a-secret", gotA["token"])

	gotB, err := store.GetDecryptedConfig(ctx, "tenant-b", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, "tenant-b-secret", gotB["token"])
}

func TestPluginAccessStore_CrossTenantIsolation_ListTenantPlugins(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-a", "jira", nil, "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-b", "pagerduty", nil, "admin"))

	aRecords, err := store.ListTenantPlugins(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, []string{"gitlab", "jira"}, pluginAccessNames(aRecords))

	bRecords, err := store.ListTenantPlugins(ctx, "tenant-b")
	require.NoError(t, err)
	assert.Equal(t, []string{"pagerduty"}, pluginAccessNames(bRecords))
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestPluginAccessStore_GetAccess_NotEnabled_ReturnsErrPluginNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	_, err := store.GetAccess(ctx, "tenant-a", "nonexistent-plugin")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_GetDecryptedConfig_NotEnabled_ReturnsErrPluginNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	_, err := store.GetDecryptedConfig(ctx, "tenant-a", "nonexistent-plugin")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_GetDecryptedConfig_EnabledWithoutConfig_ReturnsErrPluginNotConfigured(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Enable without any config.
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	_, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotConfigured)
}

func TestPluginAccessStore_GetMaskedConfig_NotEnabled_ReturnsErrPluginNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	_, err := store.GetMaskedConfig(ctx, "tenant-a", "nonexistent-plugin")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_GetMaskedConfig_EnabledWithoutConfig_ReturnsErrPluginNotConfigured(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	_, err := store.GetMaskedConfig(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotConfigured)
}

// ---------------------------------------------------------------------------
// StoreConfigSchema / GetConfigSchema
// ---------------------------------------------------------------------------

func TestPluginAccessStore_ConfigSchema_RoundTrip(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	schema := `{"type":"object","properties":{"token":{"type":"string","secret":true}}}`
	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", schema))

	got, err := store.GetConfigSchema(ctx, "gitlab")
	require.NoError(t, err)
	assert.Equal(t, schema, got)
}

func TestPluginAccessStore_GetConfigSchema_Missing_ReturnsEmptyString(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	got, err := store.GetConfigSchema(ctx, "no-such-plugin")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPluginAccessStore_StoreConfigSchema_EmptyString_IsNoOp(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Storing an empty schema must not error and must not persist anything.
	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", ""))

	got, err := store.GetConfigSchema(ctx, "gitlab")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPluginAccessStore_StoreConfigSchema_OverwritesPrevious(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	first := `{"type":"object","properties":{"token":{"type":"string"}}}`
	second := `{"type":"object","properties":{"token":{"type":"string","secret":true}}}`

	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", first))
	require.NoError(t, store.StoreConfigSchema(ctx, "gitlab", second))

	got, err := store.GetConfigSchema(ctx, "gitlab")
	require.NoError(t, err)
	assert.Equal(t, second, got)
}

// ---------------------------------------------------------------------------
// Key scheme helpers (unit tests — no Redis needed)
// ---------------------------------------------------------------------------

func TestPluginAccessStoreKeyHelpers(t *testing.T) {
	tests := []struct {
		name string
		fn   func() string
		want string
	}{
		{
			name: "accessKey",
			fn:   func() string { return accessKey("acme", "gitlab") },
			want: "plugin-access:acme:gitlab",
		},
		{
			name: "configKey",
			fn:   func() string { return configKey("acme", "gitlab") },
			want: "plugin-config:acme:gitlab",
		},
		{
			name: "schemaKey",
			fn:   func() string { return schemaKey("gitlab") },
			want: "plugin-schema:gitlab",
		},
		{
			name: "accessPattern",
			fn:   func() string { return accessPattern("acme") },
			want: "plugin-access:acme:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.fn())
		})
	}
}

// ---------------------------------------------------------------------------
// extractSecretFields (unit tests — no Redis needed)
// ---------------------------------------------------------------------------

func TestExtractSecretFields(t *testing.T) {
	tests := []struct {
		name       string
		schemaJSON string
		want       map[string]bool
	}{
		{
			name: "marks secret fields",
			schemaJSON: `{
				"type": "object",
				"properties": {
					"token":  {"type": "string", "secret": true},
					"url":    {"type": "string"},
					"apiKey": {"type": "string", "secret": true}
				}
			}`,
			want: map[string]bool{"token": true, "apiKey": true},
		},
		{
			name:       "empty schema returns empty map",
			schemaJSON: `{}`,
			want:       map[string]bool{},
		},
		{
			name:       "invalid JSON returns empty map",
			schemaJSON: `not-json`,
			want:       map[string]bool{},
		},
		{
			name: "no properties key returns empty map",
			schemaJSON: `{
				"type": "object"
			}`,
			want: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSecretFields(tt.schemaJSON)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// maskString (unit tests — no Redis needed)
// ---------------------------------------------------------------------------

func TestMaskString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "short", want: "••••••••"},         // <= 8 chars
		{input: "12345678", want: "••••••••"},      // exactly 8 chars
		{input: "123456789", want: "1234••••6789"}, // > 8 chars: first 4 + ••••  + last 4
		{input: "ghp_supersecrettoken123456", want: "ghp_••••3456"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, maskString(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// ListAvailablePlugins (minimal smoke test via stub registry)
// ---------------------------------------------------------------------------

func TestPluginAccessStore_ListAvailablePlugins_EmptyWhenNoSystemPlugins(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// The stubComponentRegistry returns nothing, so the catalog must be empty.
	catalog, err := store.ListAvailablePlugins(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Empty(t, catalog)
}

// ---------------------------------------------------------------------------
// EffectiveReadEnabled / EffectiveWriteEnabled (unit tests — no Redis)
// ---------------------------------------------------------------------------

func TestPluginAccess_EffectiveAccess_LegacyEnabledRecord(t *testing.T) {
	// A record with Enabled=true and both granular flags false must be treated
	// as full read+write for backward compatibility.
	access := &ComponentAccess{
		TenantID:     "t",
		PluginName:   "p",
		Enabled:      true,
		ReadEnabled:  false,
		WriteEnabled: false,
	}

	assert.True(t, access.EffectiveReadEnabled(), "legacy record must grant read")
	assert.True(t, access.EffectiveWriteEnabled(), "legacy record must grant write")
}

func TestPluginAccess_EffectiveAccess_ReadOnly(t *testing.T) {
	access := &ComponentAccess{
		TenantID:     "t",
		PluginName:   "p",
		Enabled:      true,
		ReadEnabled:  true,
		WriteEnabled: false,
	}

	assert.True(t, access.EffectiveReadEnabled())
	assert.False(t, access.EffectiveWriteEnabled())
}

func TestPluginAccess_EffectiveAccess_WriteOnly(t *testing.T) {
	access := &ComponentAccess{
		TenantID:     "t",
		PluginName:   "p",
		Enabled:      true,
		ReadEnabled:  false,
		WriteEnabled: true,
	}

	assert.False(t, access.EffectiveReadEnabled())
	assert.True(t, access.EffectiveWriteEnabled())
}

func TestPluginAccess_EffectiveAccess_DisabledRecordGrantsNothing(t *testing.T) {
	access := &ComponentAccess{
		TenantID:     "t",
		PluginName:   "p",
		Enabled:      false,
		ReadEnabled:  true,
		WriteEnabled: true,
	}

	assert.False(t, access.EffectiveReadEnabled(), "disabled record must not grant read even if flag is set")
	assert.False(t, access.EffectiveWriteEnabled(), "disabled record must not grant write even if flag is set")
}

// ---------------------------------------------------------------------------
// SetAccessGranularity
// ---------------------------------------------------------------------------

func TestPluginAccessStore_SetAccessGranularity_ReadOnly(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", true, false))

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.True(t, access.ReadEnabled)
	assert.False(t, access.WriteEnabled)
	assert.True(t, access.EffectiveReadEnabled())
	assert.False(t, access.EffectiveWriteEnabled())
}

func TestPluginAccessStore_SetAccessGranularity_WriteOnly(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", false, true))

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.False(t, access.ReadEnabled)
	assert.True(t, access.WriteEnabled)
}

func TestPluginAccessStore_SetAccessGranularity_BothEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", true, true))

	access, err := store.GetAccess(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.True(t, access.ReadEnabled)
	assert.True(t, access.WriteEnabled)
}

func TestPluginAccessStore_SetAccessGranularity_FailsWhenNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	err := store.SetAccessGranularity(ctx, "tenant-a", "nonexistent", true, false)
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_SetAccessGranularity_PreservesConfig(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	cfg := map[string]any{"token": "secret-token-value-here"}
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", cfg, "admin"))

	// Change granularity — config must survive.
	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", true, false))

	got, err := store.GetDecryptedConfig(ctx, "tenant-a", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, "secret-token-value-here", got["token"])
}

// ---------------------------------------------------------------------------
// CheckAccess
// ---------------------------------------------------------------------------

func TestPluginAccessStore_CheckAccess_LegacyRecord_GrantsReadAndWrite(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	// Enable without granular flags — legacy full-access semantics.
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", false), "read must be allowed")
	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", true), "write must be allowed")
}

func TestPluginAccessStore_CheckAccess_ReadOnlyRecord_DeniesWrite(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", true, false))

	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", false), "read must be allowed")
	assert.ErrorIs(t, store.CheckAccess(ctx, "tenant-a", "gitlab", true), ErrComponentAccessDenied, "write must be denied")
}

func TestPluginAccessStore_CheckAccess_WriteOnlyRecord_DeniesRead(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", false, true))

	assert.ErrorIs(t, store.CheckAccess(ctx, "tenant-a", "gitlab", false), ErrComponentAccessDenied, "read must be denied")
	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", true), "write must be allowed")
}

func TestPluginAccessStore_CheckAccess_NotEnabled_ReturnsErrPluginNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	err := store.CheckAccess(ctx, "tenant-a", "nonexistent", false)
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}

func TestPluginAccessStore_CheckAccess_BothGranted_GrantsReadAndWrite(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.SetAccessGranularity(ctx, "tenant-a", "gitlab", true, true))

	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", false))
	assert.NoError(t, store.CheckAccess(ctx, "tenant-a", "gitlab", true))
}

func TestPluginAccessStore_CheckAccess_AfterDisable_ReturnsErrPluginNotEnabled(t *testing.T) {
	store, _ := newTestPluginAccessStore(t)
	ctx := context.Background()

	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))
	require.NoError(t, store.Disable(ctx, "tenant-a", "gitlab"))

	err := store.CheckAccess(ctx, "tenant-a", "gitlab", false)
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}
