package providerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// staticKeyProvider returns a fixed 32-byte key. Used only in tests.
type staticKeyProvider struct {
	key []byte
}

func newStaticKeyProvider() *staticKeyProvider {
	// 32 deterministic bytes — never use in production.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &staticKeyProvider{key: key}
}

func (p *staticKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	return p.key, nil
}

func (p *staticKeyProvider) Name() string { return "static-test" }

func (p *staticKeyProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

func (p *staticKeyProvider) Close() error { return nil }

var _ crypto.KeyProvider = (*staticKeyProvider)(nil)

// setupTestStore returns a ProviderConfigStore backed by an in-process miniredis,
// plus the raw miniredis handle for critical-assertion access.
func setupTestStore(t *testing.T) (ProviderConfigStore, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	enc := crypto.NewAESGCMEncryptor()
	kp := newStaticKeyProvider()

	store, err := NewStore(client, enc, kp)
	require.NoError(t, err)

	return store, mr
}

// defaultInput returns a valid ProviderConfigInput for testing.
func defaultInput(name string) *ProviderConfigInput {
	return &ProviderConfigInput{
		Name:         name,
		Type:         llm.ProviderAnthropic,
		DefaultModel: "claude-3-5-sonnet",
		Credentials: map[string]string{
			"api_key": "sk-ant-api03-0123456789abcdef",
		},
		Enabled:      true,
		SetAsDefault: false,
	}
}

// ---------------------------------------------------------------------------
// NewStore
// ---------------------------------------------------------------------------

func TestNewStore_NilKeyProvider(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	_, err := NewStore(client, crypto.NewAESGCMEncryptor(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyProviderUnset)
}

func TestNewStore_NilEncryptor(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	_, err := NewStore(client, nil, newStaticKeyProvider())
	require.Error(t, err)
}

func TestNewStore_NilClient(t *testing.T) {
	_, err := NewStore(nil, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestCreate_RoundTrip(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-a"

	input := defaultInput("my-anthropic")
	cfg, err := store.Create(ctx, tenantID, input)
	require.NoError(t, err)

	assert.NotEmpty(t, cfg.ID)
	assert.Equal(t, tenantID, cfg.TenantID)
	assert.Equal(t, "my-anthropic", cfg.Name)
	assert.Equal(t, llm.ProviderAnthropic, cfg.Type)
	assert.Equal(t, "claude-3-5-sonnet", cfg.DefaultModel)
	assert.True(t, cfg.Enabled)
	assert.False(t, cfg.IsDefault)
	assert.NotZero(t, cfg.CreatedAt)
	assert.NotZero(t, cfg.UpdatedAt)

	// Credentials must be masked in the returned record.
	maskedKey, ok := cfg.CredentialsMasked["api_key"]
	require.True(t, ok, "api_key must be present in masked map")
	assert.Equal(t, "****cdef", maskedKey, "mask should be ****<last4>")
	assert.NotContains(t, maskedKey, "sk-ant", "plaintext must not appear in masked value")
}

func TestCreate_AlreadyExists(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "tenant-a", defaultInput("dup"))
	require.NoError(t, err)

	_, err = store.Create(ctx, "tenant-a", defaultInput("dup"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyExists)
}

func TestCreate_UnsupportedType(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	input := defaultInput("bad-type")
	input.Type = llm.ProviderType("totally_fake")

	_, err := store.Create(ctx, "tenant-a", input)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedType)
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestGet_AfterCreate(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-get"

	input := defaultInput("openai-prod")
	input.Type = llm.ProviderOpenAI
	input.Credentials = map[string]string{
		"api_key": "sk-openai-abcdef123456",
	}

	_, err := store.Create(ctx, tenantID, input)
	require.NoError(t, err)

	got, err := store.Get(ctx, tenantID, "openai-prod")
	require.NoError(t, err)

	assert.Equal(t, "openai-prod", got.Name)
	assert.Equal(t, llm.ProviderOpenAI, got.Type)

	// Verify masking: "sk-openai-abcdef123456" → "****3456"
	assert.Equal(t, "****3456", got.CredentialsMasked["api_key"])
}

func TestGet_NotFound(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "tenant-x", "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestUpdate_RoundTrip(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-upd"

	_, err := store.Create(ctx, tenantID, defaultInput("to-update"))
	require.NoError(t, err)

	updated := &ProviderConfigInput{
		Name:         "to-update",
		Type:         llm.ProviderAnthropic,
		DefaultModel: "claude-3-opus",
		Credentials:  map[string]string{"api_key": "new-key-12345678"},
		Enabled:      false,
	}
	cfg, err := store.Update(ctx, tenantID, "to-update", updated)
	require.NoError(t, err)

	assert.Equal(t, "claude-3-opus", cfg.DefaultModel)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "****5678", cfg.CredentialsMasked["api_key"])

	// Verify timestamps: CreatedAt preserved, UpdatedAt advanced.
	got, err := store.Get(ctx, tenantID, "to-update")
	require.NoError(t, err)
	assert.Equal(t, cfg.CreatedAt, got.CreatedAt)
	assert.True(t, got.UpdatedAt.Equal(cfg.UpdatedAt) || got.UpdatedAt.After(cfg.CreatedAt))
}

func TestUpdate_NotFound(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.Update(ctx, "tenant-x", "ghost", defaultInput("ghost"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestDelete_ThenGet(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-del"

	_, err := store.Create(ctx, tenantID, defaultInput("to-delete"))
	require.NoError(t, err)

	err = store.Delete(ctx, tenantID, "to-delete")
	require.NoError(t, err)

	_, err = store.Get(ctx, tenantID, "to-delete")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestDelete_NotFound(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	err := store.Delete(ctx, "tenant-x", "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestList_TenantIsolation(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	// Tenant A creates a provider.
	_, err := store.Create(ctx, "tenant-A", defaultInput("anthro"))
	require.NoError(t, err)

	// Tenant B creates its own provider.
	_, err = store.Create(ctx, "tenant-B", defaultInput("openai"))
	require.NoError(t, err)

	// Tenant A can only see its own.
	listA, err := store.List(ctx, "tenant-A")
	require.NoError(t, err)
	require.Len(t, listA, 1)
	assert.Equal(t, "anthro", listA[0].Name)

	// Tenant B can only see its own.
	listB, err := store.List(ctx, "tenant-B")
	require.NoError(t, err)
	require.Len(t, listB, 1)
	assert.Equal(t, "openai", listB[0].Name)

	// A list for an unknown tenant returns empty, not an error.
	listC, err := store.List(ctx, "tenant-C")
	require.NoError(t, err)
	assert.Empty(t, listC)
}

func TestList_MultipleProviders(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-multi"

	names := []string{"p1", "p2", "p3"}
	for _, name := range names {
		inp := defaultInput(name)
		_, err := store.Create(ctx, tenantID, inp)
		require.NoError(t, err)
	}

	list, err := store.List(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

func TestSetDefault_GetDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-def"

	_, err := store.Create(ctx, tenantID, defaultInput("primary"))
	require.NoError(t, err)

	err = store.SetDefault(ctx, tenantID, "primary")
	require.NoError(t, err)

	got, err := store.GetDefault(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "primary", got.Name)
}

func TestSetDefault_UnknownProvider(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	err := store.SetDefault(ctx, "tenant-x", "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetDefault_NoDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.GetDefault(ctx, "tenant-nodefault")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestDelete_ClearsDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-deldef"

	_, err := store.Create(ctx, tenantID, defaultInput("solo"))
	require.NoError(t, err)
	require.NoError(t, store.SetDefault(ctx, tenantID, "solo"))

	require.NoError(t, store.Delete(ctx, tenantID, "solo"))

	_, err = store.GetDefault(ctx, tenantID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// FallbackChain
// ---------------------------------------------------------------------------

func TestFallbackChain_RoundTrip(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-fb"

	// Create providers a and b.
	_, err := store.Create(ctx, tenantID, defaultInput("a"))
	require.NoError(t, err)
	_, err = store.Create(ctx, tenantID, defaultInput("b"))
	require.NoError(t, err)

	err = store.SetFallbackChain(ctx, tenantID, []string{"a", "b"})
	require.NoError(t, err)

	chain, err := store.GetFallbackChain(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, chain)
}

func TestGetFallbackChain_Empty(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	chain, err := store.GetFallbackChain(ctx, "tenant-empty-fb")
	require.NoError(t, err)
	assert.Equal(t, []string{}, chain)
}

func TestSetFallbackChain_UnknownProvider(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-fbunk"

	_, err := store.Create(ctx, tenantID, defaultInput("real"))
	require.NoError(t, err)

	err = store.SetFallbackChain(ctx, tenantID, []string{"real", "ghost"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// Resolve (execution path)
// ---------------------------------------------------------------------------

func TestResolve_ReturnsPlaintext(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-resolve"

	input := defaultInput("anthro-resolve")
	input.Credentials = map[string]string{
		"api_key": "sk-ant-api03-plaintext-key-here",
	}
	_, err := store.Create(ctx, tenantID, input)
	require.NoError(t, err)

	dec, err := store.Resolve(ctx, tenantID, "anthro-resolve")
	require.NoError(t, err)

	// Plaintext must match what was written.
	assert.Equal(t, "sk-ant-api03-plaintext-key-here", dec.Credentials["api_key"])

	// The embedded ProviderConfig must have masked credentials.
	assert.Equal(t, "****here", dec.CredentialsMasked["api_key"])
}

func TestResolve_NotFound(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.Resolve(ctx, "tenant-x", "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// CRITICAL: encryption assertion
// ---------------------------------------------------------------------------

// TestEncryptionActuallyHappened reads the raw Redis key via miniredis and
// asserts that the stored bytes are NOT JSON-parseable as a ProviderConfig.
// This test would fail if encryption were accidentally skipped.
func TestEncryptionActuallyHappened(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	enc := crypto.NewAESGCMEncryptor()
	kp := newStaticKeyProvider()
	store, err := NewStore(client, enc, kp)
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := "tenant-enc"
	input := defaultInput("enc-test")
	input.Credentials = map[string]string{
		"api_key": "super-secret-key-0123456789",
	}

	_, err = store.Create(ctx, tenantID, input)
	require.NoError(t, err)

	// Read the raw bytes directly from miniredis, bypassing the store entirely.
	rawKey := providerKey(tenantID, "enc-test")
	rawBytes, err := mr.Get(rawKey)
	require.NoError(t, err, "raw key must exist in Redis")
	require.NotEmpty(t, rawBytes)

	// The raw bytes are a JSON-encoded storedRecord (outer wrapper with ID, Name,
	// EncryptedPayload, IV, Salt). The outer struct is plaintext JSON — that is
	// intentional and expected. What must NOT be plaintext is the encryptedPayload
	// nested inside EncryptedPayload — that must be AES-GCM ciphertext.

	// CRITICAL: the raw bytes must not contain the plaintext credential value.
	assert.NotContains(t, rawBytes, "super-secret-key",
		"CRITICAL: plaintext credential must not appear in raw Redis storage")

	// The outer storedRecord wrapper must be valid JSON (it's the envelope).
	var rec storedRecord
	require.NoError(t, json.Unmarshal([]byte(rawBytes), &rec),
		"outer storedRecord wrapper must be valid JSON")
	require.NotEmpty(t, rec.EncryptedPayload, "encrypted payload must be populated")
	require.NotEmpty(t, rec.IV, "IV must be populated")
	require.NotEmpty(t, rec.Salt, "salt must be populated")

	// Attempt to unmarshal the raw EncryptedPayload bytes as an encryptedPayload JSON.
	// This MUST fail because EncryptedPayload is AES-256-GCM ciphertext — not JSON.
	// If it succeeds, encryption was skipped and credentials are stored in plaintext.
	var leaked encryptedPayload
	unmarshalErr := json.Unmarshal(rec.EncryptedPayload, &leaked)
	assert.Error(t, unmarshalErr,
		"CRITICAL: EncryptedPayload must not be JSON-parseable as encryptedPayload — encryption must have occurred")
}

// ---------------------------------------------------------------------------
// Masking rules
// ---------------------------------------------------------------------------

func TestMaskCredential_Rules(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},               // empty → empty
		{"abc", "****"},        // < 8 chars → full mask
		{"1234567", "****"},    // 7 chars (< 8) → full mask
		{"12345678", "****5678"}, // exactly 8 → ****<last4>
		{"sk-ant-api03-abcdef", "****cdef"}, // long key
	}
	for _, tt := range tests {
		got := maskCredential(tt.input)
		assert.Equal(t, tt.want, got, "maskCredential(%q)", tt.input)
	}
}

func TestAsRecord_MasksAllFields(t *testing.T) {
	cfg := &ProviderConfig{
		ID:       types.NewID(),
		TenantID: "t1",
		Name:     "test",
		Type:     llm.ProviderAnthropic,
	}
	creds := map[string]string{
		"api_key":     "sk-ant-api03-abcdef1234567890",
		"short":       "abc",        // < 8 — full mask
		"exactly8":    "12345678",   // = 8 — ****5678
		"empty_field": "",           // empty — stays empty
	}
	masked := AsRecord(cfg, creds)
	assert.Equal(t, "****7890", masked.CredentialsMasked["api_key"])
	assert.Equal(t, "****", masked.CredentialsMasked["short"])
	assert.Equal(t, "****5678", masked.CredentialsMasked["exactly8"])
	assert.Equal(t, "", masked.CredentialsMasked["empty_field"])
}

// ---------------------------------------------------------------------------
// validateType helper
// ---------------------------------------------------------------------------

func TestValidateType_Supported(t *testing.T) {
	for _, pt := range llm.SupportedProviderTypes() {
		err := validateType(pt)
		assert.NoError(t, err, "validateType(%q) should succeed for supported type", pt)
	}
}

func TestValidateType_Unsupported(t *testing.T) {
	err := validateType(llm.ProviderType("totally_fake_provider"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedType)
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation (additional explicit test)
// ---------------------------------------------------------------------------

func TestTenantA_DoesNotSeeB(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, "alpha", defaultInput("secret-config"))
	require.NoError(t, err)

	// Tenant beta cannot Get or Resolve tenant alpha's config.
	_, err = store.Get(ctx, "beta", "secret-config")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound, "cross-tenant Get must return ErrNotFound")

	_, err = store.Resolve(ctx, "beta", "secret-config")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound, "cross-tenant Resolve must return ErrNotFound")

	listBeta, err := store.List(ctx, "beta")
	require.NoError(t, err)
	assert.Empty(t, listBeta, "cross-tenant List must return empty")
}

// ---------------------------------------------------------------------------
// ErrKeyProviderUnset sentinel errors
// ---------------------------------------------------------------------------

func TestSentinelErrors_Unwrap(t *testing.T) {
	assert.True(t, errors.Is(ErrNotFound, ErrNotFound))
	assert.True(t, errors.Is(ErrAlreadyExists, ErrAlreadyExists))
	assert.True(t, errors.Is(ErrUnsupportedType, ErrUnsupportedType))
	assert.True(t, errors.Is(ErrKeyProviderUnset, ErrKeyProviderUnset))
}

// ---------------------------------------------------------------------------
// Error path: key provider failure propagates through Create
// ---------------------------------------------------------------------------

// failingKeyProvider returns an error from GetEncryptionKey.
type failingKeyProvider struct{}

func (p *failingKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	return nil, errors.New("key provider is unavailable")
}
func (p *failingKeyProvider) Name() string                              { return "failing" }
func (p *failingKeyProvider) Health(_ context.Context) types.HealthStatus { return types.Unhealthy("") }
func (p *failingKeyProvider) Close() error                              { return nil }

var _ crypto.KeyProvider = (*failingKeyProvider)(nil)

func TestCreate_KeyProviderFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), &failingKeyProvider{})
	require.NoError(t, err)

	_, err = store.Create(context.Background(), "tenant-kpfail", defaultInput("any"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key provider is unavailable")
}

func TestGet_KeyProviderFailure(t *testing.T) {
	// First create with a working key provider, then swap to a broken one to test
	// decryption failure on Get.
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Create with good key provider.
	goodStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)
	_, err = goodStore.Create(context.Background(), "tenant-badkp", defaultInput("prov"))
	require.NoError(t, err)

	// Now try to Get with a failing key provider.
	badStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), &failingKeyProvider{})
	require.NoError(t, err)
	_, err = badStore.Get(context.Background(), "tenant-badkp", "prov")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key provider is unavailable")
}

func TestResolve_KeyProviderFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	goodStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)
	_, err = goodStore.Create(context.Background(), "tenant-resolve-fail", defaultInput("prov"))
	require.NoError(t, err)

	badStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), &failingKeyProvider{})
	require.NoError(t, err)
	_, err = badStore.Resolve(context.Background(), "tenant-resolve-fail", "prov")
	require.Error(t, err)
}

func TestUpdate_KeyProviderFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	goodStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)
	_, err = goodStore.Create(context.Background(), "tenant-upd-fail", defaultInput("prov"))
	require.NoError(t, err)

	// Update with a broken key provider — should fail during decrypt of existing.
	badStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), &failingKeyProvider{})
	require.NoError(t, err)
	_, err = badStore.Update(context.Background(), "tenant-upd-fail", "prov", defaultInput("prov"))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// List with corrupted / unreadable key (key provider fails mid-list)
// ---------------------------------------------------------------------------

func TestList_KeyProviderFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	goodStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)
	_, err = goodStore.Create(context.Background(), "tenant-list-fail", defaultInput("prov"))
	require.NoError(t, err)

	badStore, err := NewStore(client, crypto.NewAESGCMEncryptor(), &failingKeyProvider{})
	require.NoError(t, err)
	_, err = badStore.List(context.Background(), "tenant-list-fail")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetFallbackChain with corrupted data (non-JSON)
// ---------------------------------------------------------------------------

func TestGetFallbackChain_CorruptedData(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := "tenant-corrupt-fb"

	// Write garbage directly into the fallback key.
	key := fallbackKey(tenantID)
	require.NoError(t, client.Set(ctx, key, "not-valid-json", 0).Err())

	_, err = store.GetFallbackChain(ctx, tenantID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

// ---------------------------------------------------------------------------
// SetFallbackChain with empty slice (no providers to validate)
// ---------------------------------------------------------------------------

func TestSetFallbackChain_EmptySlice(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	// Setting an empty chain is valid (clears it).
	err := store.SetFallbackChain(ctx, "tenant-empty-chain", []string{})
	require.NoError(t, err)

	chain, err := store.GetFallbackChain(ctx, "tenant-empty-chain")
	require.NoError(t, err)
	assert.Equal(t, []string{}, chain)
}

// ---------------------------------------------------------------------------
// Delete does not clear default when different provider is default
// ---------------------------------------------------------------------------

func TestDelete_DoesNotClearOtherDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-del-other-default"

	_, err := store.Create(ctx, tenantID, defaultInput("primary"))
	require.NoError(t, err)
	_, err = store.Create(ctx, tenantID, defaultInput("secondary"))
	require.NoError(t, err)

	require.NoError(t, store.SetDefault(ctx, tenantID, "primary"))
	require.NoError(t, store.Delete(ctx, tenantID, "secondary"))

	// Default should still be primary.
	got, err := store.GetDefault(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "primary", got.Name)
}

// ---------------------------------------------------------------------------
// Update preserves CreatedAt
// ---------------------------------------------------------------------------

func TestUpdate_PreservesCreatedAt(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-created-at"

	created, err := store.Create(ctx, tenantID, defaultInput("prov"))
	require.NoError(t, err)
	origCreatedAt := created.CreatedAt

	updated, err := store.Update(ctx, tenantID, "prov", defaultInput("prov"))
	require.NoError(t, err)

	assert.True(t, updated.CreatedAt.Equal(origCreatedAt),
		"Update must preserve CreatedAt; got %v, want %v", updated.CreatedAt, origCreatedAt)
	assert.True(t, updated.UpdatedAt.Equal(origCreatedAt) || updated.UpdatedAt.After(origCreatedAt),
		"UpdatedAt must be >= CreatedAt")
}

// ---------------------------------------------------------------------------
// Update with SetAsDefault=true
// ---------------------------------------------------------------------------

func TestUpdate_SetAsDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-upd-default"

	_, err := store.Create(ctx, tenantID, defaultInput("prov"))
	require.NoError(t, err)

	inp := defaultInput("prov")
	inp.SetAsDefault = true
	updated, err := store.Update(ctx, tenantID, "prov", inp)
	require.NoError(t, err)
	assert.True(t, updated.IsDefault)

	got, err := store.GetDefault(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "prov", got.Name)
}

// ---------------------------------------------------------------------------
// Update type validation
// ---------------------------------------------------------------------------

func TestUpdate_UnsupportedType(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-upd-badtype"

	_, err := store.Create(ctx, tenantID, defaultInput("prov"))
	require.NoError(t, err)

	inp := defaultInput("prov")
	inp.Type = llm.ProviderType("bogus_type")
	_, err = store.Update(ctx, tenantID, "prov", inp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedType)
}

// ---------------------------------------------------------------------------
// readRecord error from closed client
// ---------------------------------------------------------------------------

func TestReadRecord_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	// Create a record with a working connection.
	ctx := context.Background()
	_, err = store.Create(ctx, "tenant-rderr", defaultInput("prov"))
	require.NoError(t, err)

	// Close the miniredis to simulate a Redis failure.
	mr.Close()

	_, err = store.Get(ctx, "tenant-rderr", "prov")
	require.Error(t, err)
	// Error should not be ErrNotFound; it should be a connection error.
	assert.False(t, errors.Is(err, ErrNotFound), "closed-client error should not be ErrNotFound")
}

// ---------------------------------------------------------------------------
// GetDefault non-nil Redis error (distinct from Nil / not-found)
// ---------------------------------------------------------------------------

func TestGetDefault_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = store.Create(ctx, "tenant-defrd", defaultInput("prov"))
	require.NoError(t, err)
	require.NoError(t, store.SetDefault(ctx, "tenant-defrd", "prov"))

	mr.Close()

	_, err = store.GetDefault(ctx, "tenant-defrd")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
}

// ---------------------------------------------------------------------------
// SetFallbackChain with all valid names (complete happy path)
// ---------------------------------------------------------------------------

func TestSetFallbackChain_AllValid(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-fb-allvalid"

	names := []string{"x", "y", "z"}
	for _, n := range names {
		_, err := store.Create(ctx, tenantID, defaultInput(n))
		require.NoError(t, err)
	}

	err := store.SetFallbackChain(ctx, tenantID, names)
	require.NoError(t, err)

	chain, err := store.GetFallbackChain(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, names, chain)
}

// ---------------------------------------------------------------------------
// SetFallbackChain: Redis error during validation read
// ---------------------------------------------------------------------------

func TestSetFallbackChain_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := "tenant-fb-rderr"
	_, err = store.Create(ctx, tenantID, defaultInput("prov"))
	require.NoError(t, err)

	// Close Redis to force a connection error during validation read.
	mr.Close()

	err = store.SetFallbackChain(ctx, tenantID, []string{"prov"})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
}

// ---------------------------------------------------------------------------
// List: Redis connection error
// ---------------------------------------------------------------------------

func TestList_RedisConnectionError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = store.Create(ctx, "tenant-list-rderr", defaultInput("prov"))
	require.NoError(t, err)

	mr.Close()

	_, err = store.List(ctx, "tenant-list-rderr")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// SetDefault: Redis error
// ---------------------------------------------------------------------------

func TestSetDefault_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})

	store, err := NewStore(client, crypto.NewAESGCMEncryptor(), newStaticKeyProvider())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = store.Create(ctx, "tenant-setdef-rd", defaultInput("prov"))
	require.NoError(t, err)

	// Verify the provider first (before closing), then close Redis before SET.
	// We need to close AFTER reading the provider record but before writing the default key.
	// The simplest approach: close Redis so the readRecord inside SetDefault fails.
	mr.Close()

	err = store.SetDefault(ctx, "tenant-setdef-rd", "prov")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// decryptPayload: JSON unmarshal on good plaintext
// ---------------------------------------------------------------------------

func TestDecryptPayload_CorruptedCiphertext(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	enc := crypto.NewAESGCMEncryptor()
	kp := newStaticKeyProvider()
	store, err := NewStore(client, enc, kp)
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := "tenant-corrupt"
	_, err = store.Create(ctx, tenantID, defaultInput("prov"))
	require.NoError(t, err)

	// Overwrite the stored record with a storedRecord that has garbage in
	// EncryptedPayload so decryption fails.
	key := providerKey(tenantID, "prov")
	// Get the real record first.
	rawBytes, redisErr := mr.Get(key)
	require.NoError(t, redisErr)

	var rec storedRecord
	require.NoError(t, json.Unmarshal([]byte(rawBytes), &rec))

	// Corrupt the encrypted payload.
	rec.EncryptedPayload = []byte("completely_garbage_ciphertext_data_here")
	corrupted, marshalErr := json.Marshal(rec)
	require.NoError(t, marshalErr)
	require.NoError(t, client.Set(ctx, key, corrupted, 0).Err())

	// Now Get should fail with a decryption error.
	_, err = store.Get(ctx, tenantID, "prov")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

// ---------------------------------------------------------------------------
// Create with SetAsDefault=true
// ---------------------------------------------------------------------------

func TestCreate_SetAsDefault(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()
	tenantID := "tenant-create-default"

	input := defaultInput("default-provider")
	input.SetAsDefault = true
	cfg, err := store.Create(ctx, tenantID, input)
	require.NoError(t, err)
	assert.True(t, cfg.IsDefault)

	got, err := store.GetDefault(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "default-provider", got.Name)
}
