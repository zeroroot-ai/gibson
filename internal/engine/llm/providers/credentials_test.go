package providers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Stubs for secrets.Service used by credential resolution tests.
// ---------------------------------------------------------------------------

type credTestBroker struct {
	getVal []byte
	getErr error
}

func (b *credTestBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return b.getVal, b.getErr
}
func (b *credTestBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return nil
}
func (b *credTestBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error { return nil }
func (b *credTestBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b *credTestBroker) Health(_ context.Context) error { return nil }
func (b *credTestBroker) Probe(_ context.Context) error  { return nil }
func (b *credTestBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true, MaxValueBytes: 1 << 20}
}

var _ sdksecrets.Broker = (*credTestBroker)(nil)

type credTestRegistry struct {
	broker sdksecrets.Broker
	err    error
}

func (r *credTestRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, r.err
}

type credTestCircuit struct{}

func (c *credTestCircuit) Execute(_, _ string, fn func() error) error { return fn() }

type credTestAuditor struct{}

func (a *credTestAuditor) Audit(_ context.Context, _ secrets.AuditEvent) {}

func buildCredTestService(t *testing.T, val []byte, err error) *secrets.Service {
	t.Helper()
	broker := &credTestBroker{getVal: val, getErr: err}
	reg := &credTestRegistry{broker: broker}
	svc, svcErr := secrets.NewService(reg, &credTestCircuit{}, &credTestAuditor{})
	require.NoError(t, svcErr)
	return svc
}

func ctxWithTestTenant() context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID("test-tenant"))
}

// ---------------------------------------------------------------------------
// resolveCredential tests — broker-first path
// ---------------------------------------------------------------------------

func TestResolveCredential_BrokerFirst_RawBytes(t *testing.T) {
	// Broker returns raw bytes (not JSON).
	svc := buildCredTestService(t, []byte("broker-secret"), nil)

	got, err := resolveCredential(ctxWithTestTenant(), svc, llm.ProviderConfig{}, "testprov", "api_key", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "broker-secret", got)
}

func TestResolveCredential_BrokerFirst_JSONBlob(t *testing.T) {
	// Broker returns a JSON blob with "value" field.
	svc := buildCredTestService(t, []byte(`{"value":"json-secret"}`), nil)

	got, err := resolveCredential(ctxWithTestTenant(), svc, llm.ProviderConfig{}, "testprov", "api_key", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "json-secret", got)
}

func TestResolveCredential_BrokerFirst_APIKeyField(t *testing.T) {
	// Broker returns a JSON blob with "api_key" field.
	svc := buildCredTestService(t, []byte(`{"api_key":"json-api-key"}`), nil)

	got, err := resolveCredential(ctxWithTestTenant(), svc, llm.ProviderConfig{}, "testprov", "", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "json-api-key", got)
}

func TestResolveCredential_BrokerNotFound_FallsBackToExtra(t *testing.T) {
	// Broker returns ErrNotFound → fall back to cfg.Extra.
	svc := buildCredTestService(t, nil, fmt.Errorf("not found: %w", sdksecrets.ErrNotFound))

	cfg := llm.ProviderConfig{Extra: map[string]string{"my_token": "extra-value"}}
	got, err := resolveCredential(ctxWithTestTenant(), svc, cfg, "testprov", "my_token", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "extra-value", got)
}

func TestResolveCredential_BrokerNotFound_FallsBackToAPIKey(t *testing.T) {
	// Broker returns ErrNotFound → fall back to cfg.APIKey (extraKey == "").
	svc := buildCredTestService(t, nil, fmt.Errorf("not found: %w", sdksecrets.ErrNotFound))

	cfg := llm.ProviderConfig{APIKey: "cfg-api-key"}
	got, err := resolveCredential(ctxWithTestTenant(), svc, cfg, "testprov", "", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "cfg-api-key", got)
}

func TestResolveCredential_NilService_FallsBackToExtra(t *testing.T) {
	// No service → falls back to cfg.Extra.
	cfg := llm.ProviderConfig{Extra: map[string]string{"my_token": "extra-value"}}
	got, err := resolveCredential(context.Background(), nil, cfg, "testprov", "my_token", "ABSENT", true)
	require.NoError(t, err)
	assert.Equal(t, "extra-value", got)
}

// ---------------------------------------------------------------------------
// Original resolveCredential tests (without broker) — behavior preserved.
// ---------------------------------------------------------------------------

func TestResolveCredential_Precedence(t *testing.T) {
	t.Setenv("TESTPROV_KEY", "from-env")
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")

	tests := []struct {
		name     string
		cfg      llm.ProviderConfig
		extraKey string
		envVar   string
		required bool
		wantVal  string
		wantErr  bool
	}{
		{
			name: "extra map wins over api_key and env",
			cfg: llm.ProviderConfig{
				APIKey: "from-apikey",
				Extra:  map[string]string{"my_token": "from-extra"},
			},
			extraKey: "my_token",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-extra",
		},
		{
			name: "api_key used when extraKey is empty",
			cfg: llm.ProviderConfig{
				APIKey: "from-apikey",
			},
			extraKey: "",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-apikey",
		},
		{
			name:     "env falls through when extra and api_key both empty (dev fallback enabled)",
			cfg:      llm.ProviderConfig{},
			extraKey: "",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-env",
		},
		{
			name:     "extra key miss falls through to env",
			cfg:      llm.ProviderConfig{Extra: map[string]string{"other_key": "x"}},
			extraKey: "my_token",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-env",
		},
		{
			name:     "missing + required returns AuthError naming both sources",
			cfg:      llm.ProviderConfig{},
			extraKey: "my_token",
			envVar:   "ABSENT_VAR_XYZ",
			required: true,
			wantErr:  true,
		},
		{
			name:     "missing + not-required returns empty string, no error",
			cfg:      llm.ProviderConfig{},
			extraKey: "my_token",
			envVar:   "ABSENT_VAR_XYZ",
			required: false,
			wantVal:  "",
		},
		{
			name:     "extraKey empty + api_key empty + env empty + required = error",
			cfg:      llm.ProviderConfig{},
			extraKey: "",
			envVar:   "ABSENT_VAR_XYZ",
			required: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveCredential(context.Background(), nil, tt.cfg, "testprov", tt.extraKey, tt.envVar, tt.required)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), "missing credential")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVal, got)
		})
	}
}

// TestResolveCredential_ErrorMessage_MentionsHint ensures operators get a
// pointer to either the Extra key, the APIKey field, or the env var.
func TestResolveCredential_ErrorMessage_MentionsHint(t *testing.T) {
	_, err := resolveCredential(context.Background(), nil, llm.ProviderConfig{}, "bedrock", "aws_access_key_id", "AWS_ACCESS_KEY_ID", true)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "aws_access_key_id")
	assert.Contains(t, msg, "AWS_ACCESS_KEY_ID")
}

func TestRedactCredentialKeys_IncludesEveryProviderSecret(t *testing.T) {
	keys := redactCredentialKeys()
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	// Spot-check the keys every provider relies on. If a new provider is
	// added without updating this list, the observability redaction
	// allowlist will leak credentials.
	required := []string{
		"api_key",
		"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
		"cloudflare_account_id", "cloudflare_api_token",
		"huggingface_api_token",
		"mistral_api_key", "cohere_api_key",
	}
	for _, k := range required {
		assert.True(t, set[k], "redactCredentialKeys() missing %q", k)
	}
}

// TestResolveCredential_EnvFallbackDisabledByDefault verifies that env-var
// fallback is off unless GIBSON_DEV_ENV_FALLBACK=true.
func TestResolveCredential_EnvFallbackDisabledByDefault(t *testing.T) {
	t.Setenv("MY_SECRET_KEY", "from-env")
	// GIBSON_DEV_ENV_FALLBACK is NOT set → env fallback disabled.
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "false")

	_, err := resolveCredential(context.Background(), nil, llm.ProviderConfig{}, "testprov", "", "MY_SECRET_KEY", true)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "missing credential")
}
