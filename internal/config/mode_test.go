package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseMode
// ---------------------------------------------------------------------------

func TestParseMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Mode
		wantErr bool
	}{
		// Valid: lowercase
		{name: "saas lowercase", input: "saas", want: ModeSaaS},
		{name: "selfhost lowercase", input: "selfhost", want: ModeSelfhost},
		{name: "dev lowercase", input: "dev", want: ModeDev},

		// Valid: mixed case
		{name: "SaaS mixed", input: "SaaS", want: ModeSaaS},
		{name: "Selfhost mixed", input: "Selfhost", want: ModeSelfhost},
		{name: "Dev mixed", input: "Dev", want: ModeDev},

		// Valid: all upper
		{name: "SAAS upper", input: "SAAS", want: ModeSaaS},
		{name: "SELFHOST upper", input: "SELFHOST", want: ModeSelfhost},
		{name: "DEV upper", input: "DEV", want: ModeDev},

		// Invalid: empty returns error
		{name: "empty string", input: "", wantErr: true},

		// Invalid: unrecognised value
		{name: "bogus", input: "bogus", wantErr: true},
		{name: "production", input: "production", wantErr: true},
		{name: "staging", input: "staging", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMode(tc.input)
			if tc.wantErr {
				require.Error(t, err, "expected an error for input %q", tc.input)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Mode.String()
// ---------------------------------------------------------------------------

func TestModeString(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeSaaS, "saas"},
		{ModeSelfhost, "selfhost"},
		{ModeDev, "dev"},
		{ModeUnset, "unset"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.mode.String(), "Mode(%d).String()", int(tc.mode))
	}
}

// ---------------------------------------------------------------------------
// loadMode (via env var)
// ---------------------------------------------------------------------------

func TestLoadMode_UnsetDefaultsSelfhost(t *testing.T) {
	t.Setenv("GIBSON_MODE", "")

	m, err := loadMode()
	require.NoError(t, err)
	assert.Equal(t, ModeSelfhost, m, "unset GIBSON_MODE should default to selfhost")
}

func TestLoadMode_Saas(t *testing.T) {
	t.Setenv("GIBSON_MODE", "saas")

	m, err := loadMode()
	require.NoError(t, err)
	assert.Equal(t, ModeSaaS, m)
}

func TestLoadMode_InvalidError(t *testing.T) {
	t.Setenv("GIBSON_MODE", "production")

	_, err := loadMode()
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// loadStrictTenant (via env var)
// ---------------------------------------------------------------------------

func TestLoadStrictTenant_UnsetDefaultsFalse(t *testing.T) {
	t.Setenv("GIBSON_STRICT_TENANT", "")

	strict, err := loadStrictTenant()
	require.NoError(t, err)
	assert.False(t, strict, "unset GIBSON_STRICT_TENANT should default to false")
}

func TestLoadStrictTenant_TrueValues(t *testing.T) {
	for _, val := range []string{"1", "true", "yes", "TRUE", "YES"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("GIBSON_STRICT_TENANT", val)
			strict, err := loadStrictTenant()
			require.NoError(t, err)
			assert.True(t, strict, "GIBSON_STRICT_TENANT=%q should resolve to true", val)
		})
	}
}

func TestLoadStrictTenant_FalseValues(t *testing.T) {
	for _, val := range []string{"0", "false", "no", "FALSE", "NO"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("GIBSON_STRICT_TENANT", val)
			strict, err := loadStrictTenant()
			require.NoError(t, err)
			assert.False(t, strict, "GIBSON_STRICT_TENANT=%q should resolve to false", val)
		})
	}
}

func TestLoadStrictTenant_InvalidError(t *testing.T) {
	t.Setenv("GIBSON_STRICT_TENANT", "maybe")

	_, err := loadStrictTenant()
	require.Error(t, err, "invalid GIBSON_STRICT_TENANT value should return an error")
	assert.Contains(t, err.Error(), "maybe")
}

// ---------------------------------------------------------------------------
// Config loader integration: env vars → Config fields
// ---------------------------------------------------------------------------

func TestConfigLoader_ModeAndStrictTenantFromEnv(t *testing.T) {
	t.Setenv("GIBSON_MODE", "saas")
	t.Setenv("GIBSON_STRICT_TENANT", "1")

	cfg := DefaultConfig()
	err := applyRuntimeEnvOverrides(cfg)
	require.NoError(t, err)

	assert.Equal(t, ModeSaaS, cfg.Mode(), "GIBSON_MODE=saas should resolve to ModeSaaS")
	assert.True(t, cfg.StrictTenant(), "GIBSON_STRICT_TENANT=1 should resolve to true")
}

func TestConfigLoader_DefaultsWhenEnvUnset(t *testing.T) {
	t.Setenv("GIBSON_MODE", "")
	t.Setenv("GIBSON_STRICT_TENANT", "")

	cfg := DefaultConfig()
	err := applyRuntimeEnvOverrides(cfg)
	require.NoError(t, err)

	assert.Equal(t, ModeSelfhost, cfg.Mode(), "unset GIBSON_MODE should default to selfhost")
	assert.False(t, cfg.StrictTenant(), "unset GIBSON_STRICT_TENANT should default to false")
}

func TestConfigLoader_InvalidStrictTenantError(t *testing.T) {
	t.Setenv("GIBSON_MODE", "")
	t.Setenv("GIBSON_STRICT_TENANT", "maybe")

	cfg := DefaultConfig()
	err := applyRuntimeEnvOverrides(cfg)
	require.Error(t, err, "invalid GIBSON_STRICT_TENANT should cause a load error")
	assert.Contains(t, err.Error(), "maybe")
}

func TestConfigLoader_SelfhostMode(t *testing.T) {
	t.Setenv("GIBSON_MODE", "selfhost")
	t.Setenv("GIBSON_STRICT_TENANT", "0")

	cfg := DefaultConfig()
	err := applyRuntimeEnvOverrides(cfg)
	require.NoError(t, err)

	assert.Equal(t, ModeSelfhost, cfg.Mode())
	assert.False(t, cfg.StrictTenant())
}

func TestConfigLoader_DevMode(t *testing.T) {
	t.Setenv("GIBSON_MODE", "dev")
	t.Setenv("GIBSON_STRICT_TENANT", "false")

	cfg := DefaultConfig()
	err := applyRuntimeEnvOverrides(cfg)
	require.NoError(t, err)

	assert.Equal(t, ModeDev, cfg.Mode())
	assert.False(t, cfg.StrictTenant())
}
