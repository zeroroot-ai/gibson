package client

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveToken_FlagPrecedence(t *testing.T) {
	// Set up environment variable to verify flag takes precedence
	t.Setenv(EnvDaemonToken, "env-token")

	opts := TokenOptions{
		FlagToken:   "flag-token",
		ConfigToken: "config-token",
	}

	token, source := ResolveToken(opts)

	assert.Equal(t, "flag-token", token)
	assert.Equal(t, TokenSourceFlag, source)
}

func TestResolveToken_EnvPrecedence(t *testing.T) {
	// Set up environment variable
	t.Setenv(EnvDaemonToken, "env-token")

	opts := TokenOptions{
		FlagToken:   "", // No flag
		ConfigToken: "config-token",
	}

	token, source := ResolveToken(opts)

	assert.Equal(t, "env-token", token)
	assert.Equal(t, TokenSourceEnv, source)
}

func TestResolveToken_ConfigPrecedence(t *testing.T) {
	// Ensure no environment variable is set
	os.Unsetenv(EnvDaemonToken)

	opts := TokenOptions{
		FlagToken:   "", // No flag
		ConfigToken: "config-token",
	}

	token, source := ResolveToken(opts)

	assert.Equal(t, "config-token", token)
	assert.Equal(t, TokenSourceConfig, source)
}

func TestResolveToken_NoToken(t *testing.T) {
	// Ensure no environment variable is set
	os.Unsetenv(EnvDaemonToken)

	opts := TokenOptions{
		FlagToken:   "",
		ConfigToken: "",
	}

	token, source := ResolveToken(opts)

	assert.Equal(t, "", token)
	assert.Equal(t, TokenSourceNone, source)
}

func TestResolveToken_FlagOverridesAll(t *testing.T) {
	// Set up all sources
	t.Setenv(EnvDaemonToken, "env-token")

	opts := TokenOptions{
		FlagToken:   "flag-token",
		ConfigToken: "config-token",
	}

	token, source := ResolveToken(opts)

	// Flag should win
	assert.Equal(t, "flag-token", token)
	assert.Equal(t, TokenSourceFlag, source)
}

func TestResolveToken_EnvOverridesConfig(t *testing.T) {
	// Set up env and config
	t.Setenv(EnvDaemonToken, "env-token")

	opts := TokenOptions{
		FlagToken:   "", // No flag
		ConfigToken: "config-token",
	}

	token, source := ResolveToken(opts)

	// Env should win over config
	assert.Equal(t, "env-token", token)
	assert.Equal(t, TokenSourceEnv, source)
}

func TestResolveToken_EmptyStringsAreNoToken(t *testing.T) {
	// Test that empty strings are treated as "no token"
	os.Unsetenv(EnvDaemonToken)

	tests := []struct {
		name        string
		flagToken   string
		configToken string
		expectToken string
		expectSrc   TokenSource
	}{
		{
			name:        "flag empty, config has value",
			flagToken:   "",
			configToken: "config-token",
			expectToken: "config-token",
			expectSrc:   TokenSourceConfig,
		},
		{
			name:        "both empty",
			flagToken:   "",
			configToken: "",
			expectToken: "",
			expectSrc:   TokenSourceNone,
		},
		{
			name:        "flag has value, config empty",
			flagToken:   "flag-token",
			configToken: "",
			expectToken: "flag-token",
			expectSrc:   TokenSourceFlag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := TokenOptions{
				FlagToken:   tt.flagToken,
				ConfigToken: tt.configToken,
			}

			token, source := ResolveToken(opts)

			assert.Equal(t, tt.expectToken, token)
			assert.Equal(t, tt.expectSrc, source)
		})
	}
}

func TestEnvDaemonToken_ConstantValue(t *testing.T) {
	// Ensure the constant has the expected value
	assert.Equal(t, "GIBSON_DAEMON_TOKEN", EnvDaemonToken)
}

func TestTokenSource_StringValues(t *testing.T) {
	// Verify TokenSource constant values for logging/debugging
	assert.Equal(t, TokenSource("none"), TokenSourceNone)
	assert.Equal(t, TokenSource("flag"), TokenSourceFlag)
	assert.Equal(t, TokenSource("env"), TokenSourceEnv)
	assert.Equal(t, TokenSource("config"), TokenSourceConfig)
}

func TestResolveToken_WithRealEnvironment(t *testing.T) {
	// Test with actual environment variable setting
	testToken := "real-env-token-123"
	t.Setenv(EnvDaemonToken, testToken)

	// Verify environment variable was set
	envValue := os.Getenv(EnvDaemonToken)
	require.Equal(t, testToken, envValue)

	opts := TokenOptions{
		FlagToken:   "",
		ConfigToken: "",
	}

	token, source := ResolveToken(opts)

	assert.Equal(t, testToken, token)
	assert.Equal(t, TokenSourceEnv, source)
}
