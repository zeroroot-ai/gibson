package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCallbackConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.Callback.Enabled, "Callback should be enabled by default")
	assert.Equal(t, "0.0.0.0:50001", cfg.Callback.ListenAddress, "Default listen address should be 0.0.0.0:50001")
	assert.Equal(t, "", cfg.Callback.AdvertiseAddress, "Default advertise address should be empty")
}

func TestCallbackConfig_EnvironmentOverrides(t *testing.T) {
	// Save original env vars
	origListen := os.Getenv("GIBSON_CALLBACK_LISTEN_ADDRESS")
	origAdvertise := os.Getenv("GIBSON_CALLBACK_ADVERTISE_ADDR")
	defer func() {
		os.Setenv("GIBSON_CALLBACK_LISTEN_ADDRESS", origListen)
		os.Setenv("GIBSON_CALLBACK_ADVERTISE_ADDR", origAdvertise)
	}()

	// Test with environment variables set
	os.Setenv("GIBSON_CALLBACK_LISTEN_ADDRESS", "127.0.0.1:9999")
	os.Setenv("GIBSON_CALLBACK_ADVERTISE_ADDR", "gibson:9999")

	cfg := CallbackConfig{
		Enabled:          true,
		ListenAddress:    "0.0.0.0:50001",
		AdvertiseAddress: "",
	}

	cfg.ApplyEnvironmentOverrides()

	assert.Equal(t, "127.0.0.1:9999", cfg.ListenAddress, "Listen address should be overridden by env var")
	assert.Equal(t, "gibson:9999", cfg.AdvertiseAddress, "Advertise address should be overridden by env var")
}

func TestCallbackConfig_EnvironmentOverrides_EmptyEnv(t *testing.T) {
	// Save original env vars
	origListen := os.Getenv("GIBSON_CALLBACK_LISTEN_ADDRESS")
	origAdvertise := os.Getenv("GIBSON_CALLBACK_ADVERTISE_ADDR")
	defer func() {
		os.Setenv("GIBSON_CALLBACK_LISTEN_ADDRESS", origListen)
		os.Setenv("GIBSON_CALLBACK_ADVERTISE_ADDR", origAdvertise)
	}()

	// Clear environment variables
	os.Unsetenv("GIBSON_CALLBACK_LISTEN_ADDRESS")
	os.Unsetenv("GIBSON_CALLBACK_ADVERTISE_ADDR")

	cfg := CallbackConfig{
		Enabled:          true,
		ListenAddress:    "0.0.0.0:50001",
		AdvertiseAddress: "original:50001",
	}

	cfg.ApplyEnvironmentOverrides()

	assert.Equal(t, "0.0.0.0:50001", cfg.ListenAddress, "Listen address should not change when env var is empty")
	assert.Equal(t, "original:50001", cfg.AdvertiseAddress, "Advertise address should not change when env var is empty")
}
