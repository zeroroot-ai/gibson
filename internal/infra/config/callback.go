package config

import "os"

// CallbackConfig contains configuration for the callback server.
// The callback server allows external gRPC agents to access harness functionality
// (LLM completions, tool execution, memory, GraphRAG, findings) by connecting
// back to Gibson Core's HarnessCallbackService.
type CallbackConfig struct {
	// ListenAddress is the address the callback server listens on (e.g., "0.0.0.0:50001")
	ListenAddress string `mapstructure:"listen_address" yaml:"listen_address"`

	// AdvertiseAddress is the address sent to agents as the callback endpoint
	// (e.g., "gibson:50001" for Docker networking)
	// If empty, ListenAddress is used
	AdvertiseAddress string `mapstructure:"advertise_address" yaml:"advertise_address"`

	// Enabled controls whether the callback server is started
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

// ApplyEnvironmentOverrides checks for environment variables and overrides
// the config values if they are set.
//
// Supported environment variables:
//   - GIBSON_CALLBACK_LISTEN_ADDRESS: overrides ListenAddress
//   - GIBSON_CALLBACK_ADVERTISE_ADDR: overrides AdvertiseAddress
func (c *CallbackConfig) ApplyEnvironmentOverrides() {
	if listenAddr := os.Getenv("GIBSON_CALLBACK_LISTEN_ADDRESS"); listenAddr != "" {
		c.ListenAddress = listenAddr
	}

	if advertiseAddr := os.Getenv("GIBSON_CALLBACK_ADVERTISE_ADDR"); advertiseAddr != "" {
		c.AdvertiseAddress = advertiseAddr
	}
}
