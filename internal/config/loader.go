package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// ConfigLoader handles loading configuration from files.
type ConfigLoader interface {
	Load(path string) (*Config, error)
	LoadWithDefaults(path string) (*Config, error)
}

// viperConfigLoader implements ConfigLoader using Viper.
type viperConfigLoader struct {
	validator ConfigValidator
}

// NewConfigLoader creates a new ConfigLoader instance.
func NewConfigLoader(validator ConfigValidator) ConfigLoader {
	return &viperConfigLoader{
		validator: validator,
	}
}

// Load loads configuration from the specified file path.
// Returns an error if the file doesn't exist or cannot be parsed.
func (l *viperConfigLoader) Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal into Config struct first
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Read raw config into map for environment variable interpolation
	rawConfig := v.AllSettings()
	interpolatedConfig := interpolateEnvVars(rawConfig)

	// Apply environment variable interpolation to the unmarshaled config
	if interpolatedMap, ok := interpolatedConfig.(map[string]interface{}); ok {
		if err := applyInterpolation(&cfg, interpolatedMap); err != nil {
			return nil, fmt.Errorf("failed to apply environment variable interpolation: %w", err)
		}

		// Warn if deprecated database section is present
		if _, hasDatabase := interpolatedMap["database"]; hasDatabase {
			slog.Warn("DEPRECATED: 'database' section in config is deprecated and will be removed in a future version. Please migrate to Redis-based state storage using the 'redis' section.")
		}
	}

	// Validate the loaded configuration
	if err := l.validator.Validate(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// LoadWithDefaults loads configuration from the specified file path.
// If the file doesn't exist, returns default configuration.
// If the file exists, it merges file values on top of defaults (missing sections get defaults).
func (l *viperConfigLoader) LoadWithDefaults(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// No file, just validate and return defaults
		if err := l.validator.Validate(cfg); err != nil {
			return nil, fmt.Errorf("default configuration validation failed: %w", err)
		}
		return cfg, nil
	}

	// File exists, load and merge on top of defaults
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal into the cfg struct (which already has defaults)
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Read raw config into map for environment variable interpolation
	rawConfig := v.AllSettings()
	interpolatedConfig := interpolateEnvVars(rawConfig)

	// Apply environment variable interpolation to the unmarshaled config
	if interpolatedMap, ok := interpolatedConfig.(map[string]interface{}); ok {
		if err := applyInterpolation(cfg, interpolatedMap); err != nil {
			return nil, fmt.Errorf("failed to apply environment variable interpolation: %w", err)
		}

		// Warn if deprecated database section is present
		if _, hasDatabase := interpolatedMap["database"]; hasDatabase {
			slog.Warn("DEPRECATED: 'database' section in config is deprecated and will be removed in a future version. Please migrate to Redis-based state storage using the 'redis' section.")
		}
	}

	// Validate the loaded configuration
	if err := l.validator.Validate(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// interpolateEnvVars recursively interpolates environment variables in the config map.
// Supports ${VAR_NAME} syntax.
func interpolateEnvVars(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			result[key] = interpolateEnvVars(value)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = interpolateEnvVars(value)
		}
		return result
	case string:
		return interpolateString(v)
	default:
		return v
	}
}

// interpolateString replaces ${VAR_NAME} or ${VAR_NAME:-default} with environment variable values.
func interpolateString(s string) string {
	// Regular expression to match ${VAR_NAME} or ${VAR_NAME:-default}
	re := regexp.MustCompile(`\$\{([^}]+)\}`)

	return re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract content between ${ and }
		content := strings.TrimSuffix(strings.TrimPrefix(match, "${"), "}")

		// Check for default value syntax: VAR_NAME:-default
		var varName, defaultValue string
		if idx := strings.Index(content, ":-"); idx != -1 {
			varName = content[:idx]
			defaultValue = content[idx+2:]
		} else {
			varName = content
			defaultValue = ""
		}

		// Get environment variable value
		if envValue := os.Getenv(varName); envValue != "" {
			return envValue
		}

		// Return default value if provided, otherwise empty string
		if defaultValue != "" {
			return defaultValue
		}

		// If no default and env not set, return empty string (not the original match)
		return ""
	})
}

// applyInterpolation applies the interpolated values back to the Config struct.
func applyInterpolation(cfg *Config, interpolated map[string]interface{}) error {
	// Apply Core config interpolation
	if core, ok := interpolated["core"].(map[string]interface{}); ok {
		if homeDir, ok := core["home_dir"].(string); ok {
			cfg.Core.HomeDir = interpolateString(homeDir)
		}
		if dataDir, ok := core["data_dir"].(string); ok {
			cfg.Core.DataDir = interpolateString(dataDir)
		}
		if cacheDir, ok := core["cache_dir"].(string); ok {
			cfg.Core.CacheDir = interpolateString(cacheDir)
		}
	}

	// Apply Security config interpolation
	if security, ok := interpolated["security"].(map[string]interface{}); ok {
		if algo, ok := security["encryption_algorithm"].(string); ok {
			cfg.Security.EncryptionAlgorithm = interpolateString(algo)
		}
		if kd, ok := security["key_derivation"].(string); ok {
			cfg.Security.KeyDerivation = interpolateString(kd)
		}
	}

	// Apply LLM config interpolation
	if llm, ok := interpolated["llm"].(map[string]interface{}); ok {
		if provider, ok := llm["default_provider"].(string); ok {
			cfg.LLM.DefaultProvider = interpolateString(provider)
		}
	}

	// Apply Logging config interpolation
	if logging, ok := interpolated["logging"].(map[string]interface{}); ok {
		if level, ok := logging["level"].(string); ok {
			cfg.Logging.Level = interpolateString(level)
		}
		if format, ok := logging["format"].(string); ok {
			cfg.Logging.Format = interpolateString(format)
		}
	}

	// Apply Tracing config interpolation
	if tracing, ok := interpolated["tracing"].(map[string]interface{}); ok {
		if endpoint, ok := tracing["endpoint"].(string); ok {
			cfg.Tracing.Endpoint = interpolateString(endpoint)
		}
	}

	// Apply Daemon config interpolation
	if daemon, ok := interpolated["daemon"].(map[string]interface{}); ok {
		if grpcAddr, ok := daemon["grpc_address"].(string); ok {
			cfg.Daemon.GRPCAddress = interpolateString(grpcAddr)
		}
	}

	// Apply Langfuse config interpolation
	if langfuse, ok := interpolated["langfuse"].(map[string]interface{}); ok {
		if host, ok := langfuse["host"].(string); ok {
			cfg.Langfuse.Host = interpolateString(host)
		}
		if publicKey, ok := langfuse["public_key"].(string); ok {
			cfg.Langfuse.PublicKey = interpolateString(publicKey)
		}
		if secretKey, ok := langfuse["secret_key"].(string); ok {
			cfg.Langfuse.SecretKey = interpolateString(secretKey)
		}
	}

	// Apply Plugins config interpolation
	if plugins, ok := interpolated["plugins"].(map[string]interface{}); ok {
		if cfg.Plugins == nil {
			cfg.Plugins = make(PluginsConfig)
		}
		for pluginName, pluginConfig := range plugins {
			if pluginMap, ok := pluginConfig.(map[string]interface{}); ok {
				cfg.Plugins[pluginName] = make(map[string]string)
				for key, value := range pluginMap {
					if strVal, ok := value.(string); ok {
						cfg.Plugins[pluginName][key] = interpolateString(strVal)
					}
				}
			}
		}
	}

	// Apply ActivityLogging config interpolation
	if activityLogging, ok := interpolated["activity_logging"].(map[string]interface{}); ok {
		if level, ok := activityLogging["level"].(string); ok {
			cfg.ActivityLogging.Level = interpolateString(level)
		}
		if output, ok := activityLogging["output"].(string); ok {
			cfg.ActivityLogging.Output = interpolateString(output)
		}
		if filePath, ok := activityLogging["file_path"].(string); ok {
			cfg.ActivityLogging.FilePath = interpolateString(filePath)
		}
	}

	// Apply Registry config interpolation
	if registry, ok := interpolated["registry"].(map[string]interface{}); ok {
		if listenAddr, ok := registry["listen_address"].(string); ok {
			cfg.Registry.ListenAddress = interpolateString(listenAddr)
		}
	}

	// Apply GraphRAG/Neo4j config interpolation
	if graphrag, ok := interpolated["graphrag"].(map[string]interface{}); ok {
		if neo4j, ok := graphrag["neo4j"].(map[string]interface{}); ok {
			if uri, ok := neo4j["uri"].(string); ok {
				cfg.GraphRAG.Neo4j.URI = interpolateString(uri)
			}
			if username, ok := neo4j["username"].(string); ok {
				cfg.GraphRAG.Neo4j.Username = interpolateString(username)
			}
			if password, ok := neo4j["password"].(string); ok {
				cfg.GraphRAG.Neo4j.Password = interpolateString(password)
			}
		}
	}

	// Apply Redis config interpolation
	if redis, ok := interpolated["redis"].(map[string]interface{}); ok {
		if url, ok := redis["url"].(string); ok {
			cfg.Redis.URL = interpolateString(url)
		}
		if password, ok := redis["password"].(string); ok {
			cfg.Redis.Password = interpolateString(password)
		}
		if tlsCertFile, ok := redis["tls_cert_file"].(string); ok {
			cfg.Redis.TLSCertFile = interpolateString(tlsCertFile)
		}
		if tlsKeyFile, ok := redis["tls_key_file"].(string); ok {
			cfg.Redis.TLSKeyFile = interpolateString(tlsKeyFile)
		}
		if tlsCAFile, ok := redis["tls_ca_file"].(string); ok {
			cfg.Redis.TLSCAFile = interpolateString(tlsCAFile)
		}
		if sentinelMaster, ok := redis["sentinel_master"].(string); ok {
			cfg.Redis.SentinelMaster = interpolateString(sentinelMaster)
		}
		// Handle string arrays for cluster and sentinel addresses
		if clusterAddrs, ok := redis["cluster_addrs"].([]interface{}); ok {
			cfg.Redis.ClusterAddrs = make([]string, len(clusterAddrs))
			for i, addr := range clusterAddrs {
				if strAddr, ok := addr.(string); ok {
					cfg.Redis.ClusterAddrs[i] = interpolateString(strAddr)
				}
			}
		}
		if sentinelAddrs, ok := redis["sentinel_addrs"].([]interface{}); ok {
			cfg.Redis.SentinelAddrs = make([]string, len(sentinelAddrs))
			for i, addr := range sentinelAddrs {
				if strAddr, ok := addr.(string); ok {
					cfg.Redis.SentinelAddrs[i] = interpolateString(strAddr)
				}
			}
		}
	}

	return nil
}
