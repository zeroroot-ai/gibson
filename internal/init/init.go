package init

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
)

// InitOptions configures the initialization process
type InitOptions struct {
	// HomeDir is the root directory for Gibson installation
	// If empty, uses the default from config.DefaultConfig()
	HomeDir string

	// NonInteractive skips all prompts and uses defaults
	// Useful for CI/CD and automated deployments
	NonInteractive bool

	// Force recreates components even if they already exist
	// WARNING: This can overwrite existing configurations
	Force bool
}

// InitResult contains the results of the initialization process
type InitResult struct {
	// HomeDir is the final home directory used
	HomeDir string

	// DirsCreated lists all directories that were created (not pre-existing)
	DirsCreated []string

	// ConfigCreated indicates whether a new config was created
	ConfigCreated bool

	// KeyCreated indicates whether a new encryption key was created
	KeyCreated bool

	// Errors contains any non-fatal errors encountered
	Errors []error

	// Warnings contains any warning messages
	Warnings []string
}

// Initializer defines the interface for Gibson initialization
type Initializer interface {
	// Initialize performs the complete initialization process
	Initialize(ctx context.Context, opts InitOptions) (*InitResult, error)

	// Validate checks if an existing setup is valid
	Validate(ctx context.Context, homeDir string) (*ValidationResult, error)
}

// DefaultInitializer implements Initializer with default behavior
type DefaultInitializer struct {
	configLoader config.ConfigLoader
	keyManager   crypto.KeyManagerInterface
}

// NewInitializer creates a new DefaultInitializer with the provided dependencies
func NewInitializer(
	configLoader config.ConfigLoader,
	keyManager crypto.KeyManagerInterface,
) *DefaultInitializer {
	return &DefaultInitializer{
		configLoader: configLoader,
		keyManager:   keyManager,
	}
}

// NewDefaultInitializer creates a new DefaultInitializer with standard dependencies
func NewDefaultInitializer() *DefaultInitializer {
	return NewInitializer(
		config.NewConfigLoader(config.NewValidator()),
		crypto.NewFileKeyManager(),
	)
}

// Initialize performs the complete Gibson Framework initialization process
// in the following order:
//
//  1. Determine and create home directory
//  2. Create standard directory structure
//  3. Generate or load configuration
//  4. Generate or load encryption key
//  5. Validate the complete setup
//
// The function is designed to be idempotent when Force=false - running it multiple
// times on the same directory will not create duplicate resources or fail.
//
// Note: Database initialization is handled by Redis StateClient during daemon startup.
func (i *DefaultInitializer) Initialize(ctx context.Context, opts InitOptions) (*InitResult, error) {
	result := &InitResult{
		DirsCreated: []string{},
		Errors:      []error{},
		Warnings:    []string{},
	}

	// Step 1: Determine home directory
	homeDir := opts.HomeDir
	if homeDir == "" {
		defaultCfg := config.DefaultConfig()
		homeDir = defaultCfg.Core.HomeDir
	}
	result.HomeDir = homeDir

	// Create the home directory itself
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create home directory %s: %w", homeDir, err)
	}

	// Step 2: Create directory structure
	dirCfg := DefaultDirectories(homeDir)
	if err := i.createDirectoriesWithTracking(dirCfg, result, opts.Force); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	// Step 3: Generate or load configuration
	configPath := filepath.Join(homeDir, "config.yaml")
	if err := i.initializeConfig(configPath, homeDir, result, opts.Force); err != nil {
		return nil, fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// Step 4: Generate or load encryption key
	keyPath := filepath.Join(homeDir, "master.key")
	if err := i.initializeKey(keyPath, result, opts.Force); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption key: %w", err)
	}

	// Step 5: Validate the complete setup
	validation, err := i.Validate(ctx, homeDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("post-initialization validation failed: %w", err))
	} else if !validation.Valid {
		for _, verr := range validation.Errors {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %s", verr.Component, verr.Message))
		}
	}

	// Add validation warnings to result
	for _, warning := range validation.Warnings {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", warning.Component, warning.Message))
	}

	return result, nil
}

// createDirectoriesWithTracking creates directories and tracks which ones were actually created
func (i *DefaultInitializer) createDirectoriesWithTracking(
	cfg DirectoryConfig,
	result *InitResult,
	force bool,
) error {
	for _, dir := range cfg.Dirs {
		fullPath := filepath.Join(cfg.HomeDir, dir)

		// Check if directory already exists
		_, err := os.Stat(fullPath)
		existed := err == nil

		// Create directory
		if err := os.MkdirAll(fullPath, cfg.Permission); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
		}

		// Track if this was a new directory
		if !existed {
			result.DirsCreated = append(result.DirsCreated, fullPath)
		}
	}

	return nil
}

// initializeConfig creates or updates the configuration file
func (i *DefaultInitializer) initializeConfig(
	configPath string,
	homeDir string,
	result *InitResult,
	force bool,
) error {
	// Check if config already exists
	_, err := os.Stat(configPath)
	configExists := err == nil

	if configExists && !force {
		// Load existing config to verify it's valid
		_, err := i.configLoader.Load(configPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("existing config is invalid: %v", err))
		}
		return nil
	}

	// Create new config
	cfg := config.DefaultConfig()
	cfg.Core.HomeDir = homeDir
	cfg.Core.DataDir = filepath.Join(homeDir, "data")
	cfg.Core.CacheDir = filepath.Join(homeDir, "cache")

	// Write config to file
	if err := writeConfigFile(configPath, cfg); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	result.ConfigCreated = true
	if configExists {
		result.Warnings = append(result.Warnings, "overwrote existing configuration (--force mode)")
	}

	return nil
}

// initializeKey creates or loads the encryption key
func (i *DefaultInitializer) initializeKey(
	keyPath string,
	result *InitResult,
	force bool,
) error {
	// Check if key already exists
	keyExists := i.keyManager.KeyExists(keyPath)

	if keyExists && !force {
		// Verify the existing key is valid
		_, err := i.keyManager.LoadKey(keyPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("existing key is invalid: %v", err))
		}
		return nil
	}

	// Generate new key
	key, err := i.keyManager.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Save key with secure permissions
	if err := i.keyManager.SaveKey(key, keyPath); err != nil {
		return fmt.Errorf("failed to save encryption key: %w", err)
	}

	result.KeyCreated = true
	if keyExists {
		result.Warnings = append(result.Warnings, "overwrote existing encryption key (--force mode)")
	}

	return nil
}

// Validate checks if an existing Gibson installation is valid
func (i *DefaultInitializer) Validate(ctx context.Context, homeDir string) (*ValidationResult, error) {
	return ValidateSetup(homeDir)
}

// writeConfigFile writes a Config to a YAML file
func writeConfigFile(path string, cfg *config.Config) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Convert config to YAML using gopkg.in/yaml.v3
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	// Write YAML with the config structure
	content := fmt.Sprintf(`core:
  home_dir: %s
  data_dir: %s
  cache_dir: %s
  parallel_limit: %d
  timeout: %s
  debug: %t

redis:
  url: %s
  password: ""
  database: %d

security:
  encryption_algorithm: %s
  key_derivation: %s
  ssl_validation: %t
  audit_logging: %t

llm:
  default_provider: "%s"

logging:
  level: %s
  format: %s

tracing:
  enabled: %t
  endpoint: "%s"

metrics:
  enabled: %t
  port: %d

registry:
  type: %s
  data_dir: %s
  listen_address: %s
  namespace: %s
  ttl: %s
  tls:
    enabled: %t
`,
		cfg.Core.HomeDir,
		cfg.Core.DataDir,
		cfg.Core.CacheDir,
		cfg.Core.ParallelLimit,
		cfg.Core.Timeout,
		cfg.Core.Debug,
		cfg.Redis.URL,
		cfg.Redis.Database,
		cfg.Security.EncryptionAlgorithm,
		cfg.Security.KeyDerivation,
		cfg.Security.SSLValidation,
		cfg.Security.AuditLogging,
		cfg.LLM.DefaultProvider,
		cfg.Logging.Level,
		cfg.Logging.Format,
		cfg.Tracing.Enabled,
		cfg.Tracing.Endpoint,
		cfg.Metrics.Enabled,
		cfg.Metrics.Port,
		cfg.Registry.Type,
		cfg.Registry.DataDir,
		cfg.Registry.ListenAddress,
		cfg.Registry.Namespace,
		cfg.Registry.TTL,
		cfg.Registry.TLS.Enabled,
	)

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
