package init

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
)

// ValidationResult contains the results of setup validation
type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []ValidationWarning
}

// ValidationError represents a validation error with context and remediation
type ValidationError struct {
	Component string // Which component failed (directories, config, key, redis)
	Message   string // What went wrong
	Action    string // What the user should do to fix it
}

// ValidationWarning represents a non-fatal validation issue
type ValidationWarning struct {
	Component string // Which component has the warning
	Message   string // What the warning is about
}

// ValidateSetup performs comprehensive validation of a Gibson installation
// It checks:
//   - All required directories exist with correct permissions
//   - Configuration file exists and is valid
//   - Encryption key exists with secure permissions (0600)
//
// Note: Redis connectivity is validated at daemon startup, not here.
//
// Returns a ValidationResult indicating whether the setup is valid and
// detailing any errors or warnings found.
func ValidateSetup(homeDir string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
	}

	// Validate home directory exists
	if err := validateHomeDir(homeDir, result); err != nil {
		return nil, err
	}

	// Validate directory structure
	validateDirectoryStructure(homeDir, result)

	// Validate configuration file
	validateConfigFile(homeDir, result)

	// Validate encryption key
	validateEncryptionKey(homeDir, result)

	// Set overall validity based on whether any errors were found
	result.Valid = len(result.Errors) == 0

	return result, nil
}

// validateHomeDir checks that the home directory exists and is a directory
func validateHomeDir(homeDir string, result *ValidationResult) error {
	info, err := os.Stat(homeDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.Errors = append(result.Errors, ValidationError{
				Component: "home_directory",
				Message:   fmt.Sprintf("home directory does not exist: %s", homeDir),
				Action:    fmt.Sprintf("run 'gibson init' or create directory with: mkdir -p %s", homeDir),
			})
			result.Valid = false
			return nil // Not a fatal error for validation
		}
		return fmt.Errorf("failed to stat home directory: %w", err)
	}

	if !info.IsDir() {
		result.Errors = append(result.Errors, ValidationError{
			Component: "home_directory",
			Message:   fmt.Sprintf("home path exists but is not a directory: %s", homeDir),
			Action:    fmt.Sprintf("remove the file and run 'gibson init': rm %s && gibson init", homeDir),
		})
		result.Valid = false
	}

	return nil
}

// validateDirectoryStructure checks that all required directories exist
func validateDirectoryStructure(homeDir string, result *ValidationResult) {
	dirCfg := DefaultDirectories(homeDir)
	missing, badPerms, err := ValidateDirectories(dirCfg)

	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Component: "directories",
			Message:   fmt.Sprintf("failed to validate directories: %v", err),
			Action:    "check directory permissions and run 'gibson init'",
		})
		result.Valid = false
		return
	}

	// Report missing directories
	for _, dir := range missing {
		result.Errors = append(result.Errors, ValidationError{
			Component: "directories",
			Message:   fmt.Sprintf("required directory missing: %s", dir),
			Action:    fmt.Sprintf("create directory with: mkdir -p %s", dir),
		})
		result.Valid = false
	}

	// Report incorrect permissions as warnings (not fatal)
	for _, permInfo := range badPerms {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Component: "directories",
			Message:   fmt.Sprintf("incorrect permissions: %s", permInfo),
		})
	}
}

// validateConfigFile checks that the configuration file exists and is valid
func validateConfigFile(homeDir string, result *ValidationResult) {
	configPath := filepath.Join(homeDir, "config.yaml")

	// Check if config file exists
	info, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Errors = append(result.Errors, ValidationError{
				Component: "config",
				Message:   fmt.Sprintf("configuration file not found: %s", configPath),
				Action:    "run 'gibson init' to create default configuration",
			})
			result.Valid = false
			return
		}
		result.Errors = append(result.Errors, ValidationError{
			Component: "config",
			Message:   fmt.Sprintf("failed to stat config file: %v", err),
			Action:    "check file permissions and run 'gibson init'",
		})
		result.Valid = false
		return
	}

	// Check if it's a file (not a directory)
	if info.IsDir() {
		result.Errors = append(result.Errors, ValidationError{
			Component: "config",
			Message:   fmt.Sprintf("config path is a directory: %s", configPath),
			Action:    fmt.Sprintf("remove directory and run 'gibson init': rm -rf %s && gibson init", configPath),
		})
		result.Valid = false
		return
	}

	// Try to load the config to verify it's valid
	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.Load(configPath)
	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Component: "config",
			Message:   fmt.Sprintf("invalid configuration file: %v", err),
			Action:    "fix configuration file or run 'gibson init --force' to recreate",
		})
		result.Valid = false
		return
	}

	// Validate config content
	if cfg.Core.HomeDir != homeDir {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Component: "config",
			Message:   fmt.Sprintf("config home_dir (%s) doesn't match current home (%s)", cfg.Core.HomeDir, homeDir),
		})
	}

	// Validate Redis configuration
	if cfg.Redis.URL == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Component: "config",
			Message:   "Redis address is empty, daemon startup will fail",
		})
	}
}

// validateEncryptionKey checks that the encryption key exists with secure permissions
func validateEncryptionKey(homeDir string, result *ValidationResult) {
	keyPath := filepath.Join(homeDir, "master.key")

	// Check if key file exists
	info, err := os.Stat(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Errors = append(result.Errors, ValidationError{
				Component: "encryption_key",
				Message:   fmt.Sprintf("encryption key not found: %s", keyPath),
				Action:    "run 'gibson init' to generate encryption key",
			})
			result.Valid = false
			return
		}
		result.Errors = append(result.Errors, ValidationError{
			Component: "encryption_key",
			Message:   fmt.Sprintf("failed to stat key file: %v", err),
			Action:    "check file permissions and run 'gibson init'",
		})
		result.Valid = false
		return
	}

	// Check permissions (must be 0600 for security)
	actualPerms := info.Mode().Perm()
	expectedPerms := os.FileMode(crypto.KeyFilePermission)

	if actualPerms != expectedPerms {
		result.Errors = append(result.Errors, ValidationError{
			Component: "encryption_key",
			Message:   fmt.Sprintf("insecure key file permissions: got %o, expected %o", actualPerms, expectedPerms),
			Action:    fmt.Sprintf("fix permissions with: chmod %o %s", expectedPerms, keyPath),
		})
		result.Valid = false
		return
	}

	// Try to load the key to verify it's valid
	keyManager := crypto.NewFileKeyManager()
	_, err = keyManager.LoadKey(keyPath)
	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Component: "encryption_key",
			Message:   fmt.Sprintf("invalid encryption key: %v", err),
			Action:    "run 'gibson init --force' to regenerate encryption key (WARNING: will lose access to encrypted data)",
		})
		result.Valid = false
		return
	}
}
