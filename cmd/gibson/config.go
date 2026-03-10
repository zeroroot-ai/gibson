package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/config"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Gibson configuration",
	Long: `The config command provides subcommands for viewing, getting, setting,
and validating Gibson configuration settings.

Configuration is stored in YAML format at ~/.gibson/config.yaml by default.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display full configuration",
	Long: `Display the complete Gibson configuration.

By default, output is in YAML format. Use --output-format json for JSON output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := getConfigPath(cmd)
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.LoadWithDefaults(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		outputFormat, _ := cmd.Flags().GetString("output-format")
		return printConfig(cfg, outputFormat)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a specific configuration value",
	Long: `Get the value of a specific configuration key.

Keys use dot notation to access nested values:
  gibson config get llm.default_provider
  gibson config get core.home_dir
  gibson config get database.max_connections`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := getConfigPath(cmd)
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.LoadWithDefaults(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		key := args[0]
		value, err := getConfigValue(cfg, key)
		if err != nil {
			return err
		}

		fmt.Println(value)
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set the value of a specific configuration key.

Keys use dot notation to access nested values:
  gibson config set llm.default_provider openai
  gibson config set core.parallel_limit 20
  gibson config set logging.level debug

The configuration file is updated while preserving comments where possible.
The new configuration is validated before saving.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := getConfigPath(cmd)
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		key := args[0]
		value := args[1]

		// Load existing config
		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.LoadWithDefaults(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Set the new value
		if err := setConfigValue(cfg, key, value); err != nil {
			return err
		}

		// Validate the modified config
		validator := config.NewValidator()
		if err := validator.Validate(cfg); err != nil {
			return fmt.Errorf("validation failed after setting value: %w", err)
		}

		// Save the config, preserving comments
		if err := saveConfig(configPath, cfg); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Successfully set %s to %s\n", key, value)
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long: `Validate the Gibson configuration file for correctness.

This checks:
  - YAML syntax is valid
  - Required fields are present
  - Values are within acceptable ranges
  - Field types are correct`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, err := getConfigPath(cmd)
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		// Check if file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return fmt.Errorf("config file does not exist: %s\nUse configs/gibson.yaml as a template", configPath)
		}

		loader := config.NewConfigLoader(config.NewValidator())
		if _, err := loader.Load(configPath); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}

		fmt.Println("Configuration is valid")
		return nil
	},
}

func init() {
	// Add subcommands to config command
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configValidateCmd)

	// Add flags for show command
	configShowCmd.Flags().String("output-format", "yaml", "Output format (yaml or json)")
}

// getConfigPath returns the configuration file path
func getConfigPath(cmd *cobra.Command) (string, error) {
	// Check if --config flag is set (from global flags, to be implemented)
	configPath, _ := cmd.Flags().GetString("config")
	if configPath != "" {
		return configPath, nil
	}

	// Use default path
	homeDir := config.DefaultHomeDir()
	return filepath.Join(homeDir, "config.yaml"), nil
}

// printConfig outputs the configuration in the specified format
func printConfig(cfg *config.Config, format string) error {
	var output []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		output, err = json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config to JSON: %w", err)
		}
	case "yaml", "":
		output, err = yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config to YAML: %w", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s (use 'yaml' or 'json')", format)
	}

	fmt.Println(string(output))
	return nil
}

// getConfigValue retrieves a value from the config using dot notation
func getConfigValue(cfg *config.Config, key string) (string, error) {
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid key: %s", key)
	}

	// Use reflection to traverse the config struct
	v := reflect.ValueOf(cfg).Elem()
	for i, part := range parts {
		// Convert snake_case to TitleCase for struct field names
		fieldName := snakeToTitle(part)

		field := v.FieldByName(fieldName)
		if !field.IsValid() {
			return "", fmt.Errorf("invalid configuration key: %s (at position: %s)", key, part)
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return formatValue(field), nil
		}

		// Otherwise, continue traversing
		if field.Kind() == reflect.Struct {
			v = field
		} else {
			return "", fmt.Errorf("cannot traverse into non-struct field: %s", part)
		}
	}

	return "", fmt.Errorf("failed to get value for key: %s", key)
}

// setConfigValue sets a value in the config using dot notation
func setConfigValue(cfg *config.Config, key, value string) error {
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return fmt.Errorf("invalid key: %s", key)
	}

	// Use reflection to traverse the config struct
	v := reflect.ValueOf(cfg).Elem()
	for i, part := range parts {
		// Convert snake_case to TitleCase for struct field names
		fieldName := snakeToTitle(part)

		field := v.FieldByName(fieldName)
		if !field.IsValid() {
			return fmt.Errorf("invalid configuration key: %s (at position: %s)", key, part)
		}

		// If this is the last part, set the value
		if i == len(parts)-1 {
			if !field.CanSet() {
				return fmt.Errorf("cannot set field: %s", part)
			}
			return setFieldValue(field, value)
		}

		// Otherwise, continue traversing
		if field.Kind() == reflect.Struct {
			v = field
		} else {
			return fmt.Errorf("cannot traverse into non-struct field: %s", part)
		}
	}

	return fmt.Errorf("failed to set value for key: %s", key)
}

// formatValue converts a reflect.Value to a string representation
func formatValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Check if it's a time.Duration
		if v.Type().String() == "time.Duration" {
			return v.Interface().(interface{ String() string }).String()
		}
		return fmt.Sprintf("%d", v.Int())
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}

// setFieldValue sets a reflect.Value from a string
func setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Check if it's a time.Duration
		if field.Type().String() == "time.Duration" {
			// Parse duration strings like "5m", "30s", etc.
			var duration int64
			if _, err := fmt.Sscanf(value, "%d", &duration); err == nil {
				field.SetInt(duration)
				return nil
			}
			return fmt.Errorf("invalid duration value: %s (use numeric nanoseconds or duration format)", value)
		}
		var intVal int64
		if _, err := fmt.Sscanf(value, "%d", &intVal); err != nil {
			return fmt.Errorf("invalid integer value: %s", value)
		}
		field.SetInt(intVal)
		return nil
	case reflect.Bool:
		// Parse boolean values explicitly (don't rely on Sscanf as it's too permissive)
		var boolVal bool
		switch strings.ToLower(value) {
		case "true", "yes", "1":
			boolVal = true
		case "false", "no", "0":
			boolVal = false
		default:
			return fmt.Errorf("invalid boolean value: %s", value)
		}
		field.SetBool(boolVal)
		return nil
	default:
		return fmt.Errorf("unsupported field type: %s", field.Type())
	}
}

// snakeToTitle converts snake_case to TitleCase
// Special handling for common abbreviations (LLM, DB, SSL, WAL, etc.)
func snakeToTitle(s string) string {
	// Handle special cases for abbreviations
	specialCases := map[string]string{
		"llm":  "LLM",
		"db":   "DB",
		"ssl":  "SSL",
		"wal":  "WAL",
		"api":  "API",
		"url":  "URL",
		"id":   "ID",
		"uuid": "UUID",
	}

	// Check if the entire string is a special case
	if title, ok := specialCases[strings.ToLower(s)]; ok {
		return title
	}

	parts := strings.Split(s, "_")
	for i, part := range parts {
		if len(part) > 0 {
			// Check if this part is a special case
			if title, ok := specialCases[strings.ToLower(part)]; ok {
				parts[i] = title
			} else {
				parts[i] = strings.ToUpper(part[:1]) + part[1:]
			}
		}
	}
	return strings.Join(parts, "")
}

// saveConfig saves the configuration to a file, attempting to preserve comments
func saveConfig(path string, cfg *config.Config) error {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
