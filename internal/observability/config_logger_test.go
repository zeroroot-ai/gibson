package observability

import (
	"log/slog"
	"os"
	"testing"
)

// TestDefaultConfig verifies that DefaultConfig returns expected defaults.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Expected Level=Info, got %v", cfg.Level)
	}

	if cfg.Output != os.Stdout {
		t.Errorf("Expected Output=os.Stdout, got %v", cfg.Output)
	}

	if !cfg.RedactSensitive {
		t.Errorf("Expected RedactSensitive=true, got false")
	}

	if cfg.MaxContentLength != 500 {
		t.Errorf("Expected MaxContentLength=500, got %d", cfg.MaxContentLength)
	}

	if cfg.Component != "gibson" {
		t.Errorf("Expected Component=gibson, got %s", cfg.Component)
	}
}

// TestConfigFromEnv_NoEnvVar verifies ConfigFromEnv returns defaults when no env var is set.
func TestConfigFromEnv_NoEnvVar(t *testing.T) {
	// Clear the env var to ensure clean test
	os.Unsetenv("GIBSON_LOG_LEVEL")

	cfg := ConfigFromEnv()

	// Should match DefaultConfig()
	if cfg.Level != slog.LevelInfo {
		t.Errorf("Expected Level=Info when no env var, got %v", cfg.Level)
	}
}

// TestConfigFromEnv_Debug verifies ConfigFromEnv parses debug level.
func TestConfigFromEnv_Debug(t *testing.T) {
	os.Setenv("GIBSON_LOG_LEVEL", "debug")
	defer os.Unsetenv("GIBSON_LOG_LEVEL")

	cfg := ConfigFromEnv()

	if cfg.Level != slog.LevelDebug {
		t.Errorf("Expected Level=Debug, got %v", cfg.Level)
	}
}

// TestConfigFromEnv_Info verifies ConfigFromEnv parses info level.
func TestConfigFromEnv_Info(t *testing.T) {
	os.Setenv("GIBSON_LOG_LEVEL", "info")
	defer os.Unsetenv("GIBSON_LOG_LEVEL")

	cfg := ConfigFromEnv()

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Expected Level=Info, got %v", cfg.Level)
	}
}

// TestConfigFromEnv_Warn verifies ConfigFromEnv parses warn level.
func TestConfigFromEnv_Warn(t *testing.T) {
	os.Setenv("GIBSON_LOG_LEVEL", "warn")
	defer os.Unsetenv("GIBSON_LOG_LEVEL")

	cfg := ConfigFromEnv()

	if cfg.Level != slog.LevelWarn {
		t.Errorf("Expected Level=Warn, got %v", cfg.Level)
	}
}

// TestConfigFromEnv_Error verifies ConfigFromEnv parses error level.
func TestConfigFromEnv_Error(t *testing.T) {
	os.Setenv("GIBSON_LOG_LEVEL", "error")
	defer os.Unsetenv("GIBSON_LOG_LEVEL")

	cfg := ConfigFromEnv()

	if cfg.Level != slog.LevelError {
		t.Errorf("Expected Level=Error, got %v", cfg.Level)
	}
}

// TestConfigFromEnv_CaseInsensitive verifies ConfigFromEnv is case-insensitive.
func TestConfigFromEnv_CaseInsensitive(t *testing.T) {
	testCases := []struct {
		input    string
		expected slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"Debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"Info", slog.LevelInfo},
		{"WARN", slog.LevelWarn},
		{"Warn", slog.LevelWarn},
		{"ERROR", slog.LevelError},
		{"Error", slog.LevelError},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			os.Setenv("GIBSON_LOG_LEVEL", tc.input)
			defer os.Unsetenv("GIBSON_LOG_LEVEL")

			cfg := ConfigFromEnv()

			if cfg.Level != tc.expected {
				t.Errorf("Input %q: expected Level=%v, got %v", tc.input, tc.expected, cfg.Level)
			}
		})
	}
}

// TestConfigFromEnv_InvalidValue verifies ConfigFromEnv defaults to Info for invalid values.
func TestConfigFromEnv_InvalidValue(t *testing.T) {
	testCases := []string{
		"invalid",
		"trace",
		"fatal",
		"",
		"123",
		"debug123",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			os.Setenv("GIBSON_LOG_LEVEL", tc)
			defer os.Unsetenv("GIBSON_LOG_LEVEL")

			cfg := ConfigFromEnv()

			if cfg.Level != slog.LevelInfo {
				t.Errorf("Invalid input %q: expected Level=Info (default), got %v", tc, cfg.Level)
			}
		})
	}
}
