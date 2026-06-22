package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// minimalCfg returns a config.Config that satisfies daemon.New without
// requiring any external services (Redis, FGA, Postgres).
// Tests that call daemon.New with this config do NOT start any services —
// New() only initializes the struct, not the Redis connection.
func minimalCfg() *config.Config {
	return &config.Config{
		Registry: config.RegistryConfig{
			Namespace: "test",
			TTL:       "30s",
		},
		Callback: config.CallbackConfig{
			Enabled:          false,
			ListenAddress:    "localhost:0",
			AdvertiseAddress: "localhost:0",
		},
		Daemon: config.DaemonConfig{
			GRPCAddress: "localhost:0",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// TestOptions_NilConfig verifies that New(nil) returns an error wrapping ErrInvalidConfig.
func TestOptions_NilConfig(t *testing.T) {
	t.Parallel()
	_, err := New(nil)
	if err == nil {
		t.Fatal("New(nil) should return an error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestOptions_WithHomeDir verifies that WithHomeDir overrides the config-derived home.
func TestOptions_WithHomeDir(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()
	cfg.Core.HomeDir = "/from/config"

	d, err := New(cfg, WithHomeDir("/from/option"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.homeDir != "/from/option" {
		t.Errorf("homeDir = %q, want /from/option", impl.homeDir)
	}
}

// TestOptions_WithHomeDir_FallsBackToCfg verifies that when WithHomeDir is omitted,
// the home directory comes from cfg.Core.HomeDir.
func TestOptions_WithHomeDir_FallsBackToCfg(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()
	cfg.Core.HomeDir = "/from/config"

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.homeDir != "/from/config" {
		t.Errorf("homeDir = %q, want /from/config", impl.homeDir)
	}
}

// TestOptions_WithLogger_CustomLogger verifies that WithLogger stores the injected logger.
func TestOptions_WithLogger_CustomLogger(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	var buf bytes.Buffer
	custom := slog.New(slog.NewJSONHandler(&buf, nil))

	d, err := New(cfg, WithLogger(custom))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.injectedLogger != custom {
		t.Error("injectedLogger should be the custom logger passed via WithLogger")
	}
}

// TestOptions_WithLogger_Nil verifies that WithLogger(nil) is treated the same
// as not calling WithLogger — New succeeds and falls back to slog.Default().
func TestOptions_WithLogger_Nil(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	d, err := New(cfg, WithLogger(nil))
	if err != nil {
		t.Fatalf("New(cfg, WithLogger(nil)) should not fail; err: %v", err)
	}
	impl := d.(*daemonImpl)
	// Nil injection → injectedLogger remains nil; New uses slog.Default() as fallback.
	if impl.injectedLogger != nil {
		t.Error("injectedLogger should remain nil when WithLogger(nil) is called")
	}
	// The logger field itself should be non-nil (NewLoggerFromSlog used slog.Default()).
	if impl.logger == nil {
		t.Error("logger field should not be nil after New()")
	}
}

// TestOptions_WithLogger_Default verifies that omitting WithLogger uses slog.Default().
func TestOptions_WithLogger_Default(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	// injectedLogger is nil because no WithLogger was supplied.
	if impl.injectedLogger != nil {
		t.Error("injectedLogger should be nil when WithLogger is not supplied")
	}
	// logger (the observability.Logger wrapper) is still built from slog.Default().
	if impl.logger == nil {
		t.Error("logger field should not be nil after New()")
	}
}

// TestOptions_WithMetricsRegisterer verifies that the custom registerer is stored.
func TestOptions_WithMetricsRegisterer(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	reg := prometheus.NewRegistry()
	d, err := New(cfg, WithMetricsRegisterer(reg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.metricsRegisterer != reg {
		t.Error("metricsRegisterer should be the custom registry passed via WithMetricsRegisterer")
	}
}

// TestOptions_Default_MetricsRegisterer verifies that the default registerer is prometheus.DefaultRegisterer.
func TestOptions_Default_MetricsRegisterer(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.metricsRegisterer != prometheus.DefaultRegisterer {
		t.Error("metricsRegisterer should default to prometheus.DefaultRegisterer")
	}
}

// TestOptions_MultipleOptions verifies that multiple options all apply.
func TestOptions_MultipleOptions(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	reg := prometheus.NewRegistry()

	d, err := New(cfg,
		WithLogger(logger),
		WithHomeDir("/multi/test"),
		WithMetricsRegisterer(reg),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)

	if impl.injectedLogger != logger {
		t.Error("injectedLogger mismatch after multiple options")
	}
	if impl.homeDir != "/multi/test" {
		t.Errorf("homeDir = %q, want /multi/test", impl.homeDir)
	}
	if impl.metricsRegisterer != reg {
		t.Error("metricsRegisterer mismatch after multiple options")
	}
}

// TestOptions_LastOptionWins verifies that the last option for a given field wins.
func TestOptions_LastOptionWins(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	d, err := New(cfg,
		WithHomeDir("/first"),
		WithHomeDir("/second"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.homeDir != "/second" {
		t.Errorf("homeDir = %q, want /second (last-wins)", impl.homeDir)
	}
}
