package daemon

import (
	"bytes"
	"log/slog"
	"testing"
)

// TestNew_DefaultLogger verifies that New(cfg) without WithLogger wraps slog.Default().
func TestNew_DefaultLogger(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)

	// When no logger is injected, injectedLogger remains nil.
	if impl.injectedLogger != nil {
		t.Error("injectedLogger should be nil when WithLogger is not called")
	}
	// The wrapping observability.Logger should exist.
	if impl.logger == nil {
		t.Error("logger should not be nil after New()")
	}
	// The underlying slog.Logger should be slog.Default() (same pointer).
	if impl.logger.Slog() != slog.Default() {
		t.Error("internal slog.Logger should be slog.Default() when WithLogger is not supplied")
	}
}

// TestNew_CustomLogger verifies that New(cfg, WithLogger(custom)) uses the custom logger.
func TestNew_CustomLogger(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()

	var buf bytes.Buffer
	custom := slog.New(slog.NewJSONHandler(&buf, nil))

	d, err := New(cfg, WithLogger(custom))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)

	if impl.logger == nil {
		t.Fatal("logger should not be nil")
	}
	// The wrapped slog.Logger should be the one we passed in.
	if impl.logger.Slog() != custom {
		t.Error("internal slog.Logger should be the custom logger passed via WithLogger")
	}
}

// TestNew_NilConfig verifies that New(nil) returns ErrInvalidConfig.
// This duplicates options_test.go by design — daemon_test.go locks the New contract.
func TestNew_NilConfig(t *testing.T) {
	t.Parallel()
	_, err := New(nil)
	if err == nil {
		t.Fatal("New(nil) should return an error")
	}
}

// TestNew_GRPCAddress verifies that the gRPC address comes from cfg.Daemon.GRPCAddress.
func TestNew_GRPCAddress(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()
	cfg.Daemon.GRPCAddress = "example.com:9999"

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.grpcAddr != "example.com:9999" {
		t.Errorf("grpcAddr = %q, want example.com:9999", impl.grpcAddr)
	}
}

// TestNew_GRPCAddress_Default verifies the default gRPC address when cfg.Daemon.GRPCAddress is empty.
func TestNew_GRPCAddress_Default(t *testing.T) {
	t.Parallel()
	cfg := minimalCfg()
	cfg.Daemon.GRPCAddress = "" // force default path

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.grpcAddr != "localhost:50002" {
		t.Errorf("grpcAddr = %q, want localhost:50002 (default)", impl.grpcAddr)
	}
}

// TestNew_HomeDir_Precedence verifies the home directory resolution order:
// WithHomeDir > cfg.Core.HomeDir > system default.
func TestNew_HomeDir_Precedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cfgHomeDir    string
		optionHomeDir string
		wantHomeDir   string
	}{
		{
			name:          "option wins over config",
			cfgHomeDir:    "/cfg/home",
			optionHomeDir: "/opt/home",
			wantHomeDir:   "/opt/home",
		},
		{
			name:          "config used when no option",
			cfgHomeDir:    "/cfg/home",
			optionHomeDir: "",
			wantHomeDir:   "/cfg/home",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := minimalCfg()
			cfg.Core.HomeDir = tc.cfgHomeDir

			var opts []Option
			if tc.optionHomeDir != "" {
				opts = append(opts, WithHomeDir(tc.optionHomeDir))
			}

			d, err := New(cfg, opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			impl := d.(*daemonImpl)
			if impl.homeDir != tc.wantHomeDir {
				t.Errorf("homeDir = %q, want %q", impl.homeDir, tc.wantHomeDir)
			}
		})
	}
}

// TestNew_ActivationsInitialized verifies that internal maps are initialized after New().
func TestNew_ActivationsInitialized(t *testing.T) {
	t.Parallel()
	d, err := New(minimalCfg())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	impl := d.(*daemonImpl)
	if impl.activeMissions == nil {
		t.Error("activeMissions map should be initialized")
	}
	if impl.agentState == nil {
		t.Error("agentState map should be initialized")
	}
}
