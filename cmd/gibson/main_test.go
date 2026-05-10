package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/pkg/version"
)

// fakeDaemon is a test double for daemonRunner.
type fakeDaemon struct {
	runErr error
	ran    bool
}

func (f *fakeDaemon) Run(_ context.Context) error {
	f.ran = true
	return f.runErr
}

// fakeFactory builds a daemonFactory that always returns fd.
func fakeFactory(fd *fakeDaemon) daemonFactory {
	return func(_ *config.Config, _ ...daemon.Option) (daemonRunner, error) {
		return fd, nil
	}
}

// errorFactory always returns a construction error.
func errorFactory(err error) daemonFactory {
	return func(_ *config.Config, _ ...daemon.Option) (daemonRunner, error) {
		return nil, err
	}
}

// writeTempConfig creates a minimal valid YAML config file and returns its path.
func writeTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Minimal YAML: only the keys that survive LoadWithDefaults without errors.
	if err := os.WriteFile(path, []byte("logging:\n  level: info\n"), 0o600); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}

// writeMalformedConfig creates a config file with invalid YAML.
func writeMalformedConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(":\t: bad yaml {\n"), 0o600); err != nil {
		t.Fatalf("writeMalformedConfig: %v", err)
	}
	return path
}

func Test_run(t *testing.T) {
	// Subtests are run sequentially to avoid races on any shared state.
	// Each subtest provides its own factory to inject fake daemons.

	tests := []struct {
		name       string
		args       func(t *testing.T) []string
		factory    func(t *testing.T) daemonFactory
		wantCode   int
		wantStdout string // substring that must appear in stdout
		wantStderr string // substring that must appear in stderr
	}{
		{
			name: "--version prints version",
			args: func(*testing.T) []string { return []string{"--version"} },
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{})
			},
			wantCode:   0,
			wantStdout: version.Version,
		},
		{
			name: "--help exits 0",
			args: func(*testing.T) []string { return []string{"--help"} },
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{})
			},
			wantCode: 0,
		},
		{
			name: "unknown flag exits 1",
			args: func(*testing.T) []string { return []string{"--not-a-flag"} },
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{})
			},
			wantCode:   1,
			wantStderr: "flag provided but not defined",
		},
		{
			name: "missing config file succeeds with defaults",
			args: func(*testing.T) []string {
				return []string{"--config", "/nonexistent/path/config.yaml"}
			},
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{})
			},
			wantCode: 0,
		},
		{
			name: "malformed config file exits 1",
			args: func(t *testing.T) []string {
				return []string{"--config", writeMalformedConfig(t)}
			},
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{})
			},
			wantCode: 1,
		},
		{
			name: "happy path: daemon Run called",
			args: func(t *testing.T) []string {
				return []string{"--config", writeTempConfig(t)}
			},
			factory: func(t *testing.T) daemonFactory {
				fd := &fakeDaemon{}
				t.Cleanup(func() {
					if !fd.ran {
						t.Error("expected daemon.Run to be called")
					}
				})
				return fakeFactory(fd)
			},
			wantCode: 0,
		},
		{
			name: "daemon construction error exits 1",
			args: func(t *testing.T) []string {
				return []string{"--config", writeTempConfig(t)}
			},
			factory: func(*testing.T) daemonFactory {
				return errorFactory(errors.New("init failed"))
			},
			wantCode:   1,
			wantStderr: "init failed",
		},
		{
			name: "daemon Run error exits 1",
			args: func(t *testing.T) []string {
				return []string{"--config", writeTempConfig(t)}
			},
			factory: func(*testing.T) daemonFactory {
				return fakeFactory(&fakeDaemon{runErr: errors.New("port already in use")})
			},
			wantCode:   1,
			wantStderr: "port already in use",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			args := tc.args(t)
			factory := tc.factory(t)

			code := run(ctx, args, &stdout, &stderr, factory)

			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s",
					code, tc.wantCode, stdout.String(), stderr.String())
			}
			if tc.wantStdout != "" && !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout does not contain %q\ngot: %s", tc.wantStdout, stdout.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr does not contain %q\ngot: %s", tc.wantStderr, stderr.String())
			}
		})
	}
}

func Test_newLogger_noPanic(_ *testing.T) {
	// Verify newLogger doesn't panic for various writer types.
	cfg := &config.Config{}
	cfg.Logging.Level = "info"
	_ = newLogger(&bytes.Buffer{}, cfg)
	_ = newLogger(os.Stdout, cfg)
}

func Test_resolveHome(t *testing.T) {
	// Not parallel: uses t.Setenv.

	t.Run("prefers cfg.Core.HomeDir", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Core.HomeDir = "/from/config"
		if got := resolveHome(cfg); got != "/from/config" {
			t.Errorf("resolveHome = %q, want /from/config", got)
		}
	})

	t.Run("falls back to GIBSON_HOME env", func(t *testing.T) {
		cfg := &config.Config{}
		t.Setenv("GIBSON_HOME", "/from/env")
		if got := resolveHome(cfg); got != "/from/env" {
			t.Errorf("resolveHome = %q, want /from/env", got)
		}
	})

	t.Run("falls back to DefaultHomeDir when GIBSON_HOME empty", func(t *testing.T) {
		cfg := &config.Config{}
		t.Setenv("GIBSON_HOME", "")
		got := resolveHome(cfg)
		if got == "" {
			t.Error("resolveHome returned empty string")
		}
	})
}

// Test_malformedConfig exercises malformed-config path explicitly.
func Test_malformedConfig(t *testing.T) {
	path := writeMalformedConfig(t)
	var stdout, stderr bytes.Buffer
	ctx := context.Background()
	code := run(ctx, []string{"--config", path}, &stdout, &stderr, fakeFactory(&fakeDaemon{}))
	if code != 1 {
		t.Errorf("expected exit 1 for malformed config, got %d\nstderr: %s", code, stderr.String())
	}
	_ = fmt.Sprintf("stderr: %s", stderr.String()) // suppress "declared and not used"
}

// Test_setecIntegrationSelfCheck removed 2026-05-10 — startup self-check
// dropped along with all Setec gating per operator decision (unlimited
// usage). The build-tag is still emitted as a startup log line for
// observability, but no longer gates startup.
