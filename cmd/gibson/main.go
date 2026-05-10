package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/pkg/version"
)

// daemonRunner is the subset of daemon.Daemon used by run.
type daemonRunner interface {
	Run(context.Context) error
}

// daemonFactory constructs a daemonRunner from a config and options.
// Replaceable in tests.
type daemonFactory func(*config.Config, ...daemon.Option) (daemonRunner, error)

// defaultDaemonFactory wraps daemon.New to satisfy daemonFactory.
var defaultDaemonFactory daemonFactory = func(cfg *config.Config, opts ...daemon.Option) (daemonRunner, error) {
	return daemon.New(cfg, opts...)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Force-exit on second signal: after first signal ctx is cancelled,
	// a subsequent unhandled signal terminates the process immediately.
	go func() {
		<-ctx.Done()
		stop() // deregister so next SIGINT/SIGTERM is not captured
		select {}
	}()

	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultDaemonFactory))
}

// run is the fully-testable entry point. It returns an exit code.
func run(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	factory daemonFactory,
) int {
	fs := flag.NewFlagSet("gibson", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		cfgPath = fs.String("config", "", "path to gibson.yaml (default: ~/.gibson/config.yaml)")
		showVer = fs.Bool("version", false, "print version and exit")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	if *showVer {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	// Resolve config path.
	if *cfgPath == "" {
		homeDir := config.DefaultHomeDir()
		if h := os.Getenv("GIBSON_HOME"); h != "" {
			homeDir = h
		}
		*cfgPath = config.DefaultConfigPath(homeDir)
	}

	// Load configuration (uses defaults when file is absent).
	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.LoadWithDefaults(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "gibson: config error: %v\n", err)
		return 1
	}

	// Apply env-var override for gRPC address (R3.6: env-reading lives in main).
	if addr := os.Getenv("GIBSON_DAEMON_GRPC_ADDR"); addr != "" {
		cfg.Daemon.GRPCAddress = addr
	}

	// Build structured logger (text for interactive TTY, JSON elsewhere).
	logger := newLogger(stdout, cfg)

	// Spec setec-sandbox-prod-default R1.3: emit the build-tag status on every
	// startup so operators have an immediate, log-grep-able signal that the
	// running binary has the Setec sandbox adapter linked in.
	logger.Info("setec_integration build tag",
		"status", version.BuildTagSetecIntegration,
		"version", version.Version,
		"commit", version.GitCommit,
	)

	// Spec setec-sandbox-prod-default R1.4: production-mode (GIBSON_MODE=saas)
	// fail-closed self-check. If the daemon was built without the
	// setec_integration build tag and is starting in SaaS mode, refuse to
	// continue. The check runs BEFORE any network dial, BEFORE the daemon
	// constructor, so a misconfigured CI cannot ship a no-sandbox image to
	// production by accident.
	//
	// The audit DB is not yet available here (daemon hasn't initialised), so
	// the startup_refused event is emitted as a structured log line carrying
	// the audit fields a downstream collector can persist; CLAUDE.md notes
	// that pino/JSON logs are the canonical structured-event surface for
	// pre-daemon failures.
	if cfg.Mode() == config.ModeSaaS && version.BuildTagSetecIntegration != "on" {
		logger.Error("startup_refused",
			"event", "startup_refused",
			"reason", "missing_build_tag_setec_integration",
			"mode", cfg.Mode().String(),
			"build_tag_setec_integration", version.BuildTagSetecIntegration,
			"version", version.Version,
			"commit", version.GitCommit,
			"message", "GIBSON_MODE=saas requires the setec_integration build tag; refusing to start without sandbox adapter compiled in",
		)
		fmt.Fprintf(stderr, "gibson: startup refused: GIBSON_MODE=saas requires the setec_integration build tag (BuildTagSetecIntegration=%q); rebuild with `-tags setec_integration` or run with GIBSON_MODE=selfhost/dev\n", version.BuildTagSetecIntegration)
		return 1
	}

	// Resolve home directory for daemon.
	homeDir := resolveHome(cfg)

	// Construct and start daemon.
	d, err := factory(cfg, daemon.WithLogger(logger), daemon.WithHomeDir(homeDir))
	if err != nil {
		fmt.Fprintf(stderr, "gibson: daemon init error: %v\n", err)
		return 1
	}

	if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "gibson: %v\n", err)
		return 1
	}

	return 0
}

// newLogger builds a *slog.Logger. It uses text format when w is a TTY,
// JSON otherwise (daemon / container / CI environments).
func newLogger(w io.Writer, cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	}
	opts := &slog.HandlerOptions{Level: level}

	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// resolveHome returns the Gibson home directory from config, environment, or default.
func resolveHome(cfg *config.Config) string {
	if cfg.Core.HomeDir != "" {
		return cfg.Core.HomeDir
	}
	if h := os.Getenv("GIBSON_HOME"); h != "" {
		return h
	}
	return config.DefaultHomeDir()
}
