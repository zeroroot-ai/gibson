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
	"github.com/zero-day-ai/gibson/internal/sandbox/health"
	"github.com/zero-day-ai/gibson/internal/secrets/jwtsource"
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

// vaultJWTSourceCloser is the minimum surface main.go needs from a JWT
// source: it must satisfy jwtsource.JWTSource (so daemon.WithVaultJWTSource
// accepts it) AND expose Close() so the shutdown path can release the
// underlying SPIRE Workload API connection.
type vaultJWTSourceCloser interface {
	jwtsource.JWTSource
	Close() error
}

// vaultJWTSourceFactory constructs the daemon's Vault JWT source.
// Replaceable in tests so they can avoid blocking on a real SPIRE
// Workload API socket.
type vaultJWTSourceFactory func(ctx context.Context, socketPath string) (vaultJWTSourceCloser, error)

// defaultVaultJWTSourceFactory wraps jwtsource.NewSPIREJWTSource. This is
// the production path: blocks until the SPIRE Workload API has pushed
// the first JWT bundle, returns an error if the socket is unreachable.
var defaultVaultJWTSourceFactory vaultJWTSourceFactory = func(ctx context.Context, socketPath string) (vaultJWTSourceCloser, error) {
	return jwtsource.NewSPIREJWTSource(ctx, socketPath)
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

	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultDaemonFactory, defaultVaultJWTSourceFactory))
}

// run is the fully-testable entry point. It returns an exit code.
func run(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	factory daemonFactory,
	jwtSourceFactory vaultJWTSourceFactory,
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

	// Emit the build-tag status on startup so operators have a log-grep-able
	// signal that the running binary has the Setec sandbox adapter linked in.
	// Production gating on the tag was removed (gates dropped 2026-05-10) —
	// the daemon now starts in any mode regardless of build-tag, and falls
	// back to the no-op stub when the tag is absent.
	logger.Info("setec_integration build tag",
		"status", version.BuildTagSetecIntegration,
		"version", version.Version,
		"commit", version.GitCommit,
	)

	// Surface the active Setec tier as a Prometheus gauge for the
	// dashboard's tier indicator panel. Reads GIBSON_SETEC_TIER from
	// the env (set by the chart's values.yaml setec.tier default of
	// "production"); empty value is a no-op for unit-test binaries
	// that don't wire the chart env. SetTier is idempotent — repeated
	// calls have no effect (the gauge MUST NOT flap).
	health.SetTier(os.Getenv("GIBSON_SETEC_TIER"))

	// Resolve home directory for daemon.
	homeDir := resolveHome(cfg)

	// Vault auth/jwt audience — ADR-0009 amendment (docs#34). When set, the
	// daemon's broker stack will mint SPIRE JWT-SVIDs against this audience
	// for every AuthMethodJWT Vault login. The bound_audiences on each
	// per-tenant Vault role (gibson-plugin-<tenant_id>, written by
	// tenant-operator#148) MUST include this exact value. Empty audience is
	// permitted today: it means the daemon will fail any AuthMethodJWT
	// refresh with a clear error pointing operators at this env var. Once
	// gibson#169 wires SPIREJWTSource the audience becomes mandatory.
	vaultJWTAudience := os.Getenv("GIBSON_DAEMON_VAULT_JWT_AUDIENCE")

	// Vault JWT source — SPIRE Workload API JWT-SVID source (gibson#169).
	//
	// The chart mounts the SPIRE agent's Workload API socket on the
	// gibson statefulset (deploy#354). The socket path is sourced from
	// GIBSON_DAEMON_SPIRE_SOCKET; empty value falls back to
	// jwtsource.DefaultSPIRESocketPath (unix:///run/spire/sockets/api.sock).
	//
	// Fail-loud: if the socket is unreachable at boot, the daemon
	// refuses to start. There is no silent fallback to
	// DisabledJWTSource — that would let the daemon come up but fail
	// every AuthMethodJWT broker refresh with a confusing per-tenant
	// error. Missing socket means the chart is misconfigured.
	//
	// Spec: ADR-0009 amendment (docs#34); gibson#167 PRD.
	vaultJWTSource, err := jwtSourceFactory(ctx, os.Getenv("GIBSON_DAEMON_SPIRE_SOCKET"))
	if err != nil {
		fmt.Fprintf(stderr, "gibson: SPIRE JWT source init error: %v\n", err)
		return 1
	}
	// Close the SPIRE Workload API connection on shutdown. The daemon's
	// graceful-shutdown chain handles its own resources; the JWT source
	// is owned by main and closed alongside the daemon. The defer
	// ordering — Close after Run returns — matches the pattern used for
	// other process-lifetime resources.
	defer func() {
		if cerr := vaultJWTSource.Close(); cerr != nil {
			fmt.Fprintf(stderr, "gibson: SPIRE JWT source close error: %v\n", cerr)
		}
	}()

	// Construct and start daemon.
	d, err := factory(cfg,
		daemon.WithLogger(logger),
		daemon.WithHomeDir(homeDir),
		daemon.WithVaultJWTSource(vaultJWTSource),
		daemon.WithVaultJWTAudience(vaultJWTAudience),
	)
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
