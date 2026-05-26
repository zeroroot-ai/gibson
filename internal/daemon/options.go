package daemon

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zeroroot-ai/gibson/internal/secrets/jwtsource"
)

// ErrInvalidConfig is returned by New when the provided config is nil.
// Callers can match it with errors.Is(err, daemon.ErrInvalidConfig).
var ErrInvalidConfig = errors.New("daemon: invalid config")

// Option is a functional option for configuring a daemon instance.
// It follows the same pattern as EventBusOption in eventbus.go.
type Option func(*daemonImpl)

// WithLogger sets the slog.Logger used by the daemon and all subsystems it
// constructs.
//
// Passing nil is equivalent to not calling WithLogger: the daemon falls back
// to slog.Default() in both cases.
func WithLogger(l *slog.Logger) Option {
	return func(d *daemonImpl) {
		d.injectedLogger = l
	}
}

// WithHomeDir sets the Gibson home directory (typically ~/.gibson).
// It overrides any value derived from cfg.Core.HomeDir.
//
// Fallback order when WithHomeDir is not supplied:
//  1. cfg.Core.HomeDir
//  2. $HOME/.gibson
//  3. /var/lib/gibson
func WithHomeDir(dir string) Option {
	return func(d *daemonImpl) {
		d.homeDir = dir
	}
}

// WithMetricsRegisterer sets the Prometheus registerer used for daemon metrics.
// Defaults to prometheus.DefaultRegisterer when not supplied.
func WithMetricsRegisterer(reg prometheus.Registerer) Option {
	return func(d *daemonImpl) {
		d.metricsRegisterer = reg
	}
}

// WithVaultJWTSource sets the JWTSource used by the daemon's broker stack
// to mint SPIRE JWT-SVIDs for Vault auth/jwt logins.
//
// Passing nil is equivalent to not calling this option: the daemon falls
// back to jwtsource.DisabledJWTSource{}, which surfaces a clear
// ErrJWTSourceDisabled error on any tenant whose broker config selects
// AuthMethodJWT — pointing operators at gibson#169 (the SPIREJWTSource
// concrete implementation).
//
// Spec: ADR-0009 amendment (docs#34); gibson#167 PRD; gibson#168.
func WithVaultJWTSource(src jwtsource.JWTSource) Option {
	return func(d *daemonImpl) {
		d.vaultJWTSource = src
	}
}

// WithVaultJWTAudience sets the SPIRE JWT-SVID audience the daemon requests
// when minting Vault auth/jwt logins. It must match bound_audiences on the
// per-tenant Vault role (gibson-plugin-<tenant_id>) written by
// tenant-operator#148.
//
// Today the audience is sourced from the env var
// GIBSON_DAEMON_VAULT_JWT_AUDIENCE (read in cmd/gibson/main.go). If the
// audience is empty AND a real JWTSource (i.e. anything other than
// DisabledJWTSource) is wired, broker init will reject any AuthMethodJWT
// refresh with a clear error.
//
// Passing "" is equivalent to not calling this option.
//
// Spec: ADR-0009 amendment (docs#34); gibson#168.
func WithVaultJWTAudience(audience string) Option {
	return func(d *daemonImpl) {
		d.vaultJWTAudience = audience
	}
}
