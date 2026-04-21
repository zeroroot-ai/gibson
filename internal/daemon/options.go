package daemon

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
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
