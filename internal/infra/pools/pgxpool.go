package pools

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxPoolOptions carries required and optional tuning for NewPgxPool.
// Required fields must be non-zero; NewPgxPool returns an error otherwise.
type PgxPoolOptions struct {
	// MaxConnLifetime is the maximum duration a connection may be reused.
	// Connections older than this are closed and replaced on the next
	// acquire.
	//
	// Required: must be > 0. A common production value is 1 hour.
	MaxConnLifetime time.Duration

	// MaxConnIdleTime is the maximum duration a connection may be idle in
	// the pool before being closed. This helps release connections that are
	// no longer needed during low-traffic periods.
	//
	// Required: must be > 0. A common production value is 30 min.
	MaxConnIdleTime time.Duration

	// MaxConns caps the total number of connections in the pool. Defaults
	// to pgxpool's default (min(4, runtime.NumCPU)) when 0.
	MaxConns int32

	// MinConns is the minimum number of connections the pool maintains.
	// Defaults to 0 (no minimum) when not set.
	MinConns int32

	// HealthCheckPeriod is how often the pool sends a health-check (ping)
	// to idle connections to verify they are still alive.
	// Defaults to 1 minute when zero.
	HealthCheckPeriod time.Duration
}

// validate returns a non-nil error if any required field is zero.
func (o PgxPoolOptions) validate() error {
	if o.MaxConnLifetime == 0 {
		return fmt.Errorf("pools.NewPgxPool: PgxPoolOptions.MaxConnLifetime is required (must be > 0)")
	}
	if o.MaxConnIdleTime == 0 {
		return fmt.Errorf("pools.NewPgxPool: PgxPoolOptions.MaxConnIdleTime is required (must be > 0)")
	}
	return nil
}

// NewPgxPool constructs a *pgxpool.Pool from dsn with required-override enforcement.
//
// Required opts fields: MaxConnLifetime, MaxConnIdleTime.
// Returns an error when either is zero or when the DSN cannot be parsed.
//
// The pool is not yet connected when returned; the first Acquire call
// establishes connections. Callers must call pool.Close when done.
func NewPgxPool(ctx context.Context, dsn string, opts PgxPoolOptions) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("pools.NewPgxPool: dsn must not be empty")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pools.NewPgxPool: parsing DSN: %w", err)
	}

	cfg.MaxConnLifetime = opts.MaxConnLifetime
	cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.HealthCheckPeriod > 0 {
		cfg.HealthCheckPeriod = opts.HealthCheckPeriod
	} else {
		cfg.HealthCheckPeriod = 1 * time.Minute
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pools.NewPgxPool: creating pool: %w", err)
	}

	return pool, nil
}
