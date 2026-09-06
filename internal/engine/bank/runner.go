// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

// TenantSource enumerates the tenants whose banks a pass reconciles. The
// daemon backs it with the Kubernetes Tenant lister; a test fakes it.
type TenantSource interface {
	ListTenants(ctx context.Context) ([]auth.TenantID, error)
}

// DefaultInterval is how often every bank is brought to its desired state.
// It is the heartbeat timeout: a member is found dead within one interval of
// the timeout, and a scale change is acted on within one interval.
const DefaultInterval = DefaultHeartbeatTimeout

// RunnerConfig is the constructor input for a Runner.
type RunnerConfig struct {
	Reconciler *Reconciler
	Tenants    TenantSource
	Interval   time.Duration
	Logger     *slog.Logger
}

// Runner drives the reconciler on a ticker, over every tenant.
type Runner struct {
	reconciler *Reconciler
	tenants    TenantSource
	interval   time.Duration
	logger     *slog.Logger
}

// NewRunner builds a Runner. Both the reconciler and the tenant source are
// required: a runner with nothing to run or nobody to run it for would tick
// forever and report nothing.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Reconciler == nil {
		return nil, errors.New("bank: NewRunner: Reconciler is required")
	}
	if cfg.Tenants == nil {
		return nil, errors.New("bank: NewRunner: Tenants is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Runner{
		reconciler: cfg.Reconciler, tenants: cfg.Tenants,
		interval: cfg.Interval, logger: cfg.Logger.With("component", "bank_runner"),
	}, nil
}

// Run reconciles at once, then on every tick, until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.Pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Pass(ctx)
		}
	}
}

// Pass reconciles every tenant once. A tenant enumeration failure skips the
// whole pass, because a partial list is indistinguishable from a shrunken one.
// A tenant's failure is logged and isolated: one broken tenant does not stop
// the others.
func (r *Runner) Pass(ctx context.Context) {
	tenants, err := r.tenants.ListTenants(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "bank reconcile: list tenants failed", "error", err)
		return
	}
	for _, tid := range tenants {
		if ctx.Err() != nil {
			return
		}
		tctx := auth.ContextWithTenantString(ctx, tid.String())
		if rerr := r.reconciler.ReconcileTenant(tctx, tid.String()); rerr != nil {
			r.logger.WarnContext(ctx, "bank reconcile: tenant pass had failures",
				"tenant", tid.String(), "error", rerr)
		}
	}
}
