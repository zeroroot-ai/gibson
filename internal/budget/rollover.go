package budget

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// PeriodRolloverJob fires once per billing period boundary (UTC
// midnight on day 1 of the month by default) and emits a marker so
// operators can trace counter resets. Actual counter zeroing is
// implicit — counters are period-keyed, so the new period's hash
// doesn't exist until the first Record call in that period.
//
// A Redis SETNX lock (budget:rollover:lock:{period}) guarantees only
// one daemon replica writes the marker; replicas that lose the race
// exit cleanly.
//
// Spec: llm-user-attribution-governance (Requirement 3.8).
type PeriodRolloverJob struct {
	rdb    redis.UniversalClient
	logger *slog.Logger
	clock  Clock

	// onRoll is called with the new period ID after the marker is
	// written. Injected so callers can fan-out an audit event without
	// this package taking a hard dependency on the audit package.
	onRoll func(ctx context.Context, period string)
}

// NewPeriodRolloverJob constructs a rollover job. Pass nil for clock to
// use time.Now; nil for onRoll to skip the audit fan-out.
func NewPeriodRolloverJob(rdb redis.UniversalClient, logger *slog.Logger, clock Clock, onRoll func(context.Context, string)) *PeriodRolloverJob {
	if logger == nil {
		logger = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	return &PeriodRolloverJob{
		rdb:    rdb,
		logger: logger.With("component", "budget_rollover"),
		clock:  clock,
		onRoll: onRoll,
	}
}

// Run blocks until ctx is cancelled, firing the rollover hook at each
// period boundary. Intended to be launched as a daemon subsystem via
// eg.Go in the main bootstrap.
func (j *PeriodRolloverJob) Run(ctx context.Context) error {
	for {
		next := PeriodResetAt(j.clock())
		wait := time.Until(next)
		if wait <= 0 {
			wait = time.Second
		}
		j.logger.InfoContext(ctx, "budget rollover: waiting for next period",
			slog.String("next_reset_at", next.Format(time.RFC3339)),
			slog.Duration("wait", wait),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		newPeriod := PeriodID(j.clock())
		j.fireIfLeader(ctx, newPeriod)
	}
}

// fireIfLeader acquires the SETNX lock for (period), logs + invokes the
// onRoll hook, and releases. Lost-race replicas exit silently.
func (j *PeriodRolloverJob) fireIfLeader(ctx context.Context, period string) {
	lockKey := "budget:rollover:lock:" + period
	ok, err := j.rdb.SetNX(ctx, lockKey, "1", 24*time.Hour).Result()
	if err != nil {
		j.logger.WarnContext(ctx, "budget rollover: SETNX failed",
			slog.String("error", err.Error()), slog.String("period", period))
		return
	}
	if !ok {
		return
	}
	j.logger.InfoContext(ctx, "budget rollover: period boundary crossed",
		slog.String("period", period))
	if j.onRoll != nil {
		j.onRoll(ctx, period)
	}
}
