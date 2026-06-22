package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
)

// catalogRefresherSubsystem wraps reconciler.CatalogFanout with a
// Serve(ctx) error method, making it suitable for use in an errgroup or
// a plain goroutine alongside the other daemon subsystems.
//
// The underlying CatalogFanout runs every 60 seconds (best-effort) and
// stops when ctx is cancelled. Failures inside the fanout are logged,
// not fatal.
type catalogRefresherSubsystem struct {
	fanout *reconciler.CatalogFanout
}

// newCatalogRefresherSubsystem creates the subsystem from a pre-built CatalogFanout.
func newCatalogRefresherSubsystem(fanout *reconciler.CatalogFanout) *catalogRefresherSubsystem {
	return &catalogRefresherSubsystem{fanout: fanout}
}

// Serve runs the catalog fan-out reconciler until ctx is cancelled.
// Returns nil on clean shutdown (ctx.Done()); the fanout's internal retry
// and interval logic handles transient errors without surfacing them here.
func (c *catalogRefresherSubsystem) Serve(ctx context.Context) error {
	c.fanout.Run(ctx)
	return nil
}
