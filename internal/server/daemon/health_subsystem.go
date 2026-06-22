package daemon

import (
	"context"
	"time"

	healthhttp "github.com/zeroroot-ai/sdk/health/http"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// healthSubsystem owns the lifecycle of the HTTP health-check server.
// It is a thin wrapper around sdk/health/http.Server that exposes a
// Serve(ctx) error method suitable for use in an errgroup or goroutine.
type healthSubsystem struct {
	srv    *healthhttp.Server
	logger *observability.Logger
}

// newHealthSubsystem creates a healthSubsystem wrapping the given server.
func newHealthSubsystem(srv *healthhttp.Server, logger *observability.Logger) *healthSubsystem {
	return &healthSubsystem{srv: srv, logger: logger}
}

// Serve starts the health server (best-effort) and blocks until ctx is cancelled,
// then performs a graceful stop with a 5-second timeout.
//
// Health server failure is non-fatal: a warning is logged and Serve returns nil
// so that a subsystem failure here never takes down the entire daemon via errgroup.
func (h *healthSubsystem) Serve(ctx context.Context) error {
	if err := h.srv.Start(); err != nil {
		h.logger.Warn(ctx, "failed to start health server (non-fatal)",
			"error", err)
		// Return nil — health server is best-effort; daemon continues without it.
		return nil
	}
	h.logger.Info(ctx, "health server started")

	<-ctx.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.srv.Stop(stopCtx); err != nil {
		h.logger.Warn(ctx, "error stopping health server", "error", err)
	}
	return nil
}
