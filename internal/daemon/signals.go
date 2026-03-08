package daemon

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/zero-day-ai/gibson/internal/observability"
)

// SignalHandler manages OS signal handling for graceful daemon shutdown.
// It listens for SIGTERM, SIGINT, and SIGQUIT signals and triggers shutdown
// via a callback function. On second signal, it forces immediate exit.
type SignalHandler struct {
	logger        *observability.Logger
	shutdownFn    func()
	signalCh      chan os.Signal
	stopCh        chan struct{}
	mu            sync.Mutex
	signalCount   int
	running       bool
	forceExitCode int // Exit code to use on forced exit (default 1)
}

// SignalHandlerConfig contains configuration for signal handling.
type SignalHandlerConfig struct {
	// ShutdownCallback is called when the first shutdown signal is received
	ShutdownCallback func()

	// ForceExitCode is the exit code to use on forced exit (default 1)
	ForceExitCode int
}

// NewSignalHandler creates a new signal handler.
//
// Parameters:
//   - cfg: Configuration for signal handling
//   - logger: Logger for signal events
//
// Returns:
//   - *SignalHandler: A new signal handler ready to be started
func NewSignalHandler(cfg SignalHandlerConfig, logger *observability.Logger) *SignalHandler {
	if cfg.ForceExitCode == 0 {
		cfg.ForceExitCode = 1
	}

	return &SignalHandler{
		logger:        logger,
		shutdownFn:    cfg.ShutdownCallback,
		signalCh:      make(chan os.Signal, 1),
		stopCh:        make(chan struct{}),
		forceExitCode: cfg.ForceExitCode,
	}
}

// Start begins listening for OS signals in a background goroutine.
// It captures SIGTERM, SIGINT, and SIGQUIT signals.
//
// On first signal:
//   - Log the signal received
//   - Call the shutdown callback function
//
// On second signal:
//   - Log forced exit warning
//   - Call os.Exit() immediately
//
// Parameters:
//   - ctx: Context for signal handler lifetime
func (sh *SignalHandler) Start(ctx context.Context) {
	sh.mu.Lock()
	if sh.running {
		sh.mu.Unlock()
		sh.logger.Warn(ctx, "signal handler already running")
		return
	}
	sh.running = true
	sh.mu.Unlock()

	// Register for signals
	// SIGINT (Ctrl+C), SIGTERM (graceful shutdown), SIGQUIT (quit with core dump)
	signal.Notify(sh.signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	sh.logger.Info(ctx, "signal handler started, listening for SIGINT, SIGTERM, SIGQUIT")

	// Start signal handling goroutine
	go sh.handleSignals(ctx)
}

// Stop stops the signal handler and cleans up resources.
func (sh *SignalHandler) Stop() {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if !sh.running {
		return
	}

	sh.running = false
	signal.Stop(sh.signalCh)
	close(sh.stopCh)
	close(sh.signalCh)
}

// handleSignals is the main signal handling loop.
func (sh *SignalHandler) handleSignals(ctx context.Context) {
	for {
		select {
		case <-sh.stopCh:
			sh.logger.Debug(ctx, "signal handler stopped")
			return

		case sig, ok := <-sh.signalCh:
			if !ok {
				sh.logger.Debug(ctx, "signal channel closed")
				return
			}

			sh.mu.Lock()
			sh.signalCount++
			count := sh.signalCount
			sh.mu.Unlock()

			sh.logger.Info(ctx, "received signal",
				"signal", sig.String(),
				"count", count)

			if count == 1 {
				// First signal - trigger graceful shutdown
				sh.handleFirstSignal(ctx, sig)
			} else {
				// Second or subsequent signal - force exit
				sh.handleForceExit(ctx, sig)
			}
		}
	}
}

// handleFirstSignal handles the first shutdown signal by calling the shutdown callback.
func (sh *SignalHandler) handleFirstSignal(ctx context.Context, sig os.Signal) {
	// Special handling for SIGQUIT - allow core dump
	if sig == syscall.SIGQUIT {
		sh.logger.Warn(ctx, "SIGQUIT received - allowing core dump generation")
		// Reset signal handler to default for SIGQUIT to allow core dump
		signal.Reset(syscall.SIGQUIT)
		// Send SIGQUIT to self to trigger core dump after graceful shutdown
		defer func() {
			sh.logger.Info(ctx, "triggering core dump after shutdown")
			syscall.Kill(syscall.Getpid(), syscall.SIGQUIT)
		}()
	}

	sh.logger.Info(ctx, "initiating graceful shutdown",
		"signal", sig.String(),
		"hint", "send signal again to force immediate exit")

	// Call shutdown callback
	if sh.shutdownFn != nil {
		sh.shutdownFn()
	} else {
		sh.logger.Warn(ctx, "no shutdown callback configured, exiting immediately")
		os.Exit(sh.forceExitCode)
	}
}

// handleForceExit handles subsequent signals by forcing immediate exit.
func (sh *SignalHandler) handleForceExit(ctx context.Context, sig os.Signal) {
	sh.logger.Warn(ctx, "force exit requested, terminating immediately",
		"signal", sig.String(),
		"signal_count", sh.signalCount)

	// Immediately exit without cleanup
	os.Exit(sh.forceExitCode)
}
