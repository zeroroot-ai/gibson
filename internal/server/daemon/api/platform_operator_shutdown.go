// Package api — platform_operator_shutdown.go implements
// PlatformOperatorService.Shutdown.
//
// Relocated to new service per admin-services-completion spec.
// Receiver type: DaemonServer implementing PlatformOperatorServiceServer.
// DaemonServer (PlatformOperatorService). Handler body is identical.
package api

import (
	"context"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// Shutdown requests graceful shutdown of the daemon.
// Requires the "platform_operator" FGA relation on system_tenant:_system.
func (s *DaemonServer) Shutdown(ctx context.Context, req *daemonoperatorv1.ShutdownRequest) (*daemonoperatorv1.ShutdownResponse, error) {
	s.logger.Info("shutdown requested via gRPC",
		"force", req.Force,
		"timeout_seconds", req.TimeoutSeconds,
	)

	// Validate this is a local daemon (not remote via GIBSON_DAEMON_ADDRESS).
	// The CLI already prevents this, but we double-check here for safety.
	if remoteAddr := os.Getenv("GIBSON_DAEMON_ADDRESS"); remoteAddr != "" {
		return &daemonoperatorv1.ShutdownResponse{
			Success: false,
			Message: "Cannot shutdown a remote daemon via this endpoint",
		}, nil
	}

	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	// Start shutdown in a goroutine so we can return the response first.
	go func() {
		time.Sleep(100 * time.Millisecond)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
		defer cancel()

		if err := s.daemon.RequestShutdown(shutdownCtx, req.Force, timeoutSeconds); err != nil {
			s.logger.Error("shutdown failed", "error", err)
		}
	}()

	return &daemonoperatorv1.ShutdownResponse{
		Success: true,
		Message: "Shutdown request accepted, daemon will stop shortly",
	}, nil
}

// shutdownUnavailableError is a helper that returns the correct error when
// the daemon is not in a state to accept a shutdown request.
func shutdownUnavailableError(msg string) error {
	return status_grpc.Errorf(codes.Unavailable, "shutdown unavailable: %s", msg)
}
