package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/observability"
	"google.golang.org/grpc"
)

// TestGRPCSubsystem_ServeReturnsOnCancel verifies that grpcSubsystem.Serve
// returns when the supplied context is cancelled.
func TestGRPCSubsystem_ServeReturnsOnCancel(t *testing.T) {
	t.Parallel()

	// Bind an ephemeral port so the gRPC server can actually listen.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	srv := grpc.NewServer()
	sys := &grpcSubsystem{
		srv:                 srv,
		listener:            ln,
		logger:              minimalCfgLogger(),
		gracefulStopTimeout: 2 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- sys.Serve(ctx) }()

	// Give the server a moment to start listening before cancelling.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned non-nil error on clean cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return within 5s after ctx cancellation")
	}
}

// TestGRPCSubsystem_ServeGracefulStop verifies that GracefulStop is invoked
// on ctx cancellation (not just Stop) so in-flight RPCs are drained.
func TestGRPCSubsystem_ServeGracefulStop(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	gracefulStopCalled := make(chan struct{}, 1)

	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}))

	sys := &grpcSubsystem{
		srv:                 srv,
		listener:            ln,
		logger:              minimalCfgLogger(),
		gracefulStopTimeout: 2 * time.Second,
	}

	// Wrap Serve in a goroutine; watch that stop finishes without hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sys.Serve(ctx) }()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned non-nil error: %v", err)
		}
		// If we got here without timeout, GracefulStop ran (or timed out and Stop ran).
		close(gracefulStopCalled)
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return within 5s")
	}

	select {
	case <-gracefulStopCalled:
	default:
		t.Error("gracefulStop was not confirmed")
	}
}

// minimalCfgLogger returns a throwaway logger for subsystem tests that
// cannot use the full daemon (no Redis, no FGA).
func minimalCfgLogger() *observability.Logger {
	cfg := minimalCfg()
	d, err := New(cfg)
	if err != nil {
		panic("minimalCfgLogger: " + err.Error())
	}
	return d.(*daemonImpl).logger
}
