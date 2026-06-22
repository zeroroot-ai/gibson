package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestUnaryPanicRecovery_StringPanic — a string panic in the handler is
// recovered, the goroutine survives, codes.Internal is returned, and the
// recovered value never leaks across the trust boundary.
func TestUnaryPanicRecovery_StringPanic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	interceptor := UnaryPanicRecovery(logger)

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		panic("synthetic panic with sensitive_tenant_id=acme")
	}

	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/envoy.service.auth.v3.Authorization/Check"},
		handler)
	if resp != nil {
		t.Fatalf("expected nil response, got %v", resp)
	}
	if err == nil {
		t.Fatal("expected error after panic, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected status error, got %T", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", st.Code())
	}
	// The generic message must NOT contain the recovered panic value.
	if strings.Contains(st.Message(), "sensitive_tenant_id") {
		t.Fatalf("panic value leaked across trust boundary: %q", st.Message())
	}
	// The stack trace IS logged (defensible — operator audit).
	if !strings.Contains(buf.String(), "sensitive_tenant_id=acme") {
		t.Fatalf("expected panic value in logs, got: %s", buf.String())
	}
}

// TestUnaryPanicRecovery_ErrorPanic — an error-typed panic value is unwrapped
// into the log without leaking on the wire.
func TestUnaryPanicRecovery_ErrorPanic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	interceptor := UnaryPanicRecovery(logger)

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		panic(errors.New("typed panic"))
	}

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if err == nil {
		t.Fatal("expected error after panic, got nil")
	}
	if !strings.Contains(buf.String(), "typed panic") {
		t.Fatalf("expected typed panic value in logs, got: %s", buf.String())
	}
}

// TestUnaryPanicRecovery_NoPanic — when the handler doesn't panic, the
// interceptor is a transparent pass-through.
func TestUnaryPanicRecovery_NoPanic(t *testing.T) {
	t.Parallel()
	interceptor := UnaryPanicRecovery(slog.Default())
	want := "ok"
	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{},
		func(_ context.Context, _ interface{}) (interface{}, error) {
			return want, nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != want {
		t.Fatalf("expected %q, got %v", want, resp)
	}
}

// TestUnaryPanicRecovery_NilLogger — interceptor accepts nil logger and
// uses slog.Default().
func TestUnaryPanicRecovery_NilLogger(t *testing.T) {
	t.Parallel()
	interceptor := UnaryPanicRecovery(nil)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{},
		func(_ context.Context, _ interface{}) (interface{}, error) {
			panic("ignored by default logger")
		})
	if err == nil {
		t.Fatal("expected error after panic, got nil")
	}
}
