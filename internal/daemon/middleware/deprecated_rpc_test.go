package middleware

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// mockTransportStream implements grpc.ServerTransportStream so that
// grpc.SetHeader writes into a metadata.MD we can inspect in tests.
type mockTransportStream struct {
	method string
	header metadata.MD
}

func (m *mockTransportStream) Method() string { return m.method }

func (m *mockTransportStream) SetHeader(md metadata.MD) error {
	if m.header == nil {
		m.header = metadata.MD{}
	}
	for k, vs := range md {
		m.header[k] = append(m.header[k], vs...)
	}
	return nil
}

func (m *mockTransportStream) SendHeader(md metadata.MD) error { return m.SetHeader(md) }
func (m *mockTransportStream) SetTrailer(md metadata.MD) error { return nil }

// newServerCtx returns a context wired with a mockTransportStream so that
// grpc.SetHeader calls inside the interceptor are captured on the stream.
func newServerCtx(method string) (context.Context, *mockTransportStream) {
	stream := &mockTransportStream{method: method}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), stream)
	return ctx, stream
}

// noopHandler is a grpc.UnaryHandler that always succeeds and records whether
// it was called.
func noopHandler(called *bool) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		*called = true
		return "ok", nil
	}
}

// TestDeprecatedRPCInterceptor_SetsHeader verifies that calling a deprecated
// RPC causes the interceptor to attach an x-deprecated response header whose
// value contains the replacement and removal-version information.
func TestDeprecatedRPCInterceptor_SetsHeader(t *testing.T) {
	deprecated := []DeprecatedRPC{
		{
			FullMethod:     "/gibson.daemon.v1.DaemonService/OldRPC",
			Replacement:    "/gibson.daemon.v1.DaemonService/NewRPC",
			RemovalVersion: "v2.0.0",
		},
	}
	interceptor := DeprecatedRPCInterceptor(deprecated)

	ctx, stream := newServerCtx("/gibson.daemon.v1.DaemonService/OldRPC")
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.daemon.v1.DaemonService/OldRPC"}

	var handlerCalled bool
	resp, err := interceptor(ctx, nil, info, noopHandler(&handlerCalled))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.True(t, handlerCalled, "handler must be called for deprecated RPCs")

	require.NotNil(t, stream.header, "response header must be set for a deprecated RPC")
	vals := stream.header.Get("x-deprecated")
	require.NotEmpty(t, vals, "x-deprecated header must be present")

	headerVal := vals[0]
	assert.True(t, strings.Contains(headerVal, "/gibson.daemon.v1.DaemonService/NewRPC"),
		"x-deprecated header should reference the replacement RPC")
	assert.True(t, strings.Contains(headerVal, "v2.0.0"),
		"x-deprecated header should reference the removal version")
}

// TestDeprecatedRPCInterceptor_NonDeprecatedPassthrough verifies that the
// interceptor does not set any header and still calls the handler when the
// invoked method is not in the deprecated list.
func TestDeprecatedRPCInterceptor_NonDeprecatedPassthrough(t *testing.T) {
	deprecated := []DeprecatedRPC{
		{
			FullMethod:     "/gibson.daemon.v1.DaemonService/OldRPC",
			Replacement:    "/gibson.daemon.v1.DaemonService/NewRPC",
			RemovalVersion: "v2.0.0",
		},
	}
	interceptor := DeprecatedRPCInterceptor(deprecated)

	ctx, stream := newServerCtx("/gibson.daemon.v1.DaemonService/ActiveRPC")
	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.daemon.v1.DaemonService/ActiveRPC"}

	var handlerCalled bool
	resp, err := interceptor(ctx, nil, info, noopHandler(&handlerCalled))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.True(t, handlerCalled, "handler must be called for non-deprecated RPCs")

	// No header should have been written for a non-deprecated method.
	assert.Empty(t, stream.header.Get("x-deprecated"),
		"x-deprecated header must not be set for a non-deprecated RPC")
}
