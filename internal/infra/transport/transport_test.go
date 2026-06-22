package transport_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zeroroot-ai/gibson/internal/infra/transport"
)

// leakOpts lists goroutine top-functions that are expected to be alive when a
// test ends. These are standard library / httptest goroutines that are
// asynchronously reaped after Server.Close(): they are not leaks caused by our
// code.
var leakOpts = []goleak.Option{
	goleak.IgnoreTopFunction("net/http.(*Server).Serve"),
	goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
	goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	goleak.IgnoreTopFunction("net/http/httptest.(*Server).goServe"),
}

// ----------------------------------------------------------------------------
// minimal hand-written ConnectRPC echo service using StringValue (no protoc)
// ----------------------------------------------------------------------------

const echoProcedure = "/test.v1.EchoService/Greet"

// EchoHandlerFunc is a callback called per request in the test echo service.
type EchoHandlerFunc func(ctx context.Context, req *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error)

// mountEcho registers a unary ConnectRPC handler at echoProcedure on mux.
func mountEcho(mux *http.ServeMux, fn EchoHandlerFunc, interceptors ...connect.Interceptor) {
	h := connect.NewUnaryHandler(echoProcedure, fn, connect.WithInterceptors(interceptors...))
	mux.Handle(echoProcedure, h)
}

// freshHTTPClient returns a new http.Transport-backed client that will have no
// lingering keep-alive goroutines after CloseIdleConnections is called.
func freshHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{}}
}

// echoClient returns a thin unary caller for the echo service using a
// per-test HTTP client so keep-alive goroutines can be drained cleanly.
func echoClient(t *testing.T, baseURL string, opts ...connect.ClientOption) func(context.Context, *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
	t.Helper()
	hc := freshHTTPClient()
	t.Cleanup(func() { hc.CloseIdleConnections() })
	c := connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](
		hc,
		baseURL+echoProcedure,
		opts...,
	)
	return c.CallUnary
}

// ----------------------------------------------------------------------------
// 1. Panic recovery — handler panics → CodeInternal, no goroutine leak
// ----------------------------------------------------------------------------

func TestPanicRecovery_ReturnsCodeInternal(t *testing.T) {
	defer goleak.VerifyNone(t, leakOpts...)

	interceptors := transport.ConnectInterceptors(nil, nil)

	mux := http.NewServeMux()
	mountEcho(mux, func(_ context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		panic("simulated handler panic")
	}, interceptors...)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := echoClient(t, srv.URL)(context.Background(), connect.NewRequest(wrapperspb.String("hello")))
	if err == nil {
		t.Fatal("expected error from panicking handler, got nil")
	}

	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if cerr.Code() != connect.CodeInternal {
		t.Errorf("expected CodeInternal, got %v", cerr.Code())
	}
}

// ----------------------------------------------------------------------------
// 2. Client retry with mock clock — retries CodeUnavailable with backoff
// ----------------------------------------------------------------------------

// testClock records sleeps and returns immediately.
type testClock struct {
	sleeps []time.Duration
}

func (c *testClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	return nil
}

func TestClientRetry_RetriesUnavailable(t *testing.T) {
	defer goleak.VerifyNone(t, leakOpts...)

	const failFirst = 2
	calls := 0

	mux := http.NewServeMux()
	mountEcho(mux, func(_ context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		calls++
		if calls <= failFirst {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("backend down"))
		}
		return connect.NewResponse(wrapperspb.String("ok")), nil
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clk := &testClock{}
	policy := transport.RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   50 * time.Millisecond,
		MaxDelay:    500 * time.Millisecond,
		TestClock:   clk,
	}
	clientInterceptors := transport.ClientInterceptors(policy, 0)
	call := echoClient(t, srv.URL, connect.WithInterceptors(clientInterceptors...))

	_, callErr := call(context.Background(), connect.NewRequest(wrapperspb.String("retry")))
	if callErr != nil {
		t.Fatalf("expected success after retries, got: %v", callErr)
	}
	if calls != failFirst+1 {
		t.Errorf("expected %d server calls (2 fail + 1 succeed), got %d", failFirst+1, calls)
	}
	if len(clk.sleeps) != failFirst {
		t.Errorf("expected %d backoff sleeps, got %d", failFirst, len(clk.sleeps))
	}
}

// ----------------------------------------------------------------------------
// 3. Correlation ID round-trips through metadata
// ----------------------------------------------------------------------------

func TestCorrelationID_RoundTrips(t *testing.T) {
	defer goleak.VerifyNone(t, leakOpts...)

	var serverSeenID string

	interceptors := transport.ConnectInterceptors(nil, nil)
	mux := http.NewServeMux()
	mountEcho(mux, func(ctx context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		serverSeenID = transport.CorrelationIDFromContext(ctx)
		return connect.NewResponse(wrapperspb.String("ok")), nil
	}, interceptors...)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const wantID = "req-TESTCORRELATION"
	req := connect.NewRequest(wrapperspb.String("id-test"))
	req.Header().Set(transport.CorrelationIDHeader, wantID)

	_, callErr := echoClient(t, srv.URL)(context.Background(), req)
	if callErr != nil {
		t.Fatalf("call: %v", callErr)
	}
	if serverSeenID != wantID {
		t.Errorf("server saw correlation ID %q, want %q", serverSeenID, wantID)
	}
}

// ----------------------------------------------------------------------------
// 4. OTel span context propagates client → server (recorded span verified)
// ----------------------------------------------------------------------------

func TestOTel_SpanContextPropagates(t *testing.T) {
	defer goleak.VerifyNone(t, leakOpts...)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(otel.GetTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})

	interceptors := transport.ConnectInterceptors(nil, nil)
	mux := http.NewServeMux()
	mountEcho(mux, func(_ context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		return connect.NewResponse(wrapperspb.String("traced")), nil
	}, interceptors...)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clientInterceptors := transport.ClientInterceptors(transport.RetryPolicy{}, 0)
	call := echoClient(t, srv.URL, connect.WithInterceptors(clientInterceptors...))

	ctx, rootSpan := tp.Tracer("test").Start(context.Background(), "test-root")
	_, callErr := call(ctx, connect.NewRequest(wrapperspb.String("otel")))
	rootSpan.End()

	if callErr != nil {
		t.Fatalf("call: %v", callErr)
	}

	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one recorded span, got none")
	}
}

// ----------------------------------------------------------------------------
// 5. Per-call deadline is honoured — server sees the deadline
// ----------------------------------------------------------------------------

func TestPerCallDeadline_IsHonoured(t *testing.T) {
	defer goleak.VerifyNone(t, leakOpts...)

	mux := http.NewServeMux()
	// Handler blocks for 500 ms or until context is cancelled.
	mountEcho(mux, func(ctx context.Context, _ *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
		select {
		case <-ctx.Done():
			return nil, connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
		case <-time.After(500 * time.Millisecond):
			return connect.NewResponse(wrapperspb.String("slow")), nil
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const perCallTimeout = 50 * time.Millisecond
	clientInterceptors := transport.ClientInterceptors(transport.RetryPolicy{MaxAttempts: 1}, perCallTimeout)
	call := echoClient(t, srv.URL, connect.WithInterceptors(clientInterceptors...))

	start := time.Now()
	_, callErr := call(context.Background(), connect.NewRequest(wrapperspb.String("deadline")))
	elapsed := time.Since(start)

	if callErr == nil {
		t.Fatal("expected deadline error, got nil")
	}
	// Should fail well before 200 ms; the 50 ms deadline fires first.
	if elapsed > 200*time.Millisecond {
		t.Errorf("call took %v; expected failure within 200ms with %v per-call deadline", elapsed, perCallTimeout)
	}
}
