// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// serveTrace starts a trace server with the transport options of the trace
// listener and no TLS. The receiver refuses a caller without a SPIFFE ID, so
// the result of an accepted message is a PermissionDenied from the handler.
func serveTrace(t *testing.T, opts []grpc.ServerOption) coltrace.TraceServiceClient {
	t.Helper()
	srv := grpc.NewServer(opts...)
	coltrace.RegisterTraceServiceServer(srv, api.NewTraceReceiver("spiffe://example.org/platform/otel-collector", nil, nil))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(64<<20)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return coltrace.NewTraceServiceClient(conn)
}

func bigSpan(n int) *coltrace.ExportTraceServiceRequest {
	return &coltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			Attributes: []*commonpb.KeyValue{{
				Key:   "gibson.request_body",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: strings.Repeat("x", n)}},
			}},
		}}}},
	}}}
}

// A span of 20 MiB reaches the handler of the trace listener. The handler then
// refuses the caller, which proves that the message passed the size limit.
func TestTraceListener_AcceptsASpanOver16MiB(t *testing.T) {
	cli := serveTrace(t, traceServerOptions())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := cli.Export(ctx, bigSpan(20<<20))
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("export of 20 MiB = %v, want PermissionDenied from the handler", err)
	}
}

// The main daemon limit stays at 16 MiB. A server with the main limit refuses
// the same span before the handler runs. This is the failing fixture of the
// trace limit.
func TestTraceListener_MainLimitRefusesTheSameSpan(t *testing.T) {
	cli := serveTrace(t, []grpc.ServerOption{grpc.MaxRecvMsgSize(maxDaemonRecvMsgBytes)})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := cli.Export(ctx, bigSpan(20<<20))
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("export of 20 MiB on the main limit = %v, want ResourceExhausted", err)
	}
}

func TestTraceListener_LimitsAreSeparate(t *testing.T) {
	if maxTraceRecvMsgBytes != 48<<20 {
		t.Errorf("trace limit = %d, want 48 MiB", maxTraceRecvMsgBytes)
	}
	if maxDaemonRecvMsgBytes >= maxTraceRecvMsgBytes {
		t.Errorf("the main limit %d is not below the trace limit %d", maxDaemonRecvMsgBytes, maxTraceRecvMsgBytes)
	}
}

// With no collector identity, the daemon builds no listener.
func TestBuildTraceServer_NoIdentityNoListener(t *testing.T) {
	t.Setenv(api.EnvTraceCollectorSVID, "")
	d := &daemonImpl{logger: minimalCfgLogger()}
	sys, err := d.buildTraceServer(context.Background())
	if err != nil || sys != nil {
		t.Fatalf("buildTraceServer = %v, %v, want nil, nil", sys, err)
	}
}

// An identity with no address, or with no SPIFFE, stops the daemon.
func TestBuildTraceServer_RefusesAnIncompleteConfig(t *testing.T) {
	t.Setenv(api.EnvTraceCollectorSVID, "spiffe://example.org/platform/otel-collector")
	t.Setenv(EnvTraceGRPCAddr, "")
	d := &daemonImpl{logger: minimalCfgLogger()}
	if _, err := d.buildTraceServer(context.Background()); err == nil {
		t.Fatal("no registry and no address was accepted")
	}
}
