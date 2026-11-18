// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/zeroroot-ai/gibson/internal/infra/grpckeepalive"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// EnvTraceGRPCAddr names the environment variable that holds the listen
// address of the OTLP trace receiver, for example ":4317".
const EnvTraceGRPCAddr = "GIBSON_TRACE_GRPC_ADDR"

// maxTraceRecvMsgBytes is the message limit of the trace listener. One span
// holds the full request body and the full response body of a model call. The
// gateway buffer is 16 MiB, so one span can be larger than 16 MiB. The main
// daemon listener keeps its own, smaller limit.
const maxTraceRecvMsgBytes = 48 * 1024 * 1024

// traceServerOptions returns the transport options of the trace listener,
// without the credentials.
func traceServerOptions(unary ...grpc.UnaryServerInterceptor) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.MaxRecvMsgSize(maxTraceRecvMsgBytes),
		grpckeepalive.Params(),
		grpckeepalive.Enforcement(),
	}
}

// traceCollectorSVIDFromEnv reads the SPIFFE ID of the trace collector.
func traceCollectorSVIDFromEnv() string {
	return strings.TrimSpace(os.Getenv(api.EnvTraceCollectorSVID))
}

// buildTraceServer builds the OTLP trace listener (gibson#1390, ADR-0172). It
// has its own port and its own server. The TLS layer accepts the one SPIFFE ID
// of the collector and no other peer. The server holds the trace service and no
// other service. With no collector identity configured, the daemon starts no
// listener and accepts no span, and the result is nil.
func (d *daemonImpl) buildTraceServer(ctx context.Context) (*grpcSubsystem, error) {
	svid := traceCollectorSVIDFromEnv()
	if svid == "" {
		d.logger.Info(ctx, "no trace collector identity is configured; the trace listener is off",
			"env", api.EnvTraceCollectorSVID)
		return nil, nil
	}
	if d.brainRegistry == nil {
		return nil, fmt.Errorf("trace listener: the brain registry is not available")
	}
	addr := strings.TrimSpace(os.Getenv(EnvTraceGRPCAddr))
	if addr == "" {
		return nil, fmt.Errorf("trace listener: %s is set and %s is not", api.EnvTraceCollectorSVID, EnvTraceGRPCAddr)
	}
	collector, err := spiffeid.FromString(svid)
	if err != nil {
		return nil, fmt.Errorf("trace listener: %s is not a SPIFFE ID: %w", api.EnvTraceCollectorSVID, err)
	}
	if d.config.Auth.SPIFFE == nil || d.config.Auth.SPIFFE.WorkloadAPISocket == "" {
		return nil, fmt.Errorf("trace listener: the collector identity needs SPIFFE mTLS, and SPIFFE is not configured")
	}
	if td := d.spiffeTrustDomain(); !collector.MemberOf(td) {
		return nil, fmt.Errorf("trace listener: %s is not in the trust domain %s", svid, td)
	}
	x509Source, ok := d.spiffeX509Source.(*workloadapi.X509Source)
	if !ok || x509Source == nil {
		return nil, fmt.Errorf("trace listener: the SPIFFE X.509 source is not open (got %T)", d.spiffeX509Source)
	}

	unaryRecovery, _, err := panicRecoveryInterceptors(d.logger.Slog(), nil)
	if err != nil {
		return nil, fmt.Errorf("trace listener: recovery interceptor: %w", err)
	}
	tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeID(collector))
	opts := append(traceServerOptions(unaryRecovery), grpc.Creds(credentials.NewTLS(tlsCfg)))
	srv := grpc.NewServer(opts...)
	coltrace.RegisterTraceServiceServer(srv, api.NewTraceReceiver(
		svid, d.brainRegistry, d.logger.WithComponent("trace-receiver").Slog()))

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("trace listener: listen on %s: %w", addr, err)
	}
	return &grpcSubsystem{
		srv:                 srv,
		listener:            lis,
		logger:              d.logger,
		gracefulStopTimeout: 10 * time.Second,
	}, nil
}
