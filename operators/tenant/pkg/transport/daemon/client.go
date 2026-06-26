// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package daemon constructs the operator's SPIFFE-mTLS gRPC client to the
// daemon's DaemonOperatorService.
//
// Phase 2 of ADR-0002 (zeroroot-ai/docs adr/0002-operator-to-daemon-transport.md):
// the operator dials the daemon directly over SPIFFE mTLS using the SPIRE
// agent's Workload API socket. The daemon's gRPC server validates the
// operator's SVID against its inbound peer allow-list (gibson#107) before
// accepting the connection. The token-source-Bearer path that the existing
// EntitlementsGRPCClient sends in `authorization` metadata stays exactly as
// it is — mTLS is workload identity; the JWT is the per-call authorization
// principal the daemon dispatches into OpenFGA.
//
// All callers should construct exactly ONE *Client per operator process and
// reuse it. The underlying X509Source streams continuous SVID rotations; a
// new Client per call would defeat that and burn the SPIRE-agent connection
// budget.
package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Options configures Client construction.
type Options struct {
	// Addr is the daemon's gRPC address (e.g. "gibson-workloads:50051"). The
	// value originates from the chart's gibson.daemonAddress helper, surfaced
	// to the operator as GIBSON_DAEMON_GRPC_ADDRESS. Required.
	Addr string

	// DaemonSVID is the SPIFFE ID the operator expects to see in the
	// daemon's leaf certificate during the mTLS handshake. The TLS config
	// rejects any connection whose server cert presents a different SVID.
	// Typically spiffe://zeroroot.ai/platform/daemon. Required.
	DaemonSVID string

	// WorkloadAPISocket overrides the SPIRE agent socket path. When empty,
	// go-spiffe uses the conventional SPIFFE_ENDPOINT_SOCKET env var, which
	// the chart's Deployment template wires to the CSI-mounted socket.
	WorkloadAPISocket string

	// DialOptions appends to the default gRPC dial options. Tests pass
	// fakes here; production passes nothing.
	DialOptions []grpc.DialOption
}

// Client wraps a long-lived gRPC connection to the daemon plus the
// underlying X509Source. Callers MUST call Close on shutdown to release the
// SPIRE-agent stream and the gRPC connection.
type Client struct {
	conn   *grpc.ClientConn
	source *workloadapi.X509Source
}

// NewClient opens a streaming X509Source against the SPIRE Workload API,
// constructs an mTLS client config that authorizes the daemon's SVID, and
// dials the daemon. The returned Client owns its X509Source and gRPC
// connection; both are released on Close. The X509Source rotates SVIDs
// automatically; callers do not need to recreate the Client periodically.
//
// Returns a wrapped error suitable for the operator's saga retry taxonomy:
// SPIRE-side failures (socket unavailable, no SVID yet) propagate as-is so
// the saga's transient retry honors them.
func NewClient(ctx context.Context, opts Options) (*Client, error) {
	if strings.TrimSpace(opts.Addr) == "" {
		return nil, fmt.Errorf("daemon-transport: Addr is required")
	}
	if strings.TrimSpace(opts.DaemonSVID) == "" {
		return nil, fmt.Errorf("daemon-transport: DaemonSVID is required (typically spiffe://zeroroot.ai/platform/daemon)")
	}
	daemonID, err := spiffeid.FromString(opts.DaemonSVID)
	if err != nil {
		return nil, fmt.Errorf("daemon-transport: DaemonSVID %q is not a parseable SPIFFE ID: %w", opts.DaemonSVID, err)
	}

	var sourceOpts []workloadapi.X509SourceOption
	if s := strings.TrimSpace(opts.WorkloadAPISocket); s != "" {
		sourceOpts = append(sourceOpts, workloadapi.WithClientOptions(workloadapi.WithAddr(s)))
	}
	source, err := workloadapi.NewX509Source(ctx, sourceOpts...)
	if err != nil {
		return nil, fmt.Errorf(
			"daemon-transport: open SPIRE workload API X509Source (socket=%q): %w",
			opts.WorkloadAPISocket, err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(daemonID))
	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	}, opts.DialOptions...)

	conn, err := grpc.NewClient(opts.Addr, dialOpts...)
	if err != nil {
		_ = source.Close()
		return nil, fmt.Errorf("daemon-transport: dial %q: %w", opts.Addr, err)
	}
	return &Client{conn: conn, source: source}, nil
}

// Conn returns the underlying gRPC connection. Callers wrap it in their
// preferred service-specific client (e.g. operatorv1.NewDaemonOperatorServiceClient).
// The returned *grpc.ClientConn must NOT be closed by the caller — its
// lifecycle is owned by Client.
func (c *Client) Conn() *grpc.ClientConn {
	return c.conn
}

// TLSConfig is exposed for tests that need to inspect the assembled TLS
// settings without going through the full dial. Production code should not
// use this.
func (c *Client) TLSConfig() *tls.Config {
	// The TLS config is held by gRPC's transport credentials; we don't
	// retain a separate copy. This is a deliberately narrow surface — if a
	// test needs more, the test should build the TLS config itself with
	// tlsconfig.MTLSClientConfig directly.
	return nil
}

// Close releases the gRPC connection and the underlying X509Source.
// Idempotent.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	var grpcErr, srcErr error
	if c.conn != nil {
		grpcErr = c.conn.Close()
		c.conn = nil
	}
	if c.source != nil {
		srcErr = c.source.Close()
		c.source = nil
	}
	if grpcErr != nil {
		return grpcErr
	}
	return srcErr
}
