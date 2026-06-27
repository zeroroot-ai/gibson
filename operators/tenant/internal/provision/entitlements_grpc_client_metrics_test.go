// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package provision

import (
	"context"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// deniedTenantOpsServer always denies ListPendingTenantOps, reproducing the
// gibson#1043 SPIFFE-allowlist regression where the daemon returned
// PermissionDenied to the operator's admin-ops drain.
type deniedTenantOpsServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
}

func (deniedTenantOpsServer) ListPendingTenantOps(context.Context, *operatorv1.ListPendingTenantOpsRequest) (*operatorv1.ListPendingTenantOpsResponse, error) {
	return nil, status.Errorf(codes.PermissionDenied, "spiffe id not on allowlist")
}

// TestListPendingTenantOps_Denied_IncrementsFailureMetric is the regression
// guard for gibson#1050: a denied operator->daemon call must bump
// gibson_tenant_operator_daemon_call_errors_total{method,outcome} so a future
// authorization regression is queryable and alertable rather than silent.
func TestListPendingTenantOps_Denied_IncrementsFailureMetric(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(gs, deniedTenantOpsServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &EntitlementsGRPCClient{
		client:   operatorv1.NewDaemonOperatorServiceClient(conn),
		audience: "gibson-daemon",
	}

	const (
		method  = "list-pending-tenant-ops"
		outcome = "permission_denied"
	)
	before := testutil.ToFloat64(metrics.DaemonCallErrors.WithLabelValues(method, outcome))

	if _, err := c.ListPendingTenantOps(context.Background()); err == nil {
		t.Fatal("expected PermissionDenied to be surfaced from the daemon")
	}

	after := testutil.ToFloat64(metrics.DaemonCallErrors.WithLabelValues(method, outcome))
	if got := after - before; got != 1 {
		t.Fatalf("DaemonCallErrors{method=%q,outcome=%q} delta = %v, want 1", method, outcome, got)
	}
}

// TestObserveDaemonCallError_NilIsNoOp guards that a successful call records no
// failure (the metric only counts errors).
func TestObserveDaemonCallError_NilIsNoOp(t *testing.T) {
	const (
		method  = "noop-success-probe"
		outcome = "permission_denied"
	)
	before := testutil.ToFloat64(metrics.DaemonCallErrors.WithLabelValues(method, outcome))
	metrics.ObserveDaemonCallError(method, nil)
	after := testutil.ToFloat64(metrics.DaemonCallErrors.WithLabelValues(method, outcome))
	if after != before {
		t.Fatalf("nil error must not increment any failure counter: before=%v after=%v", before, after)
	}
}
