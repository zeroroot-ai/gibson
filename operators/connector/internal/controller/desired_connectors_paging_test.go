// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/daemonclient"
)

// pagedDaemon is a daemon that serves the desired connectors two to a page.
type pagedDaemon struct {
	daemonoperatorv1.UnimplementedDaemonOperatorServiceServer
	mu      sync.Mutex
	desired []*daemonoperatorv1.DesiredConnector
	lists   int
	reports map[string]bool
	// failOn is the page token whose request fails with Unavailable.
	failOn string
}

const pagedDaemonPageSize = 2

func (p *pagedDaemon) ListDesiredConnectors(_ context.Context, req *daemonoperatorv1.ListDesiredConnectorsRequest) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lists++
	if p.failOn != "" && req.GetPageToken() == p.failOn {
		return nil, status.Error(codes.Unavailable, "daemon down")
	}
	start := 0
	if req.GetPageToken() != "" {
		start, _ = strconv.Atoi(req.GetPageToken())
	}
	end := min(start+pagedDaemonPageSize, len(p.desired))
	resp := &daemonoperatorv1.ListDesiredConnectorsResponse{Connectors: p.desired[start:end]}
	if end < len(p.desired) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (p *pagedDaemon) ReportConnectorStatus(_ context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest) (*daemonoperatorv1.ReportConnectorStatusResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reports[pairKey(req.GetTenantId(), req.GetConnectorId())] = true
	return &daemonoperatorv1.ReportConnectorStatusResponse{Updated: true}, nil
}

// servePaged serves the daemon over bufconn and returns a connection to it.
func servePaged(t *testing.T, daemon *pagedDaemon) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	daemonoperatorv1.RegisterDaemonOperatorServiceServer(srv, daemon)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The loop makes the ConnectorInstance of every desired connector when the
// daemon needs three pages to list them, and prunes none of the connectors on
// the last pages.
func TestDesiredConnectors_ConvergesOverSeveralPages(t *testing.T) {
	daemon := &pagedDaemon{reports: map[string]bool{}}
	for i := range 5 {
		daemon.desired = append(daemon.desired, gitlabWish(fmt.Sprintf("t%d", i)))
	}
	conn := servePaged(t, daemon)

	// The instance of the last tenant exists already, so a list that stops
	// early would prune it.
	r, c := desiredLoop(t, &fakeDesiredDaemon{}, managedCI("tenant-t4", "gitlab", connectorOperatorManagedBy))
	r.Daemon = daemonclient.NewWithConn(conn)

	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	for i := range 5 {
		if _, ok := getCI(t, c, fmt.Sprintf("tenant-t%d", i), "gitlab"); !ok {
			t.Errorf("the ConnectorInstance of t%d was not made or was pruned", i)
		}
		if !daemon.reports[pairKey(fmt.Sprintf("t%d", i), "gitlab")] {
			t.Errorf("the loop sent no report for t%d", i)
		}
	}
	if daemon.lists != 3 {
		t.Errorf("the loop made %d list calls, want 3 pages", daemon.lists)
	}
}

// When page 2 of the list fails, the pass fails and prunes nothing. A pass that
// worked on page 1 alone would delete the instances that page 2 holds.
func TestDesiredConnectors_PageErrorPrunesNothing(t *testing.T) {
	daemon := &pagedDaemon{reports: map[string]bool{}, failOn: "2"}
	for i := range 5 {
		daemon.desired = append(daemon.desired, gitlabWish(fmt.Sprintf("t%d", i)))
	}
	conn := servePaged(t, daemon)
	// The instances of t2 and t4 are on the pages after page 1.
	r, c := desiredLoop(t, &fakeDesiredDaemon{},
		managedCI("tenant-t2", "gitlab", connectorOperatorManagedBy),
		managedCI("tenant-t4", "gitlab", connectorOperatorManagedBy))
	r.Daemon = daemonclient.NewWithConn(conn)

	if err := r.converge(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("converge: %v, want an Unavailable error", err)
	}
	for _, tenant := range []string{"t2", "t4"} {
		if _, ok := getCI(t, c, "tenant-"+tenant, "gitlab"); !ok {
			t.Errorf("the ConnectorInstance of %s was pruned after a failed list", tenant)
		}
	}
	if len(daemon.reports) != 0 {
		t.Errorf("the pass reported %d connectors after a failed list, want none", len(daemon.reports))
	}
}
