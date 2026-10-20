// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemonclient

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// pagedConnectors serves a fixed list in pages. The token is the index of the
// next item. When endless is set, no page is the last one.
type pagedConnectors struct {
	daemonoperatorv1.UnimplementedDaemonOperatorServiceServer
	items   []*daemonoperatorv1.DesiredConnector
	perPage int
	endless bool
	calls   []*daemonoperatorv1.ListDesiredConnectorsRequest
}

func (p *pagedConnectors) ListDesiredConnectors(_ context.Context, req *daemonoperatorv1.ListDesiredConnectorsRequest) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	p.calls = append(p.calls, req)
	start := 0
	if req.GetPageToken() != "" && !p.endless {
		n, err := strconv.Atoi(req.GetPageToken())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "bad token")
		}
		start = n
	}
	end := min(start+p.perPage, len(p.items))
	resp := &daemonoperatorv1.ListDesiredConnectorsResponse{}
	if start < len(p.items) {
		resp.Connectors = p.items[start:end]
	}
	switch {
	case p.endless:
		// A new token for each call, so the list never ends and never loops.
		resp.NextPageToken = "n" + strconv.Itoa(len(p.calls))
	case end < len(p.items):
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func wishes(n int) []*daemonoperatorv1.DesiredConnector {
	out := make([]*daemonoperatorv1.DesiredConnector, 0, n)
	for i := range n {
		out = append(out, &daemonoperatorv1.DesiredConnector{TenantId: fmt.Sprintf("t%02d", i), ConnectorId: "gitlab"})
	}
	return out
}

// The client walks every page and asks for the largest page.
func TestListDesiredConnectors_WalksEveryPage(t *testing.T) {
	svc := &pagedConnectors{items: wishes(7), perPage: 3}
	c := dialPaged(t, svc)
	got, err := c.ListDesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("ListDesiredConnectors: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("got %d connectors, want 7", len(got))
	}
	for i, d := range got {
		if d.GetTenantId() != fmt.Sprintf("t%02d", i) {
			t.Fatalf("connector %d = %s: order or content is wrong", i, d.GetTenantId())
		}
	}
	if len(svc.calls) != 3 {
		t.Fatalf("%d calls, want 3 pages", len(svc.calls))
	}
	if svc.calls[0].GetPageToken() != "" || svc.calls[1].GetPageToken() != "3" || svc.calls[2].GetPageToken() != "6" {
		t.Errorf("tokens = %q %q %q", svc.calls[0].GetPageToken(), svc.calls[1].GetPageToken(), svc.calls[2].GetPageToken())
	}
	if svc.calls[0].GetPageSize() != pagetoken.MaxSize {
		t.Errorf("page_size = %d, want %d", svc.calls[0].GetPageSize(), pagetoken.MaxSize)
	}
}

// A list that does not end is an error. The client never returns a part of
// the list as if it were all of it.
func TestListDesiredConnectors_BoundHitIsAnError(t *testing.T) {
	svc := &pagedConnectors{items: wishes(2), perPage: 1, endless: true}
	c := dialPaged(t, svc)
	got, err := c.ListDesiredConnectors(context.Background())
	if !errors.Is(err, pagetoken.ErrTooManyPages) {
		t.Fatalf("err = %v, want ErrTooManyPages", err)
	}
	if got != nil {
		t.Fatalf("got %d connectors with the error, want none", len(got))
	}
}

// An error on a later page fails the whole list.
func TestListDesiredConnectors_LaterPageErrorFailsTheList(t *testing.T) {
	svc := &pagedConnectors{items: wishes(4), perPage: 2}
	c := dialPaged(t, &failOnToken{pagedConnectors: svc, token: "2"})
	if _, err := c.ListDesiredConnectors(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

type failOnToken struct {
	*pagedConnectors
	token string
}

func (f *failOnToken) ListDesiredConnectors(ctx context.Context, req *daemonoperatorv1.ListDesiredConnectorsRequest) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	if req.GetPageToken() == f.token {
		return nil, status.Error(codes.Unavailable, "down")
	}
	return f.pagedConnectors.ListDesiredConnectors(ctx, req)
}
