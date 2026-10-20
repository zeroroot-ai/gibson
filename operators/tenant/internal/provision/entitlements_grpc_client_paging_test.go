// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// pagedOperatorServer serves three lists, two items to a page. The token is
// the index of the next item. When endless is set, no page is the last one.
type pagedOperatorServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	n       int
	endless bool
	// failOn is the page token whose request fails with Unavailable.
	failOn string
	tokens []string
	sizes  []int32
}

const pagedPerPage = 2

// window returns the item range of the page and the next token.
func (p *pagedOperatorServer) window(token string, size int32) (start, end int, next string) {
	p.tokens = append(p.tokens, token)
	p.sizes = append(p.sizes, size)
	if token != "" && !p.endless {
		start, _ = strconv.Atoi(token)
	}
	end = min(start+pagedPerPage, p.n)
	switch {
	case p.endless:
		// A new token for each call, so the list never ends and never loops.
		next = "n" + strconv.Itoa(len(p.tokens))
	case end < p.n:
		next = strconv.Itoa(end)
	}
	return start, end, next
}

func (p *pagedOperatorServer) fails(token string) error {
	if p.failOn != "" && token == p.failOn {
		return status.Error(codes.Unavailable, "daemon down")
	}
	return nil
}

func (p *pagedOperatorServer) ListPendingTenantProvisioning(_ context.Context, req *operatorv1.ListPendingTenantProvisioningRequest) (*operatorv1.ListPendingTenantProvisioningResponse, error) {
	if err := p.fails(req.GetPageToken()); err != nil {
		return nil, err
	}
	start, end, next := p.window(req.GetPageToken(), req.GetPageSize())
	resp := &operatorv1.ListPendingTenantProvisioningResponse{NextPageToken: next}
	for i := start; i < end; i++ {
		resp.Pending = append(resp.Pending, &operatorv1.PendingTenant{TenantId: fmt.Sprintf("t%d", i)})
	}
	return resp, nil
}

func (p *pagedOperatorServer) ListPendingTenantOps(_ context.Context, req *operatorv1.ListPendingTenantOpsRequest) (*operatorv1.ListPendingTenantOpsResponse, error) {
	if err := p.fails(req.GetPageToken()); err != nil {
		return nil, err
	}
	start, end, next := p.window(req.GetPageToken(), req.GetPageSize())
	resp := &operatorv1.ListPendingTenantOpsResponse{NextPageToken: next}
	for i := start; i < end; i++ {
		resp.Ops = append(resp.Ops, &operatorv1.TenantOp{OpId: fmt.Sprintf("op%d", i)})
	}
	return resp, nil
}

func (p *pagedOperatorServer) ListDesiredCatalogPlugins(_ context.Context, req *operatorv1.ListDesiredCatalogPluginsRequest) (*operatorv1.ListDesiredCatalogPluginsResponse, error) {
	if err := p.fails(req.GetPageToken()); err != nil {
		return nil, err
	}
	start, end, next := p.window(req.GetPageToken(), req.GetPageSize())
	resp := &operatorv1.ListDesiredCatalogPluginsResponse{NextPageToken: next}
	for i := start; i < end; i++ {
		resp.Plugins = append(resp.Plugins, &operatorv1.DesiredCatalogPlugin{TenantId: fmt.Sprintf("t%d", i), PluginId: "github"})
	}
	return resp, nil
}

// Each list call walks every page, so a reconcile sees every item.
func TestOperatorLists_WalkEveryPage(t *testing.T) {
	ctx := context.Background()

	srv := &pagedOperatorServer{n: 5}
	c := bufconnClient(t, srv)
	pending, err := c.ListPendingTenantProvisioning(ctx)
	if err != nil || len(pending) != 5 || pending[4].TenantID != "t4" {
		t.Fatalf("ListPendingTenantProvisioning = %v, %v", pending, err)
	}
	if len(srv.tokens) != 3 || srv.tokens[1] != "2" || srv.tokens[2] != "4" {
		t.Errorf("page tokens = %q, want 3 pages", srv.tokens)
	}
	if srv.sizes[0] != pagetoken.MaxSize {
		t.Errorf("page_size = %d, want %d", srv.sizes[0], pagetoken.MaxSize)
	}

	srv = &pagedOperatorServer{n: 5}
	c = bufconnClient(t, srv)
	ops, err := c.ListPendingTenantOps(ctx)
	if err != nil || len(ops) != 5 || ops[4].OpID != "op4" {
		t.Fatalf("ListPendingTenantOps = %v, %v", ops, err)
	}
	if len(srv.tokens) != 3 {
		t.Errorf("ops: %d pages, want 3", len(srv.tokens))
	}

	srv = &pagedOperatorServer{n: 5}
	c = bufconnClient(t, srv)
	plugins, err := c.ListDesiredCatalogPlugins(ctx)
	if err != nil || len(plugins) != 5 || plugins[4].TenantID != "t4" {
		t.Fatalf("ListDesiredCatalogPlugins = %v, %v", plugins, err)
	}
	if len(srv.tokens) != 3 {
		t.Errorf("plugins: %d pages, want 3", len(srv.tokens))
	}
}

// A list that does not end is an error, never a part of the list.
func TestOperatorLists_BoundHitIsAnError(t *testing.T) {
	ctx := context.Background()
	c := bufconnClient(t, &pagedOperatorServer{n: 4, endless: true})
	if got, err := c.ListPendingTenantProvisioning(ctx); !errors.Is(err, pagetoken.ErrTooManyPages) || got != nil {
		t.Errorf("provisioning: %v, %v", got, err)
	}
	if got, err := c.ListPendingTenantOps(ctx); !errors.Is(err, pagetoken.ErrTooManyPages) || got != nil {
		t.Errorf("ops: %v, %v", got, err)
	}
	if got, err := c.ListDesiredCatalogPlugins(ctx); !errors.Is(err, pagetoken.ErrTooManyPages) || got != nil {
		t.Errorf("plugins: %v, %v", got, err)
	}
}

// An error on the first page or on a later page fails the whole list. The
// client never returns the pages that it read.
func TestOperatorLists_PageErrorFailsTheList(t *testing.T) {
	ctx := context.Background()
	for name, svc := range map[string]*failingFirstPage{
		"first page": {pagedOperatorServer: &pagedOperatorServer{n: 5}, first: true},
		"page 2":     {pagedOperatorServer: &pagedOperatorServer{n: 5, failOn: "2"}},
	} {
		c := bufconnClient(t, svc)
		if got, err := c.ListPendingTenantProvisioning(ctx); err == nil || got != nil {
			t.Errorf("%s, provisioning: %v, %v", name, got, err)
		}
		if got, err := c.ListPendingTenantOps(ctx); err == nil || got != nil {
			t.Errorf("%s, ops: %v, %v", name, got, err)
		}
		if got, err := c.ListDesiredCatalogPlugins(ctx); err == nil || got != nil {
			t.Errorf("%s, plugins: %v, %v", name, got, err)
		}
	}
}

// failingFirstPage fails the first page of each list when first is set.
type failingFirstPage struct {
	*pagedOperatorServer
	first bool
}

func (f *failingFirstPage) ListPendingTenantProvisioning(ctx context.Context, req *operatorv1.ListPendingTenantProvisioningRequest) (*operatorv1.ListPendingTenantProvisioningResponse, error) {
	if f.first {
		return nil, status.Error(codes.Unavailable, "daemon down")
	}
	return f.pagedOperatorServer.ListPendingTenantProvisioning(ctx, req)
}

func (f *failingFirstPage) ListPendingTenantOps(ctx context.Context, req *operatorv1.ListPendingTenantOpsRequest) (*operatorv1.ListPendingTenantOpsResponse, error) {
	if f.first {
		return nil, status.Error(codes.Unavailable, "daemon down")
	}
	return f.pagedOperatorServer.ListPendingTenantOps(ctx, req)
}

func (f *failingFirstPage) ListDesiredCatalogPlugins(ctx context.Context, req *operatorv1.ListDesiredCatalogPluginsRequest) (*operatorv1.ListDesiredCatalogPluginsResponse, error) {
	if f.first {
		return nil, status.Error(codes.Unavailable, "daemon down")
	}
	return f.pagedOperatorServer.ListDesiredCatalogPlugins(ctx, req)
}
