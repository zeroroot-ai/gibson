// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	capabilityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeGrantsReader returns a fixed list, optionally erroring.
type fakeGrantsReader struct {
	grants []GrantInfo
	err    error
}

func (f *fakeGrantsReader) ListActive(_ context.Context, _ auth.TenantID) ([]GrantInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.grants, nil
}

// fixed clock for deterministic near-expiry assertions.
var grantsTestNow = time.Unix(1700000000, 0).UTC()

func newGrantsTestServer(t *testing.T, grants []GrantInfo) (*GrantsAdminServer, *fakeGrantsReader) {
	t.Helper()
	r := &fakeGrantsReader{grants: grants}
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader: r,
		Now:    func() time.Time { return grantsTestNow },
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv, r
}

func TestListActiveGrants_RequiresTenant(t *testing.T) {
	srv, _ := newGrantsTestServer(t, nil)
	_, err := srv.ListActiveGrants(context.Background(), &tenantv1.ListActiveGrantsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestListActiveGrants_FiltersExpired(t *testing.T) {
	grants := []GrantInfo{
		{JTI: "fresh", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "agent"},
		{JTI: "expired", ExpiresAt: grantsTestNow.Add(-time.Minute), RecipientClass: "agent"},
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(resp.GetGrants()) != 1 || resp.GetGrants()[0].GetJti() != "fresh" {
		t.Errorf("expected only fresh grant, got %+v", resp.GetGrants())
	}
}

func TestListActiveGrants_NearExpiryHighlighted(t *testing.T) {
	grants := []GrantInfo{
		{JTI: "near", ExpiresAt: grantsTestNow.Add(2 * time.Minute), RecipientClass: "plugin"},
		{JTI: "far", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "plugin"},
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(resp.GetGrants()) != 2 {
		t.Fatalf("want 2 grants, got %d", len(resp.GetGrants()))
	}
	// Near-expiry grants appear first by sort order.
	if resp.GetGrants()[0].GetJti() != "near" || !resp.GetGrants()[0].GetNearExpiry() {
		t.Errorf("expected near grant first with near_expiry=true, got %+v", resp.GetGrants()[0])
	}
	if resp.GetGrants()[1].GetNearExpiry() {
		t.Errorf("far grant should not be near_expiry")
	}
}

func TestListActiveGrants_FilterByClass(t *testing.T) {
	grants := []GrantInfo{
		{JTI: "a", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "agent"},
		{JTI: "p", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "plugin"},
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{
		RecipientClassFilter: capabilityv1.RecipientClass_RECIPIENT_CLASS_PLUGIN,
	})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(resp.GetGrants()) != 1 || resp.GetGrants()[0].GetJti() != "p" {
		t.Errorf("expected only plugin grant, got %+v", resp.GetGrants())
	}
}

func TestListActiveGrants_FilterByRPC(t *testing.T) {
	grants := []GrantInfo{
		{JTI: "withGet", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "plugin", AllowedRPCs: []string{"GetCredential"}},
		{JTI: "without", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "plugin", AllowedRPCs: []string{"OtherRPC"}},
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{RpcFilter: "GetCredential"})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(resp.GetGrants()) != 1 || resp.GetGrants()[0].GetJti() != "withGet" {
		t.Errorf("expected only the withGet grant, got %+v", resp.GetGrants())
	}
}

func TestListActiveGrants_NearExpiryOnly(t *testing.T) {
	grants := []GrantInfo{
		{JTI: "near", ExpiresAt: grantsTestNow.Add(time.Minute), RecipientClass: "plugin"},
		{JTI: "far", ExpiresAt: grantsTestNow.Add(time.Hour), RecipientClass: "plugin"},
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{IncludeNearExpiryOnly: true})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if len(resp.GetGrants()) != 1 || resp.GetGrants()[0].GetJti() != "near" {
		t.Errorf("expected only the near grant, got %+v", resp.GetGrants())
	}
}

func TestListActiveGrants_Pagination(t *testing.T) {
	grants := make([]GrantInfo, 5)
	for i := range grants {
		grants[i] = GrantInfo{
			JTI:            "g" + string(rune('a'+i)),
			ExpiresAt:      grantsTestNow.Add(time.Hour + time.Duration(i)*time.Second),
			RecipientClass: "plugin",
		}
	}
	srv, _ := newGrantsTestServer(t, grants)
	ctx := ctxWithTenant(t, "acme")

	// Page 1 holds two grants and a next token.
	first, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListActiveGrants: %v", err)
	}
	if first.GetTotal() != 5 || len(first.GetGrants()) != 2 || first.GetNextPageToken() == "" {
		t.Fatalf("page 1: total=%d grants=%d next=%q", first.GetTotal(), len(first.GetGrants()), first.GetNextPageToken())
	}
	// The token walks the rest: 2 more, then the last 1 with no next token.
	second, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	if err != nil {
		t.Fatalf("ListActiveGrants page 2: %v", err)
	}
	if len(second.GetGrants()) != 2 || second.GetGrants()[0].GetJti() == first.GetGrants()[0].GetJti() {
		t.Fatalf("page 2 = %v", second.GetGrants())
	}
	last, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{PageSize: 2, PageToken: second.GetNextPageToken()})
	if err != nil {
		t.Fatalf("ListActiveGrants page 3: %v", err)
	}
	if len(last.GetGrants()) != 1 || last.GetNextPageToken() != "" {
		t.Fatalf("page 3: grants=%d next=%q", len(last.GetGrants()), last.GetNextPageToken())
	}
	// A token this server did not write is refused.
	if _, err := srv.ListActiveGrants(ctx, &tenantv1.ListActiveGrantsRequest{PageToken: "not-a-token"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad token: want InvalidArgument, got %v", err)
	}
}

func TestNewGrantsAdminServer_RequiresReader(t *testing.T) {
	if _, err := NewGrantsAdminServer(GrantsAdminConfig{}); err == nil {
		t.Errorf("want error when Reader missing")
	}
}
