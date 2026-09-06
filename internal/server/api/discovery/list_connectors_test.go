// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package discovery

// list_connectors_test.go — ListConnectors, the fourth component kind
// (ADR-0067, gibson#1551): connector items with rwx computed against
// component:connector/<id>, denying gates, and fail-closed edges.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// stubDiscoveryAuthorizer answers BatchCheck from a canned (user, relation,
// object) map and satisfies the rest of authz.Authorizer with zero values.
type stubDiscoveryAuthorizer struct {
	authz.Authorizer
	allowed map[string]bool // key: user+"|"+relation+"|"+object
	err     error
}

func (a *stubDiscoveryAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if a.err != nil {
		return nil, a.err
	}
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = a.allowed[c.User+"|"+c.Relation+"|"+c.Object]
	}
	return out, nil
}

func (a *stubDiscoveryAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if a.err != nil {
		return false, a.err
	}
	return a.allowed[user+"|"+relation+"|"+object], nil
}

type stubConnectorLister struct {
	ids []string
	err error
}

func (l *stubConnectorLister) ListEnabledConnectors(_ context.Context, _ string) ([]string, error) {
	return l.ids, l.err
}

func discoveryCallerCtx(t *testing.T, subject, tenant string) context.Context {
	t.Helper()
	// One identity carries both fields: auth.WithTenant would OVERWRITE the
	// identity (and its Subject) with a tenant-only one.
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: tid})
}

func TestListConnectors_RwxPerCaller(t *testing.T) {
	az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
		"user:alice|can_read|component:connector/gitlab":    true,
		"user:alice|can_execute|component:connector/gitlab": true,
		// can_configure absent → Write false.
		"user:alice|can_read|component:connector/osv": true,
		// osv execute denied.
		// ghost is enabled but no longer in the embedded catalog: it must
		// stay visible and gateable, falling back to its bare id.
		"user:alice|can_read|component:connector/ghost": true,
	}}
	s := NewServer(az, nil, &stubConnectorLister{ids: []string{"gitlab", "osv", "ghost"}}, nil)

	resp, err := s.ListConnectors(discoveryCallerCtx(t, "alice", "acme"), &discoverypb.ListConnectorsRequest{})
	if err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	if len(resp.GetItems()) != 3 {
		t.Fatalf("items = %d, want 3: %+v", len(resp.GetItems()), resp.GetItems())
	}
	byName := map[string]*discoverypb.CatalogItem{}
	for _, it := range resp.GetItems() {
		byName[it.GetName()] = it
		if it.GetKind() != "connector" {
			t.Errorf("%s: kind = %q, want connector", it.GetName(), it.GetKind())
		}
	}
	g := byName["gitlab"]
	if g == nil || !g.GetRwx().GetRead() || g.GetRwx().GetWrite() || !g.GetRwx().GetExecute() {
		t.Fatalf("gitlab rwx = %+v, want read+execute only", g.GetRwx())
	}
	o := byName["osv"]
	if o == nil || o.GetRwx().GetExecute() {
		t.Fatalf("osv rwx = %+v, want execute denied", o.GetRwx())
	}
	if g.GetDisplayName() == "" {
		t.Error("catalog-backed connector must carry a display name")
	}
	ghost := byName["ghost"]
	if ghost == nil || ghost.GetDisplayName() != "ghost" {
		t.Fatalf("off-catalog connector must fall back to its bare id: %+v", ghost)
	}
}

func TestListConnectors_ActionFilterExcludesDenied(t *testing.T) {
	az := &stubDiscoveryAuthorizer{allowed: map[string]bool{
		"user:alice|can_execute|component:connector/gitlab": true,
	}}
	s := NewServer(az, nil, &stubConnectorLister{ids: []string{"gitlab", "osv"}}, nil)

	resp, err := s.ListConnectors(discoveryCallerCtx(t, "alice", "acme"), &discoverypb.ListConnectorsRequest{
		Query: &discoverypb.ListQuery{Action: discoverypb.Action_ACTION_EXECUTE},
	})
	if err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	if len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != "gitlab" {
		t.Fatalf("execute filter must keep only gitlab: %+v", resp.GetItems())
	}
}

func TestListConnectors_FailClosedEdges(t *testing.T) {
	t.Run("no lister is FailedPrecondition", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{}, nil, nil, nil)
		_, err := s.ListConnectors(discoveryCallerCtx(t, "alice", "acme"), &discoverypb.ListConnectorsRequest{})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
		}
	})

	t.Run("no tenant is PermissionDenied", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{}, nil, &stubConnectorLister{}, nil)
		_, err := s.ListConnectors(context.Background(), &discoverypb.ListConnectorsRequest{})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
		}
	})

	t.Run("lister failure is Internal", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{}, nil,
			&stubConnectorLister{err: errors.New("apiserver down")}, nil)
		_, err := s.ListConnectors(discoveryCallerCtx(t, "alice", "acme"), &discoverypb.ListConnectorsRequest{})
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want Internal", status.Code(err))
		}
	})

	t.Run("authorizer failure excludes the item", func(t *testing.T) {
		s := NewServer(&stubDiscoveryAuthorizer{err: errors.New("fga down")}, nil,
			&stubConnectorLister{ids: []string{"gitlab"}}, nil)
		resp, err := s.ListConnectors(discoveryCallerCtx(t, "alice", "acme"), &discoverypb.ListConnectorsRequest{})
		if err != nil {
			t.Fatalf("ListConnectors: %v", err)
		}
		if len(resp.GetItems()) != 0 {
			t.Fatalf("a failed check must exclude the item, got: %+v", resp.GetItems())
		}
	})
}
