// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func resolveUsersServer(az authzIface, idpC idp.AdminClient) *DaemonServer {
	return &DaemonServer{logger: slog.Default(), authorizer: az, idpAdminClient: idpC}
}

// A member resolves to a name. A person who left the tenant, and an id that
// never belonged to it, both resolve to REMOVED with no name, so the
// dashboard shows "removed user" and nothing leaks across tenants.
func TestResolveUsers_MemberAndRemoved(t *testing.T) {
	az := newFakeAuthorizer().
		allow("user:caller", "member", "tenant:acme").
		allow("user:alice", "member", "tenant:acme").
		allow("user:mallory", "member", "tenant:other")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profiles: map[string]*idp.UserProfile{
		"alice":   {AccountID: "alice", DisplayName: "Alice Ng", Email: "alice@example.com"},
		"mallory": {AccountID: "mallory", DisplayName: "Mallory", Email: "mallory@other.example"},
	}}
	srv := resolveUsersServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")

	resp, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: []string{"alice", "gone", "alice", "", "mallory"}})
	if err != nil {
		t.Fatalf("ResolveUsers: %v", err)
	}
	want := []struct {
		id    string
		state tenantv1.UserRefState
		name  string
	}{
		{"alice", tenantv1.UserRefState_USER_REF_STATE_MEMBER, "Alice Ng"},
		{"gone", tenantv1.UserRefState_USER_REF_STATE_REMOVED, ""},
		{"mallory", tenantv1.UserRefState_USER_REF_STATE_REMOVED, ""},
	}
	if len(resp.GetUsers()) != len(want) {
		t.Fatalf("got %d refs, want %d (distinct, in request order): %v", len(resp.GetUsers()), len(want), resp.GetUsers())
	}
	for i, w := range want {
		got := resp.GetUsers()[i]
		if got.GetUserId() != w.id || got.GetState() != w.state || got.GetDisplayName() != w.name {
			t.Errorf("ref %d: got %s/%v/%q, want %s/%v/%q", i, got.GetUserId(), got.GetState(), got.GetDisplayName(), w.id, w.state, w.name)
		}
	}
	if resp.GetUsers()[2].GetEmail() != "" {
		t.Fatalf("a user of another tenant must not leak an address, got %q", resp.GetUsers()[2].GetEmail())
	}
}

// A member the identity provider no longer knows keeps MEMBER with an empty
// name: the caller still sees the id, and no error hides the rest of the page.
func TestResolveUsers_MemberUnknownToIdP(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	srv := resolveUsersServer(az, &fakeIDPClient{}) // GetUserProfile answers idp.ErrNotFound
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")

	resp, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: []string{"bob"}})
	if err != nil {
		t.Fatalf("ResolveUsers: %v", err)
	}
	ref := resp.GetUsers()[0]
	if ref.GetState() != tenantv1.UserRefState_USER_REF_STATE_MEMBER || ref.GetDisplayName() != "" {
		t.Fatalf("got %v/%q, want MEMBER with an empty name", ref.GetState(), ref.GetDisplayName())
	}
}

// An identity provider outage is Unavailable, never a silent "removed user".
func TestResolveUsers_IdPOutageIsUnavailable(t *testing.T) {
	az := newFakeAuthorizer().allow("user:bob", "member", "tenant:acme")
	idpC := &mfaResetTestIDP{fakeIDPClient: &fakeIDPClient{}, profileErr: errors.New("zitadel: dial tcp: connection refused")}
	srv := resolveUsersServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")

	_, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: []string{"bob"}})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}

func TestResolveUsers_Limits(t *testing.T) {
	srv := resolveUsersServer(newFakeAuthorizer(), &fakeIDPClient{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")

	if _, err := srv.ResolveUsers(context.Background(), &tenantv1.ResolveUsersRequest{UserIds: []string{"a"}}); status_grpc.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: got %v, want Unauthenticated", err)
	}
	resp, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{})
	if err != nil || len(resp.GetUsers()) != 0 {
		t.Fatalf("empty request: got %v / %d refs, want none", err, len(resp.GetUsers()))
	}
	ids := make([]string, maxResolveUsers+1)
	for i := range ids {
		ids[i] = "u" + strconv.Itoa(i)
	}
	if _, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: ids}); status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("over the limit: got %v, want InvalidArgument", err)
	}
	unconfigured := &DaemonServer{logger: slog.Default()}
	if _, err := unconfigured.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: []string{"a"}}); status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("unconfigured: got %v, want Unavailable", err)
	}
}

// batchFailAuthorizer answers BatchCheck with a scripted error or a short
// result, the two ways an authorizer can fail the membership check.
type batchFailAuthorizer struct {
	authzIface
	err   error
	short bool
}

func (a *batchFailAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if a.err != nil {
		return nil, a.err
	}
	if a.short {
		return make([]bool, len(checks)-1), nil
	}
	return make([]bool, len(checks)), nil
}

// A failed membership check is Unavailable: the caller must never read a
// missing answer as "removed user".
func TestResolveUsers_MembershipCheckFailureIsUnavailable(t *testing.T) {
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")
	for name, az := range map[string]authzIface{
		"error": &batchFailAuthorizer{authzIface: newFakeAuthorizer(), err: errors.New("fga: unavailable")},
		"short": &batchFailAuthorizer{authzIface: newFakeAuthorizer(), short: true},
	} {
		srv := resolveUsersServer(az, &fakeIDPClient{})
		_, err := srv.ResolveUsers(ctx, &tenantv1.ResolveUsersRequest{UserIds: []string{"a", "b"}})
		if status_grpc.Code(err) != codes.Unavailable {
			t.Fatalf("%s: got %v, want Unavailable", name, err)
		}
	}
}
