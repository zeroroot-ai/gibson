// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for fgaAuthorizer.ListUsers / ListUsersOfType, in particular the
// subject-type guard: OpenFGA answers a listing whose subject-type filter the
// relation cannot admit with a successful, EMPTY list, which a caller reads as
// "nobody holds this". Both methods therefore refuse such a listing up front,
// from the embedded model.fga, rather than passing the ambiguity on. Uses
// httptest.Server the same way client_conditional_test.go does — no
// testcontainers, no real OpenFGA.
package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// listUsersServer returns an httptest.Server that answers POST .../list-users
// with the given JSON body (an OpenFGA ListUsersResponse) and 200 OK.
func listUsersServer(t *testing.T, responseBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/list-users") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseBody))
	}))
}

// TestListUsers_NonEmptyResult exercises the "found users" branch: ListUsers
// must return the FGA user references and log at Debug (not Warn).
func TestListUsers_NonEmptyResult(t *testing.T) {
	srv := listUsersServer(t, `{"users":[{"object":{"type":"user","id":"alice"}},{"object":{"type":"user","id":"bob"}}]}`)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	users, err := az.ListUsers(context.Background(), "tenant", "tenant:acme", "member")
	if err != nil {
		t.Fatalf("ListUsers: unexpected error: %v", err)
	}
	want := []string{"user:alice", "user:bob"}
	if len(users) != len(want) {
		t.Fatalf("ListUsers: got %v, want %v", users, want)
	}
	for i, w := range want {
		if users[i] != w {
			t.Errorf("ListUsers[%d] = %q, want %q", i, users[i], w)
		}
	}
}

// TestListUsers_EmptyResult exercises the "zero users" branch on a relation
// that CAN hold users: an empty answer is a real answer and must come back as
// an empty slice with no error.
func TestListUsers_EmptyResult(t *testing.T) {
	srv := listUsersServer(t, `{"users":[]}`)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	users, err := az.ListUsers(context.Background(), "tenant", "tenant:acme", "member")
	if err != nil {
		t.Fatalf("ListUsers: unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("ListUsers: got %v, want empty", users)
	}
}

// TestListUsers_RefusesRelationThatCannotHoldUsers is the regression for
// GHSA-9728-chcc-p2v7.
//
// This test previously asserted the bug: it called ListUsers("team", …,
// "parent") — declared [tenant] in model.fga — and required a nil error with
// an empty slice. That is exactly what OpenFGA answers, and exactly what a
// caller cannot act on: a guard asking "does anyone already hold this?" reads
// the empty list as "no" and lets the request through, forever, for every
// input.
//
// The listing must now fail instead. A caller has to handle an error; it does
// not have to disbelieve an empty slice.
func TestListUsers_RefusesRelationThatCannotHoldUsers(t *testing.T) {
	// The server would answer 200 with an empty list. It must never be asked.
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	for _, tc := range []struct{ objectType, object, relation string }{
		// team.parent: [tenant] — the live case; CreateTeam's squat guard.
		{"team", "team:ops", "parent"},
		// secret.can_resolve: [plugin_principal] — structurally user-free by
		// design (spec non-plugin-secret-isolation).
		{"secret", "secret:tenant-acme/cred", "can_resolve"},
		// system_tenant.parent: [tenant] — the catalog fan-out's enumeration.
		{"system_tenant", "system_tenant:_system", "parent"},
	} {
		t.Run(tc.objectType+"."+tc.relation, func(t *testing.T) {
			users, err := az.ListUsers(context.Background(), tc.objectType, tc.object, tc.relation)
			if err == nil {
				t.Fatalf("ListUsers(%s, %s) returned %v with no error; it can never match a user and must say so",
					tc.objectType, tc.relation, users)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want ErrInvalidArgument (the caller named an impossible query, FGA is fine)", err)
			}
			if users != nil {
				t.Errorf("users = %v, want nil — a partial answer invites the same misreading", users)
			}
		})
	}
	if called {
		t.Error("the refused query still reached FGA; it must be rejected before the call")
	}
}

// TestListUsersOfType_RefusesUnreachableSubjectType is the same guard on the
// typed variant. ListUsersOfType's doc used to claim OpenFGA errors on a
// mismatch while ListUsers' doc claimed it returns empty; the two cannot both
// be true, and believing the wrong one is how the guard above shipped.
func TestListUsersOfType_RefusesUnreachableSubjectType(t *testing.T) {
	srv := listUsersServer(t, `{"users":[]}`)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	// tenant.member does hold users and agent principals, but never tenants.
	_, err := az.ListUsersOfType(context.Background(), "tenant", "tenant:acme", "member", "tenant")
	if err == nil {
		t.Fatal("ListUsersOfType accepted a subject type the relation cannot yield")
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("error = %v, want ErrInvalidArgument", err)
	}

	// The typed query the catalog fan-out and CreateTeam actually make must
	// still go through.
	if _, err := az.ListUsersOfType(context.Background(), "team", "team:ops", "parent", "tenant"); err != nil {
		t.Errorf("ListUsersOfType(team.parent, tenant): %v", err)
	}
}

// TestListUsers_AcceptsUsersReachedThroughAUserset guards the other direction:
// the check follows usersets, so a relation declared [team#member] does admit
// "user" (team#member expands to users) and must not be refused. A guard that
// only looked at the literal bracket list would break this caller.
func TestListUsers_AcceptsUsersReachedThroughAUserset(t *testing.T) {
	srv := listUsersServer(t, `{"users":[{"object":{"type":"user","id":"alice"}}]}`)
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	users, err := az.ListUsers(context.Background(), "component", "component:nmap", "team_write_disabled")
	if err != nil {
		t.Fatalf("ListUsers(component.team_write_disabled): %v", err)
	}
	if len(users) != 1 || users[0] != "user:alice" {
		t.Errorf("users = %v, want [user:alice]", users)
	}
}

// TestListUsers_ServerError_MapsToSDKError verifies that a non-2xx FGA
// response flows through mapSDKError, same contract as the sibling
// Write/UpdateConditionalTuple error-mapping tests in
// client_conditional_test.go.
func TestListUsers_ServerError_MapsToSDKError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"internal_error","message":"internal server error"}`))
	}))
	defer srv.Close()

	az := newTestFgaAuthorizer(t, srv.URL)
	_, err := az.ListUsers(context.Background(), "tenant", "tenant:acme", "member")
	if err == nil {
		t.Fatal("ListUsers: expected error from a 500 response, got nil")
	}
}
