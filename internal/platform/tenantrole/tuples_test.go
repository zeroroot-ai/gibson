// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// baseAuthorizer implements every authz.Authorizer method with a value no
// test in this file exercises — every case here cares only about ReadTuples
// / WriteAndDelete (or their absence).
type baseAuthorizer struct{}

func (baseAuthorizer) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (baseAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (baseAuthorizer) Write(context.Context, []authz.Tuple) error  { return nil }
func (baseAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (baseAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) ListUsers(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
func (baseAuthorizer) StoreID() string { return "" }
func (baseAuthorizer) ModelID() string { return "" }
func (baseAuthorizer) Close() error    { return nil }

// authorizerNoExtras is an Authorizer with neither TupleReader nor
// AtomicWriter — AuthzTuples must refuse it.
type authorizerNoExtras struct{ baseAuthorizer }

// authorizerReaderOnly has TupleReader but not AtomicWriter — still refused.
type authorizerReaderOnly struct {
	baseAuthorizer
	tuples []authz.Tuple
	err    error
}

func (a *authorizerReaderOnly) ReadTuples(context.Context, string, string, string) ([]authz.Tuple, error) {
	return a.tuples, a.err
}

// fakeFullAuthorizer implements both TupleReader and AtomicWriter, with the
// call recorded for assertions.
type fakeFullAuthorizer struct {
	baseAuthorizer
	tuples  []authz.Tuple
	readErr error

	writeErr        error
	lastWrites      []authz.Tuple
	lastDeletes     []authz.Tuple
	writeAndDeleteN int
}

func (a *fakeFullAuthorizer) ReadTuples(_ context.Context, _, _, _ string) ([]authz.Tuple, error) {
	if a.readErr != nil {
		return nil, a.readErr
	}
	return a.tuples, nil
}

func (a *fakeFullAuthorizer) WriteAndDelete(_ context.Context, writes, deletes []authz.Tuple) error {
	a.writeAndDeleteN++
	a.lastWrites = writes
	a.lastDeletes = deletes
	return a.writeErr
}

func TestAuthzTuples_RefusesAnAuthorizerWithNeitherExtension(t *testing.T) {
	_, err := tenantrole.AuthzTuples(authorizerNoExtras{})
	if err == nil || !strings.Contains(err.Error(), "TupleReader") {
		t.Fatalf("AuthzTuples(no extras): err = %v, want a TupleReader error", err)
	}
}

func TestAuthzTuples_RefusesAnAuthorizerWithOnlyTupleReader(t *testing.T) {
	_, err := tenantrole.AuthzTuples(&authorizerReaderOnly{})
	if err == nil || !strings.Contains(err.Error(), "AtomicWriter") {
		t.Fatalf("AuthzTuples(reader only): err = %v, want an AtomicWriter error", err)
	}
}

func TestAuthzTuples_AcceptsAnAuthorizerWithBothExtensions(t *testing.T) {
	tuples, err := tenantrole.AuthzTuples(&fakeFullAuthorizer{})
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	if tuples == nil {
		t.Fatal("AuthzTuples returned a nil Tuples with no error")
	}
}

func TestAuthzTuples_ReadRolesFiltersToRoleRelationsZitadelUsersAndRequestedIDs(t *testing.T) {
	fa := &fakeFullAuthorizer{tuples: []authz.Tuple{
		{User: "user:111111111111111111", Relation: "owner", Object: "tenant:acme"},               // kept (in role set, real user, requested)
		{User: "user:222222222222222222", Relation: "admin", Object: "tenant:acme"},               // dropped: not requested
		{User: "user:111111111111111111", Relation: "tenant_enabled", Object: "tenant:acme"},      // dropped: not a role relation
		{User: "agent_principal:x", Relation: "member", Object: "tenant:acme"},                    // dropped: not a Zitadel user subject
		{User: "user:zeroroot.ai/platform/e2e-runner", Relation: "member", Object: "tenant:acme"}, // dropped: SPIFFE-shaped
		{User: "user:bob-id", Relation: "member", Object: "tenant:acme"},                          // dropped: human-readable, not numeric
	}}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}

	got, err := tuples.ReadRoles(context.Background(), "acme", []string{"111111111111111111"})
	if err != nil {
		t.Fatalf("ReadRoles: %v", err)
	}
	if len(got) != 1 || got[0].User != "user:111111111111111111" || got[0].Relation != "owner" {
		t.Fatalf("ReadRoles = %+v, want exactly [user:111111111111111111 owner tenant:acme]", got)
	}
}

func TestAuthzTuples_ReadRolesWithNoRequestedUsersReturnsEveryRoleTuple(t *testing.T) {
	fa := &fakeFullAuthorizer{tuples: []authz.Tuple{
		{User: "user:111111111111111111", Relation: "owner", Object: "tenant:acme"},
		{User: "user:222222222222222222", Relation: "admin", Object: "tenant:acme"},
	}}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}

	got, err := tuples.ReadRoles(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("ReadRoles: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ReadRoles with no user filter = %+v, want both tuples", got)
	}
}

func TestAuthzTuples_ReadRolesWrapsAReaderError(t *testing.T) {
	fa := &fakeFullAuthorizer{readErr: errors.New("boom")}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	if _, err := tuples.ReadRoles(context.Background(), "acme", nil); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("ReadRoles error = %v, want it to wrap the reader's error", err)
	}
}

func TestAuthzTuples_WriteAndDeletePassesBothListsThrough(t *testing.T) {
	fa := &fakeFullAuthorizer{}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}

	writes := []tenantrole.Tuple{{User: "user:alice", Relation: "owner", Object: "tenant:acme"}}
	deletes := []tenantrole.Tuple{{User: "user:bob", Relation: "admin", Object: "tenant:acme"}}
	if err := tuples.WriteAndDelete(context.Background(), writes, deletes); err != nil {
		t.Fatalf("WriteAndDelete: %v", err)
	}
	if fa.writeAndDeleteN != 1 {
		t.Fatalf("writeAndDeleteN = %d, want 1", fa.writeAndDeleteN)
	}
	if len(fa.lastWrites) != 1 || fa.lastWrites[0].User != "user:alice" {
		t.Fatalf("lastWrites = %+v, want the one write tuple translated through", fa.lastWrites)
	}
	if len(fa.lastDeletes) != 1 || fa.lastDeletes[0].User != "user:bob" {
		t.Fatalf("lastDeletes = %+v, want the one delete tuple translated through", fa.lastDeletes)
	}
}

func TestAuthzTuples_WriteAndDeleteWithNoTuplesSendsNilSlices(t *testing.T) {
	fa := &fakeFullAuthorizer{}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	if err := tuples.WriteAndDelete(context.Background(), nil, nil); err != nil {
		t.Fatalf("WriteAndDelete: %v", err)
	}
	if fa.lastWrites != nil || fa.lastDeletes != nil {
		t.Fatalf("lastWrites=%v lastDeletes=%v, want both nil for an empty call", fa.lastWrites, fa.lastDeletes)
	}
}

func TestAuthzTuples_WriteAndDeleteWrapsAWriterError(t *testing.T) {
	fa := &fakeFullAuthorizer{writeErr: errors.New("kaboom")}
	tuples, err := tenantrole.AuthzTuples(fa)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	err = tuples.WriteAndDelete(context.Background(), []tenantrole.Tuple{{User: "user:a", Relation: "owner", Object: "tenant:acme"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "kaboom") {
		t.Fatalf("WriteAndDelete error = %v, want it to wrap the writer's error", err)
	}
}
