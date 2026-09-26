// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga_test

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// stubTenantRoleFGA is a minimal Client that serves TenantRoleTuples tests
// from an in-memory tuple list, reusing the fakeFGAClient shape but with a
// real Read implementation (fakeFGAClient.Read always answers empty).
type stubTenantRoleFGA struct {
	fakeFGAClient
	stored []fga.Tuple
}

func (s *stubTenantRoleFGA) Read(_ context.Context, filter fga.Tuple) ([]fga.Tuple, error) {
	var out []fga.Tuple
	for _, t := range s.stored {
		if filter.Object != "" && filter.Object != t.Object {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func TestTenantRoleTuples_ReadRolesFiltersToRoleRelationsAndZitadelUserSubjects(t *testing.T) {
	stub := &stubTenantRoleFGA{stored: []fga.Tuple{
		{User: "user:100000000000000001", Relation: "owner", Object: "tenant:acme"},
		{User: "user:100000000000000002", Relation: "writer", Object: "tenant:acme"},
		{User: "agent_principal:e2e-runner", Relation: "member", Object: "tenant:acme"},           // non-user subject
		{User: "user:zeroroot.ai/platform/e2e-runner", Relation: "member", Object: "tenant:acme"}, // gibson#14: user:-typed but not a Zitadel id
		{User: "user:100000000000000003", Relation: "tenant_enabled", Object: "tenant:acme"},      // non-role relation
		{User: "user:100000000000000004", Relation: "owner", Object: "tenant:other"},              // different tenant
	}}
	tt := fga.NewTenantRoleTuples(stub)

	got, err := tt.ReadRoles(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("ReadRoles: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ReadRoles = %+v, want exactly the two role tuples for Zitadel user: subjects on tenant:acme", got)
	}
}

func TestTenantRoleTuples_ReadRolesFiltersByUserIDs(t *testing.T) {
	stub := &stubTenantRoleFGA{stored: []fga.Tuple{
		{User: "user:111", Relation: "owner", Object: "tenant:acme"},
		{User: "user:222", Relation: "writer", Object: "tenant:acme"},
	}}
	tt := fga.NewTenantRoleTuples(stub)

	got, err := tt.ReadRoles(context.Background(), "acme", []string{"222"})
	if err != nil {
		t.Fatalf("ReadRoles: %v", err)
	}
	if len(got) != 1 || got[0].User != "user:222" {
		t.Fatalf("ReadRoles = %+v, want only the 222 tuple", got)
	}
}

func TestTenantRoleTuples_WriteAndDeleteDelegates(t *testing.T) {
	stub := &stubTenantRoleFGA{}
	tt := fga.NewTenantRoleTuples(stub)

	writes := []tenantrole.Tuple{{User: "user:bob", Relation: "owner", Object: "tenant:acme"}}
	deletes := []tenantrole.Tuple{{User: "user:alice", Relation: "owner", Object: "tenant:acme"}}
	if err := tt.WriteAndDelete(context.Background(), writes, deletes); err != nil {
		t.Fatalf("WriteAndDelete: %v", err)
	}
	if len(stub.writes) != 1 || stub.writes[0][0].User != "user:bob" {
		t.Fatalf("writes = %+v", stub.writes)
	}
	if len(stub.deletes) != 1 || stub.deletes[0][0].User != "user:alice" {
		t.Fatalf("deletes = %+v", stub.deletes)
	}
}
