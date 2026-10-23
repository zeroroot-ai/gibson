// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// TestE2EPeerTenant: the runner's SVID may assert a tenant through the
// identity header; any other SVID, a missing header or a malformed tenant
// yields the zero tenant.
func TestE2EPeerTenant(t *testing.T) {
	md := grpcmetadata.Pairs(auth.HeaderTenant, "acme")
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), md, testTD); got.String() != "acme" {
		t.Fatalf("runner with header: %v", got)
	}
	if got := e2ePeerTenant("spiffe://zeroroot.ai/platform/tenant-operator", md, testTD); got != (auth.TenantID{}) {
		t.Fatalf("another peer must not assert a tenant: %v", got)
	}
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), grpcmetadata.MD{}, testTD); got != (auth.TenantID{}) {
		t.Fatalf("no header: %v", got)
	}
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), grpcmetadata.Pairs(auth.HeaderTenant, "not a tenant!"), testTD); got != (auth.TenantID{}) {
		t.Fatalf("malformed header: %v", got)
	}
}

// TestE2EPeerTenant_TheMemberAssertsATenant: the exit-test member may assert a
// tenant through the identity header, as the runner does (gibson#1257).
func TestE2EPeerTenant_TheMemberAssertsATenant(t *testing.T) {
	md := grpcmetadata.Pairs(auth.HeaderTenant, "acme")
	if got := e2ePeerTenant(e2eMemberSVID(testTD), md, testTD); got.String() != "acme" {
		t.Fatalf("member with header: %v", got)
	}
	if got := e2ePeerTenant(e2eMemberSVID(testTD), grpcmetadata.MD{}, testTD); got != (auth.TenantID{}) {
		t.Fatalf("member without header: %v", got)
	}
}

// TestE2EMemberPolicy_HoldsOnlyExecuteLLM: a member that could call more than
// the one RPC would stop proving what a plain member gets. A second method in
// the policy fails this test.
func TestE2EMemberPolicy_HoldsOnlyExecuteLLM(t *testing.T) {
	methods := e2ePeerMethodPolicies(testTD)[e2eMemberSVID(testTD)]
	if len(methods) != 1 || !methods["/gibson.tenant.v1.ProviderService/ExecuteLLM"] {
		t.Fatalf("the member policy must be exactly ExecuteLLM, got %v", methods)
	}
	if e2eMemberSVID(testTD) == e2eRunnerSVID(testTD) {
		t.Fatal("the member and the runner must be two identities")
	}
}

// TestSeedE2ERunnerTenancy_TheMemberHoldsNoAdminRelation: the seed writes the
// member tuple for the member and never the admin tuple (gibson#1257).
func TestSeedE2ERunnerTenancy_TheMemberHoldsNoAdminRelation(t *testing.T) {
	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
	t.Setenv("GIBSON_PLATFORM_TENANT", "primary")
	fa := &fakeAuthorizer{deny: true}
	seedE2ERunnerTenancy(context.Background(), fa, slog.Default(), testTD)
	memberUser := e2eMemberFGAUser(testTD)
	var relations []string
	for _, tu := range fa.written {
		if tu.User == memberUser {
			relations = append(relations, tu.Relation)
		}
	}
	if len(relations) != 1 || relations[0] != "member" {
		t.Fatalf("the member must hold the member relation only, got %v (all writes: %v)", relations, fa.written)
	}
}
