// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/compliance"
	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func complianceTestPack() ontology.DomainPack {
	return ontology.DomainPack{
		Name: "fw", Version: 2,
		Controls: []ontology.Control{
			{ID: "ac-2", Title: "Account Management", Family: "ac", FamilyTitle: "Access Control"},
			{ID: "ac-6", Title: "Least Privilege", Family: "ac", FamilyTitle: "Access Control"},
			{ID: "au-9", Title: "Protection of Audit Information", Family: "au", FamilyTitle: "Audit"},
		},
		MappingRules: []ontology.MappingRule{
			{ControlID: "ac-2", Expression: `event.action == "never"`},
			{ControlID: "ac-6", Expression: `event.action == "agent_grant_added"`},
		},
	}
}

// newComplianceService returns the service over a sqlmock audit_log, and a
// brain registry in which the tenant "acme" enabled the pack "fw".
func newComplianceService(t *testing.T) (*ComplianceService, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	reg := brain.NewRegistry(context.Background(), braintest.StoreFactory(), brain.BeliefSystem)
	reg.For("acme").Submit(brain.DomainPackEnabled{Name: "fw", Version: 2})
	require.Eventually(t, func() bool { return len(reg.For("acme").DomainPacks()) == 1 }, 5*time.Second, 10*time.Millisecond)
	reader, err := compliance.NewReader(db, ontology.NewDomainPackCatalog(complianceTestPack()), BrainEnabledPacks{Registry: reg})
	require.NoError(t, err)
	return NewComplianceService(reader), mock
}

func TestListComplianceEvidence_MapsTheReport(t *testing.T) {
	s, mock := newComplianceService(t)
	at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery("FROM   audit_log").WillReturnRows(sqlmock.NewRows(
		[]string{"id", "action", "target_type", "target_id", "decision", "actor_id", "actor_type", "created_at"}).
		AddRow(int64(7), "agent_grant_added", "agent_grant", "agent_principal:a", "allow", "user-1", "user", at))

	resp, err := s.ListComplianceEvidence(tenantCtx("acme"), &tenantv1.ListComplianceEvidenceRequest{
		Pack:      "fw",
		StartTime: timestamppb.New(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)),
		EndTime:   timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)),
	})
	require.NoError(t, err)
	assert.Equal(t, "fw", resp.GetPack())
	assert.Equal(t, int32(2), resp.GetPackVersion())
	assert.Equal(t, int32(2), resp.GetControlsWithRule())
	assert.Equal(t, int32(3), resp.GetControlsTotal())
	require.Len(t, resp.GetControls(), 3)
	assert.Equal(t, tenantv1.ControlEvidence_STATE_NO_EVENTS, resp.GetControls()[0].GetState())
	assert.Nil(t, resp.GetControls()[0].GetLastEventTime())
	assert.Equal(t, tenantv1.ControlEvidence_STATE_HAS_EVIDENCE, resp.GetControls()[1].GetState())
	assert.Equal(t, int64(1), resp.GetControls()[1].GetEventCount())
	assert.Equal(t, at, resp.GetControls()[1].GetLastEventTime().AsTime())
	assert.Equal(t, tenantv1.ControlEvidence_STATE_NO_RULE, resp.GetControls()[2].GetState())
	require.Len(t, resp.GetEvents(), 1)
	assert.Equal(t, "7", resp.GetEvents()[0].GetAuditRecordId())
	assert.Equal(t, []string{"ac-6"}, resp.GetEvents()[0].GetControlIds())
	assert.Empty(t, resp.GetNextPageToken())
}

func TestListComplianceEvidence_Errors(t *testing.T) {
	s, _ := newComplianceService(t)
	cases := map[string]struct {
		ctx  context.Context
		req  *tenantv1.ListComplianceEvidenceRequest
		want codes.Code
	}{
		"no tenant":   {context.Background(), &tenantv1.ListComplianceEvidenceRequest{Pack: "fw"}, codes.PermissionDenied},
		"no pack":     {tenantCtx("acme"), &tenantv1.ListComplianceEvidenceRequest{}, codes.InvalidArgument},
		"unknown":     {tenantCtx("acme"), &tenantv1.ListComplianceEvidenceRequest{Pack: "other"}, codes.NotFound},
		"not enabled": {tenantCtx("beta"), &tenantv1.ListComplianceEvidenceRequest{Pack: "fw"}, codes.FailedPrecondition},
		"bad token":   {tenantCtx("acme"), &tenantv1.ListComplianceEvidenceRequest{Pack: "fw", PageToken: "!!"}, codes.InvalidArgument},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.ListComplianceEvidence(tc.ctx, tc.req)
			assert.Equal(t, tc.want, grpcCode(err))
		})
	}
}

func TestControlStates_CoverEachState(t *testing.T) {
	for _, st := range []compliance.State{compliance.StateNoRule, compliance.StateNoEvents, compliance.StateHasEvidence} {
		assert.NotEqual(t, tenantv1.ControlEvidence_STATE_UNSPECIFIED, controlStates[st], "state %d", st)
	}
}

// TestListComplianceEvidence_AuthzEntry pins the authorization of the RPC:
// the admin relation on the tenant of the identity. Owner and Admin hold
// admin, and Writer and Member do not (TestModel_TenantRoleHierarchy proves
// the hierarchy on a real OpenFGA server).
func TestListComplianceEvidence_AuthzEntry(t *testing.T) {
	e, ok := registry.Registry["/gibson.tenant.v1.ComplianceService/ListComplianceEvidence"]
	require.True(t, ok, "the RPC must have an entry in the authz registry")
	assert.Equal(t, "admin", e.Relation)
	assert.Equal(t, "tenant", e.ObjectType)
	assert.Equal(t, "tenant_from_identity", e.ObjectDeriver)
	assert.False(t, e.Unauthenticated)
}
