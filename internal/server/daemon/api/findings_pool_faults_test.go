// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// failingPool is a data-plane pool that cannot give a connection. Each other
// method of the interface is left unset, so a test that reaches one fails loud.
type failingPool struct {
	datapool.Pool
	err error
}

func (p failingPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) { return nil, p.err }

func serverWithPool(p datapool.Pool) *DaemonServer {
	return &DaemonServer{poolGetter: func() datapool.Pool { return p }}
}

func tenantContext(tenant string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "u1", Tenant: auth.MustNewTenantID(tenant)})
}

// A pool error keeps its class: a data plane that is not ready is a failed
// precondition, an evicted pool is a retry, and any other error is internal.
func poolErrorCases() map[string]struct {
	err  error
	want codes.Code
} {
	return map[string]struct {
		err  error
		want codes.Code
	}{
		"not provisioned": {&datapool.NotProvisionedError{Tenant: "acme", Reason: "no data plane"}, codes.FailedPrecondition},
		"evicted":         {&datapool.EvictedError{Tenant: "acme"}, codes.Unavailable},
		"other":           {errors.New("the connection broke"), codes.Internal},
	}
}

func TestExportFindings_PoolFailuresKeepTheirClass(t *testing.T) {
	for name, tt := range poolErrorCases() {
		for _, withEvidence := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				srv := serverWithPool(failingPool{err: tt.err})
				_, err := srv.ExportFindings(tenantContext("acme"), &tenantv1.ExportFindingsRequest{
					IncludeEvidence: withEvidence,
					FindingIds:      []string{"5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e"},
					Filters:         &tenantv1.FindingFilters{Type: []string{"sqli"}, MissionId: "6c5c9f0f-9f9f-4d9f-8f9f-9f9f9f9f9f9f", Search: "x"},
				})
				assert.Equal(t, tt.want, code(err), "error = %v", err)
			})
		}
	}
}

func TestExportFindings_RefusesACallWithNoTenant(t *testing.T) {
	srv := serverWithPool(failingPool{err: errors.New("unused")})
	_, err := srv.ExportFindings(context.Background(), &tenantv1.ExportFindingsRequest{})
	assert.Equal(t, codes.PermissionDenied, code(err))
}

func TestExportFindings_ANilPoolFromTheGetterIsUnavailable(t *testing.T) {
	srv := &DaemonServer{poolGetter: func() datapool.Pool { return nil }}
	_, err := srv.ExportFindings(tenantContext("acme"), &tenantv1.ExportFindingsRequest{})
	assert.Equal(t, codes.Unavailable, code(err))
	_, err = srv.GetFinding(tenantContext("acme"), &tenantv1.GetFindingRequest{FindingId: "x"})
	assert.Equal(t, codes.Unavailable, code(err))
}

func TestGetFinding_Refusals(t *testing.T) {
	srv := serverWithPool(failingPool{err: errors.New("unused")})
	_, err := srv.GetFinding(context.Background(), &tenantv1.GetFindingRequest{FindingId: "x"})
	assert.Equal(t, codes.PermissionDenied, code(err), "no tenant")

	_, err = srv.GetFinding(tenantContext("acme"), &tenantv1.GetFindingRequest{FindingId: "not-a-uuid"})
	assert.Equal(t, codes.InvalidArgument, code(err), "a finding id that is not a UUID")
}

func TestGetFinding_PoolFailuresKeepTheirClass(t *testing.T) {
	for name, tt := range poolErrorCases() {
		t.Run(name, func(t *testing.T) {
			srv := serverWithPool(failingPool{err: tt.err})
			_, err := srv.GetFinding(tenantContext("acme"), &tenantv1.GetFindingRequest{
				FindingId: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e",
			})
			assert.Equal(t, tt.want, code(err), "error = %v", err)
		})
	}
}

func TestFindingFiltersToQuery(t *testing.T) {
	assert.Zero(t, len(tenantv1FindingFiltersToQuery(nil).Severities), "no filters")

	q := tenantv1FindingFiltersToQuery(&tenantv1.FindingFilters{
		Severity: []string{"high", "critical"}, Search: "login", Type: []string{"sqli", "xss"}, MissionId: "m1",
	})
	assert.Equal(t, []string{"high", "critical"}, q.Severities)
	assert.Equal(t, "login", q.Search)
	assert.Equal(t, "sqli", q.Category, "only the first type is used")
	assert.Equal(t, "m1", q.MissionID.String())

	empty := tenantv1FindingFiltersToQuery(&tenantv1.FindingFilters{})
	assert.Empty(t, empty.Category)
	assert.Empty(t, empty.MissionID.String())
}

func TestFindingToRow_HoldsTheDiscoveryTimeAndSerializeFindingsKeepsEachRecord(t *testing.T) {
	created := time.Date(2026, 11, 18, 10, 30, 0, 0, time.FixedZone("x", 3600))
	f := finding.EnhancedFinding{Finding: agent.Finding{
		ID: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e", Title: "T", Severity: agent.SeverityHigh, CreatedAt: created,
	}}
	row := findingToRow(f, false)
	assert.Equal(t, "2026-11-18T09:30:00Z", row.DiscoveredAt, "the time is in UTC")

	for _, format := range []string{"csv", "json", "sarif"} {
		data, err := serializeFindings(format, []finding.EnhancedFinding{f, f}, "acme", false)
		require.NoError(t, err, format)
		assert.Equal(t, 2, strings.Count(string(data), "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e"), format)
	}
}
