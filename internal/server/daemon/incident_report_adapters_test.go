// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

var auditColumns = []string{
	"id", "tenant_id", "actor_id", "actor_type", "action", "target_type", "target_id", "decision", "metadata", "created_at",
}

func TestAuditGrantChanges_ReadsTheRecordsOfOnePrincipalInOneTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	until := time.Unix(1700000500, 0)
	meta := []byte(`{"object":"component:connector/okta-response","relation":"can_execute"}`)

	// The added records: one row. The removed records: none.
	mock.ExpectQuery("SELECT COUNT").WithArgs("acme", "agent_grant_added", "agent_principal:p1", until).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("FROM   audit_log").WithArgs("acme", "agent_grant_added", "agent_principal:p1", until, auditPageSize, 0).
		WillReturnRows(sqlmock.NewRows(auditColumns).AddRow(
			"a1", "acme", "user-admin", "user", "agent_grant_added", "agent_grant", "agent_principal:p1", "allow", meta,
			time.Unix(1700000100, 0)))
	mock.ExpectQuery("SELECT COUNT").WithArgs("acme", "agent_grant_removed", "agent_principal:p1", until).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	got, err := auditGrantChanges{q: audit.NewQuery(db)}.GrantChanges(context.Background(), "acme", "agent_principal:p1", until)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "user-admin", got[0].ActorID, "the actor of the record is the grantor")
	require.NoError(t, mock.ExpectationsWereMet(), "each read names the tenant and the principal")
}

func TestAuditGrantChanges_AReadThatFailsIsAnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("SELECT COUNT").WillReturnError(errors.New("db down"))

	_, err = auditGrantChanges{q: audit.NewQuery(db)}.GrantChanges(context.Background(), "acme", "p", time.Now())

	require.ErrorContains(t, err, "db down")
}

// A principal with more records than the bound is an error, because a record
// that is left out could name the wrong grantor.
func TestAuditGrantChanges_MoreRecordsThanTheBoundIsAnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	for range auditMaxPages {
		mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(auditMaxPages * auditPageSize * 2))
		mock.ExpectQuery("FROM   audit_log").WillReturnRows(sqlmock.NewRows(auditColumns))
	}

	_, err = auditGrantChanges{q: audit.NewQuery(db)}.GrantChanges(context.Background(), "acme", "p", time.Now())

	require.ErrorContains(t, err, "more than")
}

func TestRegisterIncidentReport_WiresTheGrantorRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	d := &daemonImpl{
		logger: testObsLogger(), platformDB: db,
		brainRegistry: brain.NewRegistry(ctx, braintest.StoreFactory()),
	}

	require.NoError(t, d.registerIncidentReport(ctx, grpc.NewServer()))
}
