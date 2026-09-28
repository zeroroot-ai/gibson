// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

// agent_by_principal_test.go covers AgentByPrincipal on the store and
// LookupEnrolledAgent on the service: the read that turns the verified
// principal on a submitted finding into the registered agent name and the
// enrolling person (gibson#208).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var agentColumns = []string{
	"id", "host_id", "tenant_id", "user_id", "name", "mode",
	"public_key_jwk", "status", "session_ttl_s", "max_lifetime_s",
	"last_active_at", "expires_at", "principal_ref", "created_at",
}

func enrolledAgentRow(id, name, userID, principal string) *sqlmock.Rows {
	return sqlmock.NewRows(agentColumns).AddRow(
		id, "host-1", "acme", userID, name, "autonomous",
		[]byte(`{}`), "active", 3600, 86400,
		nil, nil, principal, time.Now(),
	)
}

func TestStore_AgentByPrincipal(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the active agent enrolled under the principal", func(t *testing.T) {
		store, mock, rec := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_agents").
			WillReturnRows(enrolledAgentRow("agt_1", "zerocool-demo", "user-9", "agent_principal:sa-1"))

		ag, err := store.AgentByPrincipal(ctx, "acme", "agent_principal:sa-1")
		require.NoError(t, err)
		require.NotNil(t, ag)
		assert.Equal(t, "zerocool-demo", ag.Name)
		assert.Equal(t, "user-9", ag.UserID)

		sql := normaliseSQL(rec.all())
		assert.Contains(t, sql, "tenant_id = $1", "the read must be tenant-scoped")
		assert.Contains(t, sql, "principal_ref = $2")
		assert.Contains(t, sql, "status = 'active'", "a revoked agent must not name a finding")
		assert.Contains(t, sql, "ORDER BY a.created_at DESC LIMIT 1")
	})

	t.Run("returns nil when the principal has no active agent", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_agents").
			WillReturnRows(sqlmock.NewRows(agentColumns))

		ag, err := store.AgentByPrincipal(ctx, "acme", "agent_principal:sa-1")
		require.NoError(t, err)
		assert.Nil(t, ag)
	})

	t.Run("input guards", func(t *testing.T) {
		store, _, _ := newMockedStore(t)
		_, err := store.AgentByPrincipal(ctx, "", "agent_principal:sa-1")
		require.ErrorContains(t, err, "tenant is required")
		_, err = store.AgentByPrincipal(ctx, "acme", "")
		require.ErrorContains(t, err, "principal_ref is required")
	})

	t.Run("a store failure is an error", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_agents").WillReturnError(errors.New("boom"))

		_, err := store.AgentByPrincipal(ctx, "acme", "agent_principal:sa-1")
		require.ErrorContains(t, err, "boom")
	})
}

func TestService_LookupEnrolledAgent(t *testing.T) {
	ctx := context.Background()

	t.Run("names the agent and the enroller", func(t *testing.T) {
		m := newMockedService(t)
		m.mock.ExpectQuery("FROM   capability_grant_agents").
			WillReturnRows(enrolledAgentRow("agt_1", "zerocool-demo", "user-9", "agent_principal:sa-1"))

		name, enrolledBy, err := m.svc.LookupEnrolledAgent(ctx, "acme", "agent_principal:sa-1")
		require.NoError(t, err)
		assert.Equal(t, "zerocool-demo", name)
		assert.Equal(t, "user-9", enrolledBy)
	})

	t.Run("an unknown principal answers empty", func(t *testing.T) {
		m := newMockedService(t)
		m.mock.ExpectQuery("FROM   capability_grant_agents").
			WillReturnRows(sqlmock.NewRows(agentColumns))

		name, enrolledBy, err := m.svc.LookupEnrolledAgent(ctx, "acme", "agent_principal:nobody")
		require.NoError(t, err)
		assert.Empty(t, name)
		assert.Empty(t, enrolledBy)
	})

	t.Run("an empty principal or tenant never queries", func(t *testing.T) {
		m := newMockedService(t)
		name, enrolledBy, err := m.svc.LookupEnrolledAgent(ctx, "", "agent_principal:sa-1")
		require.NoError(t, err)
		assert.Empty(t, name+enrolledBy)
		name, enrolledBy, err = m.svc.LookupEnrolledAgent(ctx, "acme", "")
		require.NoError(t, err)
		assert.Empty(t, name+enrolledBy)
		require.NoError(t, m.mock.ExpectationsWereMet())
	})
}
