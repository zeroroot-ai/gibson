// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_GrantByID(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	t.Run("reads the grant with the owner, inside the tenant", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("AND  g.id = $2").
			WithArgs("acme", "g1").
			WillReturnRows(sqlmock.NewRows([]string{"id", "agent_id", "capability_name", "component_ref", "status", "granted_at", "user_id", "principal_ref"}).
				AddRow("g1", "a1", "execute:tool:mcp:okta", "component:connector/okta", "active", at, "user-7", "agent_principal:p1"))
		got, err := store.GrantByID(ctx, "acme", "g1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "g1", got.ID)
		assert.Equal(t, "user-7", got.OwnerUserID)
		assert.Equal(t, "agent_principal:p1", got.PrincipalRef)
		assert.Equal(t, at, got.GrantedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("an id of no grant of the tenant reads nil", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("AND  g.id = $2").WithArgs("acme", "g-other").WillReturnError(sql.ErrNoRows)
		got, err := store.GrantByID(ctx, "acme", "g-other")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("refuses an empty tenant and an empty id before it queries", func(t *testing.T) {
		store, _, _ := newMockedStore(t)
		_, err := store.GrantByID(ctx, "", "g1")
		require.Error(t, err)
		_, err = store.GrantByID(ctx, "acme", "")
		require.Error(t, err)
	})
}

func TestStore_ConnectorGrantID(t *testing.T) {
	ctx := context.Background()

	t.Run("names the active grant of the principal on the connector", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("a.principal_ref = $2").
			WithArgs("acme", "agent_principal:p1", "component:connector/okta", "execute:tool:mcp:okta").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("g9"))
		got, err := store.ConnectorGrantID(ctx, "acme", "agent_principal:p1", "okta")
		require.NoError(t, err)
		assert.Equal(t, "g9", got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no grant row reads empty", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("a.principal_ref = $2").WillReturnError(sql.ErrNoRows)
		got, err := store.ConnectorGrantID(ctx, "acme", "user:alice", "okta")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
