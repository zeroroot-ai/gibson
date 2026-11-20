// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_GrantsByAgentName(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	t.Run("reads the grants of the agent with the owner, inside the tenant", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("capability_grant_agents a ON a.id = g.agent_id").
			WithArgs("acme", "incident-response").
			WillReturnRows(sqlmock.NewRows([]string{"id", "agent_id", "capability_name", "component_ref", "status", "granted_at", "user_id"}).
				AddRow("g1", "a1", "execute:tool:mcp:okta:revoke_user_sessions", "component:mcp:okta:revoke_user_sessions", "active", at, "user-7"))

		got, err := store.GrantsByAgentName(ctx, "acme", "incident-response")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "g1", got[0].ID)
		assert.Equal(t, "user-7", got[0].OwnerUserID)
		assert.Equal(t, at, got[0].GrantedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("refuses an empty tenant and an empty name before it queries", func(t *testing.T) {
		store, _, _ := newMockedStore(t)
		_, err := store.GrantsByAgentName(ctx, "", "incident-response")
		require.Error(t, err)
		_, err = store.GrantsByAgentName(ctx, "acme", "")
		require.Error(t, err)
	})
}
