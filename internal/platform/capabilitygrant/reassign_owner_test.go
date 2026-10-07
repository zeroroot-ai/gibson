// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

// reassign_owner_test.go covers ReassignOwner: a removal moves the owner user
// of each enrollment row of a principal, inside the tenant (gibson#568).

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ReassignOwner(t *testing.T) {
	ctx := context.Background()

	t.Run("moves the host and agent rows of the principal in one transaction", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectBegin()
		mock.ExpectExec("UPDATE capability_grant_hosts SET user_id").
			WithArgs("acme", "agent_principal:sa-1", "user-2").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("UPDATE capability_grant_agents SET user_id").
			WithArgs("acme", "agent_principal:sa-1", "user-2").
			WillReturnResult(sqlmock.NewResult(0, 2))
		mock.ExpectCommit()

		n, err := store.ReassignOwner(ctx, "acme", "agent_principal:sa-1", "user-2")
		require.NoError(t, err)
		assert.EqualValues(t, 3, n)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("a failed update rolls back", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectBegin()
		mock.ExpectExec("UPDATE capability_grant_hosts SET user_id").WillReturnError(errors.New("boom"))
		mock.ExpectRollback()

		_, err := store.ReassignOwner(ctx, "acme", "agent_principal:sa-1", "user-2")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("refuses an empty tenant, principal or owner", func(t *testing.T) {
		store, _, _ := newMockedStore(t)
		for _, args := range [][3]string{{"", "p", "u"}, {"t", "", "u"}, {"t", "p", ""}} {
			_, err := store.ReassignOwner(ctx, args[0], args[1], args[2])
			require.Error(t, err)
		}
	})
}
