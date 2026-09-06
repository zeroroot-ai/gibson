// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

// active_grant_id_test.go covers ActiveGrantID on both the store and the
// service — the query gibson#1358 uses to record which grant authorized a
// component-originated mission (the authorization answer and the attribution
// answer in one call).

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ActiveGrantID(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the grant id when an active grant exists", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_grants").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("grant-123"))

		id, err := store.ActiveGrantID(ctx, "acme", "agent:recon", "mission:originate")
		require.NoError(t, err)
		assert.Equal(t, "grant-123", id)
	})

	t.Run("returns empty when no active grant exists", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		// An empty result set makes QueryRow.Scan return sql.ErrNoRows, which
		// the store maps to "" (denied), not an error.
		mock.ExpectQuery("FROM   capability_grant_grants").
			WillReturnRows(sqlmock.NewRows([]string{"id"}))

		id, err := store.ActiveGrantID(ctx, "acme", "agent:recon", "mission:originate")
		require.NoError(t, err)
		assert.Empty(t, id)
	})

	t.Run("scopes the query to the tenant", func(t *testing.T) {
		store, mock, rec := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_grants").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("g1"))
		_, err := store.ActiveGrantID(ctx, "acme", "agent:recon", "mission:originate")
		require.NoError(t, err)
		assert.Contains(t, normaliseSQL(rec.all()), "tenant_id = $1",
			"ActiveGrantID must be tenant-scoped")
	})

	t.Run("input guards", func(t *testing.T) {
		store, _, _ := newMockedStore(t)
		_, err := store.ActiveGrantID(ctx, "", "p", "c")
		require.ErrorContains(t, err, "tenant is required")
		_, err = store.ActiveGrantID(ctx, "acme", "", "c")
		require.ErrorContains(t, err, "principal_ref is required")
		_, err = store.ActiveGrantID(ctx, "acme", "p", "")
		require.ErrorContains(t, err, "capability_name is required")
	})
}

func TestService_ActiveGrantID(t *testing.T) {
	ctx := context.Background()

	t.Run("empty inputs deny without touching the store", func(t *testing.T) {
		// A nil store proves the guards short-circuit before any query.
		svc := &CapabilityGrantService{logger: slog.New(slog.DiscardHandler)}
		for _, in := range [][3]string{{"", "p", "c"}, {"t", "", "c"}, {"t", "p", ""}} {
			id, err := svc.ActiveGrantID(ctx, in[0], in[1], in[2])
			require.NoError(t, err)
			assert.Empty(t, id)
		}
	})

	t.Run("delegates to the store and returns its id", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_grants").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("grant-abc"))
		svc := &CapabilityGrantService{store: store, logger: slog.New(slog.DiscardHandler)}

		id, err := svc.ActiveGrantID(ctx, "acme", "agent:recon", "mission:originate")
		require.NoError(t, err)
		assert.Equal(t, "grant-abc", id)
	})

	t.Run("wraps a store error", func(t *testing.T) {
		store, mock, _ := newMockedStore(t)
		mock.ExpectQuery("FROM   capability_grant_grants").
			WillReturnError(errors.New("connection refused"))
		svc := &CapabilityGrantService{store: store, logger: slog.New(slog.DiscardHandler)}

		_, err := svc.ActiveGrantID(ctx, "acme", "agent:recon", "mission:originate")
		require.ErrorContains(t, err, "ActiveGrantID")
	})
}
