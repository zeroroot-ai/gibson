// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var afterCols = []string{
	"id", "tenant_id", "actor_id", "actor_type", "action",
	"target_type", "target_id", "decision", "metadata", "created_at",
}

func afterRow(id string, at time.Time) []driver.Value {
	return []driver.Value{id, "acme", "u1", "user", "model_resolved", "model", "p/m", "", []byte(`{}`), at}
}

func TestPosition_RoundTrips(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	pos := Position(PgEntry{ID: "42", CreatedAt: at})
	got, id, err := parsePosition(pos)
	require.NoError(t, err)
	assert.True(t, got.Equal(at))
	assert.Equal(t, int64(42), id)
}

func TestParsePosition_RefusesJunk(t *testing.T) {
	for _, pos := range []string{"", "nobar", "x|1", "1|y"} {
		_, _, err := parsePosition(pos)
		assert.ErrorIs(t, err, ErrBadPosition, pos)
	}
}

func TestListAfter_FirstPageUsesNoOffsetAndReportsMore(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := sqlmock.NewRows(afterCols).
		AddRow(afterRow("3", now)...).AddRow(afterRow("2", now)...).AddRow(afterRow("1", now)...)
	mock.ExpectQuery(`(?s)ORDER\s+BY created_at DESC, id DESC\s+LIMIT\s+\$3`).
		WithArgs("acme", "model_resolved", 3).WillReturnRows(rows)

	got, more, err := NewQuery(db).ListAfter(context.Background(), "acme", Filters{Action: "model_resolved"}, "", 2)
	require.NoError(t, err)
	assert.True(t, more)
	require.Len(t, got, 2)
	assert.Equal(t, "3", got[0].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListAfter_NextPageAddsTheKeysetCondition(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	at := time.Date(2026, 10, 1, 12, 0, 0, 5000, time.UTC)
	mock.ExpectQuery(`\(created_at, id\) < \(\$2, \$3\)`).
		WithArgs("acme", at, int64(7), 11).
		WillReturnRows(sqlmock.NewRows(afterCols).AddRow(afterRow("6", at)...))

	got, more, err := NewQuery(db).ListAfter(context.Background(), "acme", Filters{},
		Position(PgEntry{ID: "7", CreatedAt: at}), 10)
	require.NoError(t, err)
	assert.False(t, more)
	assert.Len(t, got, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListAfter_Refusals(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	q := NewQuery(db)

	_, _, err = q.ListAfter(context.Background(), "", Filters{}, "", 10)
	assert.Error(t, err)
	_, _, err = q.ListAfter(context.Background(), "acme", Filters{}, "junk", 10)
	assert.ErrorIs(t, err, ErrBadPosition)

	mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("boom"))
	_, _, err = q.ListAfter(context.Background(), "acme", Filters{}, "", 0)
	assert.ErrorContains(t, err, "boom")
}

func TestListAfter_ScanFailureIsReported(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))
	_, _, err = NewQuery(db).ListAfter(context.Background(), "acme", Filters{}, "", 5)
	assert.Error(t, err)
}
