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
	defer func() { _ = db.Close() }()
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
	defer func() { _ = db.Close() }()
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
	defer func() { _ = db.Close() }()
	q := NewQuery(db)

	_, _, err = q.ListAfter(context.Background(), "", Filters{}, "", 10)
	require.Error(t, err)
	_, _, err = q.ListAfter(context.Background(), "acme", Filters{}, "junk", 10)
	require.ErrorIs(t, err, ErrBadPosition)

	mock.ExpectQuery(`SELECT`).WillReturnError(errors.New("boom"))
	_, _, err = q.ListAfter(context.Background(), "acme", Filters{}, "", 0)
	assert.ErrorContains(t, err, "boom")
}

func TestListAfter_ScanFailureIsReported(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("1"))
	_, _, err = NewQuery(db).ListAfter(context.Background(), "acme", Filters{}, "", 5)
	assert.Error(t, err)
}

// List keeps its paging rules: it clamps the limit and the offset, returns
// early on an empty count, and reports each database error.
func TestList_ClampsPagingAndReportsErrors(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	q := NewQuery(db)

	_, _, err = q.List(ctx, "", Filters{}, 10, 0)
	require.Error(t, err)

	mock.ExpectQuery(`SELECT COUNT`).WillReturnError(errors.New("count down"))
	_, _, err = q.List(ctx, "acme", Filters{}, 10, 0)
	require.ErrorContains(t, err, "count down")

	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"n"}).AddRow(0))
	got, total, err := q.List(ctx, "acme", Filters{Action: "x"}, 10, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Zero(t, total)

	// A limit of 0 becomes 100 and an offset of -1 becomes 0.
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"n"}).AddRow(1))
	mock.ExpectQuery(`LIMIT\s+\$2 OFFSET \$3`).WithArgs("acme", 100, 0).
		WillReturnRows(sqlmock.NewRows(afterCols).AddRow(afterRow("1", now)...))
	got, total, err = q.List(ctx, "acme", Filters{}, 0, -1)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, got, 1)

	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"n"}).AddRow(1))
	mock.ExpectQuery(`LIMIT`).WillReturnError(errors.New("query down"))
	_, _, err = q.List(ctx, "acme", Filters{}, 10, 0)
	require.ErrorContains(t, err, "query down")

	mock.ExpectQuery(`SELECT COUNT`).WillReturnRows(sqlmock.NewRows([]string{"n"}).AddRow(1))
	mock.ExpectQuery(`LIMIT`).WillReturnRows(sqlmock.NewRows(afterCols).
		AddRow(afterRow("1", now)...).RowError(0, errors.New("row broke")))
	_, _, err = q.List(ctx, "acme", Filters{}, 10, 0)
	require.ErrorContains(t, err, "row broke")
}

func TestBuildWhere_UsesEachFilter(t *testing.T) {
	since := time.Now()
	until := since.Add(time.Hour)
	where, args, next := buildWhere("acme", Filters{
		ActorID: "a", Action: "b", TargetType: "c", TargetID: "d", Since: &since, Until: &until,
	})
	assert.Contains(t, where, "created_at <= $7")
	assert.Len(t, args, 7)
	assert.Equal(t, 8, next)
}
