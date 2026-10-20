// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — query.go
//
// Query provides paginated, filtered reads against the Postgres audit_log
// table. It complements the append-only Writer by giving callers a way to
// retrieve audit records for a given tenant.
//
// All queries are tenant-scoped: tenant_id = $1 is always included in the
// WHERE clause, enforcing hard multi-tenant isolation.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Filter and result types
// ---------------------------------------------------------------------------

// Filters controls which rows are returned by Query.List.
// All fields are optional; zero values disable the corresponding filter.
type Filters struct {
	// ActorID filters by the actor_id column (exact match).
	ActorID string

	// Action filters by the action column (exact match).
	Action string

	// TargetType filters by the target_type column (exact match).
	TargetType string

	// TargetID filters by the target_id column (exact match).
	TargetID string

	// Since restricts results to rows with created_at >= Since.
	Since *time.Time

	// Until restricts results to rows with created_at <= Until.
	Until *time.Time
}

// PgEntry is a single row read from the audit_log table.
type PgEntry struct {
	ID         string
	TenantID   string
	ActorID    string
	ActorType  string
	Action     string
	TargetType string
	TargetID   string
	Decision   string
	Metadata   json.RawMessage
	CreatedAt  time.Time
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

// Query provides read access to the Postgres audit_log table.
//
// Query is safe for concurrent use.
type Query struct {
	db *sql.DB
}

// NewQuery constructs a Query backed by the given *sql.DB.
// db must be non-nil.
func NewQuery(db *sql.DB) *Query {
	if db == nil {
		panic("audit.NewQuery: db must not be nil")
	}
	return &Query{db: db}
}

// buildWhere builds the WHERE clause of a list query from the non-empty
// filter fields. $1 is always tenant_id. It returns the clause, its arguments
// and the number of the next free parameter.
func buildWhere(tenantID string, filters Filters) (where string, args []interface{}, nextParam int) {
	conds := []string{"tenant_id = $1"}
	args = []interface{}{tenantID}
	nextParam = 2 // $2 onward for additional filters

	addFilter := func(col, val string) {
		conds = append(conds, fmt.Sprintf("%s = $%d", col, nextParam))
		args = append(args, val)
		nextParam++
	}
	addTimeFilter := func(col, op string, t *time.Time) {
		conds = append(conds, fmt.Sprintf("%s %s $%d", col, op, nextParam))
		args = append(args, *t)
		nextParam++
	}

	if filters.ActorID != "" {
		addFilter("actor_id", filters.ActorID)
	}
	if filters.Action != "" {
		addFilter("action", filters.Action)
	}
	if filters.TargetType != "" {
		addFilter("target_type", filters.TargetType)
	}
	if filters.TargetID != "" {
		addFilter("target_id", filters.TargetID)
	}
	if filters.Since != nil {
		addTimeFilter("created_at", ">=", filters.Since)
	}
	if filters.Until != nil {
		addTimeFilter("created_at", "<=", filters.Until)
	}

	return strings.Join(conds, " AND "), args, nextParam
}

// List returns a paginated slice of audit entries for tenantID that match
// filters, along with the total count of matching rows (before pagination).
//
// tenantID must be non-empty. limit controls the page size; offset the
// starting row. Both are applied after filtering.
//
// Returns (entries, totalCount, error).
func (q *Query) List(
	ctx context.Context,
	tenantID string,
	filters Filters,
	limit, offset int,
) ([]PgEntry, int, error) {
	if tenantID == "" {
		return nil, 0, errors.New("audit.Query.List: tenantID must not be empty")
	}

	where, args, nextParam := buildWhere(tenantID, filters)

	// Count query — same WHERE clause, no pagination.
	countQuery := "SELECT COUNT(*) FROM audit_log WHERE " + where
	var total int
	if err := q.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("audit.Query.List: count: %w", err)
	}

	if total == 0 {
		return []PgEntry{}, 0, nil
	}

	// Clamp pagination parameters to sane defaults.
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Data query — ordered by created_at DESC (newest first).
	dataQuery := fmt.Sprintf(`
SELECT id, tenant_id, actor_id, actor_type, action,
       target_type, target_id, COALESCE(decision, ''), metadata, created_at
FROM   audit_log
WHERE  %s
ORDER  BY created_at DESC
LIMIT  $%d OFFSET $%d`,
		where, nextParam, nextParam+1,
	)
	args = append(args, limit, offset)

	rows, err := q.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit.Query.List: query: %w", err)
	}
	defer rows.Close()

	entries, err := scanEntries(rows, limit)
	if err != nil {
		return nil, 0, err
	}

	return entries, total, nil
}

// scanEntries reads every row of an audit_log select into entries.
func scanEntries(rows *sql.Rows, capHint int) ([]PgEntry, error) {
	entries := make([]PgEntry, 0, max(capHint, 0))
	for rows.Next() {
		var e PgEntry
		var metaRaw []byte
		if err := rows.Scan(
			&e.ID,
			&e.TenantID,
			&e.ActorID,
			&e.ActorType,
			&e.Action,
			&e.TargetType,
			&e.TargetID,
			&e.Decision,
			&metaRaw,
			&e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit.Query.List: scan row: %w", err)
		}
		if len(metaRaw) > 0 {
			e.Metadata = json.RawMessage(metaRaw)
		} else {
			e.Metadata = json.RawMessage("{}")
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit.Query.List: rows iteration: %w", err)
	}

	return entries, nil
}

// ErrBadPosition reports a keyset position that Position did not write.
var ErrBadPosition = errors.New("audit: the keyset position is not valid")

// Position returns the keyset position of an entry: its time to the
// microsecond (the precision of the column) and its id. The list order is
// newest first, with the id as the tie breaker.
func Position(e PgEntry) string {
	return strconv.FormatInt(e.CreatedAt.UnixMicro(), 10) + "|" + e.ID
}

func parsePosition(pos string) (time.Time, int64, error) {
	micros, id, ok := strings.Cut(pos, "|")
	if !ok {
		return time.Time{}, 0, ErrBadPosition
	}
	us, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return time.Time{}, 0, ErrBadPosition
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return time.Time{}, 0, ErrBadPosition
	}
	return time.UnixMicro(us).UTC(), n, nil
}

// ListAfter returns the next page of audit entries for tenantID that match
// filters, newest first. after is the Position of the last entry that the
// caller has, or empty for the first page. It never uses OFFSET, so a row that
// arrives between two calls does not move the window. more is true when
// another entry follows the page.
func (q *Query) ListAfter(
	ctx context.Context,
	tenantID string,
	filters Filters,
	after string,
	limit int,
) (entries []PgEntry, more bool, err error) {
	if tenantID == "" {
		return nil, false, errors.New("audit.Query.ListAfter: tenantID must not be empty")
	}
	if limit <= 0 {
		limit = 100
	}
	where, args, nextParam := buildWhere(tenantID, filters)
	if after != "" {
		at, id, perr := parsePosition(after)
		if perr != nil {
			return nil, false, perr
		}
		where += " AND (created_at, id) < ($" + strconv.Itoa(nextParam) + ", $" + strconv.Itoa(nextParam+1) + ")"
		args = append(args, at, id)
		nextParam += 2
	}
	// One row more than the page tells whether another page follows. The query
	// holds fixed column names and numbered placeholders only. Each value goes
	// in args.
	var sqlText strings.Builder
	sqlText.WriteString("SELECT id, tenant_id, actor_id, actor_type, action, ")
	sqlText.WriteString("target_type, target_id, COALESCE(decision, ''), metadata, created_at ")
	sqlText.WriteString("FROM audit_log WHERE ")
	sqlText.WriteString(where)
	sqlText.WriteString(" ORDER BY created_at DESC, id DESC LIMIT $")
	sqlText.WriteString(strconv.Itoa(nextParam))
	args = append(args, limit+1)

	rows, err := q.db.QueryContext(ctx, sqlText.String(), args...)
	if err != nil {
		return nil, false, fmt.Errorf("audit.Query.ListAfter: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries, err = scanEntries(rows, limit+1)
	if err != nil {
		return nil, false, err
	}
	if len(entries) > limit {
		return entries[:limit], true, nil
	}
	return entries, false, nil
}
