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
	"fmt"
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
		return nil, 0, fmt.Errorf("audit.Query.List: tenantID must not be empty")
	}

	// Build WHERE clause dynamically from non-empty filter fields.
	// $1 is always tenant_id.
	conds := []string{"tenant_id = $1"}
	args := []interface{}{tenantID}
	nextParam := 2 // $2 onward for additional filters

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

	where := strings.Join(conds, " AND ")

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

	entries := make([]PgEntry, 0, limit)
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
			return nil, 0, fmt.Errorf("audit.Query.List: scan row: %w", err)
		}
		if len(metaRaw) > 0 {
			e.Metadata = json.RawMessage(metaRaw)
		} else {
			e.Metadata = json.RawMessage("{}")
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("audit.Query.List: rows iteration: %w", err)
	}

	return entries, total, nil
}
