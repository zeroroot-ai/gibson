// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// MaxPageSize is the largest page that Find returns.
const MaxPageSize = 1000

// Query selects findings of the tenant. An empty field matches each finding.
type Query struct {
	// IDs limits the result to these findings.
	IDs []types.ID
	// MissionID limits the result to one mission.
	MissionID types.ID
	// Severities limits the result to these severities.
	Severities []string
	// Category limits the result to one category, without regard to case.
	Category string
	// Search matches the title or the description, without regard to case.
	Search string
	// Limit is the page size. Zero means 100. A value over MaxPageSize means
	// MaxPageSize.
	Limit int
	// Offset is the number of findings to skip.
	Offset int
}

// where builds the WHERE clause of a query and its arguments. The values are
// arguments and never part of the text of the statement.
func (q Query) where() (clause string, args []any, err error) {
	var conds []string
	add := func(cond string, arg any) {
		args = append(args, arg)
		conds = append(conds, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if len(q.IDs) > 0 {
		ids := make([]string, len(q.IDs))
		for i, id := range q.IDs {
			if err := id.Validate(); err != nil {
				return "", nil, fmt.Errorf("finding store: finding ID: %w", err)
			}
			ids[i] = id.String()
		}
		add("id = ANY(?::uuid[])", ids)
	}
	if q.MissionID != "" {
		if err := q.MissionID.Validate(); err != nil {
			return "", nil, fmt.Errorf("finding store: mission ID: %w", err)
		}
		add("mission_id = ?", q.MissionID.String())
	}
	if len(q.Severities) > 0 {
		add("severity = ANY(?::text[])", q.Severities)
	}
	if q.Category != "" {
		add("lower(document->>'category') = lower(?)", q.Category)
	}
	if q.Search != "" {
		add("(title ILIKE ? ESCAPE '\\' OR document->>'description' ILIKE ? ESCAPE '\\')", "%"+escapeLike(q.Search)+"%")
	}
	if len(conds) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func (q Query) page() (limit, offset int) {
	limit = q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	offset = q.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// Find returns one page of the findings that match the query, newest first, and
// the number of findings that match. The findings have no evidence, because a
// list does not read the finding_evidence table.
func (s *Store) Find(ctx context.Context, tenantID string, q Query) ([]finding.EnhancedFinding, int, error) {
	where, args, err := q.where()
	if err != nil {
		return nil, 0, err
	}
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("finding store: acquire conn: %w", err)
	}
	defer c.Release()
	return findPage(ctx, c.SQL(), where, args, q)
}

func findPage(
	ctx context.Context, sql datapool.SQL, where string, args []any, q Query,
) ([]finding.EnhancedFinding, int, error) {
	var total int
	if err := sql.QueryRow(ctx, `SELECT count(*) FROM findings`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("finding store: count findings: %w", err)
	}
	limit, offset := q.page()
	pageArgs := append(append([]any{}, args...), limit, offset)
	stmt := `SELECT document FROM findings` + where +
		` ORDER BY created_at DESC, id LIMIT $` + strconv.Itoa(len(args)+1) +
		` OFFSET $` + strconv.Itoa(len(args)+2)
	rows, err := sql.Query(ctx, stmt, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("finding store: list findings: %w", err)
	}
	defer rows.Close()
	out := []finding.EnhancedFinding{}
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, 0, fmt.Errorf("finding store: scan finding: %w", err)
		}
		f, err := decodeFinding(doc)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("finding store: list findings: %w", err)
	}
	return out, total, nil
}

// FindWithEvidence is Find with all evidence of each finding, as stored, in the
// stored order. It reads the finding_evidence table once for the page.
func (s *Store) FindWithEvidence(ctx context.Context, tenantID string, q Query) ([]finding.EnhancedFinding, int, error) {
	where, args, err := q.where()
	if err != nil {
		return nil, 0, err
	}
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("finding store: acquire conn: %w", err)
	}
	defer c.Release()
	sql := c.SQL()
	items, total, err := findPage(ctx, sql, where, args, q)
	if err != nil {
		return nil, 0, err
	}
	if len(items) == 0 {
		return items, total, nil
	}
	ids := make([]string, len(items))
	index := make(map[string]int, len(items))
	for i, f := range items {
		ids[i] = f.ID.String()
		index[ids[i]] = i
	}
	rows, err := sql.Query(ctx, `
SELECT finding_id::text, tier, tool_call_id, type, title, content, metadata
FROM finding_evidence WHERE finding_id = ANY($1::uuid[]) ORDER BY finding_id, position`, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("finding store: read evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			findingID  string
			tier       int16
			toolCallID *string
			typeName   string
			title      string
			content    string
			metadata   []byte
		)
		if err := rows.Scan(&findingID, &tier, &toolCallID, &typeName, &title, &content, &metadata); err != nil {
			return nil, 0, fmt.Errorf("finding store: scan evidence: %w", err)
		}
		item, err := evidenceItem(tier, toolCallID, typeName, title, content, metadata)
		if err != nil {
			return nil, 0, err
		}
		i := index[findingID]
		items[i].Evidence = append(items[i].Evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("finding store: read evidence: %w", err)
	}
	return items, total, nil
}

// evidenceItem builds the evidence item of a row.
func evidenceItem(
	tier int16, toolCallID *string, typeName, title, content string, metadata []byte,
) (*typespb.Evidence, error) {
	item := &typespb.Evidence{
		Title:   title,
		Type:    typespb.EvidenceType(typespb.EvidenceType_value[typeName]),
		Content: content,
		Tier:    typespb.EvidenceTier(tier),
	}
	if toolCallID != nil {
		item.ToolCallId = *toolCallID
	}
	if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
		return nil, fmt.Errorf("finding store: decode evidence metadata: %w", err)
	}
	if len(item.Metadata) == 0 {
		item.Metadata = nil
	}
	return item, nil
}

// Bucket is the number of findings that share one label.
type Bucket struct {
	Label string
	Count uint64
}

// CountBy counts the findings of the tenant by "severity" or by "category". A
// finding with no label counts under "unknown". If window is not zero, only the
// findings that were created within the window count.
func (s *Store) CountBy(ctx context.Context, tenantID, by string, window time.Duration) ([]Bucket, error) {
	var expr string
	switch by {
	case "severity":
		expr = "coalesce(nullif(severity, ''), 'unknown')"
	case "category":
		expr = "coalesce(nullif(document->>'category', ''), 'unknown')"
	default:
		return nil, fmt.Errorf("finding store: cannot count by %q", by)
	}
	stmt := `SELECT ` + expr + ` AS label, count(*) FROM findings`
	var args []any
	if window > 0 {
		stmt += ` WHERE created_at > now() - make_interval(secs => $1)`
		args = append(args, window.Seconds())
	}
	stmt += ` GROUP BY label ORDER BY count(*) DESC, label`
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("finding store: acquire conn: %w", err)
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("finding store: count findings: %w", err)
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var (
			label string
			n     int64
		)
		if err := rows.Scan(&label, &n); err != nil {
			return nil, fmt.Errorf("finding store: scan count: %w", err)
		}
		out = append(out, Bucket{Label: label, Count: rowCount(n)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding store: count findings: %w", err)
	}
	return out, nil
}

// DailyCounts returns the number of findings created on each UTC day of the
// last `days` days, keyed by "2006-01-02". A day with no finding is absent.
func (s *Store) DailyCounts(ctx context.Context, tenantID string, days int) (map[string]uint64, error) {
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("finding store: acquire conn: %w", err)
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx, `
SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, count(*)
FROM findings WHERE created_at > now() - make_interval(days => $1)
GROUP BY day`, days)
	if err != nil {
		return nil, fmt.Errorf("finding store: count findings by day: %w", err)
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var (
			day string
			n   int64
		)
		if err := rows.Scan(&day, &n); err != nil {
			return nil, fmt.Errorf("finding store: scan day count: %w", err)
		}
		out[day] = rowCount(n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding store: count findings by day: %w", err)
	}
	return out, nil
}

// rowCount turns the result of count(*) into an unsigned number. A count is
// never negative, so a negative value gives zero and never wraps.
func rowCount(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
