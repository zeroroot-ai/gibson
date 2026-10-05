// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package compliance is the first compliance reader (ADR-0113, gibson#674).
// For one tenant, one framework pack and one time range, it returns the
// audit events that are evidence for each control of the pack.
//
// The reader evaluates the mapping rules of the pack at read time, over the
// Postgres audit_log table. No write path stamps a control id onto an
// event. The report holds evidence only: it never states a verdict about a
// control, it holds no score, and it never says that a tenant is compliant.
package compliance

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/auditcel"
)

const (
	// DefaultRange is the time range of a query that names no start.
	DefaultRange = 90 * 24 * time.Hour
	// DefaultPageSize is the page size of a query that names none.
	DefaultPageSize = 100
	// MaxPageSize is the largest page size.
	MaxPageSize = 500
)

// Errors that the caller maps to a status code.
var (
	// ErrInvalidQuery is a query that the reader refuses: an empty tenant or
	// pack, an end before the start, a negative page size, or a page token
	// that does not belong to this query.
	ErrInvalidQuery = errors.New("compliance: invalid query")
	// ErrUnknownPack is a pack that is not in the catalog.
	ErrUnknownPack = errors.New("compliance: the pack is not in the catalog")
	// ErrNotAFramework is a catalog pack with no control list.
	ErrNotAFramework = errors.New("compliance: the pack has no control list")
	// ErrPackNotEnabled is a pack that the tenant did not enable.
	ErrPackNotEnabled = errors.New("compliance: the tenant has not enabled the pack")
)

// State is the evidence state of one control. It is never a verdict.
type State int

const (
	// StateNoRule: the pack has no mapping rule for the control. The text
	// for it is "No automated evidence".
	StateNoRule State = iota + 1
	// StateNoEvents: the control has a rule, and no event in the range
	// matched it.
	StateNoEvents
	// StateHasEvidence: one event or more in the range matched the rule.
	StateHasEvidence
)

// ControlEvidence is the evidence of one control in the range.
type ControlEvidence struct {
	ID            string
	Title         string
	Family        string
	FamilyTitle   string
	State         State
	EventCount    int64
	LastEventTime time.Time // zero when EventCount is 0
}

// EvidenceEvent is one audit record that is evidence for one control or
// more.
type EvidenceEvent struct {
	AuditRecordID string
	Time          time.Time
	Action        string
	ActorID       string
	ActorType     string
	ResourceType  string
	ResourceID    string
	Effect        string
	ControlIDs    []string
}

// Report is the result of one query.
type Report struct {
	Pack             string
	PackVersion      int
	ControlsWithRule int
	ControlsTotal    int
	Start, End       time.Time
	// Controls holds each control of the pack, in pack order, on each page.
	Controls []ControlEvidence
	// Events is one page of evidence events, oldest first.
	Events []EvidenceEvent
	// NextPageToken is empty on the last page.
	NextPageToken string
}

// Query names the tenant, the pack and the range. A zero End is now. A zero
// Start is End minus DefaultRange.
type Query struct {
	Tenant    string
	Pack      string
	Start     time.Time
	End       time.Time
	PageSize  int
	PageToken string
}

// EnabledPacks reports whether a tenant enabled a pack. The daemon answers
// it from the World of the tenant.
type EnabledPacks interface {
	IsDomainPackEnabled(ctx context.Context, tenant, pack string) (bool, error)
}

// Reader answers compliance queries.
type Reader struct {
	db      *sql.DB
	catalog *ontology.DomainPackCatalog
	enabled EnabledPacks
	now     func() time.Time
}

// NewReader returns a Reader. Each dependency is required.
func NewReader(db *sql.DB, catalog *ontology.DomainPackCatalog, enabled EnabledPacks) (*Reader, error) {
	switch {
	case db == nil:
		return nil, errors.New("compliance: NewReader: db is required")
	case catalog == nil:
		return nil, errors.New("compliance: NewReader: catalog is required")
	case enabled == nil:
		return nil, errors.New("compliance: NewReader: enabled packs source is required")
	}
	return &Reader{db: db, catalog: catalog, enabled: enabled, now: time.Now}, nil
}

// pageCursor is the decoded page token. It binds the token to the query, so
// that a token is refused with a different pack or range.
type pageCursor struct {
	Pack    string `json:"p"`
	Start   int64  `json:"s"`
	End     int64  `json:"e"`
	AfterID int64  `json:"a"`
}

func encodeCursor(c pageCursor) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("compliance: encode page token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(token string) (pageCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return pageCursor{}, fmt.Errorf("%w: page token: %w", ErrInvalidQuery, err)
	}
	var c pageCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return pageCursor{}, fmt.Errorf("%w: page token: %w", ErrInvalidQuery, err)
	}
	return c, nil
}

// normalize applies the defaults of a query and refuses a bad one.
func (r *Reader) normalize(q Query) (Query, int64, error) {
	if q.Tenant == "" || q.Pack == "" {
		return q, 0, fmt.Errorf("%w: tenant and pack are required", ErrInvalidQuery)
	}
	if q.End.IsZero() {
		q.End = r.now()
	}
	if q.Start.IsZero() {
		q.Start = q.End.Add(-DefaultRange)
	}
	q.Start, q.End = q.Start.UTC().Truncate(time.Microsecond), q.End.UTC().Truncate(time.Microsecond)
	if !q.End.After(q.Start) {
		return q, 0, fmt.Errorf("%w: the end of the range must be after its start", ErrInvalidQuery)
	}
	switch {
	case q.PageSize < 0:
		return q, 0, fmt.Errorf("%w: page size must not be negative", ErrInvalidQuery)
	case q.PageSize == 0:
		q.PageSize = DefaultPageSize
	case q.PageSize > MaxPageSize:
		q.PageSize = MaxPageSize
	}
	var after int64
	if q.PageToken != "" {
		c, err := decodeCursor(q.PageToken)
		if err != nil {
			return q, 0, err
		}
		if c.Pack != q.Pack || c.Start != q.Start.UnixMicro() || c.End != q.End.UnixMicro() {
			return q, 0, fmt.Errorf("%w: the page token belongs to a different query", ErrInvalidQuery)
		}
		after = c.AfterID
	}
	return q, after, nil
}

// Evidence runs one query.
//
// It reads each audit record of the tenant in [Start, End), oldest first,
// and evaluates each mapping rule of the pack on it. The counts and the last
// event time of each control cover the whole range, on each page. Events
// holds one page of the records that matched a rule, after the record that
// the page token names.
func (r *Reader) Evidence(ctx context.Context, q Query) (*Report, error) {
	q, afterID, err := r.normalize(q)
	if err != nil {
		return nil, err
	}
	pack, ok := r.catalog.Get(q.Pack)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPack, q.Pack)
	}
	if len(pack.Controls) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNotAFramework, q.Pack)
	}
	enabled, err := r.enabled.IsDomainPackEnabled(ctx, q.Tenant, q.Pack)
	if err != nil {
		return nil, fmt.Errorf("compliance: read the enabled packs of the tenant: %w", err)
	}
	if !enabled {
		return nil, fmt.Errorf("%w: %q", ErrPackNotEnabled, q.Pack)
	}
	rules, err := auditcel.LoadMappingRules(&pack)
	if err != nil {
		return nil, fmt.Errorf("compliance: %w", err)
	}

	report := newReport(&pack, q)
	index := make(map[string]int, len(report.Controls))
	for i, c := range report.Controls {
		index[c.ID] = i
	}
	order := ruleOrder(&pack, rules)

	rows, err := r.db.QueryContext(ctx, `
SELECT id, action, COALESCE(target_type, ''), COALESCE(target_id, ''), COALESCE(decision, ''),
       actor_id, actor_type, created_at
FROM   audit_log
WHERE  tenant_id = $1 AND created_at >= $2 AND created_at < $3
ORDER  BY id ASC`, q.Tenant, q.Start, q.End)
	if err != nil {
		return nil, fmt.Errorf("compliance: read audit_log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var lastID int64
	more := false
	for rows.Next() {
		var (
			id int64
			ev auditcel.Event
		)
		if err := rows.Scan(&id, &ev.Action, &ev.ResourceType, &ev.ResourceID, &ev.Effect,
			&ev.ActorID, &ev.ActorType, &ev.Time); err != nil {
			return nil, fmt.Errorf("compliance: scan audit_log: %w", err)
		}
		matched, err := matchRules(ctx, order, rules, ev)
		if err != nil {
			return nil, err
		}
		if len(matched) == 0 {
			continue
		}
		for _, controlID := range matched {
			c := &report.Controls[index[controlID]]
			c.State = StateHasEvidence
			c.EventCount++
			if ev.Time.After(c.LastEventTime) {
				c.LastEventTime = ev.Time
			}
		}
		if id <= afterID {
			continue
		}
		if len(report.Events) == q.PageSize {
			more = true
			continue
		}
		report.Events = append(report.Events, EvidenceEvent{
			AuditRecordID: strconv.FormatInt(id, 10),
			Time:          ev.Time,
			Action:        ev.Action,
			ActorID:       ev.ActorID,
			ActorType:     ev.ActorType,
			ResourceType:  ev.ResourceType,
			ResourceID:    ev.ResourceID,
			Effect:        ev.Effect,
			ControlIDs:    matched,
		})
		lastID = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("compliance: read audit_log: %w", err)
	}
	if more {
		token, err := encodeCursor(pageCursor{
			Pack: q.Pack, Start: q.Start.UnixMicro(), End: q.End.UnixMicro(), AfterID: lastID,
		})
		if err != nil {
			return nil, err
		}
		report.NextPageToken = token
	}
	return report, nil
}

// newReport returns a report with each control of the pack in its first
// state: StateNoRule, or StateNoEvents for a control with a rule.
func newReport(pack *ontology.DomainPack, q Query) *Report {
	withRule, total := pack.RuleCoverage()
	hasRule := make(map[string]bool, len(pack.MappingRules))
	for _, r := range pack.MappingRules {
		hasRule[r.ControlID] = true
	}
	report := &Report{
		Pack:             pack.Name,
		PackVersion:      pack.Version,
		ControlsWithRule: withRule,
		ControlsTotal:    total,
		Start:            q.Start,
		End:              q.End,
		Controls:         make([]ControlEvidence, len(pack.Controls)),
	}
	for i, c := range pack.Controls {
		state := StateNoRule
		if hasRule[c.ID] {
			state = StateNoEvents
		}
		report.Controls[i] = ControlEvidence{
			ID: c.ID, Title: c.Title, Family: c.Family, FamilyTitle: c.FamilyTitle, State: state,
		}
	}
	return report
}

// ruleOrder returns the control ids of the rules in pack order, so that the
// ControlIDs of an event have the same order on each run.
func ruleOrder(pack *ontology.DomainPack, rules map[string]*auditcel.CompiledRule) []string {
	out := make([]string, 0, len(rules))
	for _, c := range pack.Controls {
		if _, ok := rules[c.ID]; ok {
			out = append(out, c.ID)
		}
	}
	return out
}

// matchRules returns the control ids whose rule matches ev. An evaluation
// error fails the query: a rule that cannot be evaluated is not "no match".
func matchRules(ctx context.Context, order []string, rules map[string]*auditcel.CompiledRule, ev auditcel.Event) ([]string, error) {
	var matched []string
	for _, controlID := range order {
		ok, err := rules[controlID].Match(ctx, ev)
		if err != nil {
			return nil, fmt.Errorf("compliance: control %q: %w", controlID, err)
		}
		if ok {
			matched = append(matched, controlID)
		}
	}
	return matched, nil
}
