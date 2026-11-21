// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/sdk/auth"
)

// Errors that the caller maps to a status code.
var (
	// ErrInvalidQuery is a request with no incident key or a key that is too long.
	ErrInvalidQuery = errors.New("incidentreport: invalid query")
	// ErrNotFound is an incident that the graph of the tenant does not hold.
	ErrNotFound = errors.New("incidentreport: no such incident")
	// ErrNoTenant is a call with no tenant in its context.
	ErrNoTenant = errors.New("incidentreport: no tenant in the context")
)

// maxKeyLen bounds the incident key.
const maxKeyLen = 1024

// GraphReader runs one read query on the graph of the tenant of ctx. The
// implementation takes the tenant from ctx and from nothing else.
type GraphReader interface {
	Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)
}

// HistoryReader returns the events of the Timeline of the tenant of ctx that
// the store appended at from or later, in order, and the position of the
// first of them in the whole history. The zero time reads the whole history.
// The implementation takes the tenant from ctx and from nothing else.
type HistoryReader interface {
	HistoryFrom(ctx context.Context, from time.Time) (evs []brain.Event, offset uint64, err error)
}

// historySlack is how much earlier than the first sight of the incident the
// read of the history starts. The events of an incident start with its first
// alert (review R5).
const historySlack = time.Hour

// Grant is a grant of a capability to an agent, and the person who gave it.
type Grant struct {
	ID            string
	Capability    string
	GrantedBy     string
	GrantedAtUnix int64
}

// GrantResolver reads a grant by its id. The id comes from the Timeline event
// of the call (agent_tool_call.observed), which the daemon wrote when the
// grant allowed the call (gibson#1474). It returns nil and no error when the
// tenant holds no grant with the id.
type GrantResolver interface {
	GrantByID(ctx context.Context, tenant, grantID string) (*Grant, error)
}

// Reader builds incident reports.
type Reader struct {
	graph   GraphReader
	history HistoryReader
	grants  GrantResolver
}

// NewReader returns a Reader. Each source is required.
func NewReader(graph GraphReader, history HistoryReader, grants GrantResolver) (*Reader, error) {
	if graph == nil || history == nil || grants == nil {
		return nil, errors.New("incidentreport: the graph, the history and the grant resolver are required")
	}
	return &Reader{graph: graph, history: history, grants: grants}, nil
}

// Report returns the report of one incident of the tenant of ctx.
func (r *Reader) Report(ctx context.Context, incidentKey string) (*Report, error) {
	if incidentKey == "" || len(incidentKey) > maxKeyLen {
		return nil, ErrInvalidQuery
	}
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, ErrNoTenant
	}
	tenant := tenantID.String()
	params := map[string]any{"incident": incidentKey, "limit": int64(maxLines)}

	alertRows, err := r.graph.Read(ctx, alertsCypher, params)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read alerts: %w", err)
	}
	if len(alertRows) == 0 {
		return nil, ErrNotFound
	}
	reachedRows, err := r.graph.Read(ctx, reachedCypher, params)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read reach: %w", err)
	}
	causeRows, err := r.graph.Read(ctx, causesCypher, params)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read causes: %w", err)
	}
	fixRows, err := r.graph.Read(ctx, fixesCypher, params)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read fixes: %w", err)
	}
	// The read of the history starts at the first sight of the incident and
	// its alerts, so a report never reads the whole history of the tenant
	// (review R5). A node with no time reads all of it.
	history, offset, err := r.history.HistoryFrom(ctx, incidentStart(alertRows))
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read the Timeline: %w", err)
	}

	ix := BuildIndexFrom(history, offset)
	rep := Assemble(incidentKey, ix, alertRows, reachedRows, causeRows, fixRows)
	for i := range rep.Actions {
		a := &rep.Actions[i]
		if a.Outcome == OutcomeRefused || a.GrantID == "" {
			continue // a refused call has no grant, and a call with no grant id has none to read
		}
		g, gerr := r.grants.GrantByID(ctx, tenant, a.GrantID)
		if gerr != nil {
			return nil, fmt.Errorf("incidentreport: read the grant of %s: %w", a.ToolID, gerr)
		}
		if g != nil {
			a.Grant = &GrantLine{ID: g.ID, Capability: g.Capability, GrantedBy: g.GrantedBy, GrantedAtUnix: g.GrantedAtUnix}
		}
	}
	return rep, nil
}

// Assemble maps the rows of the graph and the index of the Timeline onto the
// report. It reads no store, so a test can run it with plain rows.
//
// A row that lacks a column gives the zero value of that field. A row with no
// key is dropped, because it names no node.
func Assemble(incident string, ix *Index, alertRows, reachedRows, causeRows, fixRows []map[string]any) *Report {
	rep := &Report{IncidentKey: incident, TimelineTotal: ix.total}

	var alertKeys []string
	for _, row := range alertRows {
		key := str(row, "alert_key")
		if key == "" {
			continue // the OPTIONAL MATCH of an incident with no alert
		}
		alertKeys = append(alertKeys, key)
		rep.Alerts = append(rep.Alerts, AlertLine{
			Key: key, Title: str(row, "title"), Source: str(row, "source"), Severity: str(row, "severity"),
			Frame: ix.entityFrame(labelAlert, key),
		})
	}
	for _, row := range reachedRows {
		key := str(row, "key")
		if key == "" {
			continue
		}
		label := reachedLabel(row)
		rep.Reached = append(rep.Reached, ReachedLine{
			Label: label, Key: key, AlertKey: str(row, "alert_key"), Frame: ix.entityFrame(label, key),
		})
	}
	for _, row := range causeRows {
		id := str(row, "finding_key")
		if id == "" {
			continue
		}
		rep.Causes = append(rep.Causes, CauseLine{
			FindingKey: id, Title: str(row, "title"), Severity: str(row, "severity"), Status: str(row, "status"),
			Raised: ix.findingFrame(id), History: ix.statusHistory(id),
		})
	}
	for _, row := range fixRows {
		id, mr := str(row, "finding_key"), str(row, "mr_key")
		if id == "" || mr == "" {
			continue // a cause with no merge request has no fix line yet
		}
		rep.Fixes = append(rep.Fixes, FixLine{
			FindingKey: id, MergeRequestKey: mr, URL: str(row, "mr_url"), Ref: str(row, "mr_ref"),
			Frame: ix.entityFrame(labelMergeRequest, mr), VerifiedBy: str(row, "pipeline_key"),
			Verified: ix.verifiedFrame(id),
		})
	}
	rep.Actions = ix.actions(incident, alertKeys)
	return rep
}

// actions returns the response actions of the incident, in Timeline order. A
// call belongs to the incident when it is in a mission or run that observed the
// incident or one of its alerts, and its tool is a response action.
func (ix *Index) actions(incident string, alerts []string) []ActionLine {
	scope := ix.missionIDs(incident, alerts)
	var out []ActionLine
	for _, c := range ix.calls {
		act, ok := lookupAction(c.ev.ToolName)
		if !ok {
			continue
		}
		if !scope[c.ev.MissionID] && !scope[c.ev.MissionRunID] {
			continue
		}
		connector, tool := splitToolID(act.ToolID)
		out = append(out, ActionLine{
			ToolID: act.ToolID, Connector: connector, Tool: tool,
			AgentName: ix.runs[c.ev.RunID],
			GrantID:   c.ev.GrantID,
			Outcome:   classify(c.ev.Err, c.ev.Result),
			Error:     c.ev.Err, Result: c.ev.Result,
			Controls: append([]string(nil), act.Controls...),
			Frame:    frameAt(c.seq),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Frame.TimelineSeq < out[j].Frame.TimelineSeq })
	return out
}

// ControlIDs returns the sorted, unique control ids of a report: the controls
// that its response actions are evidence for.
func (r *Report) ControlIDs() []string {
	seen := map[string]bool{}
	for _, a := range r.Actions {
		for _, c := range a.Controls {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func str(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// reachedLabel picks one label of a reached node, the same one on each read:
// the first label in sort order that the Taxonomy admits, else the first in
// sort order. A row with a single "label" column keeps it.
func reachedLabel(row map[string]any) string {
	if l := str(row, "label"); l != "" {
		return l
	}
	var labels []string
	switch v := row["labels"].(type) {
	case []string:
		labels = append(labels, v...)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				labels = append(labels, s)
			}
		}
	}
	sort.Strings(labels)
	for _, l := range labels {
		if taxonomy.Global.ClassifyNode(l).InTaxonomy {
			return l
		}
	}
	if len(labels) > 0 {
		return labels[0]
	}
	return ""
}

// incidentStart is the time from which the report reads the history: the
// first sight of the incident and of its alerts, less historySlack. It is the
// zero time when a node has no first sight.
func incidentStart(alertRows []map[string]any) time.Time {
	var first int64
	for _, row := range alertRows {
		for _, col := range []string{"incident_first_seen", "alert_first_seen"} {
			v, ok := row[col].(int64)
			if !ok || v <= 0 {
				if col == "incident_first_seen" || str(row, "alert_key") != "" {
					return time.Time{}
				}
				continue
			}
			if first == 0 || v < first {
				first = v
			}
		}
	}
	if first == 0 {
		return time.Time{}
	}
	return time.UnixMilli(first).Add(-historySlack)
}
