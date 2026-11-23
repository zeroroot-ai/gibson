// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/sdk/auth"
)

// history is a small Timeline of one incident. The index of an event is its
// position.
func history() []brain.Event {
	return []brain.Event{
		/* 0 */ brain.AgentRunObserved{RunID: "run-1", AgentName: "incident-response"},
		/* 1 */ brain.EntityObserved{Label: "Alert", Key: "alert-1", MissionID: "m-1"},
		/* 2 */ brain.EntityObserved{Label: "Incident", Key: "inc-1", MissionID: "m-1"},
		/* 3 */ brain.EntityObserved{Label: "Host", Key: "host-9", MissionID: "m-1"},
		/* 4 */ brain.AgentToolCallObserved{ToolCallID: "c1", MissionID: "m-1", RunID: "run-1", ToolName: "mcp:crowdstrike-response:contain_host", Result: `{"accepted":true}`, GrantID: "g-1"},
		/* 5 */ brain.AgentToolCallObserved{ToolCallID: "c2", MissionID: "m-1", RunID: "run-1", ToolName: "mcp:okta-response:revoke_user_sessions", Err: "permission denied: the grant does not allow this tool"},
		/* 6 */ brain.AgentToolCallObserved{ToolCallID: "c3", MissionID: "m-1", RunID: "run-1", ToolName: "mcp:okta-response:suspend_user", Err: "pending authorization", GrantID: "g-1"},
		/* 7 */ brain.AgentToolCallObserved{ToolCallID: "c4", MissionID: "m-1", RunID: "run-1", ToolName: "native:nmap"},
		/* 8 */ brain.AgentToolCallObserved{ToolCallID: "c5", MissionID: "m-OTHER", RunID: "run-1", ToolName: "mcp:crowdstrike-response:contain_host"},
		/* 9 */ brain.FindingRaised{ID: "f-1", Title: "Exposed token", MissionID: "m-1"},
		/* 10 */ brain.EntityObserved{Label: "MergeRequest", Key: "mr-1", MissionID: "m-1"},
		/* 11 */ brain.FindingStatusChanged{ID: "f-1", Status: "fixing"},
		/* 12 */ brain.FindingStatusChanged{ID: "f-1", Status: "fixed"},
		/* 13 */ brain.FindingStatusChanged{ID: "f-1", Status: "verified"},
	}
}

func rows(kv ...map[string]any) []map[string]any { return kv }

func sampleReport() *Report {
	return Assemble("inc-1", BuildIndexFrom(history(), 0),
		rows(map[string]any{"alert_key": "alert-1", "title": "Beacon", "source": "crowdstrike", "severity": "high"}),
		rows(map[string]any{"alert_key": "alert-1", "label": "Host", "key": "host-9"}),
		rows(map[string]any{"finding_key": "f-1", "title": "Exposed token", "severity": "high", "status": "verified"}),
		rows(map[string]any{"finding_key": "f-1", "mr_key": "mr-1", "mr_url": "https://git/mr/1", "mr_ref": "fix/1", "pipeline_key": "pl-7"}),
	)
}

// Each line carries the position of its event, and the replay position is one
// after it, because GetFrameAt folds the first N events.
func TestAssemble_EachLineHasItsReplayFrame(t *testing.T) {
	rep := sampleReport()
	if got := rep.Alerts[0].Frame; got != (Frame{TimelineSeq: 1, ReplaySeq: 2, Known: true}) {
		t.Errorf("alert frame = %+v", got)
	}
	if got := rep.Reached[0].Frame; got != (Frame{TimelineSeq: 3, ReplaySeq: 4, Known: true}) {
		t.Errorf("reached frame = %+v", got)
	}
	if got := rep.Causes[0].Raised; got.TimelineSeq != 9 {
		t.Errorf("cause raised frame = %+v", got)
	}
	if got := rep.Fixes[0].Frame; got.TimelineSeq != 10 {
		t.Errorf("fix frame = %+v", got)
	}
	if got := rep.Fixes[0].Verified; !got.Known || got.TimelineSeq != 13 {
		t.Errorf("verified frame = %+v", got)
	}
	if rep.Fixes[0].VerifiedBy != "pl-7" {
		t.Errorf("verified by = %q", rep.Fixes[0].VerifiedBy)
	}
	if rep.TimelineTotal != 14 {
		t.Errorf("total = %d", rep.TimelineTotal)
	}
	seqs := make([]uint64, 0, len(rep.Causes[0].History))
	for _, h := range rep.Causes[0].History {
		seqs = append(seqs, h.Frame.TimelineSeq)
	}
	if !slices.Equal(seqs, []uint64{11, 12, 13}) {
		t.Errorf("status history seqs = %v", seqs)
	}
}

// Only the response actions of the incident are in the report: not a native
// tool, and not a call of another mission.
func TestAssemble_ListsOnlyTheResponseActionsOfTheIncident(t *testing.T) {
	rep := sampleReport()
	got := make([]string, 0, len(rep.Actions))
	for _, a := range rep.Actions {
		got = append(got, a.ToolID+"@"+string(a.Outcome))
	}
	want := []string{
		"mcp:crowdstrike-response:contain_host@done",
		"mcp:okta-response:revoke_user_sessions@refused",
		"mcp:okta-response:suspend_user@pending_authorization",
	}
	if !slices.Equal(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
	if a := rep.Actions[0]; a.AgentName != "incident-response" || a.Connector != "crowdstrike-response" || a.Tool != "contain_host" {
		t.Errorf("action = %+v", a)
	}
	if a := rep.Actions[1]; a.Frame.TimelineSeq != 5 || a.Error == "" {
		t.Errorf("a refused action keeps its error and its frame: %+v", a)
	}
}

// A line that the Timeline does not hold stays in the report with Known false.
func TestAssemble_ALineWithNoEventHasNoFrame(t *testing.T) {
	rep := Assemble("inc-1", BuildIndexFrom(nil, 0),
		rows(map[string]any{"alert_key": "a-x"}), nil, nil, nil)
	if len(rep.Alerts) != 1 || rep.Alerts[0].Frame.Known {
		t.Errorf("alerts = %+v", rep.Alerts)
	}
}

// An incident with no alert returns one row with an empty alert key, because
// the alert match is optional. It gives no alert line.
func TestAssemble_DropsRowsWithNoKey(t *testing.T) {
	rep := Assemble("inc-1", BuildIndexFrom(nil, 0),
		rows(map[string]any{"alert_key": ""}),
		rows(map[string]any{"label": "Host"}),
		rows(map[string]any{"title": "no id"}),
		rows(map[string]any{"finding_key": "f-1", "mr_key": ""}))
	if len(rep.Alerts)+len(rep.Reached)+len(rep.Causes)+len(rep.Fixes) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

// A check that finds the flaw again sets the finding to open, so the proof is
// not the old `verified` event.
func TestIndex_AReopenedFindingIsNotVerified(t *testing.T) {
	ix := BuildIndexFrom([]brain.Event{
		brain.FindingStatusChanged{ID: "f", Status: "verified"},
		brain.FindingStatusChanged{ID: "f", Status: "open"},
	}, 0)
	if ix.verifiedFrame("f").Known {
		t.Error("a finding that was reopened is not verified")
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		code, err, result string
		want              Outcome
	}{
		{"", "", `{"ok":true}`, OutcomeDone},
		// The code decides. The words of "not authorized to invoke tool" hold
		// none of the old match words, and the call is a refusal (gibson#1575).
		{"not_authorized", "metatool: not authorized to invoke tool: mcp:edr:isolate_host", "", OutcomeRefused},
		{"refused", "metatool: tool blocked", "", OutcomeRefused},
		{"pending_authorization", "wait", "", OutcomePending},
		{"merge_not_granted", "wait", "", OutcomePending},
		{"failed", "grant lookup failed", "", OutcomeFailed},
		// An event with no code falls back to the words of the error.
		{"", "permission denied", "", OutcomeRefused},
		{"", "rpc error: code = PermissionDenied desc = not allowed by grant", "", OutcomeRefused},
		{"", "", "pending authorization", OutcomePending},
		{"", "PENDING_AUTHORIZATION", "", OutcomePending},
		{"", "vendor returned HTTP 500", "", OutcomeFailed},
	} {
		if got := classify(tc.code, tc.err, tc.result); got != tc.want {
			t.Errorf("classify(%q, %q, %q) = %q, want %q", tc.code, tc.err, tc.result, got, tc.want)
		}
	}
}

// Each action names controls, and each control is in the NIST 800-53 pack.
func TestResponseActions_ControlsAreInThePack(t *testing.T) {
	pack, ok := ontology.EmbeddedCatalog().Get("nist-800-53-r5")
	if !ok {
		t.Fatal("the embedded catalog must hold nist-800-53-r5")
	}
	known := map[string]bool{}
	for _, c := range pack.Controls {
		known[c.ID] = true
	}
	for _, a := range responseActions {
		if !strings.HasPrefix(a.ToolID, "mcp:") {
			t.Errorf("tool id %q is not a canonical connector tool id", a.ToolID)
		}
		if len(a.Controls) == 0 {
			t.Errorf("%s names no control", a.ToolID)
		}
		for _, c := range a.Controls {
			if !known[c] {
				t.Errorf("%s names control %q, which the pack does not hold", a.ToolID, c)
			}
		}
	}
}

func TestReport_ControlIDsAreUniqueAndSorted(t *testing.T) {
	got := sampleReport().ControlIDs()
	want := []string{"ac-12", "ac-2", "ir-4", "sc-7"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("control ids = %v, want %v", got, want)
	}
}

// ---- Reader -----------------------------------------------------------------

type fakeGraph struct {
	byQuery map[string][]map[string]any
	calls   []map[string]any
	err     error
}

func (f *fakeGraph) Read(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	f.calls = append(f.calls, params)
	return f.byQuery[cypher], f.err
}

type fakeHistory struct{ evs []brain.Event }

func (f fakeHistory) HistoryFrom(context.Context, time.Time) ([]brain.Event, uint64, error) {
	return f.evs, 0, nil
}

type fakeGrants struct{ asked []string }

func (f *fakeGrants) GrantByID(_ context.Context, tenant, id string, _ time.Time) (*Grant, error) {
	f.asked = append(f.asked, tenant+"/"+id)
	return &Grant{ID: id, Capability: "execute:tool:mcp:crowdstrike-response", GrantedBy: "user-7", GrantedAtUnix: 1700000000}, nil
}

func tenantCtx(t *testing.T) context.Context {
	t.Helper()
	id, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return auth.ContextWithTenant(context.Background(), id)
}

func newGraph() *fakeGraph {
	return &fakeGraph{byQuery: map[string][]map[string]any{
		alertsCypher:  {{"alert_key": "alert-1", "title": "Beacon"}},
		reachedCypher: {{"alert_key": "alert-1", "label": "Host", "key": "host-9"}},
		causesCypher:  {{"finding_key": "f-1", "status": "verified"}},
		fixesCypher:   {{"finding_key": "f-1", "mr_key": "mr-1"}},
	}}
}

// The grant that the event of the call names, and the person who gave it,
// reach each action that ran (gibson#1478). A refused action has no grant, and
// the resolver is not asked for it.
func TestReader_AttachesTheGrantToEachActionThatRan(t *testing.T) {
	grants := &fakeGrants{}
	r, err := NewReader(newGraph(), fakeHistory{history()}, grants)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Report(tenantCtx(t), "inc-1")
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	for _, a := range rep.Actions {
		switch a.Outcome {
		case OutcomeRefused:
			if a.Grant != nil {
				t.Errorf("a refused action has a grant: %+v", a)
			}
		case OutcomeDone, OutcomePending, OutcomeFailed:
			if a.Grant == nil || a.Grant.GrantedBy != "user-7" {
				t.Errorf("action %s has no person who gave the grant: %+v", a.ToolID, a.Grant)
			}
		}
	}
	for _, asked := range grants.asked {
		if asked != "acme/g-1" {
			t.Errorf("the resolver asked %q, want the tenant of the context", asked)
		}
	}
}

// No query carries a tenant. The only parameters are the incident key and the
// limit, so no caller input can name a tenant.
func TestReader_NoQueryTakesATenantFromTheCaller(t *testing.T) {
	g := newGraph()
	r, _ := NewReader(g, fakeHistory{history()}, &fakeGrants{})
	if _, err := r.Report(tenantCtx(t), "inc-1"); err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 4 {
		t.Fatalf("queries = %d, want 4", len(g.calls))
	}
	for _, p := range g.calls {
		if len(p) != 2 || p["incident"] != "inc-1" || p["limit"] == nil {
			t.Errorf("parameters = %v, want only incident and limit", p)
		}
	}
	for _, q := range []string{alertsCypher, reachedCypher, causesCypher, fixesCypher} {
		if strings.Contains(strings.ToLower(q), "tenant") {
			t.Errorf("a query names a tenant: %s", q)
		}
	}
}

func TestReader_RefusesACallWithNoTenantOrNoKey(t *testing.T) {
	r, _ := NewReader(newGraph(), fakeHistory{history()}, &fakeGrants{})
	if _, err := r.Report(context.Background(), "inc-1"); !errors.Is(err, ErrNoTenant) {
		t.Errorf("no tenant: err = %v", err)
	}
	if _, err := r.Report(tenantCtx(t), ""); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("no key: err = %v", err)
	}
	if _, err := r.Report(tenantCtx(t), strings.Repeat("k", maxKeyLen+1)); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("long key: err = %v", err)
	}
}

func TestReader_AnIncidentThatTheGraphDoesNotHoldIsNotFound(t *testing.T) {
	g := &fakeGraph{byQuery: map[string][]map[string]any{}}
	r, _ := NewReader(g, fakeHistory{history()}, &fakeGrants{})
	if _, err := r.Report(tenantCtx(t), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestReader_AGraphErrorIsAnErrorNotAnEmptyReport(t *testing.T) {
	g := &fakeGraph{err: errors.New("boom")}
	r, _ := NewReader(g, fakeHistory{history()}, &fakeGrants{})
	if _, err := r.Report(tenantCtx(t), "inc-1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestNewReader_RequiresEachSource(t *testing.T) {
	if _, err := NewReader(nil, fakeHistory{}, &fakeGrants{}); err == nil {
		t.Error("a nil graph must be refused")
	}
}

// The reach query returns all labels of a node, and the reader picks the same
// one on each read: the first in sort order that the Taxonomy admits
// (review m19).
func TestReachedLabel_IsTheSameOnEachRead(t *testing.T) {
	for _, labels := range [][]any{{"Host", "Asset"}, {"Asset", "Host"}} {
		if got := reachedLabel(map[string]any{"labels": labels}); got != "Host" {
			t.Fatalf("labels %v -> %q, want Host", labels, got)
		}
	}
	if got := reachedLabel(map[string]any{"labels": []any{"Zeta", "Alpha"}}); got != "Alpha" {
		t.Fatalf("no Taxonomy label -> %q, want the first in sort order", got)
	}
	for _, q := range []string{alertsCypher, reachedCypher, causesCypher, fixesCypher} {
		if strings.Contains(q, "coalesce(i.key") || strings.Contains(q, "head(labels") {
			t.Fatalf("a query keeps the form that no index serves: %s", q)
		}
	}
}

// BuildIndex reads the pointer form of an event, as the codec decodes the
// durable history, the same as the value form (review m23).
func TestBuildIndex_ReadsPointerEvents(t *testing.T) {
	value := BuildIndexFrom([]brain.Event{brain.FindingRaised{ID: "f-1"}, brain.FindingStatusChanged{ID: "f-1", Status: "fixing"}}, 0)
	ptr := BuildIndexFrom([]brain.Event{&brain.FindingRaised{ID: "f-1"}, &brain.FindingStatusChanged{ID: "f-1", Status: "fixing"}}, 0)
	if value.findingFrame("f-1") != ptr.findingFrame("f-1") || len(ptr.statusHistory("f-1")) != 1 {
		t.Fatalf("pointer events: frame %+v, history %+v", ptr.findingFrame("f-1"), ptr.statusHistory("f-1"))
	}
}

// The report reads the history from the first sight of the incident and of its
// alerts, less historySlack. A node with no first sight reads all of it. A
// part of the history keeps the positions of the whole history (review R5).
func TestIncidentStart_BoundsTheReadOfTheHistory(t *testing.T) {
	first := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	rows := []map[string]any{
		{"alert_key": "a1", "incident_first_seen": first.Add(time.Minute).UnixMilli(), "alert_first_seen": first.UnixMilli()},
		{"alert_key": "a2", "incident_first_seen": first.Add(time.Minute).UnixMilli(), "alert_first_seen": first.Add(time.Hour).UnixMilli()},
	}
	now := first.Add(24 * time.Hour)
	if got := incidentStart(rows, now); !got.Equal(first.Add(-historySlack)) {
		t.Fatalf("start = %v, want the first alert less the slack", got)
	}
	if got := incidentStart([]map[string]any{{"alert_key": "a1", "incident_first_seen": int64(0)}}, now); !got.Equal(now.Add(-historyLookback)) {
		t.Fatalf("an incident with no first sight: start = %v, want the lookback window", got)
	}
	ix := BuildIndexFrom([]brain.Event{brain.FindingRaised{ID: "f-1"}}, 40)
	if f := ix.findingFrame("f-1"); f.TimelineSeq != 40 || ix.total != 41 {
		t.Fatalf("frame = %+v, total = %d, want the position in the whole history", f, ix.total)
	}
}

type recordingHistory struct{ from []time.Time }

func (h *recordingHistory) HistoryFrom(_ context.Context, from time.Time) ([]brain.Event, uint64, error) {
	h.from = append(h.from, from)
	return nil, 0, nil
}

// A node with no first-seen time does not make the report read the whole
// history (gibson#1583). The read starts at the lookback window.
func TestReport_ANodeWithNoFirstSeenDoesNotReadTheWholeHistory(t *testing.T) {
	g := newGraph()
	g.byQuery[alertsCypher] = []map[string]any{{"alert_key": "alert-1", "title": "Beacon"}} // no first-seen columns
	h := &recordingHistory{}
	r, err := NewReader(g, h, &fakeGrants{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	if _, err := r.Report(tenantCtx(t), "inc-1"); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if len(h.from) != 1 || h.from[0].IsZero() || !h.from[0].Equal(now.Add(-historyLookback)) {
		t.Fatalf("history read from %v, want %v (not the zero time)", h.from, now.Add(-historyLookback))
	}
}
