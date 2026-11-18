// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func TestDecodeFindingFilter_EmptyMeansNoFilter(t *testing.T) {
	// An off-cluster caller that wants everything sends nothing; treating that as
	// a decode error would make the unfiltered query impossible to express.
	f, err := decodeFindingFilter(nil)
	if err != nil {
		t.Fatalf("decodeFindingFilter(nil): %v", err)
	}
	if f != (findingFilter{}) {
		t.Errorf("filter = %+v, want the zero filter", f)
	}
}

func TestDecodeFindingFilter_CarriesEveryField(t *testing.T) {
	raw := []byte(`{"severity":"high","category":"injection","mission_id":"m1","search":"redirect","limit":25,"offset":50}`)
	f, err := decodeFindingFilter(raw)
	if err != nil {
		t.Fatalf("decodeFindingFilter: %v", err)
	}
	want := findingFilter{
		Severity: "high", Category: "injection", MissionID: "m1",
		Search: "redirect", Limit: 25, Offset: 50,
	}
	if f != want {
		t.Errorf("filter = %+v, want %+v", f, want)
	}
}

func TestDecodeFindingFilter_MalformedJSONIsAnError(t *testing.T) {
	// Silently querying unfiltered would return a different result set than the
	// caller asked for — worse than refusing.
	if _, err := decodeFindingFilter([]byte(`{"severity":`)); err == nil {
		t.Fatal("expected an error for malformed filter JSON")
	}
}

// fakeLister answers Find from a fixed list and records the query.
type fakeLister struct {
	findings []finding.EnhancedFinding
	err      error
	tenant   string
	query    pgstore.Query
	calls    int
}

func (f *fakeLister) Find(_ context.Context, tenantID string, q pgstore.Query) ([]finding.EnhancedFinding, int, error) {
	f.calls++
	f.tenant, f.query = tenantID, q
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.findings, len(f.findings), nil
}

func newTestQuerier(l *fakeLister) *PoolFindingQuerier {
	return &PoolFindingQuerier{lister: l, logger: slog.New(slog.DiscardHandler)}
}

func TestFindingToSDKShape_MapsTheStoredFindingToTheSDKs(t *testing.T) {
	out := findingToSDKShape(finding.EnhancedFinding{
		Finding: agent.Finding{
			ID: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e", Title: "open redirect",
			Description: "the login next= parameter is unvalidated", Category: "injection",
			Severity: agent.SeverityHigh, SubmittedBy: "agent_principal:sa-1",
			Evidence: []*typespb.Evidence{{Content: "must not appear"}},
		},
		AgentName: "zerocool-demo",
	})
	if out["title"] != "open redirect" || out["category"] != "injection" || out["severity"] != "high" {
		t.Errorf("mapped %+v, want the SDK field names", out)
	}
	if out["agent_name"] != "zerocool-demo" {
		t.Errorf("agent_name = %v", out["agent_name"])
	}
	if md, ok := out["metadata"].(map[string]any); !ok || md["submitted_by"] != "agent_principal:sa-1" {
		t.Errorf("metadata = %v, want submitted_by", out["metadata"])
	}
	if _, has := out["evidence"]; has {
		t.Error("a list holds no evidence")
	}
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("mapped finding does not encode: %v", err)
	}
}

func TestPoolFindingQuerier_InvalidTenantIsRejectedBeforeTheQuery(t *testing.T) {
	l := &fakeLister{}
	if _, err := newTestQuerier(l).GetFindings(context.Background(), "NOT A TENANT", nil); err == nil {
		t.Fatal("expected an error for a malformed tenant")
	}
	if l.calls != 0 {
		t.Error("the store was asked for a tenant that does not parse")
	}
}

func TestPoolFindingQuerier_BadFilterFailsBeforeTheQuery(t *testing.T) {
	l := &fakeLister{}
	if _, err := newTestQuerier(l).GetFindings(context.Background(), "acme", []byte(`{"limit":`)); err == nil {
		t.Fatal("expected an error for a malformed filter")
	}
	if l.calls != 0 {
		t.Error("the store was asked to serve a request that could never run")
	}
}

func TestGetRunFindings_MalformedFilterIsRejected(t *testing.T) {
	_, err := newTestQuerier(&fakeLister{}).GetRunFindings(context.Background(), "acme", "w1", "previous", []byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for a malformed filter")
	}
	if !strings.Contains(err.Error(), "decode filter") {
		t.Errorf("error = %v, want it to name the decode failure", err)
	}
}

func TestPoolFindingQuerier_ReturnsJSONTheCallerCanDecode(t *testing.T) {
	l := &fakeLister{findings: []finding.EnhancedFinding{{Finding: agent.Finding{ID: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e", Title: "x"}}}}

	out, err := newTestQuerier(l).GetFindings(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	var decoded []map[string]any
	if jErr := json.Unmarshal(out, &decoded); jErr != nil || len(decoded) != 1 {
		t.Fatalf("GetFindings returned %s (%v)", out, jErr)
	}
	if l.tenant != "acme" {
		t.Errorf("tenant = %q", l.tenant)
	}
}

func TestPoolFindingQuerier_EmptyResultIsAnEmptyArrayNotNull(t *testing.T) {
	out, err := newTestQuerier(&fakeLister{}).GetFindings(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if strings.TrimSpace(string(out)) != "[]" {
		t.Errorf("empty result = %s, want []", out)
	}
}

func TestPoolFindingQuerier_QueryFailureIsReported(t *testing.T) {
	if _, err := newTestQuerier(&fakeLister{err: errors.New("postgres down")}).GetFindings(context.Background(), "acme", nil); err == nil {
		t.Fatal("expected the query failure to surface")
	}
}

func TestGetRunFindings_FilterFieldsSurviveToTheQuery(t *testing.T) {
	// The filter is the caller's whole request; dropping a field would answer a
	// different question than the one asked.
	l := &fakeLister{}
	mission := "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e"
	_, err := newTestQuerier(l).GetRunFindings(context.Background(), "acme", "", "all",
		[]byte(`{"severity":"high","category":"injection","search":"redirect","mission_id":"`+mission+`","limit":10,"offset":5}`))
	if err != nil {
		t.Fatalf("GetRunFindings: %v", err)
	}
	q := l.query
	if q.Category != "injection" || q.Search != "redirect" || q.Limit != 10 || q.Offset != 5 ||
		string(q.MissionID) != mission || len(q.Severities) != 1 || q.Severities[0] != "high" {
		t.Errorf("query = %+v", q)
	}
}

func TestGetRunFindings_PreviousScopeNarrowsToTheWorkItemsMission(t *testing.T) {
	l := &fakeLister{}
	work := "6c5c9f0f-9f9f-4d9f-8f9f-9f9f9f9f9f9f"
	q := newTestQuerier(l)

	if _, err := q.GetRunFindings(context.Background(), "acme", work, "previous", nil); err != nil {
		t.Fatal(err)
	}
	if string(l.query.MissionID) != work {
		t.Errorf("scope=previous mission = %q, want %q", l.query.MissionID, work)
	}
	if _, err := q.GetRunFindings(context.Background(), "acme", "", "previous", nil); err != nil {
		t.Fatal(err)
	}
	if l.query.MissionID != "" {
		t.Errorf("no work item: want the unscoped query, got mission %q", l.query.MissionID)
	}
	// A mission that is not a UUID matches no finding. The store is not asked.
	l.calls = 0
	out, err := q.GetRunFindings(context.Background(), "acme", "w1", "previous", nil)
	if err != nil || strings.TrimSpace(string(out)) != "[]" || l.calls != 0 {
		t.Errorf("non-UUID work id: out=%s err=%v calls=%d", out, err, l.calls)
	}
}
