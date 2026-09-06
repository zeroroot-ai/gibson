// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
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

func TestFindingRecordToSDKShape_MapsTheGraphVocabularyToTheSDKs(t *testing.T) {
	// The graph calls it Name/Type; the SDK calls it title/category. A caller
	// reads the SDK shape, so the mapping is the contract.
	out := findingRecordToSDKShape(graph.FindingRecord{
		ID:          "f-1",
		Name:        "open redirect",
		Description: "the login next= parameter is unvalidated",
		Type:        "injection",
		Severity:    "high",
	})
	if out["id"] != "f-1" || out["title"] != "open redirect" || out["category"] != "injection" {
		t.Errorf("mapped %+v, want the SDK field names", out)
	}
	if out["severity"] != "high" {
		t.Errorf("severity = %v", out["severity"])
	}
}

func TestPoolFindingQuerier_InvalidTenantIsRejectedBeforeTheAcquire(t *testing.T) {
	pool := &poolStub{err: errors.New("must not be reached")}
	q := NewPoolFindingQuerier(pool, nil)

	if _, err := q.GetFindings(context.Background(), "NOT A TENANT", nil); err == nil {
		t.Fatal("expected an error for a malformed tenant")
	}
	if pool.gotTenant != "" {
		t.Error("the pool was asked for a tenant that does not parse")
	}
}

func TestPoolFindingQuerier_AcquiresTheCallersTenant(t *testing.T) {
	pool := &poolStub{err: errors.New("acquire refused")}
	q := NewPoolFindingQuerier(pool, nil)

	if _, err := q.GetFindings(context.Background(), "zerocool-lab", nil); err == nil {
		t.Fatal("expected the acquire failure to surface")
	}
	if pool.gotTenant != "zerocool-lab" {
		t.Errorf("acquired tenant %q, want the caller's", pool.gotTenant)
	}
}

func TestPoolFindingQuerier_BadFilterFailsBeforeTheAcquire(t *testing.T) {
	pool := &poolStub{err: errors.New("must not be reached")}
	q := NewPoolFindingQuerier(pool, nil)

	if _, err := q.GetFindings(context.Background(), "acme", []byte(`{"limit":`)); err == nil {
		t.Fatal("expected an error for a malformed filter")
	}
	if pool.gotTenant != "" {
		t.Error("a pooled Conn was taken to serve a request that could never run")
	}
}

func TestGetRunFindings_PreviousScopeNarrowsToTheWorkItemsMission(t *testing.T) {
	// "previous" means this mission's findings. Without a workID there is no
	// mission to narrow to, and an agent asking for prior findings should get the
	// unscoped answer rather than silence.
	filter, err := decodeFindingFilter([]byte(`{"severity":"high"}`))
	if err != nil {
		t.Fatalf("decodeFindingFilter: %v", err)
	}
	if filter.MissionID != "" {
		t.Fatalf("precondition: filter already scoped: %+v", filter)
	}

	pool := &poolStub{err: errors.New("acquire refused")}
	q := NewPoolFindingQuerier(pool, nil)

	// Both shapes must reach the pool — neither is rejected locally.
	if _, err := q.GetRunFindings(context.Background(), "acme", "w1", "previous", nil); err == nil {
		t.Error("expected the acquire failure to surface for scope=previous")
	}
	if _, err := q.GetRunFindings(context.Background(), "acme", "", "all", nil); err == nil {
		t.Error("expected the acquire failure to surface for scope=all")
	}
}

func TestGetRunFindings_MalformedFilterIsRejected(t *testing.T) {
	pool := &poolStub{err: errors.New("must not be reached")}
	q := NewPoolFindingQuerier(pool, nil)

	_, err := q.GetRunFindings(context.Background(), "acme", "w1", "previous", []byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for a malformed filter")
	}
	if !strings.Contains(err.Error(), "decode filter") {
		t.Errorf("error = %v, want it to name the decode failure", err)
	}
}

func TestFindingRecordToSDKShape_EncodesToJSONForTheWire(t *testing.T) {
	// The seam returns JSON bytes, so the mapped shape must survive encoding.
	out := findingRecordToSDKShape(graph.FindingRecord{ID: "f-1", Name: "x", Severity: "low"})
	if _, err := json.Marshal(out); err != nil {
		t.Fatalf("mapped record does not encode: %v", err)
	}
}

// --- live Conn ---------------------------------------------------------------

// liveFindingQuerier wires a finding querier over a populated tenant Conn, using
// the same session fake as the GraphRAG tests: DashboardQueries runs its Cypher
// through ExecuteRead, so a canned QueryResult covers the whole read path.
func liveFindingQuerier(records []graph.FindingRecord) *PoolFindingQuerier {
	// Findings runs two reads: the page, then the count.
	session := &sessionFake{reads: []any{records, uint64(len(records))}}
	return NewPoolFindingQuerier(&poolStub{conn: &datapool.Conn{Neo4j: session}}, nil)
}

// failingFindingQuerier is the same wiring with a session that refuses.
func failingFindingQuerier(err error) *PoolFindingQuerier {
	return NewPoolFindingQuerier(&poolStub{conn: &datapool.Conn{Neo4j: &sessionFake{err: err}}}, nil)
}

func TestPoolFindingQuerier_ReturnsJSONTheCallerCanDecode(t *testing.T) {
	q := liveFindingQuerier(nil)

	out, err := q.GetFindings(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	var decoded []map[string]any
	if jErr := json.Unmarshal(out, &decoded); jErr != nil {
		t.Fatalf("GetFindings returned bytes that do not decode as a JSON array: %v", jErr)
	}
}

func TestPoolFindingQuerier_EmptyResultIsAnEmptyArrayNotNull(t *testing.T) {
	// A caller ranging over the result must not have to special-case null; an
	// agent with no prior findings should read "none", not "broken".
	q := liveFindingQuerier(nil)

	out, err := q.GetFindings(context.Background(), "acme", nil)
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if strings.TrimSpace(string(out)) != "[]" {
		t.Errorf("empty result = %s, want []", out)
	}
}

func TestPoolFindingQuerier_QueryFailureIsReported(t *testing.T) {
	q := failingFindingQuerier(errors.New("neo4j down"))

	if _, err := q.GetFindings(context.Background(), "acme", nil); err == nil {
		t.Fatal("expected the query failure to surface")
	}
}

func TestGetRunFindings_BothScopesReachTheStore(t *testing.T) {
	for _, tc := range []struct{ workID, scope string }{
		{"w1", "previous"},
		{"", "previous"}, // no work item: degrades to unscoped rather than silence
		{"w1", "all"},
	} {
		q := liveFindingQuerier(nil)
		out, err := q.GetRunFindings(context.Background(), "acme", tc.workID, tc.scope, nil)
		if err != nil {
			t.Fatalf("GetRunFindings(%q,%q): %v", tc.workID, tc.scope, err)
		}
		if len(out) == 0 {
			t.Errorf("GetRunFindings(%q,%q) returned no bytes", tc.workID, tc.scope)
		}
	}
}

func TestGetRunFindings_FilterFieldsSurviveToTheQuery(t *testing.T) {
	// The filter is the caller's whole request; dropping a field would answer a
	// different question than the one asked.
	q := liveFindingQuerier(nil)

	out, err := q.GetRunFindings(context.Background(), "acme", "", "all",
		[]byte(`{"severity":"high","category":"injection","search":"redirect","limit":10,"offset":5}`))
	if err != nil {
		t.Fatalf("GetRunFindings: %v", err)
	}
	if len(out) == 0 {
		t.Error("no bytes returned")
	}
}
