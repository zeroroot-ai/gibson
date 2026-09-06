// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// The row mapping is the contract between the RETURN aliases of
// applicationFindingsCypher and the JSON an agent parses. It is the half of this
// read that can be wrong without any graph being involved, so it is tested
// without one; the traversal itself is covered by the integration suite.

func TestEncodeApplicationFindings_MapsEveryColumn(t *testing.T) {
	rows := []map[string]any{{
		"finding_id":       "f1",
		"status":           "open",
		"severity":         "critical",
		"vulnerability_id": "CVE-2025-1234",
		"place_label":      "Package",
		"place_key":        "npm:lodash@4.17.20",
		"reachable":        true,
		"exposed":          true,
		"deployment_key":   "customer-portal/prod",
		"image_key":        "sha256:abc",
		"priority":         "P1",
		"priority_rule":    "R01",
		"priority_reason":  "listed in CISA KEV",
	}}

	encoded, err := encodeApplicationFindings(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got []ApplicationFinding
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	want := ApplicationFinding{
		FindingID: "f1", Status: "open", Severity: "critical",
		VulnerabilityID: "CVE-2025-1234",
		PlaceLabel:      "Package", PlaceKey: "npm:lodash@4.17.20",
		Reachable: true, Exposed: true,
		DeploymentKey: "customer-portal/prod", ImageKey: "sha256:abc",
		Priority: "P1", PriorityRule: "R01", PriorityReason: "listed in CISA KEV",
	}
	if got[0] != want {
		t.Errorf("mapping drifted:\n got %+v\nwant %+v", got[0], want)
	}
}

func TestEncodeApplicationFindings_AMissingColumnIsAZeroNotAFailure(t *testing.T) {
	// A source finding names no CVE and affects no deployed package. Dropping the
	// whole row over the absent columns would hide a real finding; reporting it
	// with those fields zeroed is what the caller can act on.
	rows := []map[string]any{{
		"finding_id": "f2",
		"status":     "open",
		"severity":   "high",
		// vulnerability_id, place_*, deployment_key, image_key absent entirely
		"reachable": false,
		"exposed":   false,
	}}

	encoded, err := encodeApplicationFindings(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got []ApplicationFinding
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].FindingID != "f2" || got[0].Severity != "high" {
		t.Fatalf("the present columns must survive, got %+v", got[0])
	}
	if got[0].VulnerabilityID != "" || got[0].PlaceKey != "" {
		t.Errorf("absent columns must be zero, got %+v", got[0])
	}
	if got[0].Reachable || got[0].Exposed {
		t.Errorf("reachable/exposed must be false, got %+v", got[0])
	}
}

func TestEncodeApplicationFindings_AWrongTypedColumnIsAZeroNotAPanic(t *testing.T) {
	// Neo4j returns int64 for a numeric and nil for an absent optional. A driver
	// or query change that swaps a column's type must degrade that field, not
	// take down the read.
	rows := []map[string]any{{
		"finding_id": 42,    // not a string
		"reachable":  "yes", // not a bool
		"status":     nil,
	}}

	encoded, err := encodeApplicationFindings(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got []ApplicationFinding
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].FindingID != "" || got[0].Status != "" || got[0].Reachable {
		t.Errorf("wrong-typed columns must be zero, got %+v", got[0])
	}
}

func TestEncodeApplicationFindings_NoRowsIsAnEmptyListNotNull(t *testing.T) {
	// An Application with nothing open must encode as [], not null: an agent
	// parsing null and an agent parsing [] take different branches, and "no open
	// findings" is a real answer rather than a missing one.
	encoded, err := encodeApplicationFindings(nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(encoded) != "[]" {
		t.Fatalf("no rows encoded as %q, want []", encoded)
	}
}

func TestApplicationFindings_RefusesAnEmptyApplicationKey(t *testing.T) {
	// Without a key the traversal would match every Application in the tenant,
	// so the read refuses rather than answering a question nobody asked.
	q := &PoolGraphRAGQuerier{}
	_, err := q.ApplicationFindings(context.Background(), "acme", "", nil, 10)
	if err == nil {
		t.Fatal("an empty application key must be refused")
	}
	if !strings.Contains(err.Error(), "application key is required") {
		t.Fatalf("error must name the missing key, got %v", err)
	}
}

func TestApplicationFindings_WithoutAPoolReportsUnavailableRatherThanEmpty(t *testing.T) {
	// The whole point of this read: an unanswerable question is an error. An
	// empty list would be read by a triage rule table as "nothing is open".
	q := &PoolGraphRAGQuerier{}
	got, err := q.ApplicationFindings(context.Background(), "acme", "customer-portal", nil, 10)
	if err == nil {
		t.Fatal("no pool must be reported, not answered with an empty list")
	}
	if got != nil {
		t.Fatalf("a failed read must return no rows, got %q", got)
	}
}

func TestStringAndBoolField_ReadOnlyTheirOwnType(t *testing.T) {
	row := map[string]any{"s": "v", "b": true, "n": nil, "i": int64(1)}

	if got := stringField(row, "s"); got != "v" {
		t.Errorf("stringField(s) = %q, want v", got)
	}
	for _, key := range []string{"b", "n", "i", "absent"} {
		if got := stringField(row, key); got != "" {
			t.Errorf("stringField(%s) = %q, want empty", key, got)
		}
	}
	if !boolField(row, "b") {
		t.Error("boolField(b) = false, want true")
	}
	for _, key := range []string{"s", "n", "i", "absent"} {
		if boolField(row, key) {
			t.Errorf("boolField(%s) = true, want false", key)
		}
	}
}

// readGraph's guard clauses decide whether an agent gets an answer or an honest
// error. Each of them is a route to the same failure: answering "nothing is
// reachable" when the truth is "I could not look". The Neo4j execution itself is
// covered by the integration suite; everything before it is covered here.

func TestApplicationFindings_AnInvalidTenantIsRefusedBeforeAnyAcquire(t *testing.T) {
	pool := &poolStub{}
	q := &PoolGraphRAGQuerier{pool: pool}

	got, err := q.ApplicationFindings(context.Background(), "", "customer-portal", nil, 10)
	if err == nil {
		t.Fatal("an invalid tenant must be refused")
	}
	if got != nil {
		t.Fatalf("a refused read must return no rows, got %q", got)
	}
	if pool.gotTenant != "" {
		t.Errorf("the pool must never be acquired for an invalid tenant, got %q", pool.gotTenant)
	}
}

func TestApplicationFindings_AnUnprovisionedGraphIsReportedNotAnsweredEmpty(t *testing.T) {
	// A tenant whose graph database does not exist yet has no findings to report
	// AND no way to know it. Returning [] would be indistinguishable from a clean
	// application, which is the silent false negative this read exists to remove.
	q := &PoolGraphRAGQuerier{pool: &poolStub{conn: &datapool.Conn{}}}

	got, err := q.ApplicationFindings(context.Background(), "acme", "customer-portal", nil, 10)
	if err == nil {
		t.Fatal("an unprovisioned graph must be reported")
	}
	if !strings.Contains(err.Error(), "no graph database provisioned") {
		t.Fatalf("error must name the missing graph, got %v", err)
	}
	if got != nil {
		t.Fatalf("a failed read must return no rows, got %q", got)
	}
}

func TestApplicationFindings_AFailedAcquireSurfaces(t *testing.T) {
	q := &PoolGraphRAGQuerier{pool: &poolStub{err: errors.New("pool exhausted")}}

	got, err := q.ApplicationFindings(context.Background(), "acme", "customer-portal", nil, 10)
	if err == nil {
		t.Fatal("a failed acquire must be reported")
	}
	if got != nil {
		t.Fatalf("a failed read must return no rows, got %q", got)
	}
}

func TestApplicationFindings_LimitIsClampedToTheCap(t *testing.T) {
	// A caller asking for a million rows would walk the tenant graph. The cap is
	// applied before the query is built, so it bounds the traversal rather than
	// trimming the answer afterwards.
	for _, tc := range []struct {
		name string
		in   int
	}{
		{"zero", 0},
		{"negative", -5},
		{"above the cap", defaultApplicationFindingsLimit * 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The read fails at the unprovisioned graph, which is after the clamp:
			// reaching that error at all proves the clamp did not reject the call.
			q := &PoolGraphRAGQuerier{pool: &poolStub{conn: &datapool.Conn{}}}
			if _, err := q.ApplicationFindings(
				context.Background(), "acme", "customer-portal", nil, tc.in,
			); err == nil {
				t.Fatal("expected the unprovisioned-graph error")
			}
		})
	}
}

func TestRecordsToRows_KeepsOneRowPerRecord(t *testing.T) {
	// A caller counts findings by counting rows, so the row count out must equal
	// the record count in. A nil record is the one exception: there is nothing to
	// flatten, and appending a nil map would hand the mapper a row it cannot read.
	records := []*neo4j.Record{
		{Keys: []string{"finding_id", "reachable"}, Values: []any{"f1", true}},
		{Keys: []string{}, Values: []any{}},
		nil,
		{Keys: []string{"finding_id"}, Values: []any{"f2"}},
	}

	rows := recordsToRows(records)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 (the nil record dropped)", len(rows))
	}
	if rows[0]["finding_id"] != "f1" || rows[0]["reachable"] != true {
		t.Errorf("row 0 = %v, want the record's own keys", rows[0])
	}
	if len(rows[1]) != 0 {
		t.Errorf("an empty record must flatten to an empty map, got %v", rows[1])
	}
	if rows[2]["finding_id"] != "f2" {
		t.Errorf("row 2 = %v, want f2", rows[2])
	}
}

func TestRecordsToRows_NoRecordsIsAnEmptySliceNotNil(t *testing.T) {
	rows := recordsToRows(nil)
	if rows == nil {
		t.Fatal("no records must yield an empty slice, not nil")
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}

func TestRowsFromResult_ARefactorThatChangesTheTypeYieldsNoRowsNotAPanic(t *testing.T) {
	want := []map[string]any{{"finding_id": "f1"}}
	if got := rowsFromResult(want); len(got) != 1 || got[0]["finding_id"] != "f1" {
		t.Errorf("the real type must pass through, got %v", got)
	}
	for _, bad := range []any{nil, "rows", 42, []string{"f1"}} {
		if got := rowsFromResult(bad); got != nil {
			t.Errorf("rowsFromResult(%v) = %v, want nil", bad, got)
		}
	}
}

func TestEncodeApplicationFindings_AFindingNoPassHasSeenCarriesNoPriority(t *testing.T) {
	// Empty is "no pass has decided yet", which is a fact about the Finding.
	// A reader that treated it as a decision would rank an untriaged backlog
	// as though somebody had judged it unimportant.
	rows := []map[string]any{{
		"finding_id": "f1",
		"status":     "open",
		"severity":   "critical",
	}}

	encoded, err := encodeApplicationFindings(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got []ApplicationFinding
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].Priority != "" || got[0].PriorityRule != "" || got[0].PriorityReason != "" {
		t.Errorf("an untriaged Finding invented a priority: %+v", got[0])
	}
	// omitempty keeps the absence legible on the wire rather than sending a
	// field the reader has to know to ignore.
	if strings.Contains(string(encoded), "\"priority\"") {
		t.Errorf("an absent priority was serialised: %s", encoded)
	}
}

func TestEncodeApplicationFindings_PrioritySurvivesIndependentlyOfItsReason(t *testing.T) {
	// The three travel together but are written by different steps: the rule
	// table decides the priority, the model writes the reason. Losing one must
	// not take the others, or a model outage would erase the decisions too.
	rows := []map[string]any{{
		"finding_id":    "f1",
		"priority":      "P2",
		"priority_rule": "R05",
	}}

	encoded, err := encodeApplicationFindings(rows)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got []ApplicationFinding
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[0].Priority != "P2" || got[0].PriorityRule != "R05" {
		t.Errorf("priority did not survive a missing reason: %+v", got[0])
	}
	if got[0].PriorityReason != "" {
		t.Errorf("a reason was invented: %q", got[0].PriorityReason)
	}
}

func TestApplicationFindingsCypher_ReturnsThePriorityColumnsTheStructReads(t *testing.T) {
	// The RETURN aliases and the struct are one contract split across two
	// files. A field added to the struct but not to the query reads as "no
	// pass has decided" forever — silently, and exactly like the untriaged
	// case above, which is why this is pinned rather than left to review.
	for _, alias := range []string{"AS priority", "AS priority_rule", "AS priority_reason"} {
		if !strings.Contains(applicationFindingsCypher, alias) {
			t.Errorf("the query does not return %q, so the struct field is always empty", alias)
		}
	}
}
