// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"regexp"
	"strings"
	"testing"
)

// gibson#550: GetMissionGraph traversed an edge direction nothing writes, so a
// live registered RPC — /gibson.graph.v1.GraphService/GetMissionGraph — answered
// every call with an empty graph. These tests pin the directions, because a
// reader and a writer disagreeing about one is invisible without a database.

// TestMissionGraphCypher_DoesNotTraverseIntoARun is the regression. The only
// BELONGS_TO anything writes is (MissionRun)-[:BELONGS_TO]->(Mission). Nothing
// writes an edge INTO a run, so matching one meant zero rows.
func TestMissionGraphCypher_DoesNotTraverseIntoARun(t *testing.T) {
	intoARun := regexp.MustCompile(`-\[:BELONGS_TO\]->\(\s*(run|r)\s*[:)]`)
	if loc := intoARun.FindString(missionGraphCypher); loc != "" {
		t.Errorf("the query traverses INTO a run (%q); nothing writes that edge, so it returns nothing:\n%s",
			loc, missionGraphCypher)
	}
}

// TestMissionGraphCypher_TraversesTheWrittenDirections: each OPTIONAL MATCH has
// to name an edge some writer produces, in the direction it produces it.
func TestMissionGraphCypher_TraversesTheWrittenDirections(t *testing.T) {
	// Each entry is the pattern the query must contain, paired with the writer
	// that produces that edge in that direction.
	for _, want := range []struct{ pattern, writtenBy string }{
		{"(mn:MissionNode)-[:PART_OF]->(m)", "queries.CreateMissionNode"},
		{"(r:MissionRun)-[:BELONGS_TO]->(m)", "queries.CreateMissionRun"},
		{"(m)-[:TARGETS]->(t:Target)", "the projector's upsertTargetCypher"},
	} {
		if !strings.Contains(missionGraphCypher, want.pattern) {
			t.Errorf("the query does not traverse %s, which %s writes", want.pattern, want.writtenBy)
		}
	}
}

// TestMissionGraphCypher_AnchorsOnTheMissionAndOptionalsTheRest: the original
// used a second non-OPTIONAL MATCH, so one empty leg emptied the whole result.
// A mission with no runs yet must still return its own node.
func TestMissionGraphCypher_AnchorsOnTheMissionAndOptionalsTheRest(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(missionGraphCypher), "\n")
	var matches []string
	for _, l := range lines {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "MATCH ") || strings.HasPrefix(t, "OPTIONAL MATCH ") {
			matches = append(matches, t)
		}
	}
	if len(matches) < 2 {
		t.Fatalf("found %d MATCH clauses; the query was reshaped and these assertions no longer apply", len(matches))
	}
	if !strings.HasPrefix(matches[0], "MATCH (m:Mission") {
		t.Errorf("the query does not anchor on the Mission; first clause is %q", matches[0])
	}
	for _, m := range matches[1:] {
		if !strings.HasPrefix(m, "OPTIONAL MATCH ") {
			t.Errorf("clause %q is not OPTIONAL; one empty leg would empty the whole result, "+
				"which is exactly how this query returned nothing", m)
		}
	}
}

// TestMissionGraphCypher_UsesThePromotedLabelCase: Neo4j labels are case
// sensitive, and the lowercase :mission_run could never carry a Taxonomy
// uniqueness constraint because constraintStatements only emits PascalCase.
func TestMissionGraphCypher_UsesThePromotedLabelCase(t *testing.T) {
	lowercase := regexp.MustCompile(`\(\s*\w*\s*:(mission_run|mission_node|mission)\b`)
	if loc := lowercase.FindString(missionGraphCypher); loc != "" {
		t.Errorf("the query uses a lowercase label (%q); Neo4j labels are case sensitive, "+
			"so it matches no node the writers create", loc)
	}
}
