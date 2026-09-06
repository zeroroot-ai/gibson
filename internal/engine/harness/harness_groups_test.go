// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"reflect"
	"sort"
	"testing"
)

// AgentHarness must satisfy every capability group it is composed of. Dropping
// or renaming a group fails the build here rather than silently shrinking the
// interface.
//
// Group names are shared with the SDK's agent.Harness deliberately; see
// sdk docs/adr/0002-harness-capability-groups.md.
var (
	_ LLMCaller       = AgentHarness(nil)
	_ ToolCaller      = AgentHarness(nil)
	_ PluginCaller    = AgentHarness(nil)
	_ Delegator       = AgentHarness(nil)
	_ WorldEmitter    = AgentHarness(nil)
	_ KnowledgeReader = AgentHarness(nil)
	_ WorkspaceAccess = AgentHarness(nil)
)

// TestAgentHarnessMethodSetUnchanged pins the method set across the grouping
// refactor, which is meant to be purely structural.
func TestAgentHarnessMethodSetUnchanged(t *testing.T) {
	want := []string{
		"CallToolProto", "CallToolProtoStream", "ListTools",
		"GetToolDescriptor", "GetToolCapabilities", "GetAllToolCapabilities",
		"Complete", "CompleteWithTools", "Stream",
		"CompleteStructuredAny", "CompleteStructuredAnyWithUsage",
		"DelegateToAgent", "ListAgents",
		"GetFindings", "GetMissionRunHistory", "GetRunFindings",
		// Graph reads, added deliberately (#492): the daemon-side harness had no
		// graph surface at all, which is why a dispatched agent could not read
		// the tenant graph.
		"QueryNodes", "FindSimilarAttacks", "GetAttackChains",
		"FindSimilarFindings", "GetRelatedFindings",
		// ApplicationFindings is a traversal rather than a search, added because
		// the reads above could not answer whether a running Deployment actually
		// contains the code a Finding affects (gibson#1669).
		"ApplicationFindings",
		"ListPlugins", "QueryPlugin",
		"Logger", "Metrics", "Mission", "MissionExecutionContext", "MissionID",
		"SubmitFinding", "Target", "TokenUsage", "Tracer",
		"Workspace", "Workspaces",
	}
	sort.Strings(want)

	tp := reflect.TypeOf((*AgentHarness)(nil)).Elem()
	got := make([]string, 0, tp.NumMethod())
	for i := range tp.NumMethod() {
		got = append(got, tp.Method(i).Name)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("AgentHarness has %d methods, expected %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("method set differs at %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestGroupsAreDisjoint catches a method landing in two groups: it still
// compiles, still satisfies AgentHarness, and leaves nobody able to say which
// group owns it.
func TestGroupsAreDisjoint(t *testing.T) {
	groups := map[string]reflect.Type{
		"LLMCaller":       reflect.TypeOf((*LLMCaller)(nil)).Elem(),
		"ToolCaller":      reflect.TypeOf((*ToolCaller)(nil)).Elem(),
		"PluginCaller":    reflect.TypeOf((*PluginCaller)(nil)).Elem(),
		"Delegator":       reflect.TypeOf((*Delegator)(nil)).Elem(),
		"WorldEmitter":    reflect.TypeOf((*WorldEmitter)(nil)).Elem(),
		"KnowledgeReader": reflect.TypeOf((*KnowledgeReader)(nil)).Elem(),
		"WorkspaceAccess": reflect.TypeOf((*WorkspaceAccess)(nil)).Elem(),
	}
	owner := map[string]string{}
	for name, tp := range groups {
		for i := range tp.NumMethod() {
			m := tp.Method(i).Name
			if prev, dup := owner[m]; dup {
				t.Errorf("method %q is in both %s and %s; a method belongs to exactly one group", m, prev, name)
				continue
			}
			owner[m] = name
		}
	}
}

// TestKnowledgeReaderConvergedWithTheSDK records that the asymmetry this epic
// existed to close is closed.
//
// This test previously asserted the OPPOSITE — four reads here, none of the five
// graph ones — and it was written to fail the moment that changed, so that
// closing the gap had to be a deliberate act touching both sides. This is that
// act. The daemon-side KnowledgeReader now carries the same reads the SDK's
// does; a dispatched agent can read the tenant graph.
//
// It is nine since sdk#537: ApplicationFindings is a traversal, not a search,
// added because none of the others could answer whether a running Deployment
// actually contains the code a Finding affects (gibson#1669). The count stays
// pinned so the next addition is as deliberate as this one.
func TestKnowledgeReaderConvergedWithTheSDK(t *testing.T) {
	tp := reflect.TypeOf((*KnowledgeReader)(nil)).Elem()
	if got := tp.NumMethod(); got != 9 {
		t.Fatalf("daemon-side KnowledgeReader has %d reads, expected 9", got)
	}
	for _, graphRead := range []string{"QueryNodes", "FindSimilarAttacks", "GetAttackChains", "FindSimilarFindings", "GetRelatedFindings", "ApplicationFindings"} {
		if _, ok := tp.MethodByName(graphRead); !ok {
			t.Errorf("%s is missing; a dispatched agent cannot read the graph without it", graphRead)
		}
	}
	// The two scope-specific run reads collapsed into one that takes a scope.
	for _, gone := range []string{"GetPreviousRunFindings", "GetAllRunFindings"} {
		if _, ok := tp.MethodByName(gone); ok {
			t.Errorf("%s still exists; it should have collapsed into GetRunFindings(scope)", gone)
		}
	}
}
