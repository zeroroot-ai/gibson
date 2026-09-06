// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strings"
	"testing"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc"
)

// The emit contract is append-only (ADR-0012, "Write contract"): an agent emits
// observations, and the reducer folds while the projector materialises. It never
// updates or deletes. Deletion is a platform operation on the Timeline, not an
// agent capability — which removes a whole class of question (there is no update
// path to authorise) and means a compromised tool cannot erase the evidence of
// itself.
//
// This file is the guard on that property. "An emit attempting to modify an
// existing node has no such path to call" is not a runtime check — there is
// nothing to reject, because the RPC does not exist — so the way to test it is
// to assert the absence over the real, generated service descriptors.

// mutatingVerbs are the leading verbs that name a write against state that is
// already there. Append verbs (Submit, Observe, Report, Record, Register,
// Queue, Create, Enqueue) are deliberately absent: appending is the whole point
// of the emit path.
var mutatingVerbs = []string{
	"Update", "Delete", "Remove", "Patch", "Drop", "Overwrite",
	"Modify", "Set", "Store", "Write", "Merge", "Prune", "Purge",
	"Truncate", "Replace", "Edit", "Detach",
}

// graphNouns are the things the Knowledge graph is made of. A method only trips
// the guard when a mutating verb is applied to one of these: the agent surface
// legitimately mutates other kinds of state (plugin configuration, workspace
// files, mission lifecycle), and conflating those with graph writes would make
// the guard fire on things ADR-0012 does not govern.
var graphNouns = []string{
	"Node", "Relationship", "Edge", "Entity", "Graph", "Observation",
	"Finding", "Host", "Port", "Domain", "Subdomain", "Account",
	"Credential", "Attack", "Taxonomy",
}

// mutatesExistingGraphState reports whether an RPC name reads as a mutation of
// graph state that already exists — the shape of call ADR-0012 says must not be
// reachable by an agent.
func mutatesExistingGraphState(method string) bool {
	verb := ""
	for _, v := range mutatingVerbs {
		if strings.HasPrefix(method, v) {
			verb = v
			break
		}
	}
	if verb == "" {
		return false
	}
	rest := method[len(verb):]
	for _, n := range graphNouns {
		if strings.Contains(rest, n) {
			return true
		}
	}
	return false
}

// TestMutatesExistingGraphStateFires is the guard on the guard. A predicate that
// silently never matches would make TestAgentSurfaceIsAppendOnly pass for the
// wrong reason, so the classifier is pinned against both the names it must catch
// and the names it must not.
func TestMutatesExistingGraphStateFires(t *testing.T) {
	mustCatch := []string{
		// The generic graph-write RPCs ADR-0012 rejects. sdk#451 already
		// removed these from ComponentService; naming them here is what stops
		// them coming back unnoticed.
		"StoreNode",
		"StoreRelationship",
		// Shapes nobody has proposed, listed so the predicate is pinned to the
		// property rather than to two historical names.
		"UpdateNode", "DeleteFinding", "RemoveEntity", "PatchHost",
		"DropGraph", "MergeNode", "OverwriteObservation", "PurgeFindings",
		"SetCredentialProperties", "WriteEdge", "DetachRelationship",
	}
	for _, name := range mustCatch {
		if !mutatesExistingGraphState(name) {
			t.Errorf("%s is a graph mutation but the guard does not catch it", name)
		}
	}

	mustNotCatch := []string{
		// Appends. These are the emit path and must stay callable.
		"SubmitFinding", "Observe", "SubmitResult", "RecordSpan", "RegisterComponent",
		"CreateMission", "QueueToolWork", "ReportStepHints",
		// Reads.
		"QueryNodes", "GetFindings", "FindSimilarFindings", "GetRelatedFindings",
		"ValidateGraphNode", "ValidateRelationship", "GenerateNodeID",
		"GetTaxonomySchema", "GetAttackChains", "ListAgents",
		// Mutations of state that is not the graph. ADR-0012 governs graph
		// ingress; plugin configuration, workspace files and mission lifecycle
		// are different surfaces with their own authorisation.
		"UpdatePluginConfig", "EnablePlugin", "DisablePlugin",
		"WorkspaceWriteFile", "WorkspaceCommit", "CancelMission",
	}
	for _, name := range mustNotCatch {
		if mutatesExistingGraphState(name) {
			t.Errorf("%s is not a graph mutation but the guard catches it", name)
		}
	}
}

// serviceMethods returns every RPC name a service exposes, unary and streaming,
// read off the generated descriptor rather than a hand-maintained list — so a
// newly added RPC is covered the moment it is generated.
func serviceMethods(desc grpc.ServiceDesc) []string {
	names := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		names = append(names, m.MethodName)
	}
	for _, s := range desc.Streams {
		names = append(names, s.StreamName)
	}
	return names
}

// TestAgentSurfaceIsAppendOnly asserts the acceptance criterion directly: there
// is no agent-reachable RPC that updates or deletes an existing entity or graph
// node, on either of the two services an agent can call.
func TestAgentSurfaceIsAppendOnly(t *testing.T) {
	surfaces := map[string]grpc.ServiceDesc{
		"HarnessCallbackService": harnesspb.HarnessCallbackService_ServiceDesc,
		"ComponentService":       componentpb.ComponentService_ServiceDesc,
	}

	for service, desc := range surfaces {
		methods := serviceMethods(desc)
		if len(methods) == 0 {
			t.Fatalf("%s exposes no methods; the descriptor did not load and this "+
				"guard would pass vacuously", service)
		}
		for _, name := range methods {
			if mutatesExistingGraphState(name) {
				t.Errorf("%s/%s is an agent-reachable graph mutation; the emit "+
					"contract is append-only (ADR-0012, \"Write contract\")", service, name)
			}
		}
	}
}
