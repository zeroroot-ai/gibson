// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// A label's identity property belongs to the LABEL, not to the write path that
// happens to be materialising it. Before gibson#1669 the entity path merged
// everything on `key` while the first-class projections merged on `brain_id`,
// so an agent enriching a Finding created a SECOND :Finding beside the real one
// and every priority or status it wrote landed on a node nothing references.

func identOf(t *testing.T, label, key string) map[string]any {
	t.Helper()
	params, err := entityUpsertParams(brain.EntitySnapshot{Label: label, Key: key})
	if err != nil {
		t.Fatalf("entityUpsertParams(%s): %v", label, err)
	}
	ident, ok := params["ident"].(map[string]any)
	if !ok {
		t.Fatalf("ident is %T, want a parameter map", params["ident"])
	}
	return ident
}

func TestEntityUpsertParams_AFirstClassLabelIsIdentifiedTheSameWayItsProjectionIdentifiesIt(t *testing.T) {
	// Finding, Host and the rest are merged by their projections on brain_id.
	// An entity write naming one of them has to use the same property or the two
	// writers of one label diverge into two nodes.
	for _, label := range []string{"Finding", "Host", "Domain", "Subdomain", "Account", "Credential", "AgentRun", "LlmCall", "Hypothesis"} {
		t.Run(label, func(t *testing.T) {
			ident := identOf(t, label, "brain-1")
			if got, ok := ident["brain_id"]; !ok || got != "brain-1" {
				t.Fatalf("%s identity = %v, want {brain_id: brain-1}", label, ident)
			}
			if _, wrong := ident["key"]; wrong {
				t.Fatalf("%s must not be identified by key: %v", label, ident)
			}
		})
	}
}

func TestEntityUpsertParams_ALifecycleLabelKeepsItsNaturalKey(t *testing.T) {
	// The labels the entity path owns are identified by their natural key — a
	// CVE id, an image digest, a repository path.
	for _, label := range []string{"Application", "Repository", "Image", "Package", "Deployment", "Vulnerability", "MergeRequest", "Pipeline", "Control", "Alert", "Incident", "Countermeasure"} {
		t.Run(label, func(t *testing.T) {
			ident := identOf(t, label, "CVE-2025-1234")
			if got, ok := ident["key"]; !ok || got != "CVE-2025-1234" {
				t.Fatalf("%s identity = %v, want {key: CVE-2025-1234}", label, ident)
			}
		})
	}
}

func TestEntityUpsertParams_TheObservationEscapeHatchKeepsItsEventID(t *testing.T) {
	ident := identOf(t, taxonomy.ObservationLabel, "ev-1")
	if got, ok := ident["event_id"]; !ok || got != "ev-1" {
		t.Fatalf("identity = %v, want {event_id: ev-1}", ident)
	}
}

func TestEntityUpsertParams_ACompositeKeyLabelIsRefusedNotHalfMatched(t *testing.T) {
	// Mission is (id, tenant_id); Port and Service belong to a Host. No
	// single-property merge can express those, and a partial match would write
	// to the wrong node — so the write is refused instead.
	for _, label := range []string{"Mission", "Port", "Service"} {
		t.Run(label, func(t *testing.T) {
			_, err := entityUpsertParams(brain.EntitySnapshot{Label: label, Key: "k1"})
			if err == nil {
				t.Fatalf("%s must be refused by an entity write, not addressed by a guessed identity", label)
			}
		})
	}
}

func TestEntityUpsertParams_AnEdgeTargetUsesItsOwnLabelsIdentity(t *testing.T) {
	// An edge to a Finding must land on the Finding, not on a second node
	// wearing the label.
	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Vulnerability",
		Key:   "CVE-2025-1234",
		Edges: []brain.EntityEdge{
			{Type: "INSTANCE_OF", TargetLabel: "Finding", TargetKey: "brain-9"},
			{Type: "CONTAINS", TargetLabel: "Package", TargetKey: "pkg@1.0"},
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	edges, _ := params["edges"].([]map[string]any)
	if len(edges) != 2 {
		t.Fatalf("want 2 edges, got %d", len(edges))
	}
	byLabel := map[string]map[string]any{}
	for _, e := range edges {
		ident, _ := e["ident"].(map[string]any)
		byLabel[e["label"].(string)] = ident
	}
	if got := byLabel["Finding"]["brain_id"]; got != "brain-9" {
		t.Fatalf("Finding edge target identity = %v, want {brain_id: brain-9}", byLabel["Finding"])
	}
	if got := byLabel["Package"]["key"]; got != "pkg@1.0" {
		t.Fatalf("Package edge target identity = %v, want {key: pkg@1.0}", byLabel["Package"])
	}
}

func TestEntityUpsertParams_AnEdgeToACompositeKeyLabelIsDroppedNotGuessed(t *testing.T) {
	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Application",
		Key:   "customer-portal",
		Edges: []brain.EntityEdge{
			{Type: "RUNS_SERVICE", TargetLabel: "Service", TargetKey: "svc-1"},
			{Type: "HAS_DEPLOYMENT", TargetLabel: "Deployment", TargetKey: "prod"},
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	edges, _ := params["edges"].([]map[string]any)
	if len(edges) != 1 || edges[0]["label"] != "Deployment" {
		t.Fatalf("edges = %+v, want only the Deployment edge", edges)
	}
}

func TestEntityUpsertParams_EveryIdentityPropertyIsReserved(t *testing.T) {
	// An emitter that could set an identity property through the property map
	// could re-point a node at another node's identity.
	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Application",
		Key:   "customer-portal",
		Props: map[string]string{
			"brain_id":      "someone-elses-node",
			"event_id":      "someone-elses-event",
			"brain_host_id": "someone-elses-host",
			"key":           "someone-elses-key",
			"owner":         "platform-team",
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	props, _ := params["props"].(map[string]any)
	for _, reserved := range []string{"brain_id", "event_id", "brain_host_id", "key"} {
		if _, present := props[reserved]; present {
			t.Errorf("%q reached the property map; an emitter must not be able to set an identity", reserved)
		}
	}
	if props["owner"] != "platform-team" {
		t.Errorf("a non-identity property must survive: %+v", props)
	}
}

// The fix agent writes why it did not fix a Finding as a sighting of the
// Finding (fix-agent internal/emit). The projector stores the property on the
// Finding node, merged on brain_id, so ApplicationFinding can read it back.
func TestEntityUpsertParams_AFindingKeepsTheFixBlockedReason(t *testing.T) {
	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Finding", Key: "f-1",
		Props: map[string]string{"fix_blocked_reason": "the flaw is on a host", "brain_id": "f-2"},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	ident, _ := params["ident"].(map[string]any)
	if ident["brain_id"] != "f-1" {
		t.Fatalf("ident = %v, want brain_id f-1", ident)
	}
	props, _ := params["props"].(map[string]any)
	if props["fix_blocked_reason"] != "the flaw is on a host" {
		t.Fatalf("props = %v, want the fix blocked reason", props)
	}
	if _, ok := props["brain_id"]; ok {
		t.Fatal("a sighting rewrote the identity of the Finding")
	}
}

// The Watcher writes the place wait to its own property. An event of the agent and
// an event of the Watcher each carry only their own property, so one never erases
// the other, and clearing the place block leaves the reason of the agent.
func TestEntityUpsertParams_PlaceBlockAndAgentReasonAreSeparate(t *testing.T) {
	agent, err := entityUpsertParams(brain.EntitySnapshot{Label: "Finding", Key: "f-1",
		Props: map[string]string{"fix_blocked_reason": "the flaw is on a host"}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := entityUpsertParams(brain.EntitySnapshot{Label: "Finding", Key: "f-1",
		Props: map[string]string{"place_block": "waiting on a person: two Applications"}})
	if err != nil {
		t.Fatal(err)
	}
	clear, err := entityUpsertParams(brain.EntitySnapshot{Label: "Finding", Key: "f-1",
		Props: map[string]string{"place_block": ""}})
	if err != nil {
		t.Fatal(err)
	}
	props := func(p map[string]any) map[string]any { m, _ := p["props"].(map[string]any); return m }
	if _, ok := props(agent)["place_block"]; ok {
		t.Error("the agent event carries the place block")
	}
	if _, ok := props(set)["fix_blocked_reason"]; ok {
		t.Error("the place block event carries the reason of the agent")
	}
	if v, ok := props(clear)["place_block"]; !ok || v != "" {
		t.Errorf("clear props = %v, want an empty place_block", props(clear))
	}
	if _, ok := props(clear)["fix_blocked_reason"]; ok {
		t.Error("clearing the place block touches the reason of the agent")
	}
}
