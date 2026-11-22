// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import "testing"

// EntityObservedFromSighting is the one mapping both reporters go through — a
// tool's CustomNode and an agent's LifecycleEntityObservation (gibson#1681).
// These pin the admission rules directly, so neither caller has to re-assert
// them and they cannot drift apart.

func TestEntityObservedFromSighting_AdmitsALabelledKeyedSighting(t *testing.T) {
	ev, skipped, ok := EntityObservedFromSighting(EntitySighting{
		Label:        "Package",
		IDProperties: map[string]string{"key": "npm:lodash@4.17.20"},
		Properties:   map[string]string{"ecosystem": "npm"},
		Edges: []EntitySightingEdge{{
			Type:               "CONTAINS",
			TargetLabel:        "Image",
			TargetIDProperties: map[string]string{"key": "sha256:abc"},
		}},
	}, "scope-1", "mission-1")

	if !ok {
		t.Fatal("an admitted label with a key must be accepted")
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if ev.Label != "Package" || ev.Key != "npm:lodash@4.17.20" {
		t.Errorf("identity = %s/%s", ev.Label, ev.Key)
	}
	if ev.ScopeID != "scope-1" || ev.MissionID != "mission-1" {
		t.Errorf("attribution = %s/%s", ev.ScopeID, ev.MissionID)
	}
	if ev.Props["ecosystem"] != "npm" {
		t.Errorf("props = %v", ev.Props)
	}
	if len(ev.Edges) != 1 || ev.Edges[0].Type != "CONTAINS" || ev.Edges[0].TargetKey != "sha256:abc" {
		t.Errorf("edges = %+v", ev.Edges)
	}
}

func TestEntityObservedFromSighting_RefusesWhatTheGraphCannotAddress(t *testing.T) {
	// Not an error and not a drop: the caller lands these as an untyped
	// Observation, so the reporter's sighting is still queryable.
	for _, tc := range []struct {
		name string
		in   EntitySighting
	}{
		{"label outside the Taxonomy", EntitySighting{
			Label: "Wharrgarbl", IDProperties: map[string]string{"key": "k"},
		}},
		{"no identity properties at all", EntitySighting{Label: "Package"}},
		{"an identity property with an empty value", EntitySighting{
			Label: "Package", IDProperties: map[string]string{"key": "  "},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := EntityObservedFromSighting(tc.in, "s", "m"); ok {
				t.Error("must be refused so the caller can gate it as an Observation")
			}
		})
	}
}

func TestEntityObservedFromSighting_ABadEdgeIsSkippedAndTheEntityStillLands(t *testing.T) {
	// Losing the node over one inadmissible edge would lose more than it
	// protects: the entity is the thing the reporter actually saw.
	ev, skipped, ok := EntityObservedFromSighting(EntitySighting{
		Label:        "Image",
		IDProperties: map[string]string{"key": "sha256:abc"},
		Edges: []EntitySightingEdge{
			{Type: "WHARRGARBL", TargetLabel: "Package", TargetIDProperties: map[string]string{"key": "p"}},
			{Type: "CONTAINS", TargetLabel: "Wharrgarbl", TargetIDProperties: map[string]string{"key": "p"}},
			{Type: "CONTAINS", TargetLabel: "Package", TargetIDProperties: nil},
			{Type: "CONTAINS", TargetLabel: "Package", TargetIDProperties: map[string]string{"key": "good"}},
		},
	}, "s", "m")

	if !ok {
		t.Fatal("the entity must still land")
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3 (bad relationship, bad target label, no target key)", skipped)
	}
	if len(ev.Edges) != 1 || ev.Edges[0].TargetKey != "good" {
		t.Errorf("only the admissible edge should survive, got %+v", ev.Edges)
	}
}

// An alert names the host or the account that it affects with the key
// "connector=<id>|vendor_id=<id>" (gibson#1577). The node that the tool of the
// buyer reports has the same key, so the edge lands on that node.
func TestEntityObservedFromSighting_AnAlertAffectsANodeByTheVendorKey(t *testing.T) {
	node := func() map[string]string {
		return map[string]string{"connector": "crowdstrike", "vendor_id": "aid-77"}
	}
	for _, label := range []string{"Host", "Account", "Service"} {
		alert, skipped, ok := EntityObservedFromSighting(EntitySighting{
			Label:        "Alert",
			IDProperties: map[string]string{"connector": "crowdstrike", "vendor_id": "alert-1"},
			Edges: []EntitySightingEdge{
				{Type: "AFFECTS", TargetLabel: label, TargetIDProperties: node()},
			},
		}, "scope", "")
		if !ok || skipped != 0 || len(alert.Edges) != 1 {
			t.Fatalf("%s: ok = %v, skipped = %d, edges = %v", label, ok, skipped, alert.Edges)
		}
		const want = "connector=crowdstrike|vendor_id=aid-77"
		if e := alert.Edges[0]; e.Type != "AFFECTS" || e.TargetLabel != label || e.TargetKey != want {
			t.Errorf("%s: edge = %+v, want AFFECTS to %s %q", label, e, label, want)
		}
		target, _, ok := EntityObservedFromSighting(EntitySighting{Label: label, IDProperties: node()}, "scope", "")
		if !ok || target.Key != want {
			t.Errorf("%s: node key = %q, want the key of the edge %q", label, target.Key, want)
		}
	}
}
