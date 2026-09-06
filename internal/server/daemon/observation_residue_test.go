// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strconv"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// TestFlattenObservationKeepsScalarsAndNamesWhatItSkipped covers the residue
// walk on a variant carrying a repeated message field. A nested list has no
// single string form worth guessing at, so it is recorded as skipped rather
// than dropped: an Observation that silently claimed to be complete would
// mislead exactly the Sensing review that decides what to promote.
func TestFlattenObservationKeepsScalarsAndNamesWhatItSkipped(t *testing.T) {
	req := &harnesspb.ObserveRequest{
		Context: &harnesspb.ContextInfo{MissionId: "m"},
		Observation: &harnesspb.ObserveRequest_Host{Host: &harnesspb.HostObservation{
			Address:    "10.0.0.1",
			SshHostKey: "AAAA",
			Ports:      []*harnesspb.PortObservation{{Number: 22}},
		}},
	}

	into := map[string]string{}
	flattenObservation(req, into)

	if into["address"] != "10.0.0.1" || into["ssh_host_key"] != "AAAA" {
		t.Errorf("scalars lost: %#v", into)
	}
	if into["skipped_ports"] == "" {
		t.Errorf("the repeated field was dropped without a trace: %#v", into)
	}
	if _, ok := into["ports"]; ok {
		t.Errorf("a repeated message field was flattened into a single value: %#v", into)
	}
}

// TestFlattenObservationStopsAtThePayloadCap proves the residue is bounded. The
// cap exists so an unbounded key set cannot sprawl the graph schema one
// property at a time (ADR-0012, "Bounded").
func TestFlattenObservationStopsAtThePayloadCap(t *testing.T) {
	into := make(map[string]string, maxObservationPayloadEntries)
	for i := range maxObservationPayloadEntries {
		into["pre_"+strconv.Itoa(i)] = "x"
	}

	req := &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_Host{Host: &harnesspb.HostObservation{Address: "10.0.0.1"}},
	}
	flattenObservation(req, into)

	if len(into) != maxObservationPayloadEntries {
		t.Fatalf("payload grew past the cap: %d entries, cap %d", len(into), maxObservationPayloadEntries)
	}
	if _, ok := into["address"]; ok {
		t.Error("a field was appended after the cap was reached")
	}
}

// TestFlattenObservationOnAnEmptyRequest covers the no-variant-set path: there
// is nothing to walk, and nothing is invented.
func TestFlattenObservationOnAnEmptyRequest(t *testing.T) {
	into := map[string]string{}
	flattenObservation(&harnesspb.ObserveRequest{}, into)
	if len(into) != 0 {
		t.Fatalf("residue invented from an empty request: %#v", into)
	}
}

// TestObservationShapeFallsBackToTheTypeName covers a variant whose Go type is
// not an ObserveRequest_ wrapper. The shape is a property value, never a label,
// so an unrecognised one is recorded rather than refused.
func TestObservationShapeFallsBackToTheTypeName(t *testing.T) {
	if got := observationShape(&harnesspb.HostObservation{}); !strings.HasSuffix(got, "HostObservation") {
		t.Fatalf("observationShape fallback = %q, want the bare type name", got)
	}
	if strings.HasPrefix(observationShape(&harnesspb.HostObservation{}), "*") {
		t.Error("the shape kept its pointer marker")
	}
}

// TestObservationParamsNamespacesTheResidue is the unit-level half of the
// payload-shadowing guard: every residue key reaches Cypher under the p_
// prefix, so `SET o += $payload` cannot overwrite the node's own identity.
func TestObservationParamsNamespacesTheResidue(t *testing.T) {
	params := observationParams(brain.ObservationSnapshot{
		ID: 7, EventID: "ev-1", ScopeID: "s", MissionID: "m", Shape: "ServiceAccount",
		ContentHash: "abc", ObservedAt: 42,
		Payload: map[string]string{"event_id": "forged", "name": "default"},
	})

	if params["event_id"] != "ev-1" {
		t.Fatalf("identity parameter = %v, want ev-1", params["event_id"])
	}
	if params["id"] != int64(7) {
		t.Errorf("brain id parameter = %v (%T), want int64(7)", params["id"], params["id"])
	}
	if params["taxonomy_version"] != int64(taxonomy.Global.Version()) {
		t.Errorf("taxonomy_version = %v, want %d", params["taxonomy_version"], taxonomy.Global.Version())
	}

	payload, ok := params["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload parameter is %T, want map[string]any", params["payload"])
	}
	if _, shadowed := payload["event_id"]; shadowed {
		t.Fatal("a payload key reached Cypher under a reserved property name")
	}
	if payload[observationPayloadPrefix+"event_id"] != "forged" ||
		payload[observationPayloadPrefix+"name"] != "default" {
		t.Errorf("residue lost or renamed: %#v", payload)
	}
}

// TestVocabularyDriftNamesTheOffendingShape exercises the drift guard's failure
// path. The guard that runs in production reads the global Taxonomy, whose
// invalid states take the package init down — so the branches that report drift
// can only be reached through an explicit registry. A guard that cannot fail is
// the recurring defect class here; this is the mutation, kept.
func TestVocabularyDriftNamesTheOffendingShape(t *testing.T) {
	reg, err := taxonomy.New(1, []string{taxonomy.ObservationLabel, "Host"}, []string{"HAS_PORT"})
	if err != nil {
		t.Fatalf("taxonomy.New: %v", err)
	}

	if drift := vocabularyDrift(reg, []string{"Host"}, []string{"HAS_PORT"}); len(drift) != 0 {
		t.Fatalf("in-taxonomy vocabulary reported drift: %v", drift)
	}

	drift := vocabularyDrift(reg, []string{"Host", "host_v2"}, []string{"HAS_PORT", "POINTS_AT"})
	if len(drift) != 2 {
		t.Fatalf("drift = %v, want one node label and one relationship type", drift)
	}
	if !strings.Contains(drift[0], `"host_v2"`) || !strings.Contains(drift[1], `"POINTS_AT"`) {
		t.Errorf("drift does not name the offending shapes: %v", drift)
	}
}
