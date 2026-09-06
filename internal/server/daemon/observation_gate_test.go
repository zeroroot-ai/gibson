// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/proto"
)

// observeUnknownVariant returns an ObserveRequest carrying an observation
// variant this binary's descriptor does not know — the wire image an agent
// running a newer SDK produces. Field 99 is not in the oneof, so it decodes
// into unknown fields and req.Observation stays nil, which is exactly the
// input that used to be dropped.
func observeUnknownVariant(t *testing.T, missionID string) *harnesspb.ObserveRequest {
	t.Helper()
	known, err := proto.Marshal(&harnesspb.ObserveRequest{
		Context: &harnesspb.ContextInfo{MissionId: missionID},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// tag = field 99, wire type 2 (length-delimited), then a short payload.
	unknown := []byte{0x9a, 0x06, 0x04, 'n', 'e', 'w', '!'}

	req := &harnesspb.ObserveRequest{}
	if err := proto.Unmarshal(append(known, unknown...), req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Observation != nil {
		t.Fatal("field 99 decoded into a known variant; this fixture no longer " +
			"represents an unrecognised shape")
	}
	if len(req.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("the unknown bytes were not preserved by the decoder")
	}
	return req
}

// ---------------------------------------------------------------------------
// The gate: out of the Taxonomy is an Observation, never a rejection.
// ---------------------------------------------------------------------------

func TestGateObservationRecordsAnUnknownVariant(t *testing.T) {
	req := observeUnknownVariant(t, "mission-1")

	obs, ok := gateObservation(req, "scope-1", "mission-1", time.UnixMilli(1700000000000))
	if !ok {
		t.Fatal("an unrecognised observation variant produced nothing; an " +
			"out-of-taxonomy shape must never be lost")
	}
	if obs.Shape != unknownVariantShape {
		t.Errorf("Shape = %q, want %q", obs.Shape, unknownVariantShape)
	}
	if obs.EventID == "" {
		t.Error("Observation has no event id; identity is the Timeline event id")
	}
	if obs.ScopeID != "scope-1" || obs.MissionID != "mission-1" {
		t.Errorf("scope/mission not carried server-side: %q / %q", obs.ScopeID, obs.MissionID)
	}
	if obs.ObservedAt != 1700000000000 {
		t.Errorf("ObservedAt = %d, want 1700000000000", obs.ObservedAt)
	}
	if obs.Payload["unknown_wire_bytes_b64"] == "" {
		t.Error("the unrecognised bytes were not preserved; the residue must survive")
	}
	if !strings.Contains(obs.Payload["taxonomy_decision"], unknownVariantShape) {
		t.Errorf("payload does not record why the shape fell back: %q",
			obs.Payload["taxonomy_decision"])
	}
}

func TestGateObservationRecordsNothingWhenNothingWasObserved(t *testing.T) {
	// An ObserveRequest with no variant and no unknown bytes carries no
	// observation at all. That is the one case that legitimately records
	// nothing — it is an empty message, not a shape the Taxonomy rejected.
	empty := &harnesspb.ObserveRequest{Context: &harnesspb.ContextInfo{MissionId: "m"}}
	if _, ok := gateObservation(empty, "s", "m", time.Now()); ok {
		t.Fatal("an empty ObserveRequest produced an Observation")
	}
	if _, ok := gateObservation(nil, "s", "m", time.Now()); ok {
		t.Fatal("a nil ObserveRequest produced an Observation")
	}
}

func TestGateObservationFlattensAKnownVariant(t *testing.T) {
	// A known variant routed through the gate keeps its scalar fields as
	// residue, so a shape that is promoted later can be recognised from what
	// was already recorded.
	req := &harnesspb.ObserveRequest{
		Context:     &harnesspb.ContextInfo{MissionId: "m"},
		Observation: &harnesspb.ObserveRequest_Domain{Domain: &harnesspb.DomainObservation{Name: "example.test"}},
	}
	obs, ok := gateObservation(req, "s", "m", time.Now())
	if !ok {
		t.Fatal("a known variant produced no Observation")
	}
	if obs.Shape != "Domain" {
		t.Errorf("Shape = %q, want Domain", obs.Shape)
	}
	if obs.Payload["name"] != "example.test" {
		t.Errorf("payload lost the observed field: %#v", obs.Payload)
	}
}

func TestObservationShape(t *testing.T) {
	cases := map[any]string{
		&harnesspb.ObserveRequest_Host{}:      "Host",
		&harnesspb.ObserveRequest_Domain{}:    "Domain",
		&harnesspb.ObserveRequest_Subdomain{}: "Subdomain",
		nil:                                   "",
	}
	for variant, want := range cases {
		if got := observationShape(variant); got != want {
			t.Errorf("observationShape(%T) = %q, want %q", variant, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// End to end through the ingest sink: novel shape -> Observation,
// promoted shape -> typed node.
// ---------------------------------------------------------------------------

// t1Attr is the server-resolved attribution the ingest sink now takes
// (gibson#1256): tenant/scope/mission come from the mission record, not the
// request. These gate tests only care about tenant routing.
var t1Attr = harness.ObservationAttribution{Tenant: "t1", ScopeID: "scope-1", MissionID: "mission-1"}

func TestIngestNovelShapeProducesAnObservation(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	sink := ingestObservation(reg)

	if err := sink(context.Background(), t1Attr, observeUnknownVariant(t, "mission-1")); err != nil {
		t.Fatalf("ingest returned an error; an out-of-taxonomy shape must never be rejected: %v", err)
	}

	obs := drainObservations(t, reg, "t1", 1)
	if obs[0].Shape != unknownVariantShape {
		t.Errorf("Shape = %q, want %q", obs[0].Shape, unknownVariantShape)
	}
	if obs[0].ContentHash == "" {
		t.Error("no content hash was stamped; recurrence detection needs one")
	}

	// And nothing leaked into the typed stores.
	eng := reg.For("t1")
	if len(eng.Hosts()) != 0 || len(eng.Domains()) != 0 {
		t.Error("an out-of-taxonomy shape materialised as a typed node")
	}
}

func TestIngestPromotedShapeProducesATypedNode(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	sink := ingestObservation(reg)

	req := &harnesspb.ObserveRequest{
		Context:     &harnesspb.ContextInfo{MissionId: "mission-1"},
		Observation: &harnesspb.ObserveRequest_Domain{Domain: &harnesspb.DomainObservation{Name: "example.test"}},
	}
	if err := sink(context.Background(), t1Attr, req); err != nil {
		t.Fatalf("ingest of a promoted shape failed: %v", err)
	}

	eng := reg.For("t1")
	waitFor(t, func() bool { return len(eng.Domains()) == 1 })
	if got := eng.Domains(); got[0].Name != "example.test" {
		t.Errorf("Domain name = %q, want example.test", got[0].Name)
	}
	if len(eng.Observations()) != 0 {
		t.Error("a promoted shape also produced an Observation; the gate must " +
			"route it to exactly one of the two")
	}
	if !taxonomy.Global.ClassifyNode("Domain").InTaxonomy {
		t.Error("Domain is not in the Taxonomy, so this test proved nothing")
	}
}

// TestTwoSightingsOfTheSameFactStayDistinct is the recurrence property: the
// same shape and payload seen twice are two nodes with one content hash,
// because "seen again three weeks later" is signal.
func TestTwoSightingsOfTheSameFactStayDistinct(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	sink := ingestObservation(reg)

	for range 2 {
		if err := sink(context.Background(), t1Attr, observeUnknownVariant(t, "mission-1")); err != nil {
			t.Fatalf("ingest failed: %v", err)
		}
	}

	obs := drainObservations(t, reg, "t1", 2)
	if obs[0].EventID == obs[1].EventID {
		t.Fatal("two sightings collapsed onto one event id")
	}
	if obs[0].ContentHash != obs[1].ContentHash {
		t.Errorf("two sightings of the same fact hash differently (%q vs %q); "+
			"recurrence detection depends on them matching",
			obs[0].ContentHash, obs[1].ContentHash)
	}
}

// ---------------------------------------------------------------------------
// Replay.
// ---------------------------------------------------------------------------

// TestReplayReproducesIdenticalObservations covers the acceptance criterion
// that replaying the Timeline reproduces identical nodes. Identity is the
// Timeline event id, so folding the same events again — and restoring from a
// snapshot — must converge rather than duplicate.
func TestReplayReproducesIdenticalObservations(t *testing.T) {
	events := []brain.ObservationRecorded{
		{EventID: "ev-1", ScopeID: "s", MissionID: "m", Shape: "ServiceAccount",
			Payload: map[string]string{"name": "default"}, ObservedAt: 1},
		{EventID: "ev-2", ScopeID: "s", MissionID: "m", Shape: "ServiceAccount",
			Payload: map[string]string{"name": "default"}, ObservedAt: 2},
	}

	world := brain.NewWorld("t1")
	for _, ev := range events {
		brain.Reduce(world, ev)
	}
	first := world.ObservationSnapshot()
	if len(first) != 2 {
		t.Fatalf("folded %d observations, want 2", len(first))
	}

	t.Run("re-folding the same events converges", func(t *testing.T) {
		for _, ev := range events {
			brain.Reduce(world, ev)
		}
		again := world.ObservationSnapshot()
		if len(again) != 2 {
			t.Fatalf("re-folding duplicated nodes: %d, want 2", len(again))
		}
		assertSameObservations(t, first, again)
	})

	t.Run("snapshot restore reproduces the same nodes", func(t *testing.T) {
		restored, err := brain.RestoreWorld(brain.SnapshotWorld(world, "seq-1"), "t1")
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		assertSameObservations(t, first, restored.ObservationSnapshot())
	})
}

func assertSameObservations(t *testing.T, want, got []brain.ObservationSnapshot) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("observation count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if want[i].EventID != got[i].EventID {
			t.Errorf("[%d] EventID = %q, want %q", i, got[i].EventID, want[i].EventID)
		}
		if want[i].ID != got[i].ID {
			t.Errorf("[%d] ID = %d, want %d; ids must be replay-deterministic",
				i, got[i].ID, want[i].ID)
		}
		if want[i].ContentHash != got[i].ContentHash {
			t.Errorf("[%d] ContentHash = %q, want %q", i, got[i].ContentHash, want[i].ContentHash)
		}
		if want[i].Shape != got[i].Shape {
			t.Errorf("[%d] Shape = %q, want %q", i, got[i].Shape, want[i].Shape)
		}
		if want[i].Payload["name"] != got[i].Payload["name"] {
			t.Errorf("[%d] payload lost across replay: %#v", i, got[i].Payload)
		}
	}
}

// ---------------------------------------------------------------------------
// Projection.
// ---------------------------------------------------------------------------

// TestProjectorWritesObservations checks the projector — the sole graph writer
// — actually materialises Observations, so an out-of-taxonomy shape is
// immediately queryable rather than merely stored in the World.
func TestProjectorWritesObservations(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	eng := reg.For("t1")
	eng.Submit(brain.ObservationRecorded{
		EventID: "ev-1", ScopeID: "s", MissionID: "m", Shape: "ServiceAccount",
		Payload: map[string]string{"name": "default"}, ObservedAt: 7,
	})
	waitFor(t, func() bool { return len(eng.Observations()) == 1 })

	writer := newFakeGraphWriter()
	NewGraphProjector(reg, writer, time.Hour, nil).project(context.Background())

	writer.mu.Lock()
	defer writer.mu.Unlock()
	got := writer.observations["t1"]
	if len(got) != 1 {
		t.Fatalf("projector wrote %d observations, want 1", len(got))
	}
	if got[0].EventID != "ev-1" || got[0].Shape != "ServiceAccount" {
		t.Errorf("projected the wrong observation: %+v", got[0])
	}
}

// TestObservationPayloadCannotShadowReservedProperties is the reason the
// residue is prefixed: `SET o += $payload` would otherwise let a payload key
// overwrite the node's own identity.
func TestObservationPayloadCannotShadowReservedProperties(t *testing.T) {
	reserved := []string{"event_id", "shape", "content_hash", "scope", "mission_id", "brain_id"}
	for _, key := range reserved {
		prefixed := observationPayloadPrefix + key
		if prefixed == key {
			t.Fatalf("payload key %q is not namespaced away from the reserved property", key)
		}
		if !strings.Contains(upsertObservationCypher, key) {
			t.Errorf("reserved property %q is not actually set by the projector; "+
				"this test is guarding nothing", key)
		}
	}
	if !strings.Contains(upsertObservationCypher, "MERGE (o:Observation {event_id: $event_id})") {
		t.Error("the Observation node is not keyed by the Timeline event id")
	}
	if strings.Contains(upsertObservationCypher, "$shape`") || strings.Contains(upsertObservationCypher, "`+") {
		t.Error("the Cypher interpolates a label; the Observation label must be constant")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func drainObservations(t *testing.T, reg *brain.Registry, tenant string, want int) []brain.ObservationSnapshot {
	t.Helper()
	eng := reg.For(tenant)
	waitFor(t, func() bool { return len(eng.Observations()) == want })
	got := eng.Observations()
	if len(got) != want {
		t.Fatalf("observation count = %d, want %d", len(got), want)
	}
	return got
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// TestProjectedVocabularyMatchesTheTaxonomy is the drift guard: the sole graph
// writer must only ever write shapes the global Taxonomy admits. It fails if
// someone adds a MERGE for a label nobody promoted — the mechanism by which
// Host / HOST / host_v2 would otherwise diverge unnoticed.
func TestProjectedVocabularyMatchesTheTaxonomy(t *testing.T) {
	if drift := checkProjectedVocabulary(); len(drift) > 0 {
		t.Fatalf("projector vocabulary drifted from the Taxonomy:\n  %s",
			strings.Join(drift, "\n  "))
	}

	// The declared vocabulary must also match what the writer can actually
	// emit, or the guard above is checking a list nobody maintains. There are
	// two emission mechanisms and every declared shape must be covered by one:
	//
	//  1. A constant Cypher naming the label literally (Host, Mission, …).
	//  2. The parameterised application-lifecycle path (gibson#1656), whose
	//     label and edge types are arguments, so they can never appear as
	//     query text. A shape is covered there when the production parameter
	//     builder accepts it — which is a stronger statement than a string
	//     match, because it runs the real Taxonomy re-check rather than
	//     asserting on the shape of a query.
	cyphers := strings.Join([]string{
		upsertHostCypher, upsertMissionCypher, upsertFindingCypher,
		upsertDomainCypher, upsertSubdomainCypher, upsertCredentialCypher,
		upsertAccountCypher, upsertAgentRunCypher, upsertLlmCallCypher,
		upsertObservationCypher,
	}, "\n")
	literalNode := func(label string) bool {
		return strings.Contains(cyphers, ":"+label+" ") || strings.Contains(cyphers, ":"+label+"{") ||
			strings.Contains(cyphers, ":"+label+")")
	}
	for _, label := range projectedNodeLabels {
		if literalNode(label) {
			continue
		}
		if _, err := entityUpsertParams(brain.EntitySnapshot{Label: label, Key: "probe"}); err != nil {
			t.Errorf("node label %q is declared as projected but no Cypher MERGEs it and the "+
				"lifecycle path refuses it: %v", label, err)
		}
	}
	for _, relType := range projectedRelationshipTypes {
		if strings.Contains(cyphers, ":"+relType+"]") {
			continue
		}
		// The edge survives entityUpsertParams only when its type is admitted;
		// an unadmitted one is silently dropped, so an empty edge list is the
		// failure signal.
		params, err := entityUpsertParams(brain.EntitySnapshot{
			Label: "Application", Key: "probe",
			Edges: []brain.EntityEdge{{Type: relType, TargetLabel: "Application", TargetKey: "target"}},
		})
		if err != nil {
			t.Errorf("probing relationship type %q: %v", relType, err)
			continue
		}
		if edges, _ := params["edges"].([]map[string]any); len(edges) == 0 {
			t.Errorf("relationship type %q is declared as projected but no Cypher creates it and "+
				"the lifecycle path drops it", relType)
		}
	}
}

// ---------------------------------------------------------------------------
// Lifecycle entities an agent reports (gibson#1681)
// ---------------------------------------------------------------------------

// TestIngestLifecycleEntityProducesTheTypedEntity: before this case existed, a
// LifecycleEntityObservation fell to the default branch and landed as a generic
// Observation. Nothing was lost, but it was not the node the agent named — so
// an agent reading its own write back found it missing.
func TestIngestLifecycleEntityProducesTheTypedEntity(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	sink := ingestObservation(reg)

	req := &harnesspb.ObserveRequest{
		Context: &harnesspb.ContextInfo{MissionId: "mission-1"},
		Observation: &harnesspb.ObserveRequest_LifecycleEntity{
			LifecycleEntity: &harnesspb.LifecycleEntityObservation{
				Label:        "Package",
				IdProperties: map[string]string{"key": "npm:lodash@4.17.20"},
				Properties:   map[string]string{"ecosystem": "npm"},
				Edges: []*harnesspb.LifecycleEntityEdge{{
					Type:               "CONTAINS",
					TargetLabel:        "Image",
					TargetIdProperties: map[string]string{"key": "sha256:abc"},
				}},
			},
		},
	}
	if err := sink(context.Background(), t1Attr, req); err != nil {
		t.Fatalf("ingest of a lifecycle entity failed: %v", err)
	}

	eng := reg.For("t1")
	waitFor(t, func() bool { return len(eng.Entities()) == 1 })
	got := eng.Entities()[0]
	if got.Label != "Package" || got.Key != "npm:lodash@4.17.20" {
		t.Errorf("entity identity = %s/%s, want Package/npm:lodash@4.17.20", got.Label, got.Key)
	}

	// And it did NOT also land as an untyped Observation: one sighting is one
	// node, not a typed node plus a shadow of it.
	if obs := eng.Observations(); len(obs) != 0 {
		t.Errorf("a typed entity also produced %d Observation(s)", len(obs))
	}
}

// TestIngestLifecycleEntityOutsideTheTaxonomyStillLands: the gate is the reason
// an unknown shape is never dropped. A label the Taxonomy does not admit is not
// an error and not a silent loss — it becomes an Observation, exactly as a
// novel shape from any other reporter does (ADR-0012).
func TestIngestLifecycleEntityOutsideTheTaxonomyStillLands(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	sink := ingestObservation(reg)

	req := &harnesspb.ObserveRequest{
		Context: &harnesspb.ContextInfo{MissionId: "mission-1"},
		Observation: &harnesspb.ObserveRequest_LifecycleEntity{
			LifecycleEntity: &harnesspb.LifecycleEntityObservation{
				Label:        "Wharrgarbl",
				IdProperties: map[string]string{"key": "k1"},
			},
		},
	}
	if err := sink(context.Background(), t1Attr, req); err != nil {
		t.Fatalf("an out-of-taxonomy label must never be rejected: %v", err)
	}

	eng := reg.For("t1")
	waitFor(t, func() bool { return len(eng.Observations()) == 1 })
	if len(eng.Entities()) != 0 {
		t.Error("an out-of-taxonomy label materialised as a typed entity")
	}
}
