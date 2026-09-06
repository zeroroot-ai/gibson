// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// recordingGraph captures the Cypher a provider generates and replays canned
// rows, so query construction is testable without Neo4j.
type recordingGraph struct {
	graph.GraphClient

	cypher []string
	params []map[string]any

	result graph.QueryResult
	err    error
}

func (g *recordingGraph) Query(_ context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	g.cypher = append(g.cypher, cypher)
	g.params = append(g.params, params)
	if g.err != nil {
		return graph.QueryResult{}, g.err
	}
	return g.result, nil
}

func (g *recordingGraph) Health(context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (g *recordingGraph) lastCypher() string {
	if len(g.cypher) == 0 {
		return ""
	}
	return g.cypher[len(g.cypher)-1]
}

// recordingVector captures upserts and answers searches.
type recordingVector struct {
	upserted []vectordb.Point
	filter   *vectordb.Filter
	results  []vectordb.SearchResult
	err      error
}

func (v *recordingVector) Upsert(_ context.Context, points []vectordb.Point) error {
	if v.err != nil {
		return v.err
	}
	v.upserted = append(v.upserted, points...)
	return nil
}

func (v *recordingVector) Search(
	_ context.Context, _ []float32, _ uint64, filter *vectordb.Filter,
) ([]vectordb.SearchResult, error) {
	v.filter = filter
	if v.err != nil {
		return nil, v.err
	}
	return v.results, nil
}

func (v *recordingVector) Delete(context.Context, []string) error { return nil }

func newTestProvider() (*LocalGraphRAGProvider, *recordingGraph, *recordingVector) {
	g := &recordingGraph{}
	v := &recordingVector{}
	return NewLocalGraphRAGProvider(g, v), g, v
}

func TestInitialize_ReportsAMissingConnectionRatherThanFailingLater(t *testing.T) {
	// The seam answers Unimplemented honestly on this error. Discovering the nil
	// on first query instead would surface as a random Internal mid-mission.
	if err := NewLocalGraphRAGProvider(nil, &recordingVector{}).Initialize(context.Background()); err == nil {
		t.Error("expected an error with no graph client")
	}
	if err := NewLocalGraphRAGProvider(&recordingGraph{}, nil).Initialize(context.Background()); err == nil {
		t.Error("expected an error with no vector client")
	}
	p, _, _ := newTestProvider()
	if err := p.Initialize(context.Background()); err != nil {
		t.Errorf("Initialize with both clients: %v", err)
	}
}

func TestQueryNodes_ParameterisesValuesAndSanitisesIdentifiers(t *testing.T) {
	// Property NAMES cannot be Cypher parameters, so they are sanitised into the
	// query text; VALUES always go through parameters. Getting that backwards is
	// the injection.
	p, g, _ := newTestProvider()
	_, err := p.QueryNodes(context.Background(), NodeQuery{
		NodeTypes:  []NodeType{NodeType("Finding")},
		Properties: map[string]any{"severity` OR 1=1 //": "high"},
		Limit:      25,
	})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}

	cypher := g.lastCypher()
	if strings.Contains(cypher, "OR 1=1") || strings.Contains(cypher, "`") {
		t.Errorf("cypher carries caller text verbatim: %q", cypher)
	}
	if !strings.Contains(cypher, "n.severityOR11 = $p0") {
		t.Errorf("cypher = %q, want the sanitised property compared to a parameter", cypher)
	}
	if g.params[0]["p0"] != "high" {
		t.Errorf("params = %+v, want the value parameterised", g.params[0])
	}
	if !strings.Contains(cypher, "LIMIT 25") {
		t.Errorf("cypher = %q, want the caller's limit", cypher)
	}
}

// A relationship TYPE is a Cypher identifier too. It cannot be parameterised
// either, so it goes through sanitizeIdentifier on both read paths that splice
// one into a pattern. This was previously only asserted on the write path, and
// the write path is gone (gibson#1322).
func TestReadPaths_SanitiseRelationshipTypesIntoThePattern(t *testing.T) {
	hostile := RelationType("KNOWS]->() DETACH DELETE n //")

	t.Run("QueryRelationships", func(t *testing.T) {
		p, g, _ := newTestProvider()
		if _, err := p.QueryRelationships(context.Background(), RelQuery{
			Types: []RelationType{hostile},
		}); err != nil {
			t.Fatalf("QueryRelationships: %v", err)
		}
		cypher := g.lastCypher()
		if strings.Contains(cypher, "DETACH DELETE") || strings.Contains(cypher, "]->()") {
			t.Errorf("cypher carries caller text verbatim: %q", cypher)
		}
		if !strings.Contains(cypher, "[r:KNOWSDETACHDELETEn]") {
			t.Errorf("cypher = %q, want the sanitised relationship type in the pattern", cypher)
		}
	})

	t.Run("TraverseGraph", func(t *testing.T) {
		p, g, _ := newTestProvider()
		if _, err := p.TraverseGraph(context.Background(), "n1", 2, TraversalFilters{
			AllowedRelations: []RelationType{hostile},
		}); err != nil {
			t.Fatalf("TraverseGraph: %v", err)
		}
		cypher := g.lastCypher()
		if strings.Contains(cypher, "DETACH DELETE") || strings.Contains(cypher, "]->()") {
			t.Errorf("cypher carries caller text verbatim: %q", cypher)
		}
		if !strings.Contains(cypher, "[:KNOWSDETACHDELETEn*1..2]") {
			t.Errorf("cypher = %q, want the sanitised relationship type in the pattern", cypher)
		}
	})
}

// TestQueryNodes_SanitisesNodeTypeLabels is the NodeType sibling of
// TestReadPaths_SanitiseRelationshipTypesIntoThePattern: a node type is
// spliced into the MATCH pattern's label the same way a relationship type is
// spliced into its pattern, through local_provider.go's labelExpr, and had no
// test proving it (gibson#1440 — found by mutation-testing sanitizeIdentifier:
// every OTHER identifier-sanitisation test in this file caught the break,
// this one did not).
func TestQueryNodes_SanitisesNodeTypeLabels(t *testing.T) {
	p, g, _ := newTestProvider()
	_, err := p.QueryNodes(context.Background(), NodeQuery{
		NodeTypes: []NodeType{NodeType("Finding) DETACH DELETE (n:Evil {x:'")},
	})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	cypher := g.lastCypher()
	if strings.Contains(cypher, "DETACH DELETE") {
		t.Errorf("cypher carries caller text verbatim: %q", cypher)
	}
	if !strings.Contains(cypher, "MATCH (n:FindingDETACHDELETEnEvilx)") {
		t.Errorf("cypher = %q, want the label sanitised into a single safe identifier", cypher)
	}
}

func TestQueryNodes_UnboundedQueryStillGetsALimit(t *testing.T) {
	// A tenant graph is not bounded. An unlimited MATCH is how a session hangs.
	p, g, _ := newTestProvider()
	if _, err := p.QueryNodes(context.Background(), NodeQuery{}); err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if !strings.Contains(g.lastCypher(), "LIMIT 100") {
		t.Errorf("cypher = %q, want a default limit", g.lastCypher())
	}
}

func TestQueryNodes_DecodesRowsAndSkipsUndecodableOnes(t *testing.T) {
	good := types.NewID()
	p, g, _ := newTestProvider()
	g.result = graph.QueryResult{Records: []map[string]any{
		{"n": dbtype.Node{Labels: []string{"Finding"}, Props: map[string]any{"id": good.String(), "title": "x"}}},
		// No id: cannot be referenced, related, or fetched again.
		{"n": dbtype.Node{Labels: []string{"Finding"}, Props: map[string]any{"title": "orphan"}}},
		{"n": "not a node"},
	}}

	nodes, err := p.QueryNodes(context.Background(), NodeQuery{})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != good {
		t.Fatalf("decoded %d nodes, want only the one with a usable id", len(nodes))
	}
	if nodes[0].Properties["title"] != "x" {
		t.Errorf("properties = %+v, want the node's own", nodes[0].Properties)
	}
}

func TestTraverseGraph_BoundsDepthAndRequiresAStart(t *testing.T) {
	p, g, _ := newTestProvider()
	if _, err := p.TraverseGraph(context.Background(), "", 2, TraversalFilters{}); err == nil {
		t.Error("expected an error with no start node")
	}

	// An unbounded variable-length match is the classic Neo4j hang.
	if _, err := p.TraverseGraph(context.Background(), "n1", 500, TraversalFilters{}); err != nil {
		t.Fatalf("TraverseGraph: %v", err)
	}
	if !strings.Contains(g.lastCypher(), "*1..5") {
		t.Errorf("cypher = %q, want the hop count capped", g.lastCypher())
	}
}

func TestTraverseGraph_BlockedTypesWinOverAllowed(t *testing.T) {
	// A caller naming both means "these, but never those"; the safe reading of
	// an overlap is to exclude.
	p, g, _ := newTestProvider()
	_, err := p.TraverseGraph(context.Background(), "n1", 2, TraversalFilters{
		AllowedNodeTypes: []NodeType{NodeType("Finding")},
		BlockedNodeTypes: []NodeType{NodeType("Secret")},
		BlockedRelations: []RelationType{RelationType("DERIVED_FROM")},
	})
	if err != nil {
		t.Fatalf("TraverseGraph: %v", err)
	}
	cypher := g.lastCypher()
	if !strings.Contains(cypher, "none(l IN labels(n) WHERE l IN $blocked_labels)") {
		t.Errorf("cypher = %q, want blocked node types excluded", cypher)
	}
	if !strings.Contains(cypher, "none(r IN relationships(path) WHERE type(r) IN $blocked_rels)") {
		t.Errorf("cypher = %q, want blocked relations excluded", cypher)
	}
}

func TestVectorSearch_SkipsHitsThatCannotBeJoinedBack(t *testing.T) {
	// A point ID that is not a node ID cannot be resolved in the graph, so
	// returning it would hand the caller a result it cannot use.
	id := types.NewID()
	p, _, v := newTestProvider()
	v.results = []vectordb.SearchResult{
		{ID: id.String(), Score: 0.91, Payload: map[string]any{"title": "x"}},
		{ID: "not-an-id", Score: 0.88},
	}

	results, err := p.VectorSearch(context.Background(), []float64{0.1, 0.2}, 5, nil)
	if err != nil {
		t.Fatalf("VectorSearch: %v", err)
	}
	if len(results) != 1 || results[0].NodeID != id {
		t.Fatalf("results = %+v, want only the resolvable hit", results)
	}
	if results[0].Similarity < 0.9 {
		t.Errorf("similarity = %v, want the search score carried through", results[0].Similarity)
	}
}

func TestVectorSearch_RejectsAnEmptyEmbedding(t *testing.T) {
	// Searching with no vector would return an arbitrary slice of the collection
	// under a name that promises similarity.
	p, _, _ := newTestProvider()
	if _, err := p.VectorSearch(context.Background(), nil, 5, nil); err == nil {
		t.Error("expected an error for an empty embedding")
	}
}

func TestVectorSearch_DropsFilterTermsItCannotExpress(t *testing.T) {
	// A filter term silently meaning something else is worse than one term less.
	p, _, v := newTestProvider()
	if _, err := p.VectorSearch(context.Background(), []float64{0.1}, 3, map[string]any{
		"severity": "high",
		"nested":   map[string]any{"no": "shape for this"},
	}); err != nil {
		t.Fatalf("VectorSearch: %v", err)
	}
	if v.filter == nil || len(v.filter.Must) != 1 || v.filter.Must[0].Key != "severity" {
		t.Errorf("filter = %+v, want only the expressible term", v.filter)
	}
}

func TestClose_DoesNotTouchThePoolsConnections(t *testing.T) {
	// The datapool.Conn owns both; closing here would take a pooled session out
	// from under the pool while another request holds it.
	p, _, _ := newTestProvider()
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- NewGraphRAGStoreForOwnedProvider ---------------------------------------

// stubEmbedder is enough to satisfy the store's constructor.
type stubEmbedder struct{}

func (stubEmbedder) Embed(context.Context, string) ([]float64, error) {
	return []float64{0.1, 0.2}, nil
}
func (stubEmbedder) EmbedBatch(_ context.Context, texts []string) ([][]float64, error) {
	out := make([][]float64, len(texts))
	for i := range texts {
		out[i] = []float64{0.1, 0.2}
	}
	return out, nil
}
func (stubEmbedder) Dimensions() int { return 2 }
func (stubEmbedder) Model() string   { return "stub" }
func (stubEmbedder) Health(context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func TestNewGraphRAGStoreForOwnedProvider_SkipsConnectionValidation(t *testing.T) {
	// The point of this constructor: a session-backed provider never dials, so
	// requiring a Neo4j URI/username/password would force placeholder credentials
	// into the config — a lie the next reader would believe (gibson#1190).
	p, _, _ := newTestProvider()
	store, err := NewGraphRAGStoreForOwnedProvider(QueryConfig{}, stubEmbedder{}, p)
	if err != nil {
		t.Fatalf("NewGraphRAGStoreForOwnedProvider with no connection config: %v", err)
	}
	if store == nil {
		t.Fatal("store is nil")
	}
}

func TestNewGraphRAGStoreForOwnedProvider_StillValidatesWhatItRuns(t *testing.T) {
	// Query configuration governs the pipeline this store really executes, so it
	// is defaulted and validated even though connection config is not.
	p, _, _ := newTestProvider()
	if _, err := NewGraphRAGStoreForOwnedProvider(QueryConfig{}, nil, p); err == nil {
		t.Error("expected an error with no embedder")
	}
	if _, err := NewGraphRAGStoreForOwnedProvider(QueryConfig{}, stubEmbedder{}, nil); err == nil {
		t.Error("expected an error with no provider")
	}
}

func TestNewGraphRAGStoreForOwnedProvider_HonoursSuppliedQueryTuning(t *testing.T) {
	// The caller supplies tuning, not plumbing — an explicit QueryConfig must be
	// accepted, and a zero one defaulted rather than rejected.
	p, _, _ := newTestProvider()
	tuned, err := NewGraphRAGStoreForOwnedProvider(
		QueryConfig{DefaultTopK: 25, DefaultMaxHops: 3, MinScore: 0.5, VectorWeight: 0.7, GraphWeight: 0.3},
		stubEmbedder{}, p,
	)
	if err != nil {
		t.Fatalf("NewGraphRAGStoreForOwnedProvider with explicit tuning: %v", err)
	}
	if tuned == nil {
		t.Fatal("store is nil")
	}
}

// --- decode helpers ----------------------------------------------------------

func TestRecordsToRelationships_DecodesAndSkipsUnusableRows(t *testing.T) {
	from, to := types.NewID(), types.NewID()
	rels := recordsToRelationships([]map[string]any{
		{
			"from_id":  from.String(),
			"to_id":    to.String(),
			"rel_type": "EXPLOITS",
			"rel":      dbtype.Relationship{Props: map[string]any{"weight": 0.75, "note": "n"}},
		},
		// An endpoint that is not an ID cannot be joined to anything.
		{"from_id": "nope", "to_id": to.String(), "rel_type": "EXPLOITS"},
		{"from_id": from.String(), "to_id": "nope", "rel_type": "EXPLOITS"},
	})

	if len(rels) != 1 {
		t.Fatalf("decoded %d relationships, want only the usable one", len(rels))
	}
	r := rels[0]
	if r.FromID != from || r.ToID != to || r.Type != RelationType("EXPLOITS") {
		t.Errorf("relationship = %+v, want the row's endpoints and type", r)
	}
	if r.Weight != 0.75 {
		t.Errorf("weight = %v, want the stored value", r.Weight)
	}
	if r.Properties["note"] != "n" {
		t.Errorf("properties = %+v, want the edge's own", r.Properties)
	}
}

func TestRecordsToRelationships_MissingEdgePropsIsNotAFailure(t *testing.T) {
	// A row without the `rel` column still names both endpoints and the type,
	// which is enough to be useful.
	from, to := types.NewID(), types.NewID()
	rels := recordsToRelationships([]map[string]any{
		{"from_id": from.String(), "to_id": to.String(), "rel_type": "RELATED_TO"},
	})
	if len(rels) != 1 || rels[0].Type != RelationType("RELATED_TO") {
		t.Fatalf("decoded %+v, want one RELATED_TO relationship", rels)
	}
}

func TestParseTimeProp_UnreadableYieldsZeroNotNow(t *testing.T) {
	// A made-up timestamp is worse than an obviously absent one: it reads as
	// fact downstream.
	if got := parseTimeProp("not a time"); !got.IsZero() {
		t.Errorf("unparseable timestamp = %v, want the zero time", got)
	}
	if got := parseTimeProp(nil); !got.IsZero() {
		t.Errorf("absent timestamp = %v, want the zero time", got)
	}
	if got := parseTimeProp(12345); !got.IsZero() {
		t.Errorf("wrong-typed timestamp = %v, want the zero time", got)
	}
}

func TestParseTimeProp_AcceptsWhatTheProviderWrites(t *testing.T) {
	want := time.Date(2026, 8, 5, 21, 0, 0, 0, time.UTC)
	if got := parseTimeProp(want.Format(time.RFC3339)); !got.Equal(want) {
		t.Errorf("RFC3339 string parsed to %v, want %v", got, want)
	}
	// A node written by another path may carry a native temporal value.
	if got := parseTimeProp(want); !got.Equal(want) {
		t.Errorf("time.Time passed through as %v, want %v", got, want)
	}
}

func TestFloatProp_AcceptsBothNumericShapesNeo4jReturns(t *testing.T) {
	if got := floatProp(float64(2.5)); got != 2.5 {
		t.Errorf("float64 = %v", got)
	}
	if got := floatProp(int64(3)); got != 3 {
		t.Errorf("int64 = %v, want it widened", got)
	}
	if got := floatProp("2.5"); got != 0 {
		t.Errorf("a non-numeric weight = %v, want 0 rather than a guess", got)
	}
}

func TestStringProp_NonStringIsEmptyNotFormatted(t *testing.T) {
	if got := stringProp(42); got != "" {
		t.Errorf("non-string = %q, want empty (formatting would invent an id)", got)
	}
	if got := stringProp("x"); got != "x" {
		t.Errorf("string = %q", got)
	}
}

// --- QueryRelationships ------------------------------------------------------

func TestQueryRelationships_BuildsEveryPredicateItIsGiven(t *testing.T) {
	from, to := types.NewID(), types.NewID()
	p, g, _ := newTestProvider()
	_, err := p.QueryRelationships(context.Background(), RelQuery{
		FromID:     &from,
		ToID:       &to,
		Types:      []RelationType{RelationType("EXPLOITS"), RelationType("RELATED_TO")},
		Properties: map[string]any{"confidence": "high"},
		MinWeight:  0.4,
		Limit:      15,
	})
	if err != nil {
		t.Fatalf("QueryRelationships: %v", err)
	}

	cypher := g.lastCypher()
	for _, want := range []string{
		"a.id = $from", "b.id = $to",
		"coalesce(r.weight, 0) >= $min_weight",
		"r.confidence = $rp0",
		":EXPLOITS|RELATED_TO",
		"LIMIT 15",
	} {
		if !strings.Contains(cypher, want) {
			t.Errorf("cypher missing %q:\n%s", want, cypher)
		}
	}
	if g.params[0]["from"] != from.String() || g.params[0]["min_weight"] != 0.4 {
		t.Errorf("params = %+v, want the caller's values parameterised", g.params[0])
	}
}

func TestQueryRelationships_UnfilteredStillGetsALimit(t *testing.T) {
	p, g, _ := newTestProvider()
	if _, err := p.QueryRelationships(context.Background(), RelQuery{}); err != nil {
		t.Fatalf("QueryRelationships: %v", err)
	}
	if !strings.Contains(g.lastCypher(), "LIMIT 100") {
		t.Errorf("cypher = %q, want a default limit", g.lastCypher())
	}
}

func TestQueryRelationships_DecodesRows(t *testing.T) {
	from, to := types.NewID(), types.NewID()
	p, g, _ := newTestProvider()
	g.result = graph.QueryResult{Records: []map[string]any{{
		"from_id": from.String(), "to_id": to.String(), "rel_type": "EXPLOITS",
		"rel": dbtype.Relationship{Props: map[string]any{"weight": 0.9}},
	}}}

	rels, err := p.QueryRelationships(context.Background(), RelQuery{})
	if err != nil {
		t.Fatalf("QueryRelationships: %v", err)
	}
	if len(rels) != 1 || rels[0].FromID != from || rels[0].Weight != 0.9 {
		t.Fatalf("decoded %+v, want the row's endpoints and weight", rels)
	}
}

func TestQueryRelationships_SurfacesTheQueryFailure(t *testing.T) {
	p, g, _ := newTestProvider()
	g.err = errors.New("neo4j down")
	if _, err := p.QueryRelationships(context.Background(), RelQuery{}); err == nil {
		t.Fatal("expected the query failure to surface")
	}
}

// --- StoreRelationship / StoreNode error paths -------------------------------

// --- Health ------------------------------------------------------------------

func TestHealth_ReportsUnhealthyWithNoGraphClient(t *testing.T) {
	h := NewLocalGraphRAGProvider(nil, &recordingVector{}).Health(context.Background())
	if h.State == types.HealthStateHealthy {
		t.Errorf("health = %+v, want unhealthy with no graph client", h)
	}
}

func TestHealth_DelegatesToTheGraphClient(t *testing.T) {
	p, _, _ := newTestProvider()
	if got := p.Health(context.Background()).State; got != types.HealthStateHealthy {
		t.Errorf("health = %v, want the graph client's answer", got)
	}
}

// --- vectorPayload -----------------------------------------------------------

func TestQueryNodes_DecodesTheMissionIDWhenTheNodeCarriesOne(t *testing.T) {
	// A node's mission is how the World attributes it; dropping it on decode
	// would orphan every node from the run that produced it.
	nodeID, missionID := types.NewID(), types.NewID()
	p, g, _ := newTestProvider()
	g.result = graph.QueryResult{Records: []map[string]any{
		{"n": dbtype.Node{Labels: []string{"Finding"}, Props: map[string]any{
			"id": nodeID.String(), "mission_id": missionID.String(),
		}}},
	}}

	nodes, err := p.QueryNodes(context.Background(), NodeQuery{})
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("decoded %d nodes, want 1", len(nodes))
	}
	if nodes[0].MissionID == nil || *nodes[0].MissionID != missionID {
		t.Errorf("mission id = %v, want %v", nodes[0].MissionID, missionID)
	}
}

func TestParseTimeProp_AcceptsNeo4jsNativeTemporalType(t *testing.T) {
	// A node written by another path carries dbtype.LocalDateTime rather than a
	// string; reading it as absent would silently lose the timestamp.
	want := time.Date(2026, 8, 5, 21, 0, 0, 0, time.UTC)
	if got := parseTimeProp(dbtype.LocalDateTime(want)); !got.Equal(want) {
		t.Errorf("LocalDateTime parsed to %v, want %v", got, want)
	}
}

func TestTraverseGraph_DefaultsAndFilterDepthBothApply(t *testing.T) {
	p, g, _ := newTestProvider()

	// maxHops <= 0 is "one hop", not "unbounded".
	if _, err := p.TraverseGraph(context.Background(), "n1", 0, TraversalFilters{}); err != nil {
		t.Fatalf("TraverseGraph: %v", err)
	}
	if !strings.Contains(g.lastCypher(), "*1..1") {
		t.Errorf("cypher = %q, want a single hop by default", g.lastCypher())
	}

	// The filter's own depth is the caller's later, more specific word.
	if _, err := p.TraverseGraph(context.Background(), "n1", 5, TraversalFilters{MaxDepth: 2}); err != nil {
		t.Fatalf("TraverseGraph: %v", err)
	}
	if !strings.Contains(g.lastCypher(), "*1..2") {
		t.Errorf("cypher = %q, want the filter's depth to win", g.lastCypher())
	}
}

func TestTraverseGraph_AllowedRelationsPruneDuringExpansion(t *testing.T) {
	// Allowed relations go in the PATTERN, not the WHERE, so Neo4j prunes while
	// expanding instead of after — the difference between a bounded walk and
	// touching the whole component.
	p, g, _ := newTestProvider()
	_, err := p.TraverseGraph(context.Background(), "n1", 2, TraversalFilters{
		AllowedRelations: []RelationType{RelationType("EXPLOITS"), RelationType("RELATED_TO")},
		MinWeight:        0.3,
	})
	if err != nil {
		t.Fatalf("TraverseGraph: %v", err)
	}
	cypher := g.lastCypher()
	if !strings.Contains(cypher, ":EXPLOITS|RELATED_TO*1..2") {
		t.Errorf("cypher = %q, want the allowed types in the pattern", cypher)
	}
	if !strings.Contains(cypher, "all(r IN relationships(path) WHERE coalesce(r.weight, 0) >= $min_weight)") {
		t.Errorf("cypher = %q, want the weight floor applied to the path", cypher)
	}
}
