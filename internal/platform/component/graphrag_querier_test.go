// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

func TestProtoQueryToStoreQuery_CarriesBothSearchInputs(t *testing.T) {
	missionID := types.NewID()
	q := protoQueryToStoreQuery(&graphragpb.GraphQuery{
		Text:      "credential stuffing",
		Embedding: []float32{0.25, 0.5},
		TopK:      7,
		MinScore:  0.4,
		NodeTypes: []string{"Finding", "Host"},
		MissionId: missionID.String(),
	})
	if q.Text != "credential stuffing" || q.TopK != 7 || q.MinScore != 0.4 {
		t.Errorf("query = %+v, want the scalar fields carried", q)
	}
	if len(q.Embedding) != 2 || q.Embedding[0] != 0.25 {
		t.Errorf("embedding = %v, want the caller's vector widened to float64", q.Embedding)
	}
	if len(q.NodeTypes) != 2 {
		t.Errorf("node types = %v, want both", q.NodeTypes)
	}
	if q.MissionID == nil || *q.MissionID != missionID {
		t.Errorf("mission id = %v, want the caller's", q.MissionID)
	}
}

func TestProtoQueryToStoreQuery_EmptyQueryIsAGraphFilter(t *testing.T) {
	// A query with neither text nor embedding is a legitimate ask — it is the
	// only way to list by node type — so it must not be rejected here.
	q := protoQueryToStoreQuery(&graphragpb.GraphQuery{NodeTypes: []string{"Host"}})
	if q.Text != "" || len(q.Embedding) != 0 {
		t.Errorf("query = %+v, want no search inputs invented", q)
	}
	if len(q.NodeTypes) != 1 {
		t.Errorf("node types = %v, want the filter preserved", q.NodeTypes)
	}
}

func TestStoreNodeToProto_RoundTripsThroughValueKinds(t *testing.T) {
	id := types.NewID()
	out := storeNodeToProto(graphrag.GraphNode{
		ID:     id,
		Labels: []graphrag.NodeType{graphrag.NodeType("Finding")},
		Properties: map[string]any{
			"title":     "open redirect",
			"exploited": true,
			"count":     int64(3),
			"score":     9.1,
		},
	})
	if out.GetId() != id.String() || out.GetType() != "Finding" {
		t.Fatalf("node = %+v, want id and first label", out)
	}
	props := out.GetProperties()
	if props["title"].GetStringValue() != "open redirect" {
		t.Errorf("title = %v", props["title"])
	}
	if !props["exploited"].GetBoolValue() {
		t.Errorf("exploited = %v", props["exploited"])
	}
	if props["count"].GetIntValue() != 3 {
		t.Errorf("count = %v", props["count"])
	}
	if props["score"].GetDoubleValue() != 9.1 {
		t.Errorf("score = %v", props["score"])
	}
}

func TestAnyToProtoValue_RendersRatherThanDropsAnUnknownShape(t *testing.T) {
	// A property the caller can read as text beats a property that silently
	// disappears between the graph and the wire.
	v := anyToProtoValue([]string{"a", "b"})
	if v.GetStringValue() == "" {
		t.Errorf("value = %+v, want a rendered fallback", v)
	}
}

func TestQuerier_WithoutAPoolReportsRatherThanPanics(t *testing.T) {
	// The daemon leaves the seam nil when the pool is unavailable, but a querier
	// built with a nil pool must still answer.
	q := NewPoolGraphRAGQuerier(nil, nil, graphrag.QueryConfig{}, nil)
	if _, err := q.GetRelatedFindings(context.Background(), "acme", "f1"); err == nil {
		t.Fatal("expected an error with no pool configured")
	}
}
