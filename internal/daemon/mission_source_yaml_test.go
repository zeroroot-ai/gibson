package daemon

// mission_source_yaml_test.go — unit tests for source_yaml persistence in
// the Mission struct (Task 7) and the daemon graph bus wiring (Task 8).
//
// Full Neo4j MERGE integration is covered by the integration test suite
// (build tag: integration).  These tests verify the structural plumbing.
//
// Spec: dashboard-neo4j-crud-removal (Tasks 7 + 8).

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// TestMission_SourceYAMLField verifies that the SourceYAML field on
// mission.Mission persists through a JSON round-trip (as stored in Redis).
func TestMission_SourceYAMLField(t *testing.T) {
	t.Parallel()
	orig := &mission.Mission{
		ID:         types.NewID(),
		Name:       "test-yaml-mission",
		SourceYAML: "objectives:\n  - pentest",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored mission.Mission
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.SourceYAML != orig.SourceYAML {
		t.Errorf("SourceYAML round-trip = %q, want %q", restored.SourceYAML, orig.SourceYAML)
	}
}

// TestMission_SourceYAMLOmitEmpty verifies that an empty SourceYAML is
// omitted from the JSON representation (avoids bloating all mission records).
func TestMission_SourceYAMLOmitEmpty(t *testing.T) {
	t.Parallel()
	m := &mission.Mission{
		ID:   types.NewID(),
		Name: "no-yaml-mission",
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "source_yaml") {
		t.Errorf("expected source_yaml omitted from JSON when empty, got: %s", data)
	}
}

// TestGraphBus_NodeAddedPublish verifies that graph.Bus.Publish delivers a
// NODE_ADDED GraphUpdate with a Mission node payload — matching what
// CreateMission publishes after a successful Neo4j MERGE.
func TestGraphBus_NodeAddedPublish(t *testing.T) {
	t.Parallel()
	bus := graph.NewBus(nil)
	tenant, err := auth.NewTenantID("test-bus-tenant")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}

	sub := bus.Subscribe(tenant)
	defer bus.Unsubscribe(sub)

	update := &graphpb.GraphUpdate{
		Kind: graphpb.GraphUpdate_NODE_ADDED,
		Entity: &graphpb.GraphUpdate_Node{
			Node: &graphpb.Node{
				Id:     "mission-123",
				Labels: []string{"Mission"},
				Properties: map[string]string{
					"id":        "mission-123",
					"name":      "test-mission",
					"tenant_id": tenant.String(),
					"status":    "pending",
				},
			},
		},
	}

	bus.Publish(tenant, update)

	select {
	case got := <-sub.Ch():
		if got == nil {
			t.Fatal("received nil update")
		}
		if got.Kind != graphpb.GraphUpdate_NODE_ADDED {
			t.Errorf("Kind = %v, want NODE_ADDED", got.Kind)
		}
		nodeWrapper, ok := got.Entity.(*graphpb.GraphUpdate_Node)
		if !ok || nodeWrapper.Node == nil {
			t.Fatalf("expected GraphUpdate_Node entity, got %T", got.Entity)
		}
		if nodeWrapper.Node.Id != "mission-123" {
			t.Errorf("Node.Id = %q, want mission-123", nodeWrapper.Node.Id)
		}
	default:
		t.Error("expected update in subscriber channel, got none (bus did not deliver)")
	}
}
