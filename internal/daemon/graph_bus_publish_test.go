package daemon

// graph_bus_publish_test.go — unit tests verifying graph.Bus pub/sub delivery.
//
// Originally part of mission_source_yaml_test.go; extracted when
// GetMissionSourceYAML was deleted (gibson#299) so the graph-bus coverage
// is not lost.

import (
	"testing"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
)

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
