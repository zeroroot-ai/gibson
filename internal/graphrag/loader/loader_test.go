package loader

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNewGraphLoader(t *testing.T) {
	client := graph.NewMockGraphClient()
	loader := NewGraphLoader(client)

	assert.NotNil(t, loader)
	assert.Equal(t, client, loader.client)
}

func TestLoadResult_AddError(t *testing.T) {
	result := &LoadResult{}

	assert.False(t, result.HasErrors())
	assert.Empty(t, result.Errors)

	result.AddError(fmt.Errorf("test error"))

	assert.True(t, result.HasErrors())
	assert.Len(t, result.Errors, 1)
}

func TestLoadDiscovery_NilClient(t *testing.T) {
	loader := &GraphLoader{client: nil}
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: "test-run"}

	_, err := loader.LoadDiscovery(ctx, execCtx, &graphragpb.DiscoveryResult{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client is nil")
}

func TestLoadDiscovery_NilDiscovery(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: "test-run"}

	result, err := loader.LoadDiscovery(ctx, execCtx, nil)

	// Nil discovery returns empty result, not error
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NodesCreated)
	assert.Equal(t, 0, result.NodesUpdated)
	assert.Equal(t, 0, result.RelationshipsCreated)
}

func TestLoadDiscovery_EmptyResult(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: "test-run"}

	result, err := loader.LoadDiscovery(ctx, execCtx, &graphragpb.DiscoveryResult{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NodesCreated)
	assert.Equal(t, 0, result.NodesUpdated)
	assert.Equal(t, 0, result.RelationshipsCreated)
}

func TestLoadDiscovery_LoadHosts_Success(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Configure mock to return batch node creation result
	// The loader iterates through Records and increments NodesCreated for each record
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify the UNWIND CREATE query was called
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)

	queryStr := calls[0].Args[0].(string)
	assert.Contains(t, queryStr, "UNWIND")
	assert.Contains(t, queryStr, "CREATE")
	assert.Contains(t, queryStr, "host")
}

func TestLoadDiscovery_LoadPorts_WithParentRelationship(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation (1 record = 1 node created)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Mock for port creation (1 record = 1 node created)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		Ports: []*graphragpb.Port{
			{
				HostId:   "192.168.1.1",
				Number:   443,
				Protocol: "tcp",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // 1 host + 1 port
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // HAS_PORT relationship
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_LoadServices_WithParentRelationship(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for service creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "service-1", "idx": float64(0)},
		},
	})

	// Mock for RUNS_SERVICE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		Ports: []*graphragpb.Port{
			{
				HostId:   "192.168.1.1",
				Number:   443,
				Protocol: "tcp",
			},
		},
		Services: []*graphragpb.Service{
			{
				PortId: "192.168.1.1:443:tcp",
				Name:   "https",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 3, result.NodesCreated) // host + port + service
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 2) // HAS_PORT + RUNS_SERVICE
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_WithDiscoveredRelationship(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Mock for DISCOVERED relationships
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: "agent-run-123"}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // DISCOVERED relationship
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_QueryError(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Configure mock to return an error
	client.SetQueryError(fmt.Errorf("simulated query error"))

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	// LoadDiscovery returns errors via result, not error return
	assert.NoError(t, err)
	assert.True(t, result.HasErrors())
}

func TestLoadDiscovery_MultipleDomains(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for domain batch creation - return 3 records for 3 nodes created
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "domain-1", "idx": float64(0)},
			{"element_id": "domain-2", "idx": float64(1)},
			{"element_id": "domain-3", "idx": float64(2)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Domains: []*graphragpb.Domain{
			{Name: "example.com"},
			{Name: "test.com"},
			{Name: "demo.org"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 3, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify single UNWIND query was executed
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)

	queryStr := calls[0].Args[0].(string)
	assert.Contains(t, queryStr, "UNWIND")
	assert.Contains(t, queryStr, "domain")
}

func TestLoadDiscovery_SubdomainsWithParent(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for domain creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "domain-1", "idx": float64(0)},
		},
	})

	// Mock for subdomain creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "subdomain-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_SUBDOMAIN relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Domains: []*graphragpb.Domain{
			{Name: "example.com"},
		},
		Subdomains: []*graphragpb.Subdomain{
			{
				Name:     "www",
				DomainId: "example.com",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // domain + subdomain
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // HAS_SUBDOMAIN
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_CustomNodes(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation - returns 1 record for 1 node
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "my_custom_type",
				IdProperties: map[string]string{
					"name": "test-node",
				},
				Properties: map[string]string{
					"value": "test-value",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	if result.HasErrors() {
		t.Logf("Errors: %v", result.Errors)
	}
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify query was called with custom type
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)
	if len(calls) > 0 {
		queryStr := calls[0].Args[0].(string)
		assert.Contains(t, queryStr, "my_custom_type")
	}
}

func TestLoadDiscovery_Findings(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for finding creation - returns 1 record for 1 node
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "finding-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Title:    "SQL Injection",
				Severity: "high",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify query was called with finding type
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)
	queryStr := calls[0].Args[0].(string)
	assert.Contains(t, queryStr, "finding")
}

func TestLoadDiscovery_ExplicitRelationships(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host batch creation - returns 2 records for 2 nodes
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
			{"element_id": "host-2", "idx": float64(1)},
		},
	})

	// Mock for explicit relationship creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
			{Ip: "192.168.1.2"},
		},
		ExplicitRelationships: []*graphragpb.ExplicitRelationship{
			{
				RelationshipType: "CONNECTS_TO",
				FromType:         "host",
				FromId:           map[string]string{"ip": "192.168.1.1"},
				ToType:           "host",
				ToId:             map[string]string{"ip": "192.168.1.2"},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated)
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // explicit relationship
	assert.False(t, result.HasErrors())

	// Verify relationship query was called
	calls := client.GetCallsByMethod("Query")
	foundRelQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "CONNECTS_TO") {
			foundRelQuery = true
			break
		}
	}
	assert.True(t, foundRelQuery, "Should have executed CONNECTS_TO relationship query")
}

func TestLoadDiscovery_Technologies(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for technology creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "tech-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Technologies: []*graphragpb.Technology{
			{
				Name:     "nginx",
				Category: strPtr("Web Server"),
				Version:  strPtr("1.18.0"),
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_Certificates(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for certificate creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "cert-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Certificates: []*graphragpb.Certificate{
			{
				FingerprintSha256: strPtr("abc123def456"),
				Subject:           strPtr("CN=example.com"),
				Issuer:            strPtr("CN=Let's Encrypt"),
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_Evidence(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for finding creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "finding-1", "idx": float64(0)},
		},
	})

	// Mock for evidence creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "evidence-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_EVIDENCE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Title:    "SQL Injection",
				Severity: "high",
			},
		},
		Evidence: []*graphragpb.Evidence{
			{
				FindingId: "finding-1",
				Type:      "request",
				Content:   strPtr("GET /admin?id=1' OR '1'='1"),
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // finding + evidence
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // HAS_EVIDENCE
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_Endpoints(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for service creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "service-1", "idx": float64(0)},
		},
	})

	// Mock for RUNS_SERVICE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for endpoint creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "endpoint-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_ENDPOINT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 443, Protocol: "tcp"},
		},
		Services: []*graphragpb.Service{
			{PortId: "192.168.1.1:443:tcp", Name: "https"},
		},
		Endpoints: []*graphragpb.Endpoint{
			{
				Url:       "/api/v1/users",
				ServiceId: "192.168.1.1:443:tcp:https",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 4, result.NodesCreated) // host + port + service + endpoint
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 3) // HAS_PORT + RUNS_SERVICE + HAS_ENDPOINT
	assert.False(t, result.HasErrors())
}

func TestLoadDiscovery_CustomNodeWithParent(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Mock for parent relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{AgentRunID: ""}

	parentType := "host"
	relType := "DETECTED_ON"

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "vulnerability",
				IdProperties: map[string]string{
					"cve": "CVE-2024-1234",
				},
				Properties: map[string]string{
					"severity": "critical",
				},
				ParentType:       &parentType,
				ParentId:         map[string]string{"ip": "192.168.1.1"},
				RelationshipType: &relType,
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // host + custom node
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // DETECTED_ON
	assert.False(t, result.HasErrors())

	// Verify relationship query was made with correct type
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 3) // host create, custom create, relationship
	found := false
	for _, call := range calls {
		query := call.Args[0].(string)
		if strings.Contains(query, "DETECTED_ON") {
			found = true
			assert.Contains(t, query, "parent:host")
		}
	}
	assert.True(t, found, "Expected relationship query with DETECTED_ON")
}

func TestLoadDiscovery_MissionContextInjection(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Capture the params passed to Query
	var capturedParams map[string]any

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionID:    "mission-123",
		MissionRunID: "run-456",
		AgentRunID:   "agent-789",
		AgentName:    "network-recon",
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Get the query calls and verify mission context was passed
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)

	// The params should contain nodes with mission context
	capturedParams = calls[0].Args[1].(map[string]any)
	nodes := capturedParams["nodes"].([]map[string]any)
	assert.GreaterOrEqual(t, len(nodes), 1)

	allProps := nodes[0]["all_props"].(map[string]any)
	assert.Equal(t, "mission-123", allProps["mission_id"])
	assert.Equal(t, "run-456", allProps["mission_run_id"])
	assert.Equal(t, "agent-789", allProps["agent_run_id"])
	assert.Equal(t, "network-recon", allProps["discovered_by"])
}

// Helper function
func strPtr(s string) *string {
	return &s
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ==================== RELATIONSHIP CREATION INTEGRATION TESTS ====================

// TestRelationshipCreation_HostWithPorts verifies that HAS_PORT relationships
// are created correctly between Host and Port nodes using UUID-based identity.
func TestRelationshipCreation_HostWithPorts(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship (host to mission_run)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
		AgentRunID:   "",
	}

	// Create host with explicit ID
	hostID := "host-uuid-1"
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Id: &hostID,
				Ip: "192.168.1.100",
			},
		},
		Ports: []*graphragpb.Port{
			{
				HostId:   hostID, // Reference parent host by UUID
				Number:   443,
				Protocol: "tcp",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // 1 host + 1 port
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // At least HAS_PORT relationship
	assert.False(t, result.HasErrors())

	// Verify relationship creation query was executed
	calls := client.GetCallsByMethod("Query")
	foundRelQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "HAS_PORT") && contains(queryStr, "parent:host") {
			foundRelQuery = true
			// Verify parent matching uses the ID field
			assert.Contains(t, queryStr, "parent.id")
			break
		}
	}
	assert.True(t, foundRelQuery, "Expected HAS_PORT relationship query to be executed")
}

// TestRelationshipCreation_PortWithServices verifies that RUNS_SERVICE relationships
// are created correctly between Port and Service nodes.
func TestRelationshipCreation_PortWithServices(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-elem-1", "idx": float64(0)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})

	// Mock for service creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "service-elem-1", "idx": float64(0)},
		},
	})

	// Mock for RUNS_SERVICE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "RUNS_SERVICE"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
	}

	hostID := "host-uuid-1"
	portID := "port-uuid-1"

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.100"},
		},
		Ports: []*graphragpb.Port{
			{
				Id:       &portID,
				HostId:   hostID,
				Number:   443,
				Protocol: "tcp",
			},
		},
		Services: []*graphragpb.Service{
			{
				PortId: portID, // Reference parent port by UUID
				Name:   "https",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 3, result.NodesCreated) // host + port + service
	assert.False(t, result.HasErrors())

	// Verify RUNS_SERVICE relationship query was executed
	calls := client.GetCallsByMethod("Query")
	foundRelQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "RUNS_SERVICE") && contains(queryStr, "parent:port") {
			foundRelQuery = true
			// Verify parent matching uses port_id field from service
			assert.Contains(t, queryStr, "parent.id")
			break
		}
	}
	assert.True(t, foundRelQuery, "Expected RUNS_SERVICE relationship query to be executed")
}

// TestRelationshipCreation_RootNodeMissionRun verifies that BELONGS_TO relationships
// are created from root nodes to MissionRun.
func TestRelationshipCreation_RootNodeMissionRun(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-456",
		MissionID:    "mission-123",
	}

	hostID := "host-uuid-root"
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Id: &hostID,
				Ip: "10.0.0.1",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // BELONGS_TO relationship
	assert.False(t, result.HasErrors())

	// Verify BELONGS_TO relationship query was executed
	calls := client.GetCallsByMethod("Query")
	foundBelongsTo := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "BELONGS_TO") && contains(queryStr, "mission_run") {
			foundBelongsTo = true
			params := call.Args[1].(map[string]any)
			assert.Equal(t, "run-456", params["run_id"])
			break
		}
	}
	assert.True(t, foundBelongsTo, "Expected BELONGS_TO relationship to MissionRun")
}

// TestRelationshipCreation_MissingParent verifies that the loader handles
// missing parent nodes gracefully without failing the entire batch.
func TestRelationshipCreation_MissingParent(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for port creation (host doesn't exist)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-elem-1", "idx": float64(0)},
		},
	})

	// Mock for relationship creation - returns no results (parent not found)
	// The loader should log a warning but continue processing
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{}, // Empty result - no parent found
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
	}

	discovery := &graphragpb.DiscoveryResult{
		Ports: []*graphragpb.Port{
			{
				HostId:   "non-existent-host-id", // References non-existent parent
				Number:   8080,
				Protocol: "tcp",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	// Should not fail - nodes should still be created
	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated) // Port node created
	// Relationship may not be created, but no error should be added
	// (the loader treats missing parents as a warning, not an error)
	assert.False(t, result.HasErrors())
}

// TestRelationshipCreation_ChainedRelationships verifies that relationships
// are created correctly across a deep hierarchy: Host -> Port -> Service -> Endpoint.
func TestRelationshipCreation_ChainedRelationships(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship (host to mission_run)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})

	// Mock for service creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "service-elem-1", "idx": float64(0)},
		},
	})

	// Mock for RUNS_SERVICE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "RUNS_SERVICE"}},
		},
	})

	// Mock for endpoint creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "endpoint-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_ENDPOINT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_ENDPOINT"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-789",
	}

	hostID := "host-chain-1"
	portID := "port-chain-1"
	serviceID := "service-chain-1"

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "10.10.10.10"},
		},
		Ports: []*graphragpb.Port{
			{
				Id:       &portID,
				HostId:   hostID,
				Number:   443,
				Protocol: "tcp",
			},
		},
		Services: []*graphragpb.Service{
			{
				Id:     &serviceID,
				PortId: portID,
				Name:   "https",
			},
		},
		Endpoints: []*graphragpb.Endpoint{
			{
				ServiceId: serviceID,
				Url:       "/api/v2/users",
				Method:    strPtr("GET"),
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 4, result.NodesCreated) // host + port + service + endpoint
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 3) // At least 3 parent relationships
	assert.False(t, result.HasErrors())

	// Verify all three relationships were created
	calls := client.GetCallsByMethod("Query")
	relationships := []string{"HAS_PORT", "RUNS_SERVICE", "HAS_ENDPOINT"}
	foundRels := make(map[string]bool)

	for _, call := range calls {
		queryStr := call.Args[0].(string)
		for _, relType := range relationships {
			if contains(queryStr, relType) {
				foundRels[relType] = true
			}
		}
	}

	for _, relType := range relationships {
		assert.True(t, foundRels[relType], "Expected %s relationship to be created", relType)
	}
}

// TestRelationshipCreation_MultiplePortsPerHost verifies that multiple child nodes
// can be correctly linked to the same parent using UUID-based identity.
func TestRelationshipCreation_MultiplePortsPerHost(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship (host to mission_run)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for batch port creation (3 ports)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-elem-1", "idx": float64(0)},
			{"element_id": "port-elem-2", "idx": float64(1)},
			{"element_id": "port-elem-3", "idx": float64(2)},
		},
	})

	// Mock for HAS_PORT relationships (one per port)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
	}

	hostID := "host-multi-port"
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.50"},
		},
		Ports: []*graphragpb.Port{
			{HostId: hostID, Number: 80, Protocol: "tcp"},
			{HostId: hostID, Number: 443, Protocol: "tcp"},
			{HostId: hostID, Number: 8080, Protocol: "tcp"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 4, result.NodesCreated) // 1 host + 3 ports
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 3) // At least 3 HAS_PORT relationships
	assert.False(t, result.HasErrors())

	// Verify that relationship queries reference the same parent host ID
	calls := client.GetCallsByMethod("Query")
	relCallCount := 0
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "HAS_PORT") && contains(queryStr, "parent:host") {
			relCallCount++
			params := call.Args[1].(map[string]any)
			// All relationship queries should reference the same parent host ID
			assert.Equal(t, hostID, params["parent_id"])
		}
	}
	assert.GreaterOrEqual(t, relCallCount, 3, "Expected 3 HAS_PORT relationship queries")
}

// TestRelationshipCreation_DomainSubdomain verifies HAS_SUBDOMAIN relationships
// between Domain and Subdomain nodes.
func TestRelationshipCreation_DomainSubdomain(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for domain creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "domain-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship (domain to mission_run)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for subdomain creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "subdomain-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_SUBDOMAIN relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_SUBDOMAIN"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
	}

	domainID := "domain-uuid-1"
	discovery := &graphragpb.DiscoveryResult{
		Domains: []*graphragpb.Domain{
			{Id: &domainID, Name: "example.com"},
		},
		Subdomains: []*graphragpb.Subdomain{
			{
				DomainId: domainID, // Reference parent domain by UUID
				Name:     "api",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // domain + subdomain
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // At least HAS_SUBDOMAIN relationship
	assert.False(t, result.HasErrors())

	// Verify HAS_SUBDOMAIN relationship query was executed
	calls := client.GetCallsByMethod("Query")
	foundRelQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "HAS_SUBDOMAIN") && contains(queryStr, "parent:domain") {
			foundRelQuery = true
			break
		}
	}
	assert.True(t, foundRelQuery, "Expected HAS_SUBDOMAIN relationship query to be executed")
}

// TestRelationshipCreation_FindingEvidence verifies HAS_EVIDENCE relationships
// between Finding and Evidence nodes.
func TestRelationshipCreation_FindingEvidence(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for finding creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "finding-elem-1", "idx": float64(0)},
		},
	})

	// Mock for BELONGS_TO relationship (finding is root node)
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Mock for evidence creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "evidence-elem-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_EVIDENCE relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_EVIDENCE"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-123",
	}

	findingID := "finding-uuid-1"
	discovery := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Id:       &findingID,
				Title:    "XSS Vulnerability",
				Severity: "high",
			},
		},
		Evidence: []*graphragpb.Evidence{
			{
				FindingId: findingID, // Reference parent finding by UUID
				Type:      "request",
				Content:   strPtr("<script>alert('xss')</script>"),
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated) // finding + evidence
	assert.False(t, result.HasErrors())

	// Verify HAS_EVIDENCE relationship query was executed
	calls := client.GetCallsByMethod("Query")
	foundRelQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if contains(queryStr, "HAS_EVIDENCE") && contains(queryStr, "parent:finding") {
			foundRelQuery = true
			break
		}
	}
	assert.True(t, foundRelQuery, "Expected HAS_EVIDENCE relationship query to be executed")
}

// ==================== OBSERVABILITY INSTRUMENTATION TESTS ====================

// TestGraphWriteSpanEmission verifies that graph write operations emit tracing spans
// with correct attributes for observability.
func TestGraphWriteSpanEmission(t *testing.T) {
	// Use in-memory trace exporter to capture spans
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())

	// Set global tracer provider for this test
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
			{"element_id": "host-2", "idx": float64(1)},
		},
	})

	// Mock for BELONGS_TO relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(2)},
		},
	})

	// Mock for port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-1", "idx": float64(0)},
		},
	})

	// Mock for HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"r": map[string]any{"type": "HAS_PORT"}},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-observability-test",
		MissionID:    "mission-obs-123",
	}

	hostID := "host-span-1"
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.1"},
			{Ip: "192.168.1.2"},
		},
		Ports: []*graphragpb.Port{
			{
				HostId:   hostID,
				Number:   443,
				Protocol: "tcp",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 3, result.NodesCreated) // 2 hosts + 1 port
	assert.False(t, result.HasErrors())

	// Verify span was emitted
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1, "Expected at least one span to be emitted")

	// Find the graph store span
	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan, "Expected to find gibson.graph.store span")

	// Verify span attributes
	attrs := graphStoreSpan.Attributes
	attrMap := make(map[string]any)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	// Check entity count attribute
	entitiesCount, ok := attrMap["gibson.graph.entities_count"]
	require.True(t, ok, "Span should have gibson.graph.entities_count attribute")
	assert.Equal(t, int64(3), entitiesCount, "entities_count should be 3")

	// Check relationships count attribute
	relationshipsCount, ok := attrMap["gibson.graph.relationships_count"]
	require.True(t, ok, "Span should have gibson.graph.relationships_count attribute")
	assert.GreaterOrEqual(t, relationshipsCount.(int64), int64(1), "relationships_count should be at least 1")

	// Check entity types attribute
	entityTypes, ok := attrMap["gibson.graph.entity_types"]
	require.True(t, ok, "Span should have gibson.graph.entity_types attribute")
	entityTypesStr := entityTypes.(string)
	assert.Contains(t, entityTypesStr, "host", "entity_types should contain 'host'")
	assert.Contains(t, entityTypesStr, "port", "entity_types should contain 'port'")

	// Verify the JSON structure
	var types []string
	err = json.Unmarshal([]byte(entityTypesStr), &types)
	require.NoError(t, err, "entity_types should be valid JSON")
	assert.Contains(t, types, "host")
	assert.Contains(t, types, "port")
}

// TestGraphWriteSpanAttributes verifies that span attributes are correctly set
// for different types of graph writes.
func TestGraphWriteSpanAttributes(t *testing.T) {
	tests := []struct {
		name                  string
		discovery             *graphragpb.DiscoveryResult
		expectedEntities      int
		expectedRelationships int
		expectedEntityTypes   []string
	}{
		{
			name: "hosts only",
			discovery: &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{
					{Ip: "10.0.0.1"},
					{Ip: "10.0.0.2"},
					{Ip: "10.0.0.3"},
				},
			},
			expectedEntities:      3,
			expectedRelationships: 3, // BELONGS_TO relationships
			expectedEntityTypes:   []string{"host"},
		},
		{
			name: "domains and subdomains",
			discovery: &graphragpb.DiscoveryResult{
				Domains: []*graphragpb.Domain{
					{Name: "example.com"},
				},
				Subdomains: []*graphragpb.Subdomain{
					{DomainId: "example.com", Name: "www"},
					{DomainId: "example.com", Name: "api"},
				},
			},
			expectedEntities:      3,
			expectedRelationships: 3, // 1 BELONGS_TO + 2 HAS_SUBDOMAIN
			expectedEntityTypes:   []string{"domain", "subdomain"},
		},
		{
			name: "findings with evidence",
			discovery: &graphragpb.DiscoveryResult{
				Findings: []*graphragpb.Finding{
					{Title: "SQL Injection", Severity: "high"},
				},
				Evidence: []*graphragpb.Evidence{
					{FindingId: "finding-1", Type: "request"},
				},
			},
			expectedEntities:      2,
			expectedRelationships: 2, // 1 BELONGS_TO + 1 HAS_EVIDENCE
			expectedEntityTypes:   []string{"finding", "evidence"},
		},
		{
			name: "mixed entity types",
			discovery: &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{
					{Ip: "192.168.1.1"},
				},
				Domains: []*graphragpb.Domain{
					{Name: "test.com"},
				},
				Technologies: []*graphragpb.Technology{
					{Name: "nginx"},
				},
			},
			expectedEntities:      3,
			expectedRelationships: 3, // BELONGS_TO for each
			expectedEntityTypes:   []string{"host", "domain", "technology"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup in-memory trace exporter
			exporter := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(
				sdktrace.WithSyncer(exporter),
			)
			defer tp.Shutdown(context.Background())
			otel.SetTracerProvider(tp)

			client := graph.NewMockGraphClient()
			err := client.Connect(context.Background())
			require.NoError(t, err)

			// Setup mock responses based on expected entities/relationships
			for i := 0; i < tt.expectedEntities+tt.expectedRelationships; i++ {
				client.AddQueryResult(graph.QueryResult{
					Records: []map[string]any{
						{"element_id": fmt.Sprintf("elem-%d", i), "idx": float64(0)},
					},
				})
			}

			loader := NewGraphLoader(client)
			ctx := context.Background()
			execCtx := ExecContext{
				MissionRunID: "run-test",
			}

			result, err := loader.LoadDiscovery(ctx, execCtx, tt.discovery)
			require.NoError(t, err)
			assert.False(t, result.HasErrors())

			// Find and verify the graph store span
			spans := exporter.GetSpans()
			var graphStoreSpan *tracetest.SpanStub
			for i := range spans {
				if spans[i].Name == "gibson.graph.store" {
					graphStoreSpan = &spans[i]
					break
				}
			}
			require.NotNil(t, graphStoreSpan)

			// Verify attributes
			attrs := graphStoreSpan.Attributes
			attrMap := make(map[string]any)
			for _, attr := range attrs {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			// Verify entity types
			entityTypes, ok := attrMap["gibson.graph.entity_types"]
			require.True(t, ok)
			var types []string
			err = json.Unmarshal([]byte(entityTypes.(string)), &types)
			require.NoError(t, err)

			for _, expectedType := range tt.expectedEntityTypes {
				assert.Contains(t, types, expectedType)
			}
		})
	}
}

// TestGraphWriteSpanWithErrors verifies that spans are still emitted even when errors occur.
func TestGraphWriteSpanWithErrors(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Simulate an error during graph write
	client.SetQueryError(fmt.Errorf("simulated database error"))

	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		MissionRunID: "run-error-test",
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	// Should not return error, but should have errors in result
	assert.NoError(t, err)
	assert.True(t, result.HasErrors())

	// Verify span was still emitted
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan, "Span should be emitted even on error")

	// Verify span attributes exist (counts may be 0 due to error)
	attrs := graphStoreSpan.Attributes
	attrMap := make(map[string]any)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	_, hasEntitiesCount := attrMap["gibson.graph.entities_count"]
	assert.True(t, hasEntitiesCount, "Span should have entities_count attribute even on error")

	_, hasRelationshipsCount := attrMap["gibson.graph.relationships_count"]
	assert.True(t, hasRelationshipsCount, "Span should have relationships_count attribute even on error")
}
