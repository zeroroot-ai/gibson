package engine

import (
	"strings"
	"testing"
	"time"
)

func TestCypherBuilder_BuildNodeMerge(t *testing.T) {
	tests := []struct {
		name       string
		nodeType   string
		nodeID     string
		properties map[string]any
		wantQuery  []string // Query parts we expect to see
		wantParams []string // Parameter keys we expect
	}{
		{
			name:     "basic node merge",
			nodeType: "mission",
			nodeID:   "mission:abc123",
			properties: map[string]any{
				"name":   "Test Mission",
				"status": "running",
			},
			wantQuery: []string{
				"MERGE (n:mission {id: $id})",
				"n.name = $name",
				"n.status = $status",
				"n.updated_at = datetime($updated_at)",
				"RETURN n",
			},
			wantParams: []string{"id", "name", "status", "updated_at"},
		},
		{
			name:       "node merge without properties",
			nodeType:   "target",
			nodeID:     "target:xyz789",
			properties: map[string]any{},
			wantQuery: []string{
				"MERGE (n:target {id: $id})",
				"RETURN n",
			},
			wantParams: []string{"id"},
		},
		{
			name:     "node with special characters in type",
			nodeType: "node-type_with.special",
			nodeID:   "node:test",
			properties: map[string]any{
				"value": 42,
			},
			wantQuery: []string{
				"MERGE (n:node_type_with_special {id: $id})",
				"SET n.value = $value",
			},
			wantParams: []string{"id", "value"},
		},
		{
			name:     "node with timestamp property",
			nodeType: "event",
			nodeID:   "event:123",
			properties: map[string]any{
				"timestamp": time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			wantQuery: []string{
				"MERGE (n:event {id: $id})",
				"SET n.timestamp = $timestamp",
			},
			wantParams: []string{"id", "timestamp"},
		},
		{
			name:     "node with array properties",
			nodeType: "host",
			nodeID:   "host:192.168.1.1",
			properties: map[string]any{
				"tags":  []string{"production", "web"},
				"ports": []int{80, 443, 8080},
			},
			wantQuery: []string{
				"MERGE (n:host {id: $id})",
				"n.tags = $tags",
				"n.ports = $ports",
			},
			wantParams: []string{"id", "tags", "ports"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildNodeMerge(tt.nodeType, tt.nodeID, tt.properties)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildNodeMerge() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildNodeMerge() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}

			// Verify node ID parameter value
			if params["id"] != tt.nodeID {
				t.Errorf("BuildNodeMerge() params[id] = %v, want %v", params["id"], tt.nodeID)
			}

			// Verify parameterization (no direct values in query)
			for key, value := range tt.properties {
				// Skip complex types that won't appear directly
				if _, ok := value.(time.Time); ok {
					continue
				}
				if _, ok := value.([]string); ok {
					continue
				}
				if _, ok := value.([]int); ok {
					continue
				}

				// Simple values should not appear unparameterized
				valueStr := ""
				switch v := value.(type) {
				case string:
					valueStr = v
				}
				if valueStr != "" && strings.Contains(query, valueStr) && !strings.Contains(query, "$"+key) {
					t.Errorf("BuildNodeMerge() query contains unparameterized value: %s", valueStr)
				}
			}
		})
	}
}

func TestCypherBuilder_BuildRelationshipMerge(t *testing.T) {
	tests := []struct {
		name       string
		relType    string
		fromID     string
		toID       string
		properties map[string]any
		wantQuery  []string
		wantParams []string
	}{
		{
			name:    "basic relationship merge",
			relType: "PART_OF",
			fromID:  "tool:nmap",
			toID:    "mission:abc123",
			properties: map[string]any{
				"weight": 1.0,
			},
			wantQuery: []string{
				"MATCH (a {id: $from_id})",
				"MATCH (b {id: $to_id})",
				"MERGE (a)-[r:PART_OF]->(b)",
				"SET r.weight = $weight",
				"r.updated_at = datetime($updated_at)",
				"RETURN r",
			},
			wantParams: []string{"from_id", "to_id", "weight", "updated_at"},
		},
		{
			name:       "relationship without properties",
			relType:    "RELATES_TO",
			fromID:     "node:a",
			toID:       "node:b",
			properties: map[string]any{},
			wantQuery: []string{
				"MATCH (a {id: $from_id})",
				"MATCH (b {id: $to_id})",
				"MERGE (a)-[r:RELATES_TO]->(b)",
				"RETURN r",
			},
			wantParams: []string{"from_id", "to_id"},
		},
		{
			name:    "relationship with special characters in type",
			relType: "has-subdomain.test",
			fromID:  "domain:example.com",
			toID:    "domain:sub.example.com",
			properties: map[string]any{
				"discovered": true,
			},
			wantQuery: []string{
				"MERGE (a)-[r:HAS_SUBDOMAIN_TEST]->(b)",
			},
			wantParams: []string{"from_id", "to_id", "discovered"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildRelationshipMerge(tt.relType, tt.fromID, tt.toID, tt.properties)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildRelationshipMerge() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildRelationshipMerge() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}

			// Verify ID parameter values
			if params["from_id"] != tt.fromID {
				t.Errorf("BuildRelationshipMerge() params[from_id] = %v, want %v", params["from_id"], tt.fromID)
			}
			if params["to_id"] != tt.toID {
				t.Errorf("BuildRelationshipMerge() params[to_id] = %v, want %v", params["to_id"], tt.toID)
			}
		})
	}
}

func TestCypherBuilder_BuildBatchNodeMerge(t *testing.T) {
	tests := []struct {
		name       string
		nodeType   string
		nodes      []NodeData
		wantQuery  []string
		wantParams []string
	}{
		{
			name:     "batch merge multiple hosts",
			nodeType: "host",
			nodes: []NodeData{
				{
					ID: "host:192.168.1.1",
					Properties: map[string]any{
						"ip":     "192.168.1.1",
						"status": "up",
					},
				},
				{
					ID: "host:192.168.1.2",
					Properties: map[string]any{
						"ip":     "192.168.1.2",
						"status": "down",
					},
				},
			},
			wantQuery: []string{
				"UNWIND $nodes AS node",
				"MERGE (n:host {id: node.id})",
				"SET n += node.properties",
				"n.updated_at = datetime($updated_at)",
				"RETURN count(n) as created_count",
			},
			wantParams: []string{"nodes", "updated_at"},
		},
		{
			name:     "batch merge empty nodes",
			nodeType: "domain",
			nodes:    []NodeData{},
			wantQuery: []string{
				"UNWIND $nodes AS node",
				"MERGE (n:domain {id: node.id})",
			},
			wantParams: []string{"nodes", "updated_at"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildBatchNodeMerge(tt.nodeType, tt.nodes)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildBatchNodeMerge() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildBatchNodeMerge() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}

			// Verify nodes parameter structure
			nodes, ok := params["nodes"].([]map[string]any)
			if !ok {
				t.Errorf("BuildBatchNodeMerge() params[nodes] is not []map[string]any")
			} else if len(nodes) != len(tt.nodes) {
				t.Errorf("BuildBatchNodeMerge() params[nodes] length = %d, want %d", len(nodes), len(tt.nodes))
			}
		})
	}
}

func TestCypherBuilder_BuildBatchRelationshipMerge(t *testing.T) {
	tests := []struct {
		name          string
		relationships []RelationshipData
		wantQuery     []string
		wantParams    []string
	}{
		{
			name: "batch merge multiple relationships",
			relationships: []RelationshipData{
				{
					FromID: "tool:nmap",
					ToID:   "mission:abc",
					Type:   "PART_OF",
					Properties: map[string]any{
						"weight": 1.0,
					},
				},
				{
					FromID: "tool:masscan",
					ToID:   "mission:abc",
					Type:   "PART_OF",
					Properties: map[string]any{
						"weight": 0.8,
					},
				},
			},
			wantQuery: []string{
				"UNWIND $relationships AS rel",
				"MATCH (a {id: rel.from_id})",
				"MATCH (b {id: rel.to_id})",
				"CALL apoc.merge.relationship",
			},
			wantParams: []string{"relationships", "updated_at"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildBatchRelationshipMerge(tt.relationships)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildBatchRelationshipMerge() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildBatchRelationshipMerge() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}
		})
	}
}

func TestCypherBuilder_BuildNodeQuery(t *testing.T) {
	tests := []struct {
		name       string
		nodeType   string
		filters    map[string]any
		wantQuery  []string
		wantParams []string
	}{
		{
			name:     "query with filters",
			nodeType: "mission",
			filters: map[string]any{
				"status": "running",
				"name":   "Test",
			},
			wantQuery: []string{
				"MATCH (n:mission)",
				"WHERE n.status = $status",
				"n.name = $name",
				"RETURN n",
			},
			wantParams: []string{"status", "name"},
		},
		{
			name:     "query without filters",
			nodeType: "host",
			filters:  map[string]any{},
			wantQuery: []string{
				"MATCH (n:host)",
				"RETURN n",
			},
			wantParams: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildNodeQuery(tt.nodeType, tt.filters)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildNodeQuery() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildNodeQuery() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}
		})
	}
}

func TestCypherBuilder_BuildRelationshipQuery(t *testing.T) {
	tests := []struct {
		name        string
		relType     string
		fromFilters map[string]any
		toFilters   map[string]any
		relFilters  map[string]any
		wantQuery   []string
		wantParams  []string
	}{
		{
			name:    "query with all filters",
			relType: "PART_OF",
			fromFilters: map[string]any{
				"type": "tool",
			},
			toFilters: map[string]any{
				"type": "mission",
			},
			relFilters: map[string]any{
				"weight": 1.0,
			},
			wantQuery: []string{
				"MATCH (a)-[r:PART_OF]->(b)",
				"WHERE a.type = $from_type",
				"b.type = $to_type",
				"r.weight = $rel_weight",
				"RETURN a, r, b",
			},
			wantParams: []string{"from_type", "to_type", "rel_weight"},
		},
		{
			name:        "query without filters",
			relType:     "RELATES_TO",
			fromFilters: nil,
			toFilters:   nil,
			relFilters:  nil,
			wantQuery: []string{
				"MATCH (a)-[r:RELATES_TO]->(b)",
				"RETURN a, r, b",
			},
			wantParams: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildRelationshipQuery(tt.relType, tt.fromFilters, tt.toFilters, tt.relFilters)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildRelationshipQuery() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildRelationshipQuery() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}
		})
	}
}

func TestCypherBuilder_BuildDeleteNode(t *testing.T) {
	tests := []struct {
		name       string
		nodeID     string
		wantQuery  []string
		wantParams []string
	}{
		{
			name:   "delete node by ID",
			nodeID: "mission:abc123",
			wantQuery: []string{
				"MATCH (n {id: $id})",
				"DETACH DELETE n",
			},
			wantParams: []string{"id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCypherBuilder()
			query, params := b.BuildDeleteNode(tt.nodeID)

			// Check that all expected query parts are present
			for _, part := range tt.wantQuery {
				if !strings.Contains(query, part) {
					t.Errorf("BuildDeleteNode() query missing expected part: %s\nFull query: %s", part, query)
				}
			}

			// Check that all expected parameters are present
			for _, paramKey := range tt.wantParams {
				if _, exists := params[paramKey]; !exists {
					t.Errorf("BuildDeleteNode() params missing expected key: %s\nParams: %v", paramKey, params)
				}
			}

			// Verify ID parameter value
			if params["id"] != tt.nodeID {
				t.Errorf("BuildDeleteNode() params[id] = %v, want %v", params["id"], tt.nodeID)
			}
		})
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Mission", "mission"},
		{"Node-Type", "node_type"},
		{"node.type", "node_type"},
		{"node type", "node_type"},
		{"Node123", "node123"},
		{"_node_", "_node_"},
		{"123node", "123node"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeLabel(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeRelationType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"part_of", "PART_OF"},
		{"HAS-SUBDOMAIN", "HAS_SUBDOMAIN"},
		{"has.subdomain", "HAS_SUBDOMAIN"},
		{"HAS SUBDOMAIN", "HAS_SUBDOMAIN"},
		{"PART123", "PART123"},
		{"_PART_", "_PART_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeRelationType(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeRelationType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeProperty(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"PropertyName", "propertyname"},
		{"property-name", "property_name"},
		{"property.name", "property_name"},
		{"property name", "property_name"},
		{"property123", "property123"},
		{"_property_", "_property_"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeProperty(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeProperty(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeValue(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		input any
		want  any
	}{
		{
			name:  "nil value",
			input: nil,
			want:  nil,
		},
		{
			name:  "string value",
			input: "test",
			want:  "test",
		},
		{
			name:  "int value",
			input: 42,
			want:  42,
		},
		{
			name:  "float64 value",
			input: 3.14,
			want:  3.14,
		},
		{
			name:  "bool value",
			input: true,
			want:  true,
		},
		{
			name:  "time.Time value",
			input: now,
			want:  now.Format(time.RFC3339),
		},
		{
			name:  "string array",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "int array",
			input: []int{1, 2, 3},
			want:  []int64{1, 2, 3},
		},
		{
			name:  "float64 array",
			input: []float64{1.1, 2.2, 3.3},
			want:  []float64{1.1, 2.2, 3.3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeValue(tt.input)

			// Special handling for array comparison
			switch want := tt.want.(type) {
			case []string:
				gotArr, ok := got.([]string)
				if !ok {
					t.Errorf("normalizeValue() type = %T, want []string", got)
					return
				}
				if len(gotArr) != len(want) {
					t.Errorf("normalizeValue() length = %d, want %d", len(gotArr), len(want))
					return
				}
				for i := range want {
					if gotArr[i] != want[i] {
						t.Errorf("normalizeValue()[%d] = %v, want %v", i, gotArr[i], want[i])
					}
				}
			case []int64:
				gotArr, ok := got.([]int64)
				if !ok {
					t.Errorf("normalizeValue() type = %T, want []int64", got)
					return
				}
				if len(gotArr) != len(want) {
					t.Errorf("normalizeValue() length = %d, want %d", len(gotArr), len(want))
					return
				}
				for i := range want {
					if gotArr[i] != want[i] {
						t.Errorf("normalizeValue()[%d] = %v, want %v", i, gotArr[i], want[i])
					}
				}
			case []float64:
				gotArr, ok := got.([]float64)
				if !ok {
					t.Errorf("normalizeValue() type = %T, want []float64", got)
					return
				}
				if len(gotArr) != len(want) {
					t.Errorf("normalizeValue() length = %d, want %d", len(gotArr), len(want))
					return
				}
				for i := range want {
					if gotArr[i] != want[i] {
						t.Errorf("normalizeValue()[%d] = %v, want %v", i, gotArr[i], want[i])
					}
				}
			default:
				if got != tt.want {
					t.Errorf("normalizeValue() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestNormalizeValue_NestedMap(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	input := map[string]any{
		"name":      "test",
		"timestamp": now,
		"nested": map[string]any{
			"value": 42,
		},
	}

	got := normalizeValue(input)
	gotMap, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("normalizeValue() type = %T, want map[string]any", got)
	}

	// Check that timestamp was normalized
	if gotMap["timestamp"] != now.Format(time.RFC3339) {
		t.Errorf("normalizeValue() timestamp = %v, want %v", gotMap["timestamp"], now.Format(time.RFC3339))
	}

	// Check nested map
	nested, ok := gotMap["nested"].(map[string]any)
	if !ok {
		t.Fatalf("normalizeValue() nested type = %T, want map[string]any", gotMap["nested"])
	}
	if nested["value"] != 42 {
		t.Errorf("normalizeValue() nested[value] = %v, want 42", nested["value"])
	}
}

func TestCypherBuilder_ParameterizationSafety(t *testing.T) {
	b := NewCypherBuilder()

	// Test that potentially dangerous values are parameterized
	dangerousValue := "'; DROP TABLE nodes; --"
	query, params := b.BuildNodeMerge("test", "test:123", map[string]any{
		"name": dangerousValue,
	})

	// Query should not contain the dangerous value directly
	if strings.Contains(query, "DROP TABLE") {
		t.Errorf("BuildNodeMerge() query contains unparameterized dangerous value")
	}

	// But it should be in the parameters
	if params["name"] != dangerousValue {
		t.Errorf("BuildNodeMerge() params[name] = %v, want %v", params["name"], dangerousValue)
	}

	// Query should use parameter reference
	if !strings.Contains(query, "$name") {
		t.Errorf("BuildNodeMerge() query does not use parameter reference for name")
	}
}

func BenchmarkCypherBuilder_BuildNodeMerge(b *testing.B) {
	builder := NewCypherBuilder()
	properties := map[string]any{
		"name":   "Test Mission",
		"status": "running",
		"count":  42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.BuildNodeMerge("mission", "mission:abc123", properties)
	}
}

func BenchmarkCypherBuilder_BuildBatchNodeMerge(b *testing.B) {
	builder := NewCypherBuilder()
	nodes := make([]NodeData, 100)
	for i := 0; i < 100; i++ {
		nodes[i] = NodeData{
			ID: "host:" + string(rune(i)),
			Properties: map[string]any{
				"ip":     "192.168.1." + string(rune(i)),
				"status": "up",
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.BuildBatchNodeMerge("host", nodes)
	}
}
