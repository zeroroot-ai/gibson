package loader

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/graphrag/protoconv"
	"github.com/zeroroot-ai/sdk/graphrag/taxonomy"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GraphLoader loads proto nodes into Neo4j.
// It handles node creation, relationship creation, and provenance tracking.
type GraphLoader struct {
	client             graph.GraphClient
	tracer             trace.Tracer
	neo4jBrowserURL    string // Base URL for Neo4j Browser (for generating deep links)
	taxonomyRegistry   graphrag.TaxonomyRegistry
	validateExtensions bool // Enable validation of extension node types
}

// NewGraphLoader creates a new GraphLoader with the given Neo4j client.
func NewGraphLoader(client graph.GraphClient) *GraphLoader {
	return &GraphLoader{
		client:          client,
		tracer:          otel.Tracer("gibson.graphrag.loader"),
		neo4jBrowserURL: "", // No browser URL by default
	}
}

// WithNeo4jBrowserURL sets the Neo4j Browser URL for generating deep links.
// This is optional but recommended for enhanced observability.
func (l *GraphLoader) WithNeo4jBrowserURL(url string) *GraphLoader {
	l.neo4jBrowserURL = url
	return l
}

// WithTaxonomyRegistry sets the taxonomy registry for extension node type validation.
// This is optional - the loader works without it, but extension validation will be disabled.
func (l *GraphLoader) WithTaxonomyRegistry(r graphrag.TaxonomyRegistry) *GraphLoader {
	l.taxonomyRegistry = r
	return l
}

// WithValidateExtensions enables or disables validation of extension node types.
// When enabled, the loader will verify that custom node types are registered in the taxonomy registry.
// This is optional and defaults to false for backward compatibility.
func (l *GraphLoader) WithValidateExtensions(validate bool) *GraphLoader {
	l.validateExtensions = validate
	return l
}

// ExecContext provides execution context for tracking provenance.
// All nodes loaded in a single Load/LoadBatch call will be associated with this context.
type ExecContext struct {
	// MissionRunID is the ID of the current mission run.
	// This is the primary scope for all stored nodes and will be used
	// to create BELONGS_TO relationships for root nodes.
	MissionRunID string

	// MissionID is the ID of the mission (parent of MissionRun).
	// This is used for mission-level scoping and queries.
	MissionID string

	// AgentName is the name of the agent storing data.
	// This is used for the discovered_by provenance field on nodes.
	AgentName string

	// AgentRunID is the ID of the agent run that discovered these nodes.
	// This is used to create DISCOVERED relationships from the agent run to each node.
	AgentRunID string

	// ToolExecutionID is the ID of the tool execution that produced these nodes (optional).
	ToolExecutionID string

	// TenantID is the owning tenant for this load operation. When set, it is
	// used by callers (e.g. ingest.discoveryProcessor) to publish graph-update
	// events to the in-process Bus after a successful write.
	// Zero value means "tenant unknown" — callers that need to publish MUST
	// set this field. Loaders that do not publish may leave it as zero.
	TenantID auth.TenantID
}

// LoadResult contains statistics about a load operation.
type LoadResult struct {
	// NodesCreated is the count of new nodes created.
	NodesCreated int

	// NodesUpdated is the count of existing nodes that were updated.
	NodesUpdated int

	// RelationshipsCreated is the count of relationships created.
	RelationshipsCreated int

	// Errors contains any errors encountered during loading.
	// The loader attempts to continue processing after errors.
	Errors []error
}

// AddError adds an error to the result and returns the result for chaining.
func (r *LoadResult) AddError(err error) *LoadResult {
	r.Errors = append(r.Errors, err)
	return r
}

// HasErrors returns true if any errors were encountered.
func (r *LoadResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// buildEntityTypesJSON creates a JSON array of entity types that were written in this discovery.
// Returns a string in the format: ["host", "port", "service", ...]
func buildEntityTypesJSON(discovery *graphragpb.DiscoveryResult) string {
	var types []string
	if len(discovery.Hosts) > 0 {
		types = append(types, "host")
	}
	if len(discovery.Ports) > 0 {
		types = append(types, "port")
	}
	if len(discovery.Services) > 0 {
		types = append(types, "service")
	}
	if len(discovery.Endpoints) > 0 {
		types = append(types, "endpoint")
	}
	if len(discovery.Domains) > 0 {
		types = append(types, "domain")
	}
	if len(discovery.Subdomains) > 0 {
		types = append(types, "subdomain")
	}
	if len(discovery.Technologies) > 0 {
		types = append(types, "technology")
	}
	if len(discovery.Certificates) > 0 {
		types = append(types, "certificate")
	}
	if len(discovery.Findings) > 0 {
		types = append(types, "finding")
	}
	if len(discovery.Evidence) > 0 {
		types = append(types, "evidence")
	}
	if len(discovery.CustomNodes) > 0 {
		types = append(types, "custom_node")
	}

	// Encode as JSON array
	data, err := json.Marshal(types)
	if err != nil {
		// Fallback to empty array if marshaling fails
		return "[]"
	}
	return string(data)
}

// attachToMissionRunBatch creates BELONGS_TO relationships from root nodes to MissionRun in batch.
// Task 9.3: Root nodes are attached to MissionRun via BELONGS_TO relationship.
func (l *GraphLoader) attachToMissionRunBatch(ctx context.Context, nodeElementIDs []string, missionRunID string) (int, error) {
	if missionRunID == "" || len(nodeElementIDs) == 0 {
		return 0, nil
	}

	cypher := `
		MATCH (run:mission_run {id: $run_id})
		UNWIND $node_ids AS node_id
		MATCH (n) WHERE elementId(n) = node_id
		CREATE (n)-[:BELONGS_TO]->(run)
		RETURN count(*) as rel_count
	`

	params := map[string]any{
		"run_id":   missionRunID,
		"node_ids": nodeElementIDs,
	}

	result, err := l.client.Query(ctx, cypher, params)
	if err != nil {
		return 0, err
	}

	if len(result.Records) > 0 {
		if count, ok := result.Records[0]["rel_count"].(int64); ok {
			return int(count), nil
		} else if count, ok := result.Records[0]["rel_count"].(float64); ok {
			return int(count), nil
		}
	}

	return 0, nil
}

// createDiscoveredRelationshipsBatch creates DISCOVERED relationships in batch.
func (l *GraphLoader) createDiscoveredRelationshipsBatch(ctx context.Context, agentRunID string, elementIDs []string) (int, error) {
	cypher := `
		MATCH (run {id: $agent_run_id})
		UNWIND $element_ids AS element_id
		MATCH (node) WHERE elementId(node) = element_id
		MERGE (run)-[r:DISCOVERED]->(node)
		SET r.discovered_at = datetime()
		RETURN count(r) as rel_count
	`

	params := map[string]any{
		"agent_run_id": agentRunID,
		"element_ids":  elementIDs,
	}

	result, err := l.client.Query(ctx, cypher, params)
	if err != nil {
		return 0, err
	}

	if len(result.Records) > 0 {
		if count, ok := result.Records[0]["rel_count"].(int64); ok {
			return int(count), nil
		} else if count, ok := result.Records[0]["rel_count"].(float64); ok {
			return int(count), nil
		}
	}

	return 0, nil
}

// ==================== PROTO-FIRST LOADING ====================

// LoadDiscovery loads a DiscoveryResult proto directly into Neo4j.
// This is the proto-first approach that bypasses the domain wrapper layer.
//
// The loading order ensures parent nodes exist before children:
//  1. Hosts (root nodes)
//  2. Ports (children of hosts)
//  3. Services (children of ports)
//  4. Endpoints (children of services)
//  5. Domains (root nodes)
//  6. Subdomains (children of domains)
//  7. Technologies (root nodes)
//  8. Certificates (root nodes)
//  9. Findings (root nodes)
//
// 10. Evidence (children of findings)
// 11. CustomNodes (may be root or child)
// 12. ExplicitRelationships
//
// Each node type is processed in batch for efficiency.
func (l *GraphLoader) LoadDiscovery(ctx context.Context, execCtx ExecContext, discovery *graphragpb.DiscoveryResult) (*LoadResult, error) {
	if l.client == nil {
		return nil, types.NewError("GRAPHRAG_LOADER", "client is nil")
	}

	if discovery == nil {
		return &LoadResult{}, nil
	}

	// Start tracing span for graph write operation
	ctx, span := l.tracer.Start(ctx, "gibson.graph.store")
	defer span.End()

	result := &LoadResult{}

	// Load in proper order to ensure parent nodes exist before children
	// 1. Hosts (root nodes - no parent)
	if len(discovery.Hosts) > 0 {
		r, err := l.loadHosts(ctx, execCtx, discovery.Hosts)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load hosts: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 2. Ports (children of hosts)
	if len(discovery.Ports) > 0 {
		r, err := l.loadPorts(ctx, execCtx, discovery.Ports)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load ports: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 3. Services (children of ports)
	if len(discovery.Services) > 0 {
		r, err := l.loadServices(ctx, execCtx, discovery.Services)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load services: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 4. Endpoints (children of services)
	if len(discovery.Endpoints) > 0 {
		r, err := l.loadEndpoints(ctx, execCtx, discovery.Endpoints)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load endpoints: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 5. Domains (root nodes)
	if len(discovery.Domains) > 0 {
		r, err := l.loadDomains(ctx, execCtx, discovery.Domains)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load domains: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 6. Subdomains (children of domains)
	if len(discovery.Subdomains) > 0 {
		r, err := l.loadSubdomains(ctx, execCtx, discovery.Subdomains)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load subdomains: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 7. Technologies (root nodes)
	if len(discovery.Technologies) > 0 {
		r, err := l.loadTechnologies(ctx, execCtx, discovery.Technologies)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load technologies: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 8. Certificates (root nodes)
	if len(discovery.Certificates) > 0 {
		r, err := l.loadCertificates(ctx, execCtx, discovery.Certificates)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load certificates: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 9. Findings (root nodes)
	if len(discovery.Findings) > 0 {
		r, err := l.loadFindings(ctx, execCtx, discovery.Findings)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load findings: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 10. Evidence (children of findings)
	if len(discovery.Evidence) > 0 {
		r, err := l.loadEvidence(ctx, execCtx, discovery.Evidence)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load evidence: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 11. CustomNodes (may be root or child)
	if len(discovery.CustomNodes) > 0 {
		r, err := l.loadCustomNodes(ctx, execCtx, discovery.CustomNodes)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load custom nodes: %w", err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// 12. ExplicitRelationships
	if len(discovery.ExplicitRelationships) > 0 {
		r, err := l.loadExplicitRelationships(ctx, execCtx, discovery.ExplicitRelationships)
		if err != nil {
			result.AddError(fmt.Errorf("failed to load explicit relationships: %w", err))
		} else {
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	// Add span attributes for observability
	attrs := []attribute.KeyValue{
		attribute.Int("gibson.graph.entities_count", result.NodesCreated),
		attribute.Int("gibson.graph.relationships_count", result.RelationshipsCreated),
		attribute.String("gibson.graph.entity_types", buildEntityTypesJSON(discovery)),
	}

	// Add Neo4j Browser link if configured
	if l.neo4jBrowserURL != "" && execCtx.MissionID != "" {
		missionID := types.ID(execCtx.MissionID)
		browserURL, err := neo4j.BrowserURL(l.neo4jBrowserURL, missionID, neo4j.QueryTypeFull)
		if err == nil {
			attrs = append(attrs,
				attribute.String("neo4j_browser_url", browserURL),
				attribute.String("neo4j_query", neo4j.QueryReference(missionID, neo4j.QueryTypeFull)),
			)
		}
	}

	span.SetAttributes(attrs...)

	return result, nil
}

// loadHosts loads Host protos as root nodes attached to MissionRun.
func (l *GraphLoader) loadHosts(ctx context.Context, execCtx ExecContext, hosts []*graphragpb.Host) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(hosts))
	for i, h := range hosts {
		protos[i] = h
	}
	return l.loadProtoNodes(ctx, execCtx, "host", protos, nil, "")
}

// loadPorts loads Port protos with parent relationship to hosts.
func (l *GraphLoader) loadPorts(ctx context.Context, execCtx ExecContext, ports []*graphragpb.Port) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(ports))
	for i, p := range ports {
		protos[i] = p
	}
	return l.loadProtoNodes(ctx, execCtx, "port", protos, nil, "")
}

// loadServices loads Service protos with parent relationship to ports.
func (l *GraphLoader) loadServices(ctx context.Context, execCtx ExecContext, services []*graphragpb.Service) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(services))
	for i, s := range services {
		protos[i] = s
	}
	return l.loadProtoNodes(ctx, execCtx, "service", protos, nil, "")
}

// loadEndpoints loads Endpoint protos with parent relationship to services.
func (l *GraphLoader) loadEndpoints(ctx context.Context, execCtx ExecContext, endpoints []*graphragpb.Endpoint) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(endpoints))
	for i, e := range endpoints {
		protos[i] = e
	}
	return l.loadProtoNodes(ctx, execCtx, "endpoint", protos, nil, "")
}

// loadDomains loads Domain protos as root nodes attached to MissionRun.
func (l *GraphLoader) loadDomains(ctx context.Context, execCtx ExecContext, domains []*graphragpb.Domain) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(domains))
	for i, d := range domains {
		protos[i] = d
	}
	return l.loadProtoNodes(ctx, execCtx, "domain", protos, nil, "")
}

// loadSubdomains loads Subdomain protos with parent relationship to domains.
func (l *GraphLoader) loadSubdomains(ctx context.Context, execCtx ExecContext, subdomains []*graphragpb.Subdomain) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(subdomains))
	for i, s := range subdomains {
		protos[i] = s
	}
	return l.loadProtoNodes(ctx, execCtx, "subdomain", protos, nil, "")
}

// loadTechnologies loads Technology protos as root nodes attached to MissionRun.
func (l *GraphLoader) loadTechnologies(ctx context.Context, execCtx ExecContext, technologies []*graphragpb.Technology) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(technologies))
	for i, t := range technologies {
		protos[i] = t
	}
	return l.loadProtoNodes(ctx, execCtx, "technology", protos, nil, "")
}

// loadCertificates loads Certificate protos as root nodes attached to MissionRun.
func (l *GraphLoader) loadCertificates(ctx context.Context, execCtx ExecContext, certificates []*graphragpb.Certificate) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(certificates))
	for i, c := range certificates {
		protos[i] = c
	}
	return l.loadProtoNodes(ctx, execCtx, "certificate", protos, nil, "")
}

// LoadFindings stores a set of Finding protos in the knowledge graph as root nodes
// attached to the MissionRun identified in execCtx. This is the exported entry point
// used by the harness GraphRAG bridge to persist agent-submitted findings.
func (l *GraphLoader) LoadFindings(ctx context.Context, execCtx ExecContext, findings []*graphragpb.Finding) (*LoadResult, error) {
	return l.loadFindings(ctx, execCtx, findings)
}

// loadFindings loads Finding protos as root nodes attached to MissionRun.
func (l *GraphLoader) loadFindings(ctx context.Context, execCtx ExecContext, findings []*graphragpb.Finding) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(findings))
	for i, f := range findings {
		protos[i] = f
	}
	return l.loadProtoNodes(ctx, execCtx, "finding", protos, nil, "")
}

// loadEvidence loads Evidence protos with parent relationship to findings.
func (l *GraphLoader) loadEvidence(ctx context.Context, execCtx ExecContext, evidence []*graphragpb.Evidence) (*LoadResult, error) {
	protos := make([]protoreflect.ProtoMessage, len(evidence))
	for i, e := range evidence {
		protos[i] = e
	}
	return l.loadProtoNodes(ctx, execCtx, "evidence", protos, nil, "")
}

// loadCustomNodes loads CustomNode protos (may be root or child based on parent_type).
func (l *GraphLoader) loadCustomNodes(ctx context.Context, execCtx ExecContext, customNodes []*graphragpb.CustomNode) (*LoadResult, error) {
	result := &LoadResult{}

	// Get the current span for observability
	span := trace.SpanFromContext(ctx)

	// Process each custom node individually since they may have different types and parents
	for _, node := range customNodes {
		if node == nil {
			result.AddError(fmt.Errorf("nil custom node"))
			continue
		}

		nodeType := node.NodeType
		if nodeType == "" {
			result.AddError(fmt.Errorf("custom node missing node_type"))
			continue
		}

		// Task 4.2: Add extension logging
		// If taxonomyRegistry is set, determine the source of this node type
		extensionSource := "unknown"
		if l.taxonomyRegistry != nil {
			// Type assert to TaxonomyIntrospector to access NodeTypeSource
			// DefaultTaxonomyRegistry implements both TaxonomyRegistry and TaxonomyIntrospector
			if introspector, ok := l.taxonomyRegistry.(graphrag.TaxonomyIntrospector); ok {
				extensionSource = introspector.NodeTypeSource(nodeType)
			}
		}

		// Log at debug level
		slog.Debug("loading custom node",
			"type", nodeType,
			"source", extensionSource)

		// Add OpenTelemetry span event for observability
		span.AddEvent("loading_custom_node",
			trace.WithAttributes(
				attribute.String("node_type", nodeType),
				attribute.String("extension_source", extensionSource),
			))

		// Task 4.3: Optional property validation for extension types
		if l.validateExtensions && extensionSource != "core" && extensionSource != "unknown" {
			// Get the extension info
			if introspector, ok := l.taxonomyRegistry.(graphrag.TaxonomyIntrospector); ok {
				ext := introspector.ExtensionInfo(extensionSource)
				if ext != nil {
					// Find the NodeTypeDefinition for this node type
					var nodeDef *graphrag.NodeTypeDefinition
					for i := range ext.NodeTypes {
						if ext.NodeTypes[i].Name == nodeType {
							nodeDef = &ext.NodeTypes[i]
							break
						}
					}

					if nodeDef != nil {
						// Check required properties
						missingProps := []string{}
						for _, prop := range nodeDef.Properties {
							if prop.Required {
								// Check if the property exists in the CustomNode properties
								if _, ok := node.Properties[prop.Name]; !ok {
									missingProps = append(missingProps, prop.Name)
								}
							}
						}

						if len(missingProps) > 0 {
							// Validation failed - log warning and add span event
							slog.Warn("custom node validation failed: missing required properties",
								"type", nodeType,
								"source", extensionSource,
								"missing_properties", missingProps)

							span.AddEvent("validation_failed",
								trace.WithAttributes(
									attribute.String("node_type", nodeType),
									attribute.StringSlice("missing_properties", missingProps),
								))
						} else {
							// Validation passed
							span.AddEvent("validation_passed",
								trace.WithAttributes(
									attribute.String("node_type", nodeType),
								))
						}
					}
				}
			}
		}

		// Build parent ref if specified
		var parentRef *parentRefBuilder
		if node.ParentType != nil && *node.ParentType != "" {
			relType := "CHILD_OF"
			if node.RelationshipType != nil && *node.RelationshipType != "" {
				relType = *node.RelationshipType
			}

			// Extract parent ID field names and values from parent_id map
			idFields := make([]string, 0, len(node.ParentId))
			idValues := make(map[string]string)
			for k, v := range node.ParentId {
				idFields = append(idFields, k)
				idValues[k] = v
			}

			parentRef = &parentRefBuilder{
				nodeType:     *node.ParentType,
				idFields:     idFields,
				idValues:     idValues,
				relationship: relType,
			}
		}

		// Load single custom node
		r, err := l.loadProtoNodes(ctx, execCtx, nodeType, []protoreflect.ProtoMessage{node}, parentRef, "")
		if err != nil {
			result.AddError(fmt.Errorf("failed to load custom node type %s: %w", nodeType, err))
		} else {
			result.NodesCreated += r.NodesCreated
			result.RelationshipsCreated += r.RelationshipsCreated
			result.Errors = append(result.Errors, r.Errors...)
		}
	}

	return result, nil
}

// loadExplicitRelationships loads ExplicitRelationship protos.
func (l *GraphLoader) loadExplicitRelationships(ctx context.Context, execCtx ExecContext, relationships []*graphragpb.ExplicitRelationship) (*LoadResult, error) {
	result := &LoadResult{}

	for _, rel := range relationships {
		if rel == nil {
			result.AddError(fmt.Errorf("nil explicit relationship"))
			continue
		}

		// Build WHERE clauses for from and to nodes
		fromWhere := make([]string, 0, len(rel.FromId))
		toWhere := make([]string, 0, len(rel.ToId))
		params := make(map[string]any)

		for k, v := range rel.FromId {
			paramKey := fmt.Sprintf("from_%s", k)
			fromWhere = append(fromWhere, fmt.Sprintf("from.%s = $%s", k, paramKey))
			params[paramKey] = v
		}

		for k, v := range rel.ToId {
			paramKey := fmt.Sprintf("to_%s", k)
			toWhere = append(toWhere, fmt.Sprintf("to.%s = $%s", k, paramKey))
			params[paramKey] = v
		}

		// Add mission_run_id scoping
		if execCtx.MissionRunID != "" {
			fromWhere = append(fromWhere, "from.mission_run_id = $mission_run_id")
			toWhere = append(toWhere, "to.mission_run_id = $mission_run_id")
			params["mission_run_id"] = execCtx.MissionRunID
		}

		fromWhereStr := strings.Join(fromWhere, " AND ")
		toWhereStr := strings.Join(toWhere, " AND ")

		// Build relationship properties
		relProps := make(map[string]any)
		for k, v := range rel.Properties {
			relProps[k] = v
		}

		// Build Cypher query
		cypher := fmt.Sprintf(`
			MATCH (from:%s) WHERE %s
			MATCH (to:%s) WHERE %s
			CREATE (from)-[r:%s $rel_props]->(to)
			RETURN count(r) as rel_count
		`, rel.FromType, fromWhereStr, rel.ToType, toWhereStr, rel.RelationshipType)

		params["rel_props"] = relProps

		// Execute query
		queryResult, err := l.client.Query(ctx, cypher, params)
		if err != nil {
			result.AddError(fmt.Errorf("failed to create explicit relationship %s: %w", rel.RelationshipType, err))
			continue
		}

		if len(queryResult.Records) > 0 {
			if count, ok := queryResult.Records[0]["rel_count"].(int64); ok {
				result.RelationshipsCreated += int(count)
			} else if count, ok := queryResult.Records[0]["rel_count"].(float64); ok {
				result.RelationshipsCreated += int(count)
			}
		}
	}

	return result, nil
}

// parentRefBuilder specifies how to build parent relationships for proto nodes.
type parentRefBuilder struct {
	nodeType     string            // Parent node type (e.g., "host")
	idFields     []string          // Field names in child proto that reference parent (e.g., ["host_id"])
	idValues     map[string]string // Pre-computed parent ID values (used for CustomNode where values come from ParentId map)
	relationship string            // Relationship type (e.g., "HAS_PORT")
}

// loadProtoNodes is a helper that loads proto messages as nodes.
// It uses reflection to extract properties from the proto message.
// Parent relationships are automatically determined from the taxonomy.
//
// Parameters:
//   - nodeType: Neo4j node label (e.g., "host", "port")
//   - protos: Slice of proto messages (must implement protoreflect.ProtoMessage)
//   - parentRef: Optional override for parent relationship (for CustomNode). If nil, uses taxonomy.
//   - idField: Optional custom ID field name (defaults to auto-generated UUID)
func (l *GraphLoader) loadProtoNodes(
	ctx context.Context,
	execCtx ExecContext,
	nodeType string,
	protos []protoreflect.ProtoMessage,
	parentRef *parentRefBuilder,
	idField string,
) (*LoadResult, error) {
	if len(protos) == 0 {
		return &LoadResult{}, nil
	}

	result := &LoadResult{}
	// Use RFC3339 format (24-hour time with timezone) for consistency and readability
	discoveredAt := time.Now().UTC().Format(time.RFC3339)

	// Determine parent relationship from taxonomy if not explicitly provided
	var taxonomyRel *taxonomy.ParentRelationship
	if parentRef == nil {
		taxonomyRel = taxonomy.GetParentRelationship(nodeType)
	}

	// Build node data list for UNWIND
	nodeDataList := make([]map[string]any, 0, len(protos))
	var parentFieldValues []map[string]string // Track parent field values for relationship creation

	for _, proto := range protos {
		if proto == nil {
			result.AddError(fmt.Errorf("nil proto in %s list", nodeType))
			continue
		}

		// Extract properties from proto using protoconv
		props, err := protoconv.ToProperties(proto)
		if err != nil {
			result.AddError(fmt.Errorf("failed to extract properties from %s: %w", nodeType, err))
			continue
		}

		// Extract ID directly from proto (protoconv excludes framework fields like 'id')
		// This preserves agent-generated UUIDs for relationship linking
		protoID := extractProtoID(proto)
		if protoID != "" {
			props["id"] = protoID
		} else if idField != "" {
			if _, hasID := props[idField]; !hasID {
				props["id"] = types.NewID().String()
			}
		} else {
			if _, hasID := props["id"]; !hasID {
				props["id"] = types.NewID().String()
			}
		}

		// Inject mission context
		if execCtx.MissionID != "" {
			props["mission_id"] = execCtx.MissionID
		}
		if execCtx.MissionRunID != "" {
			props["mission_run_id"] = execCtx.MissionRunID
		}
		if execCtx.AgentRunID != "" {
			props["agent_run_id"] = execCtx.AgentRunID
		}
		if execCtx.AgentName != "" {
			props["discovered_by"] = execCtx.AgentName
		}
		props["discovered_at"] = discoveredAt

		// Track parent field values if this is a child node
		if parentRef != nil || taxonomyRel != nil {
			parentVals := make(map[string]string)

			if parentRef != nil {
				// Custom parent ref (for CustomNode)
				// If idValues are pre-computed, use them directly
				if len(parentRef.idValues) > 0 {
					for k, v := range parentRef.idValues {
						parentVals[k] = v
					}
				} else {
					// Otherwise extract from the proto's properties
					for _, fieldName := range parentRef.idFields {
						if val, ok := props[fieldName]; ok {
							parentVals[fieldName] = fmt.Sprintf("%v", val)
						}
					}
				}
			} else if taxonomyRel != nil {
				// Use taxonomy relationship
				if val, ok := props[taxonomyRel.RefField]; ok {
					parentVals[taxonomyRel.ParentField] = fmt.Sprintf("%v", val)
				}
			}

			parentFieldValues = append(parentFieldValues, parentVals)
		}

		nodeDataList = append(nodeDataList, map[string]any{
			"all_props": props,
			"index":     len(nodeDataList), // Track index for relationship creation
		})
	}

	if len(nodeDataList) == 0 {
		return result, nil
	}

	// No tenant_id property: tenant isolation is provided by the per-tenant
	// Neo4j database (database-per-tenant-data-plane, Requirement 2.6).

	// Build CREATE query with UNWIND
	cypher := fmt.Sprintf(`
		UNWIND $nodes AS nodeData
		CREATE (n:%s)
		SET n = nodeData.all_props, n.created_at = timestamp()
		RETURN elementId(n) as element_id, nodeData.index as idx
	`, nodeType)

	params := map[string]any{
		"nodes": nodeDataList,
	}

	// Execute the batch CREATE query
	queryResult, err := l.client.Query(ctx, cypher, params)
	if err != nil {
		return result, fmt.Errorf("batch node creation failed for type %s: %w", nodeType, err)
	}

	// Track element IDs for relationship creation
	elementIDs := make([]string, len(nodeDataList))
	for _, record := range queryResult.Records {
		elementID, _ := record["element_id"].(string)
		index, _ := record["idx"].(int64)
		if index == 0 {
			if indexFloat, ok := record["idx"].(float64); ok {
				index = int64(indexFloat)
			}
		}

		if int(index) < len(elementIDs) {
			elementIDs[int(index)] = elementID
		}

		result.NodesCreated++
	}

	// Create parent relationships if specified
	if parentRef != nil || taxonomyRel != nil {
		// Determine parent node type and relationship type
		var parentNodeType, relationshipType string
		if parentRef != nil {
			parentNodeType = parentRef.nodeType
			relationshipType = parentRef.relationship
		} else if taxonomyRel != nil {
			parentNodeType = taxonomyRel.ParentType
			relationshipType = taxonomyRel.Relationship
		}

		for idx, elementID := range elementIDs {
			if elementID == "" || idx >= len(parentFieldValues) {
				continue
			}

			parentVals := parentFieldValues[idx]
			if len(parentVals) == 0 {
				continue
			}

			// Build WHERE clause for parent matching
			whereClauses := make([]string, 0, len(parentVals)+1)
			parentParams := make(map[string]any)

			for fieldName, fieldValue := range parentVals {
				paramKey := fmt.Sprintf("parent_%s", fieldName)
				whereClauses = append(whereClauses, fmt.Sprintf("parent.%s = $%s", fieldName, paramKey))
				parentParams[paramKey] = fieldValue
			}

			// Add mission_run_id scoping
			if execCtx.MissionRunID != "" {
				whereClauses = append(whereClauses, "parent.mission_run_id = $mission_run_id")
				parentParams["mission_run_id"] = execCtx.MissionRunID
			}

			whereStr := strings.Join(whereClauses, " AND ")
			parentParams["child_id"] = elementID

			// Create relationship - use OPTIONAL MATCH to detect missing parents
			relCypher := fmt.Sprintf(`
				MATCH (parent:%s) WHERE %s
				MATCH (child) WHERE elementId(child) = $child_id
				CREATE (parent)-[r:%s]->(child)
				RETURN count(r) as created
			`, parentNodeType, whereStr, relationshipType)

			queryResult, err := l.client.Query(ctx, relCypher, parentParams)
			if err != nil {
				result.AddError(fmt.Errorf("failed to create parent relationship for %s: %w", nodeType, err))
				continue
			}

			// Check if relationship was actually created
			created := int64(0)
			if len(queryResult.Records) > 0 {
				if val, ok := queryResult.Records[0]["created"].(int64); ok {
					created = val
				}
			}

			if created == 0 {
				// Parent not found - log debug info
				result.AddError(fmt.Errorf("PARENT_NOT_FOUND: parent %s not found for %s relationship to %s (params: %v)",
					parentNodeType, relationshipType, nodeType, parentParams))
				continue
			}

			result.RelationshipsCreated++
		}
	} else {
		// Root node - attach to MissionRun
		if execCtx.MissionRunID != "" {
			relCount, err := l.attachToMissionRunBatch(ctx, elementIDs, execCtx.MissionRunID)
			if err != nil {
				return result, fmt.Errorf("batch MissionRun attachment failed for %s: %w", nodeType, err)
			}
			result.RelationshipsCreated += relCount
		}
	}

	// Create DISCOVERED relationships from agent run
	if execCtx.AgentRunID != "" {
		discCount, err := l.createDiscoveredRelationshipsBatch(ctx, execCtx.AgentRunID, elementIDs)
		if err != nil {
			// Non-critical error - log but don't fail
			result.AddError(fmt.Errorf("batch DISCOVERED relationship creation failed for %s: %w", nodeType, err))
		} else {
			result.RelationshipsCreated += discCount
		}
	}

	return result, nil
}

// extractProtoID extracts the 'id' field from a proto message if it exists.
// This is needed because protoconv.ToProperties excludes framework fields like 'id'.
func extractProtoID(proto protoreflect.ProtoMessage) string {
	refl := proto.ProtoReflect()
	idField := refl.Descriptor().Fields().ByName("id")
	if idField == nil {
		return ""
	}
	if !refl.Has(idField) {
		return ""
	}
	val := refl.Get(idField)
	return val.String()
}
