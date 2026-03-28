package extraction

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
)

// RelationshipBuilder constructs entity relationships from extracted discovery results.
// It builds parent-child hierarchies based on entity reference fields (host_id, port_id, etc.)
// and adds provenance properties to all relationships for traceability.
//
// Supported relationship types (from taxonomy):
//   - HAS_PORT: Host → Port
//   - RUNS_SERVICE: Port → Service
//   - HAS_ENDPOINT: Service → Endpoint
//   - USES_TECHNOLOGY: Host/Service/Endpoint → Technology
//   - AFFECTS: Finding → Target entity
//   - HAS_SUBDOMAIN: Domain → Subdomain
//   - HAS_EVIDENCE: Finding → Evidence
//   - SERVES_CERTIFICATE: Host → Certificate
//
// All relationships include provenance properties:
//   - discovered_by: Tool name that discovered the relationship
//   - discovered_at: Timestamp when discovered
//   - mission_run_id: Mission context identifier
type RelationshipBuilder struct {
	// ToolName is the name of the tool that discovered these entities
	ToolName string

	// MissionRunID is the mission context for provenance
	MissionRunID string

	// DiscoveredAt is the discovery timestamp (defaults to time.Now())
	DiscoveredAt time.Time
}

// NewRelationshipBuilder creates a new RelationshipBuilder with the specified context.
// If discoveredAt is zero, it defaults to time.Now().
func NewRelationshipBuilder(toolName, missionRunID string, discoveredAt time.Time) *RelationshipBuilder {
	if discoveredAt.IsZero() {
		discoveredAt = time.Now()
	}

	return &RelationshipBuilder{
		ToolName:     toolName,
		MissionRunID: missionRunID,
		DiscoveredAt: discoveredAt,
	}
}

// BuildRelationships constructs all relationships from a DiscoveryResult.
// It processes the discovery result in dependency order:
//  1. Asset hierarchy (Domain→Subdomain, Host→Port→Service→Endpoint)
//  2. Technology associations (USES_TECHNOLOGY from various entities)
//  3. Certificate associations (SERVES_CERTIFICATE)
//  4. Finding associations (AFFECTS from findings to target entities)
//  5. Evidence associations (HAS_EVIDENCE from findings to evidence)
//
// Returns a slice of Relationship protos with provenance properties populated.
func (rb *RelationshipBuilder) BuildRelationships(result *graphragpb.DiscoveryResult) ([]*graphragpb.Relationship, error) {
	if result == nil {
		return nil, fmt.Errorf("discovery result cannot be nil")
	}

	var relationships []*graphragpb.Relationship

	// 1. Build domain hierarchy: Domain → Subdomain (HAS_SUBDOMAIN)
	for _, subdomain := range result.Subdomains {
		if subdomain.DomainId == "" {
			continue // Skip subdomains without parent reference
		}

		rel := rb.createRelationship(subdomain.DomainId, subdomain.GetId(), "HAS_SUBDOMAIN")
		relationships = append(relationships, rel)
	}

	// 2. Build asset hierarchy: Host → Port (HAS_PORT)
	for _, port := range result.Ports {
		if port.HostId == "" {
			continue // Skip ports without parent reference
		}

		rel := rb.createRelationship(port.HostId, port.GetId(), "HAS_PORT")
		relationships = append(relationships, rel)
	}

	// 3. Build asset hierarchy: Port → Service (RUNS_SERVICE)
	for _, service := range result.Services {
		if service.PortId == "" {
			continue // Skip services without parent reference
		}

		rel := rb.createRelationship(service.PortId, service.GetId(), "RUNS_SERVICE")
		relationships = append(relationships, rel)
	}

	// 4. Build asset hierarchy: Service → Endpoint (HAS_ENDPOINT)
	for _, endpoint := range result.Endpoints {
		if endpoint.ServiceId == "" {
			continue // Skip endpoints without parent reference
		}

		rel := rb.createRelationship(endpoint.ServiceId, endpoint.GetId(), "HAS_ENDPOINT")
		relationships = append(relationships, rel)
	}

	// 5. Build technology associations: Entity → Technology (USES_TECHNOLOGY)
	for _, tech := range result.Technologies {
		if tech.GetParentId() == "" || tech.GetParentType() == "" {
			continue // Skip technologies without parent reference
		}

		rel := rb.createRelationship(tech.GetParentId(), tech.GetId(), "USES_TECHNOLOGY")
		// Add technology-specific context
		rel.Properties["technology_name"] = &graphragpb.Value{
			Kind: &graphragpb.Value_StringValue{StringValue: tech.Name},
		}
		if tech.Version != nil {
			rel.Properties["technology_version"] = &graphragpb.Value{
				Kind: &graphragpb.Value_StringValue{StringValue: *tech.Version},
			}
		}
		relationships = append(relationships, rel)
	}

	// 6. Build certificate associations: Entity → Certificate (SERVES_CERTIFICATE)
	for _, cert := range result.Certificates {
		if cert.GetParentId() == "" || cert.GetParentType() == "" {
			continue // Skip certificates without parent reference
		}

		rel := rb.createRelationship(cert.GetParentId(), cert.GetId(), "SERVES_CERTIFICATE")
		// Add certificate-specific context
		if cert.Subject != nil {
			rel.Properties["certificate_subject"] = &graphragpb.Value{
				Kind: &graphragpb.Value_StringValue{StringValue: *cert.Subject},
			}
		}
		if cert.FingerprintSha256 != nil {
			rel.Properties["certificate_fingerprint"] = &graphragpb.Value{
				Kind: &graphragpb.Value_StringValue{StringValue: *cert.FingerprintSha256},
			}
		}
		relationships = append(relationships, rel)
	}

	// 7. Build finding associations: Finding → Entity (AFFECTS)
	for _, finding := range result.Findings {
		if finding.GetParentId() == "" || finding.GetParentType() == "" {
			continue // Skip findings without target reference
		}

		rel := rb.createRelationship(finding.GetId(), finding.GetParentId(), "AFFECTS")
		// Add finding-specific context
		rel.Properties["severity"] = &graphragpb.Value{
			Kind: &graphragpb.Value_StringValue{StringValue: finding.Severity},
		}
		if finding.Confidence != nil {
			rel.Properties["confidence"] = &graphragpb.Value{
				Kind: &graphragpb.Value_DoubleValue{DoubleValue: *finding.Confidence},
			}
		}
		if finding.Category != nil {
			rel.Properties["category"] = &graphragpb.Value{
				Kind: &graphragpb.Value_StringValue{StringValue: *finding.Category},
			}
		}
		relationships = append(relationships, rel)
	}

	// 8. Build evidence associations: Finding → Evidence (HAS_EVIDENCE)
	for _, evidence := range result.Evidence {
		if evidence.FindingId == "" {
			continue // Skip evidence without parent reference
		}

		rel := rb.createRelationship(evidence.FindingId, evidence.GetId(), "HAS_EVIDENCE")
		// Add evidence-specific context
		rel.Properties["evidence_type"] = &graphragpb.Value{
			Kind: &graphragpb.Value_StringValue{StringValue: evidence.Type},
		}
		relationships = append(relationships, rel)
	}

	// 9. Build explicit relationships from custom definitions
	for _, explicitRel := range result.ExplicitRelationships {
		// For explicit relationships, we need to resolve the entity IDs from their identifying properties
		// This is a best-effort approach - in a real implementation, you'd need to look up entities
		// by their identifying properties to get their UUIDs. For now, we'll skip these as they
		// require more complex resolution logic.
		// TODO: Implement ID resolution for explicit relationships
		_ = explicitRel
	}

	return relationships, nil
}

// InferParent attempts to infer the parent entity for a given entity from a list of candidates.
// This is useful when entities don't have explicit parent ID references but can be matched
// by properties (e.g., matching a Port to a Host by IP address).
//
// The inference logic depends on the entity type:
//   - Port: Matches Host by IP address
//   - Service: Matches Port by host IP + port number + protocol
//   - Endpoint: Matches Service by URL host matching service's host
//
// Returns nil if no suitable parent can be inferred.
//
// Note: This method is provided for flexibility but is not used by BuildRelationships,
// which relies on explicit parent ID references. Use this when extracting from tools
// that don't provide parent IDs directly.
func (rb *RelationshipBuilder) InferParent(entityType, entityID string, props map[string]interface{}, candidates []*EntityCandidate) *EntityCandidate {
	// This is a placeholder for parent inference logic.
	// In practice, you would implement type-specific matching logic here.
	// For example:
	//
	// if entityType == "port" {
	//     // Find host with matching IP
	//     if hostIP, ok := props["host_ip"].(string); ok {
	//         for _, candidate := range candidates {
	//             if candidate.Type == "host" && candidate.Properties["ip"] == hostIP {
	//                 return candidate
	//             }
	//         }
	//     }
	// }

	// For now, return nil - this is an advanced feature for tools that don't
	// provide explicit parent references
	return nil
}

// EntityCandidate represents a potential parent entity for inference.
type EntityCandidate struct {
	// Type is the entity type (e.g., "host", "port", "service")
	Type string

	// ID is the entity UUID
	ID string

	// Properties contains the entity's identifying properties
	Properties map[string]interface{}
}

// createRelationship creates a Relationship proto with provenance properties.
// All relationships include:
//   - discovered_by: Tool name
//   - discovered_at: Discovery timestamp (Unix milliseconds)
//   - mission_run_id: Mission context
func (rb *RelationshipBuilder) createRelationship(fromID, toID, relType string) *graphragpb.Relationship {
	return &graphragpb.Relationship{
		FromId: fromID,
		ToId:   toID,
		Type:   relType,
		Properties: map[string]*graphragpb.Value{
			"discovered_by": {
				Kind: &graphragpb.Value_StringValue{StringValue: rb.ToolName},
			},
			"discovered_at": {
				Kind: &graphragpb.Value_TimestampValue{TimestampValue: rb.DiscoveredAt.UnixMilli()},
			},
			"mission_run_id": {
				Kind: &graphragpb.Value_StringValue{StringValue: rb.MissionRunID},
			},
		},
		MissionRunId: rb.MissionRunID,
		CreatedAt:    rb.DiscoveredAt.UnixMilli(),
	}
}

// ValidateRelationships checks that all relationships have valid from/to IDs.
// Returns an error if any relationship is invalid.
func ValidateRelationships(relationships []*graphragpb.Relationship) error {
	for i, rel := range relationships {
		if rel.FromId == "" {
			return fmt.Errorf("relationship %d: from_id cannot be empty", i)
		}
		if rel.ToId == "" {
			return fmt.Errorf("relationship %d: to_id cannot be empty", i)
		}
		if rel.Type == "" {
			return fmt.Errorf("relationship %d: type cannot be empty", i)
		}
		if rel.FromId == rel.ToId {
			return fmt.Errorf("relationship %d: from_id and to_id cannot be the same (%s)", i, rel.FromId)
		}
	}
	return nil
}
