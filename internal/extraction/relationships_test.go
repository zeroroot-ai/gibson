package extraction

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
)

func TestNewRelationshipBuilder(t *testing.T) {
	t.Run("creates builder with specified time", func(t *testing.T) {
		now := time.Now()
		rb := NewRelationshipBuilder("nmap", "mission-run-123", now)

		assert.Equal(t, "nmap", rb.ToolName)
		assert.Equal(t, "mission-run-123", rb.MissionRunID)
		assert.Equal(t, now, rb.DiscoveredAt)
	})

	t.Run("defaults to current time when zero", func(t *testing.T) {
		before := time.Now()
		rb := NewRelationshipBuilder("nmap", "mission-run-123", time.Time{})
		after := time.Now()

		assert.False(t, rb.DiscoveredAt.IsZero())
		assert.True(t, rb.DiscoveredAt.After(before) || rb.DiscoveredAt.Equal(before))
		assert.True(t, rb.DiscoveredAt.Before(after) || rb.DiscoveredAt.Equal(after))
	})
}

func TestBuildRelationships_DomainHierarchy(t *testing.T) {
	rb := NewRelationshipBuilder("subfinder", "mission-run-123", time.Now())

	domainID := "domain-uuid-1"
	subdomainID := "subdomain-uuid-1"

	result := &graphragpb.DiscoveryResult{
		Domains: []*graphragpb.Domain{
			{Id: &domainID, Name: "example.com"},
		},
		Subdomains: []*graphragpb.Subdomain{
			{Id: &subdomainID, DomainId: domainID, Name: "api"},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	require.Len(t, relationships, 1)

	rel := relationships[0]
	assert.Equal(t, domainID, rel.FromId)
	assert.Equal(t, subdomainID, rel.ToId)
	assert.Equal(t, "HAS_SUBDOMAIN", rel.Type)
	assertProvenanceProperties(t, rel, "subfinder", "mission-run-123")
}

func TestBuildRelationships_AssetHierarchy(t *testing.T) {
	rb := NewRelationshipBuilder("nmap", "mission-run-456", time.Now())

	hostID := "host-uuid-1"
	portID := "port-uuid-1"
	serviceID := "service-uuid-1"
	endpointID := "endpoint-uuid-1"

	result := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.100"},
		},
		Ports: []*graphragpb.Port{
			{Id: &portID, HostId: hostID, Number: 443, Protocol: "tcp"},
		},
		Services: []*graphragpb.Service{
			{Id: &serviceID, PortId: portID, Name: "https"},
		},
		Endpoints: []*graphragpb.Endpoint{
			{Id: &endpointID, ServiceId: serviceID, Url: "https://example.com/api"},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	require.Len(t, relationships, 3)

	// HAS_PORT: Host → Port
	assert.Equal(t, hostID, relationships[0].FromId)
	assert.Equal(t, portID, relationships[0].ToId)
	assert.Equal(t, "HAS_PORT", relationships[0].Type)

	// RUNS_SERVICE: Port → Service
	assert.Equal(t, portID, relationships[1].FromId)
	assert.Equal(t, serviceID, relationships[1].ToId)
	assert.Equal(t, "RUNS_SERVICE", relationships[1].Type)

	// HAS_ENDPOINT: Service → Endpoint
	assert.Equal(t, serviceID, relationships[2].FromId)
	assert.Equal(t, endpointID, relationships[2].ToId)
	assert.Equal(t, "HAS_ENDPOINT", relationships[2].Type)

	// All should have provenance
	for _, rel := range relationships {
		assertProvenanceProperties(t, rel, "nmap", "mission-run-456")
	}
}

func TestBuildRelationships_TechnologyAssociations(t *testing.T) {
	rb := NewRelationshipBuilder("wappalyzer", "mission-run-789", time.Now())

	serviceID := "service-uuid-1"
	techID := "tech-uuid-1"
	version := "3.11.0"

	result := &graphragpb.DiscoveryResult{
		Technologies: []*graphragpb.Technology{
			{
				Id:         &techID,
				Name:       "Django",
				Version:    &version,
				ParentId:   &serviceID,
				ParentType: strPtr("service"),
			},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	require.Len(t, relationships, 1)

	rel := relationships[0]
	assert.Equal(t, serviceID, rel.FromId)
	assert.Equal(t, techID, rel.ToId)
	assert.Equal(t, "USES_TECHNOLOGY", rel.Type)

	// Check technology-specific properties
	assert.Equal(t, "Django", getStringValue(rel.Properties["technology_name"]))
	assert.Equal(t, "3.11.0", getStringValue(rel.Properties["technology_version"]))
	assertProvenanceProperties(t, rel, "wappalyzer", "mission-run-789")
}

func TestBuildRelationships_CertificateAssociations(t *testing.T) {
	rb := NewRelationshipBuilder("tlsx", "mission-run-101", time.Now())

	hostID := "host-uuid-1"
	certID := "cert-uuid-1"
	subject := "CN=example.com"
	fingerprint := "a1b2c3d4e5f6"

	result := &graphragpb.DiscoveryResult{
		Certificates: []*graphragpb.Certificate{
			{
				Id:                &certID,
				Subject:           &subject,
				FingerprintSha256: &fingerprint,
				ParentId:          &hostID,
				ParentType:        strPtr("host"),
			},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	require.Len(t, relationships, 1)

	rel := relationships[0]
	assert.Equal(t, hostID, rel.FromId)
	assert.Equal(t, certID, rel.ToId)
	assert.Equal(t, "SERVES_CERTIFICATE", rel.Type)

	// Check certificate-specific properties
	assert.Equal(t, "CN=example.com", getStringValue(rel.Properties["certificate_subject"]))
	assert.Equal(t, "a1b2c3d4e5f6", getStringValue(rel.Properties["certificate_fingerprint"]))
	assertProvenanceProperties(t, rel, "tlsx", "mission-run-101")
}

func TestBuildRelationships_FindingAssociations(t *testing.T) {
	rb := NewRelationshipBuilder("nuclei", "mission-run-202", time.Now())

	endpointID := "endpoint-uuid-1"
	findingID := "finding-uuid-1"
	evidenceID := "evidence-uuid-1"
	confidence := 0.95
	category := "injection"

	result := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Id:         &findingID,
				Title:      "SQL Injection",
				Severity:   "high",
				Confidence: &confidence,
				Category:   &category,
				ParentId:   &endpointID,
				ParentType: strPtr("endpoint"),
			},
		},
		Evidence: []*graphragpb.Evidence{
			{
				Id:        &evidenceID,
				FindingId: findingID,
				Type:      "request",
			},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	require.Len(t, relationships, 2)

	// AFFECTS: Finding → Endpoint
	affectsRel := relationships[0]
	assert.Equal(t, findingID, affectsRel.FromId)
	assert.Equal(t, endpointID, affectsRel.ToId)
	assert.Equal(t, "AFFECTS", affectsRel.Type)
	assert.Equal(t, "high", getStringValue(affectsRel.Properties["severity"]))
	assert.Equal(t, 0.95, getDoubleValue(affectsRel.Properties["confidence"]))
	assert.Equal(t, "injection", getStringValue(affectsRel.Properties["category"]))

	// HAS_EVIDENCE: Finding → Evidence
	evidenceRel := relationships[1]
	assert.Equal(t, findingID, evidenceRel.FromId)
	assert.Equal(t, evidenceID, evidenceRel.ToId)
	assert.Equal(t, "HAS_EVIDENCE", evidenceRel.Type)
	assert.Equal(t, "request", getStringValue(evidenceRel.Properties["evidence_type"]))

	// Both should have provenance
	assertProvenanceProperties(t, affectsRel, "nuclei", "mission-run-202")
	assertProvenanceProperties(t, evidenceRel, "nuclei", "mission-run-202")
}

func TestBuildRelationships_SkipsMissingParentReferences(t *testing.T) {
	rb := NewRelationshipBuilder("nmap", "mission-run-303", time.Now())

	portID := "port-uuid-1"
	serviceID := "service-uuid-1"

	result := &graphragpb.DiscoveryResult{
		// Port without host_id - should be skipped
		Ports: []*graphragpb.Port{
			{Id: &portID, Number: 443, Protocol: "tcp"},
		},
		// Service without port_id - should be skipped
		Services: []*graphragpb.Service{
			{Id: &serviceID, Name: "https"},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	assert.Empty(t, relationships, "should skip entities without parent references")
}

func TestBuildRelationships_NilResult(t *testing.T) {
	rb := NewRelationshipBuilder("nmap", "mission-run-404", time.Now())

	_, err := rb.BuildRelationships(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discovery result cannot be nil")
}

func TestBuildRelationships_EmptyResult(t *testing.T) {
	rb := NewRelationshipBuilder("nmap", "mission-run-505", time.Now())

	result := &graphragpb.DiscoveryResult{}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)
	assert.Empty(t, relationships, "empty result should produce no relationships")
}

func TestBuildRelationships_ComplexScenario(t *testing.T) {
	rb := NewRelationshipBuilder("full-scan", "mission-run-606", time.Now())

	// Create a complex entity graph
	hostID := "host-1"
	port1ID := "port-1"
	port2ID := "port-2"
	service1ID := "service-1"
	service2ID := "service-2"
	endpoint1ID := "endpoint-1"
	tech1ID := "tech-1"
	tech2ID := "tech-2"
	finding1ID := "finding-1"
	evidence1ID := "evidence-1"

	techVersion := "2.4.41"
	techConfidence := int32(95)
	findingConfidence := 0.88

	result := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.100"},
		},
		Ports: []*graphragpb.Port{
			{Id: &port1ID, HostId: hostID, Number: 80, Protocol: "tcp"},
			{Id: &port2ID, HostId: hostID, Number: 443, Protocol: "tcp"},
		},
		Services: []*graphragpb.Service{
			{Id: &service1ID, PortId: port1ID, Name: "http"},
			{Id: &service2ID, PortId: port2ID, Name: "https"},
		},
		Endpoints: []*graphragpb.Endpoint{
			{Id: &endpoint1ID, ServiceId: service2ID, Url: "https://example.com/api"},
		},
		Technologies: []*graphragpb.Technology{
			{
				Id:         &tech1ID,
				Name:       "Apache",
				Version:    &techVersion,
				Confidence: &techConfidence,
				ParentId:   &service1ID,
				ParentType: strPtr("service"),
			},
			{
				Id:         &tech2ID,
				Name:       "OpenSSL",
				ParentId:   &service2ID,
				ParentType: strPtr("service"),
			},
		},
		Findings: []*graphragpb.Finding{
			{
				Id:         &finding1ID,
				Title:      "Outdated Apache",
				Severity:   "medium",
				Confidence: &findingConfidence,
				ParentId:   &service1ID,
				ParentType: strPtr("service"),
			},
		},
		Evidence: []*graphragpb.Evidence{
			{Id: &evidence1ID, FindingId: finding1ID, Type: "banner"},
		},
	}

	relationships, err := rb.BuildRelationships(result)
	require.NoError(t, err)

	// Expected relationships:
	// 1. host-1 → port-1 (HAS_PORT)
	// 2. host-1 → port-2 (HAS_PORT)
	// 3. port-1 → service-1 (RUNS_SERVICE)
	// 4. port-2 → service-2 (RUNS_SERVICE)
	// 5. service-2 → endpoint-1 (HAS_ENDPOINT)
	// 6. service-1 → tech-1 (USES_TECHNOLOGY)
	// 7. service-2 → tech-2 (USES_TECHNOLOGY)
	// 8. finding-1 → service-1 (AFFECTS)
	// 9. finding-1 → evidence-1 (HAS_EVIDENCE)
	require.Len(t, relationships, 9)

	// Verify all have provenance
	for _, rel := range relationships {
		assertProvenanceProperties(t, rel, "full-scan", "mission-run-606")
		assert.NotEmpty(t, rel.FromId, "from_id should not be empty")
		assert.NotEmpty(t, rel.ToId, "to_id should not be empty")
		assert.NotEmpty(t, rel.Type, "type should not be empty")
	}

	// Count relationship types
	typeCounts := make(map[string]int)
	for _, rel := range relationships {
		typeCounts[rel.Type]++
	}

	assert.Equal(t, 2, typeCounts["HAS_PORT"])
	assert.Equal(t, 2, typeCounts["RUNS_SERVICE"])
	assert.Equal(t, 1, typeCounts["HAS_ENDPOINT"])
	assert.Equal(t, 2, typeCounts["USES_TECHNOLOGY"])
	assert.Equal(t, 1, typeCounts["AFFECTS"])
	assert.Equal(t, 1, typeCounts["HAS_EVIDENCE"])
}

func TestValidateRelationships(t *testing.T) {
	now := time.Now()

	t.Run("valid relationships", func(t *testing.T) {
		relationships := []*graphragpb.Relationship{
			{FromId: "id-1", ToId: "id-2", Type: "HAS_PORT"},
			{FromId: "id-2", ToId: "id-3", Type: "RUNS_SERVICE"},
		}

		err := ValidateRelationships(relationships)
		assert.NoError(t, err)
	})

	t.Run("missing from_id", func(t *testing.T) {
		relationships := []*graphragpb.Relationship{
			{ToId: "id-2", Type: "HAS_PORT"},
		}

		err := ValidateRelationships(relationships)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "from_id cannot be empty")
	})

	t.Run("missing to_id", func(t *testing.T) {
		relationships := []*graphragpb.Relationship{
			{FromId: "id-1", Type: "HAS_PORT"},
		}

		err := ValidateRelationships(relationships)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "to_id cannot be empty")
	})

	t.Run("missing type", func(t *testing.T) {
		relationships := []*graphragpb.Relationship{
			{FromId: "id-1", ToId: "id-2"},
		}

		err := ValidateRelationships(relationships)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "type cannot be empty")
	})

	t.Run("self-referential relationship", func(t *testing.T) {
		relationships := []*graphragpb.Relationship{
			{FromId: "id-1", ToId: "id-1", Type: "HAS_PORT"},
		}

		err := ValidateRelationships(relationships)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "from_id and to_id cannot be the same")
	})

	t.Run("empty slice is valid", func(t *testing.T) {
		err := ValidateRelationships([]*graphragpb.Relationship{})
		assert.NoError(t, err)
	})

	_ = now // Suppress unused warning
}

func TestInferParent(t *testing.T) {
	rb := NewRelationshipBuilder("nmap", "mission-run-707", time.Now())

	// Currently InferParent returns nil as it's a placeholder for advanced logic
	// This test ensures the API contract is maintained
	t.Run("returns nil for unimplemented inference", func(t *testing.T) {
		candidates := []*EntityCandidate{
			{Type: "host", ID: "host-1", Properties: map[string]interface{}{"ip": "192.168.1.100"}},
		}

		parent := rb.InferParent("port", "port-1", map[string]interface{}{"host_ip": "192.168.1.100"}, candidates)
		assert.Nil(t, parent, "InferParent is not yet implemented and should return nil")
	})
}

// Helper functions

func assertProvenanceProperties(t *testing.T, rel *graphragpb.Relationship, toolName, missionRunID string) {
	t.Helper()

	require.NotNil(t, rel.Properties)
	assert.Equal(t, toolName, getStringValue(rel.Properties["discovered_by"]))
	assert.Equal(t, missionRunID, getStringValue(rel.Properties["mission_run_id"]))
	assert.NotZero(t, getTimestampValue(rel.Properties["discovered_at"]))
}

func getStringValue(v *graphragpb.Value) string {
	if v == nil {
		return ""
	}
	if sv, ok := v.Kind.(*graphragpb.Value_StringValue); ok {
		return sv.StringValue
	}
	return ""
}

func getDoubleValue(v *graphragpb.Value) float64 {
	if v == nil {
		return 0
	}
	if dv, ok := v.Kind.(*graphragpb.Value_DoubleValue); ok {
		return dv.DoubleValue
	}
	return 0
}

func getTimestampValue(v *graphragpb.Value) int64 {
	if v == nil {
		return 0
	}
	if tv, ok := v.Kind.(*graphragpb.Value_TimestampValue); ok {
		return tv.TimestampValue
	}
	return 0
}

func strPtr(s string) *string {
	return &s
}
