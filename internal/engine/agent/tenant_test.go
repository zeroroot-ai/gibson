package agent

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestFinding_WithTenant verifies the WithTenant method sets the TenantID correctly
func TestFinding_WithTenant(t *testing.T) {
	finding := NewFinding("Test Finding", "Test Description", SeverityHigh)

	// Set tenant ID
	finding = finding.WithTenant("tenant-123")

	assert.Equal(t, "tenant-123", finding.TenantID, "TenantID should be set")
}

// TestFinding_TenantSerialization verifies JSON serialization with TenantID
func TestFinding_TenantSerialization(t *testing.T) {
	finding := NewFinding("Test Finding", "Test Description", SeverityHigh)
	finding = finding.WithTenant("tenant-456")

	// Marshal to JSON
	data, err := json.Marshal(finding)
	require.NoError(t, err, "Should marshal without error")

	// Unmarshal back
	var finding2 Finding
	err = json.Unmarshal(data, &finding2)
	require.NoError(t, err, "Should unmarshal without error")

	// Verify TenantID is preserved
	assert.Equal(t, finding.TenantID, finding2.TenantID, "TenantID should be preserved through serialization")
	assert.Equal(t, "tenant-456", finding2.TenantID, "TenantID should match")
}

// TestFinding_BackwardCompatibility verifies findings without TenantID can be loaded
func TestFinding_BackwardCompatibility(t *testing.T) {
	// Simulate old JSON without tenant_id field. The ID must be a valid UUID
	// because types.ID.UnmarshalJSON now validates UUID v4 format; older
	// findings from before that validation landed should be re-keyed during
	// migration, not bypass validation here.
	oldJSON := `{
		"id": "550e8400-e29b-41d4-a716-446655440000",
		"title": "Old Finding",
		"description": "Old Description",
		"severity": "high",
		"confidence": 1.0,
		"category": "security",
		"evidence": [],
		"cwe": [],
		"metadata": {},
		"created_at": "2024-01-01T00:00:00Z"
	}`

	var finding Finding
	err := json.Unmarshal([]byte(oldJSON), &finding)
	require.NoError(t, err, "Should unmarshal old JSON without tenant_id")

	// Verify TenantID is empty (zero value) — the actual backward-compat
	// contract under test is that missing tenant_id parses as empty.
	assert.Equal(t, "", finding.TenantID, "TenantID should be empty for old data")

	// Verify other fields are loaded correctly
	assert.Equal(t, types.ID("550e8400-e29b-41d4-a716-446655440000"), finding.ID)
	assert.Equal(t, "Old Finding", finding.Title)
	assert.Equal(t, SeverityHigh, finding.Severity)
}

// TestFinding_OmitemptyBehavior verifies omitempty tag works correctly
func TestFinding_OmitemptyBehavior(t *testing.T) {
	// Finding without TenantID should not include tenant_id in JSON
	finding := NewFinding("Test", "Description", SeverityMedium)

	data, err := json.Marshal(finding)
	require.NoError(t, err)

	// Parse to map to check fields
	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	// tenant_id should not be present when empty
	_, hasTenantID := m["tenant_id"]
	assert.False(t, hasTenantID, "tenant_id should not be present when empty due to omitempty")

	// Finding with TenantID should include it
	finding = finding.WithTenant("tenant-789")
	data, err = json.Marshal(finding)
	require.NoError(t, err)

	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	tenantID, hasTenantID := m["tenant_id"]
	assert.True(t, hasTenantID, "tenant_id should be present when set")
	assert.Equal(t, "tenant-789", tenantID, "tenant_id should have correct value")
}
