package finding

import (
	"context"
	"errors"
	"testing"

	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// fakeStore is an in-memory FindingStore for tests.
type fakeStore struct {
	findings map[string]*sdkfinding.Finding
	getErr   error
	putErr   error
}

func newFakeStore() *fakeStore {
	return &fakeStore{findings: map[string]*sdkfinding.Finding{}}
}

func (f *fakeStore) GetFinding(ctx context.Context, tenant, id string) (*sdkfinding.Finding, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	// Tenant-scoped lookup — key includes tenant.
	return f.findings[tenant+"|"+id], nil
}

func (f *fakeStore) UpdateFinding(ctx context.Context, tenant string, fng *sdkfinding.Finding) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.findings[tenant+"|"+fng.ID] = fng
	return nil
}

type fakeAudit struct {
	entries []map[string]any
}

func (a *fakeAudit) Log(_ context.Context, _, _, _ string, details map[string]any) {
	a.entries = append(a.entries, details)
}

func TestUpdateComplianceMappings_Append(t *testing.T) {
	store := newFakeStore()
	store.findings["tenant-a|f1"] = &sdkfinding.Finding{
		ID: "f1",
		ComplianceMappings: []sdkfinding.ComplianceMapping{
			{Framework: "SOC2", ControlID: "CC7.1"},
		},
	}

	audit := &fakeAudit{}
	updated, err := UpdateComplianceMappings(context.Background(), store, audit, "tenant-a", ComplianceUpdate{
		FindingID: "f1",
		Mode:      UpdateModeAppend,
		Mappings: []sdkfinding.ComplianceMapping{
			{Framework: "NIST_AI_RMF", ControlID: "MEASURE.2.7"},
			{Framework: "SOC2", ControlID: "CC7.1"}, // duplicate, dedupes
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.ComplianceMappings) != 2 {
		t.Errorf("want 2 mappings (1 existing + 1 new), got %d", len(updated.ComplianceMappings))
	}
	if len(audit.entries) != 1 {
		t.Errorf("want 1 audit entry, got %d", len(audit.entries))
	}
}

func TestUpdateComplianceMappings_Replace(t *testing.T) {
	store := newFakeStore()
	store.findings["tenant-a|f1"] = &sdkfinding.Finding{
		ID: "f1",
		ComplianceMappings: []sdkfinding.ComplianceMapping{
			{Framework: "SOC2", ControlID: "CC7.1"},
			{Framework: "SOC2", ControlID: "CC6.1"},
		},
	}

	updated, err := UpdateComplianceMappings(context.Background(), store, nil, "tenant-a", ComplianceUpdate{
		FindingID: "f1",
		Mode:      UpdateModeReplace,
		Mappings: []sdkfinding.ComplianceMapping{
			{Framework: "NIST_AI_RMF", ControlID: "MEASURE.2.7"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.ComplianceMappings) != 1 {
		t.Errorf("replace should overwrite; got %d", len(updated.ComplianceMappings))
	}
	if updated.ComplianceMappings[0].Framework != "NIST_AI_RMF" {
		t.Errorf("wrong framework: %v", updated.ComplianceMappings[0])
	}
}

func TestUpdateComplianceMappings_InvalidRejected(t *testing.T) {
	store := newFakeStore()
	store.findings["tenant-a|f1"] = &sdkfinding.Finding{ID: "f1"}
	_, err := UpdateComplianceMappings(context.Background(), store, nil, "tenant-a", ComplianceUpdate{
		FindingID: "f1",
		Mode:      UpdateModeAppend,
		Mappings:  []sdkfinding.ComplianceMapping{{Framework: "SOC2"}}, // missing ControlID
	})
	if err == nil {
		t.Errorf("invalid mapping should be rejected")
	}
}

func TestUpdateComplianceMappings_NotFound(t *testing.T) {
	store := newFakeStore()
	_, err := UpdateComplianceMappings(context.Background(), store, nil, "tenant-a", ComplianceUpdate{
		FindingID: "does-not-exist",
		Mode:      UpdateModeAppend,
		Mappings:  []sdkfinding.ComplianceMapping{{Framework: "SOC2", ControlID: "CC7.1"}},
	})
	if err == nil {
		t.Errorf("expected not found error")
	}
}

func TestUpdateComplianceMappings_CrossTenantRejection(t *testing.T) {
	store := newFakeStore()
	// Finding exists under tenant-b.
	store.findings["tenant-b|f1"] = &sdkfinding.Finding{ID: "f1"}
	// Caller tries from tenant-a.
	_, err := UpdateComplianceMappings(context.Background(), store, nil, "tenant-a", ComplianceUpdate{
		FindingID: "f1",
		Mode:      UpdateModeAppend,
		Mappings:  []sdkfinding.ComplianceMapping{{Framework: "SOC2", ControlID: "CC7.1"}},
	})
	if err == nil {
		t.Errorf("cross-tenant attempt should fail with not-found")
	}
}

func TestUpdateComplianceMappings_StoreFailurePropagates(t *testing.T) {
	store := newFakeStore()
	store.findings["tenant-a|f1"] = &sdkfinding.Finding{ID: "f1"}
	store.putErr = errors.New("neo4j timeout")

	_, err := UpdateComplianceMappings(context.Background(), store, nil, "tenant-a", ComplianceUpdate{
		FindingID: "f1",
		Mode:      UpdateModeAppend,
		Mappings:  []sdkfinding.ComplianceMapping{{Framework: "SOC2", ControlID: "CC7.1"}},
	})
	if err == nil {
		t.Errorf("store error should propagate")
	}
}
