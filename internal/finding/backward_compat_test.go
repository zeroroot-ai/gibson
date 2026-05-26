package finding

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroroot-ai/sdk/finding"
)

// TestBackwardCompatibility_DirectFieldAccess verifies that the old pattern of
// directly accessing MitreAttack, MitreAtlas, and CVSSScore fields still works.
// This is the pattern used in existing agents like api-discovery.
func TestBackwardCompatibility_DirectFieldAccess(t *testing.T) {
	// Create a finding using the old pattern (direct field assignment)
	f := finding.NewFinding(
		"mission-123",
		"test-agent",
		"SQL Injection in Login Form",
		"The login endpoint is vulnerable to SQL injection",
		finding.CategoryDataExtraction,
		finding.SeverityHigh,
	)

	// Old pattern: Direct field assignment (still supported)
	cvssScore := 9.8
	f.CVSSScore = &cvssScore

	mitreAttack := &finding.MitreMapping{
		Matrix:        "enterprise",
		TacticID:      "TA0001",
		TacticName:    "Initial Access",
		TechniqueID:   "T1190",
		TechniqueName: "Exploit Public-Facing Application",
	}
	f.MitreAttack = mitreAttack

	mitreAtlas := &finding.MitreMapping{
		Matrix:        "atlas",
		TacticID:      "TA0000",
		TacticName:    "ML Attack Staging",
		TechniqueID:   "AML.T0000",
		TechniqueName: "Reconnaissance",
	}
	f.MitreAtlas = mitreAtlas

	// Verify direct field access works
	if f.CVSSScore == nil {
		t.Fatal("CVSSScore field is nil")
	}
	if *f.CVSSScore != 9.8 {
		t.Errorf("CVSSScore = %f, want 9.8", *f.CVSSScore)
	}

	if f.MitreAttack == nil {
		t.Fatal("MitreAttack field is nil")
	}
	if f.MitreAttack.TechniqueID != "T1190" {
		t.Errorf("MitreAttack.TechniqueID = %s, want T1190", f.MitreAttack.TechniqueID)
	}

	if f.MitreAtlas == nil {
		t.Fatal("MitreAtlas field is nil")
	}
	if f.MitreAtlas.Matrix != "atlas" {
		t.Errorf("MitreAtlas.Matrix = %s, want atlas", f.MitreAtlas.Matrix)
	}

	// Verify validation still works with direct fields
	if err := f.Validate(); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestBackwardCompatibility_SetterMethods verifies that the old setter methods
// (SetMitreAttack, SetMitreAtlas) still work correctly.
func TestBackwardCompatibility_SetterMethods(t *testing.T) {
	f := finding.NewFinding(
		"mission-456",
		"test-agent",
		"Privilege Escalation Vulnerability",
		"User can escalate privileges through API",
		finding.CategoryPrivilegeEscalation,
		finding.SeverityCritical,
	)

	// Old pattern: Using setter methods
	mitreAttack := finding.NewMitreMapping(
		"enterprise",
		"TA0004",
		"Privilege Escalation",
		"T1068",
		"Exploitation for Privilege Escalation",
	)
	f.SetMitreAttack(mitreAttack)

	mitreAtlas := finding.NewMitreMapping(
		"atlas",
		"TA0005",
		"ML Model Access",
		"AML.T0010",
		"Model Extraction",
	)
	f.SetMitreAtlas(mitreAtlas)

	// Verify setter methods work
	if f.MitreAttack == nil {
		t.Fatal("SetMitreAttack did not set the field")
	}
	if f.MitreAttack.TechniqueID != "T1068" {
		t.Errorf("MitreAttack.TechniqueID = %s, want T1068", f.MitreAttack.TechniqueID)
	}

	if f.MitreAtlas == nil {
		t.Fatal("SetMitreAtlas did not set the field")
	}
	if f.MitreAtlas.TechniqueID != "AML.T0010" {
		t.Errorf("MitreAtlas.TechniqueID = %s, want AML.T0010", f.MitreAtlas.TechniqueID)
	}

	// Verify UpdatedAt was updated by setters
	if f.UpdatedAt.Before(f.CreatedAt) {
		t.Error("UpdatedAt should be updated by setter methods")
	}
}

// TestBackwardCompatibility_CategoryConstants verifies that all security
// category constants still work correctly with the new string-based category system.
func TestBackwardCompatibility_CategoryConstants(t *testing.T) {
	testCases := []struct {
		name     string
		category string
		want     string
	}{
		{
			name:     "CategoryJailbreak",
			category: finding.CategoryJailbreak,
			want:     "jailbreak",
		},
		{
			name:     "CategoryPromptInjection",
			category: finding.CategoryPromptInjection,
			want:     "prompt_injection",
		},
		{
			name:     "CategoryDataExtraction",
			category: finding.CategoryDataExtraction,
			want:     "data_extraction",
		},
		{
			name:     "CategoryPrivilegeEscalation",
			category: finding.CategoryPrivilegeEscalation,
			want:     "privilege_escalation",
		},
		{
			name:     "CategoryDOS",
			category: finding.CategoryDOS,
			want:     "dos",
		},
		{
			name:     "CategoryModelManipulation",
			category: finding.CategoryModelManipulation,
			want:     "model_manipulation",
		},
		{
			name:     "CategoryInformationDisclosure",
			category: finding.CategoryInformationDisclosure,
			want:     "information_disclosure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create finding with category constant
			f := finding.NewFinding(
				"mission-789",
				"test-agent",
				"Test Finding",
				"Test description",
				tc.category,
				finding.SeverityMedium,
			)

			// Verify category was set correctly
			if f.Category != tc.want {
				t.Errorf("Category = %s, want %s", f.Category, tc.want)
			}

			// Verify category validation still works
			if err := f.Validate(); err != nil {
				t.Errorf("Validate() failed for category %s: %v", tc.category, err)
			}

			// Verify Category type methods still work
			cat := finding.Category(f.Category)
			if !cat.IsValid() {
				t.Errorf("Category.IsValid() returned false for %s", tc.category)
			}

			displayName := cat.DisplayName()
			if displayName == "" {
				t.Errorf("Category.DisplayName() returned empty string for %s", tc.category)
			}

			description := cat.Description()
			if description == "" {
				t.Errorf("Category.Description() returned empty string for %s", tc.category)
			}
		})
	}
}

// TestBackwardCompatibility_JSONSerialization verifies that findings with
// direct MITRE/CVSS fields serialize and deserialize correctly.
// This ensures existing JSON payloads from agents remain compatible.
func TestBackwardCompatibility_JSONSerialization(t *testing.T) {
	// Create a finding with all old-style fields populated
	cvssScore := 7.5
	original := &finding.Finding{
		ID:          "finding-123",
		MissionID:   "mission-456",
		AgentName:   "api-discovery",
		Title:       "Administrative Interface Exposed",
		Description: "An admin panel was discovered without authentication",
		Category:    finding.CategoryInformationDisclosure,
		Severity:    finding.SeverityHigh,
		Confidence:  0.95,
		CVSSScore:   &cvssScore,
		MitreAttack: &finding.MitreMapping{
			Matrix:        "enterprise",
			TacticID:      "TA0006",
			TacticName:    "Credential Access",
			TechniqueID:   "T1552",
			TechniqueName: "Unsecured Credentials",
		},
		MitreAtlas: &finding.MitreMapping{
			Matrix:        "atlas",
			TacticID:      "TA0003",
			TacticName:    "Persistence",
			TechniqueID:   "AML.T0015",
			TechniqueName: "Backdoor Injection",
		},
		Status:    finding.StatusOpen,
		CreatedAt: time.Now().Add(-1 * time.Hour),
		UpdatedAt: time.Now(),
	}

	// Serialize to JSON (as agents would do)
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	// Verify JSON contains expected fields
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("json.Unmarshal to map failed: %v", err)
	}

	// Verify CVSS score is present in JSON
	if _, ok := jsonMap["cvss_score"]; !ok {
		t.Error("JSON missing cvss_score field")
	}

	// Verify MITRE ATT&CK is present in JSON
	if _, ok := jsonMap["mitre_attack"]; !ok {
		t.Error("JSON missing mitre_attack field")
	}

	// Verify MITRE ATLAS is present in JSON
	if _, ok := jsonMap["mitre_atlas"]; !ok {
		t.Error("JSON missing mitre_atlas field")
	}

	// Deserialize back to Finding (as agents would do when reading)
	var deserialized finding.Finding
	if err := json.Unmarshal(jsonData, &deserialized); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	// Verify all fields were preserved
	if deserialized.ID != original.ID {
		t.Errorf("ID = %s, want %s", deserialized.ID, original.ID)
	}

	if deserialized.CVSSScore == nil {
		t.Fatal("CVSSScore is nil after deserialization")
	}
	if *deserialized.CVSSScore != *original.CVSSScore {
		t.Errorf("CVSSScore = %f, want %f", *deserialized.CVSSScore, *original.CVSSScore)
	}

	if deserialized.MitreAttack == nil {
		t.Fatal("MitreAttack is nil after deserialization")
	}
	if deserialized.MitreAttack.TechniqueID != original.MitreAttack.TechniqueID {
		t.Errorf("MitreAttack.TechniqueID = %s, want %s",
			deserialized.MitreAttack.TechniqueID, original.MitreAttack.TechniqueID)
	}

	if deserialized.MitreAtlas == nil {
		t.Fatal("MitreAtlas is nil after deserialization")
	}
	if deserialized.MitreAtlas.Matrix != original.MitreAtlas.Matrix {
		t.Errorf("MitreAtlas.Matrix = %s, want %s",
			deserialized.MitreAtlas.Matrix, original.MitreAtlas.Matrix)
	}
}

// TestBackwardCompatibility_ExistingJSONPayload verifies that a real JSON
// payload from an existing agent can be deserialized correctly.
func TestBackwardCompatibility_ExistingJSONPayload(t *testing.T) {
	// This is a representative JSON payload that would come from an agent
	// like api-discovery, using the old Finding structure
	jsonPayload := `{
		"id": "finding-abc-123",
		"mission_id": "mission-xyz-789",
		"agent_name": "api-discovery",
		"title": "Backup File Accessible",
		"description": "A SQL backup file is accessible without authentication at /admin/backup.sql",
		"category": "data_extraction",
		"severity": "critical",
		"confidence": 0.98,
		"cvss_score": 9.1,
		"mitre_attack": {
			"matrix": "enterprise",
			"tactic_id": "TA0009",
			"tactic_name": "Collection",
			"technique_id": "T1005",
			"technique_name": "Data from Local System"
		},
		"status": "open",
		"created_at": "2024-01-15T10:30:00Z",
		"updated_at": "2024-01-15T10:30:00Z"
	}`

	// Deserialize the JSON
	var f finding.Finding
	if err := json.Unmarshal([]byte(jsonPayload), &f); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	// Verify all fields were correctly deserialized
	if f.ID != "finding-abc-123" {
		t.Errorf("ID = %s, want finding-abc-123", f.ID)
	}

	if f.MissionID != "mission-xyz-789" {
		t.Errorf("MissionID = %s, want mission-xyz-789", f.MissionID)
	}

	if f.AgentName != "api-discovery" {
		t.Errorf("AgentName = %s, want api-discovery", f.AgentName)
	}

	if f.Category != "data_extraction" {
		t.Errorf("Category = %s, want data_extraction", f.Category)
	}

	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %s, want critical", f.Severity)
	}

	if f.CVSSScore == nil {
		t.Fatal("CVSSScore is nil")
	}
	if *f.CVSSScore != 9.1 {
		t.Errorf("CVSSScore = %f, want 9.1", *f.CVSSScore)
	}

	if f.MitreAttack == nil {
		t.Fatal("MitreAttack is nil")
	}
	if f.MitreAttack.TechniqueID != "T1005" {
		t.Errorf("MitreAttack.TechniqueID = %s, want T1005", f.MitreAttack.TechniqueID)
	}

	// Verify the finding is valid
	if err := f.Validate(); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestBackwardCompatibility_AgentPattern_CreateFinding verifies the exact
// pattern used in api-discovery agent (CreateFindingFromEndpoint).
func TestBackwardCompatibility_AgentPattern_CreateFinding(t *testing.T) {
	// This mimics the pattern in enterprise/agents/api-discovery/risk.go
	// function CreateFindingFromEndpoint

	// Create finding using NewFinding with string category
	category := finding.CategoryInformationDisclosure // Type is Category (string alias)
	f := finding.NewFinding(
		"mission-test",
		"api-discovery",
		"Administrative Interface Exposed",
		"An admin panel was discovered without authentication",
		category, // Category constant works as string
		finding.SeverityHigh,
	)

	// Set confidence (pattern from api-discovery)
	if err := f.SetConfidence(0.95); err != nil {
		t.Fatalf("SetConfidence() failed: %v", err)
	}

	// Add evidence (pattern from api-discovery)
	requestEvidence := finding.NewEvidence(
		finding.EvidenceHTTPRequest,
		"GET /admin",
		"Method: GET\nURL: http://target.com/admin\nStatus Code: 200",
	)
	requestEvidence.WithMetadata("method", "GET")
	requestEvidence.WithMetadata("url", "http://target.com/admin")
	requestEvidence.WithMetadata("status_code", 200)
	f.AddEvidence(*requestEvidence)

	// Add tags (pattern from api-discovery)
	f.AddTag("api-discovery")
	f.AddTag("unauthenticated")

	// Set remediation (pattern from api-discovery)
	f.Remediation = "Restrict access to administrative interfaces using authentication"

	// Verify all operations worked
	if f.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", f.Confidence)
	}

	if len(f.Evidence) != 1 {
		t.Errorf("len(Evidence) = %d, want 1", len(f.Evidence))
	}

	if len(f.Tags) != 2 {
		t.Errorf("len(Tags) = %d, want 2", len(f.Tags))
	}

	if f.Remediation == "" {
		t.Error("Remediation is empty")
	}

	// Verify category works correctly
	if f.Category != string(finding.CategoryInformationDisclosure) {
		t.Errorf("Category = %s, want %s", f.Category, finding.CategoryInformationDisclosure)
	}

	// Verify validation works
	if err := f.Validate(); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestBackwardCompatibility_CategoryParsing verifies that ParseCategory
// still works for both known and unknown categories.
func TestBackwardCompatibility_CategoryParsing(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "Known security category",
			input:     "jailbreak",
			wantError: false,
		},
		{
			name:      "Another known category",
			input:     "prompt_injection",
			wantError: false,
		},
		{
			name:      "Unknown custom category",
			input:     "compliance_violation",
			wantError: false, // Now accepts any non-empty string
		},
		{
			name:      "Empty category",
			input:     "",
			wantError: true, // Empty string still errors
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			category, err := finding.ParseCategory(tc.input)

			if tc.wantError {
				if err == nil {
					t.Error("ParseCategory() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseCategory() unexpected error: %v", err)
				}
				if string(category) != tc.input {
					t.Errorf("Category = %s, want %s", category, tc.input)
				}

				// Verify IsValid works
				if !category.IsValid() {
					t.Errorf("IsValid() returned false for %s", tc.input)
				}
			}
		})
	}
}

// TestBackwardCompatibility_MitreValidation verifies that MITRE mapping
// validation still works correctly.
func TestBackwardCompatibility_MitreValidation(t *testing.T) {
	// Valid MITRE mapping
	validMapping := &finding.MitreMapping{
		Matrix:        "enterprise",
		TacticID:      "TA0001",
		TacticName:    "Initial Access",
		TechniqueID:   "T1190",
		TechniqueName: "Exploit Public-Facing Application",
	}

	if err := validMapping.Validate(); err != nil {
		t.Errorf("Validate() failed for valid mapping: %v", err)
	}

	// Invalid MITRE mapping (missing required fields)
	invalidMapping := &finding.MitreMapping{
		Matrix:      "enterprise",
		TacticID:    "TA0001",
		TechniqueID: "T1190",
		// Missing TacticName and TechniqueName
	}

	if err := invalidMapping.Validate(); err == nil {
		t.Error("Validate() expected error for invalid mapping, got nil")
	}
}

// TestBackwardCompatibility_AllSecurityCategories verifies that all
// security categories from AllCategories() work correctly.
func TestBackwardCompatibility_AllSecurityCategories(t *testing.T) {
	categories := finding.AllCategories()

	if len(categories) != 7 {
		t.Errorf("AllCategories() returned %d categories, want 7", len(categories))
	}

	expectedCategories := map[string]bool{
		"jailbreak":              true,
		"prompt_injection":       true,
		"data_extraction":        true,
		"privilege_escalation":   true,
		"dos":                    true,
		"model_manipulation":     true,
		"information_disclosure": true,
	}

	for _, cat := range categories {
		if !expectedCategories[cat] {
			t.Errorf("Unexpected category in AllCategories(): %s", cat)
		}

		// Verify each category can be used to create a finding
		f := finding.NewFinding(
			"mission-test",
			"test-agent",
			"Test",
			"Test",
			cat,
			finding.SeverityMedium,
		)

		if err := f.Validate(); err != nil {
			t.Errorf("Validate() failed for category %s: %v", cat, err)
		}
	}
}

// TestBackwardCompatibility_CVSSScoreValidation verifies that CVSS score
// validation still works correctly.
func TestBackwardCompatibility_CVSSScoreValidation(t *testing.T) {
	testCases := []struct {
		name      string
		score     *float64
		wantError bool
	}{
		{
			name:      "Valid score 0.0",
			score:     ptr(0.0),
			wantError: false,
		},
		{
			name:      "Valid score 5.5",
			score:     ptr(5.5),
			wantError: false,
		},
		{
			name:      "Valid score 10.0",
			score:     ptr(10.0),
			wantError: false,
		},
		{
			name:      "Invalid score -1.0",
			score:     ptr(-1.0),
			wantError: true,
		},
		{
			name:      "Invalid score 11.0",
			score:     ptr(11.0),
			wantError: true,
		},
		{
			name:      "Nil score (valid)",
			score:     nil,
			wantError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := finding.NewFinding(
				"mission-test",
				"test-agent",
				"Test",
				"Test",
				finding.CategoryDataExtraction,
				finding.SeverityHigh,
			)

			f.CVSSScore = tc.score

			err := f.Validate()
			if tc.wantError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// ptr is a helper function to create a pointer to a value.
func ptr[T any](v T) *T {
	return &v
}
