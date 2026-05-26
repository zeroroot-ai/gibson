package finding

import (
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/finding/security"
)

// FindingStatus represents the lifecycle status of a finding
type FindingStatus string

const (
	StatusOpen          FindingStatus = "open"
	StatusConfirmed     FindingStatus = "confirmed"
	StatusResolved      FindingStatus = "resolved"
	StatusFalsePositive FindingStatus = "false_positive"
)

// FindingCategory represents the type of security finding
type FindingCategory string

const (
	CategoryJailbreak             FindingCategory = "jailbreak"
	CategoryPromptInjection       FindingCategory = "prompt_injection"
	CategoryDataExtraction        FindingCategory = "data_extraction"
	CategoryPrivilegeEscalation   FindingCategory = "privilege_escalation"
	CategoryDoS                   FindingCategory = "dos"
	CategoryModelManipulation     FindingCategory = "model_manipulation"
	CategoryInformationDisclosure FindingCategory = "information_disclosure"
	CategoryUncategorized         FindingCategory = "uncategorized"
)

// String returns the string representation of FindingCategory
func (fc FindingCategory) String() string {
	return string(fc)
}

// IsValid checks if the category is a valid value
func (fc FindingCategory) IsValid() bool {
	switch fc {
	case CategoryJailbreak, CategoryPromptInjection, CategoryDataExtraction,
		CategoryPrivilegeEscalation, CategoryDoS, CategoryModelManipulation,
		CategoryInformationDisclosure, CategoryUncategorized:
		return true
	default:
		return false
	}
}

// EnhancedFinding extends agent.Finding with additional classification and tracking metadata
type EnhancedFinding struct {
	agent.Finding // Embedded base finding type

	// Context
	MissionID     types.ID `json:"mission_id"`
	AgentName     string   `json:"agent_name"`
	DelegatedFrom *string  `json:"delegated_from,omitempty"`

	// Classification
	Subcategory string        `json:"subcategory"`
	Status      FindingStatus `json:"status"`
	RiskScore   float64       `json:"risk_score"` // 0.0 - 10.0 (CVSS-like)

	// Remediation
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`

	// Reproduction
	ReproSteps []ReproStep `json:"repro_steps,omitempty"`

	// Relationships
	RelatedIDs      []types.ID `json:"related_ids,omitempty"`
	OccurrenceCount int        `json:"occurrence_count"`

	// Timestamps
	UpdatedAt time.Time `json:"updated_at"`
}

// ReproStep represents a single step in a reproduction sequence
type ReproStep struct {
	StepNumber     int    `json:"step_number"`
	Description    string `json:"description"`
	ExpectedResult string `json:"expected_result"`
	EvidenceRef    string `json:"evidence_ref,omitempty"` // Reference to evidence by title
}

// SimpleMitreMapping is a simplified MITRE mapping for JSON storage
type SimpleMitreMapping struct {
	TechniqueID   string `json:"technique_id"`     // e.g., "T1566", "AML.T0043"
	TechniqueName string `json:"technique_name"`   // Human-readable name
	Tactic        string `json:"tactic,omitempty"` // e.g., "Initial Access"
}

// Classification represents the output of the finding classifier
type Classification struct {
	Category    FindingCategory       `json:"category"`
	Subcategory string                `json:"subcategory"`
	Severity    agent.FindingSeverity `json:"severity"`
	Confidence  float64               `json:"confidence"` // 0.0 - 1.0
	MitreAttack []SimpleMitreMapping  `json:"mitre_attack,omitempty"`
	MitreAtlas  []SimpleMitreMapping  `json:"mitre_atlas,omitempty"`
	RiskScore   float64               `json:"risk_score"` // 0.0 - 10.0
	Remediation string                `json:"remediation"`
	NeedsReview bool                  `json:"needs_review"` // True if classifier is uncertain

	// Metadata about the classification
	Method    ClassificationMethod `json:"method"`    // Which classifier produced this result
	Rationale string               `json:"rationale"` // Explanation for the classification
}

// ClassificationMethod indicates which classifier produced the classification
type ClassificationMethod string

const (
	MethodHeuristic ClassificationMethod = "heuristic"
	MethodLLM       ClassificationMethod = "llm"
	MethodComposite ClassificationMethod = "composite"
	MethodManual    ClassificationMethod = "manual"
)

// String returns the string representation of ClassificationMethod
func (cm ClassificationMethod) String() string {
	return string(cm)
}

// NewEnhancedFinding creates a new enhanced finding from a base finding
func NewEnhancedFinding(baseFinding agent.Finding, missionID types.ID, agentName string) EnhancedFinding {
	now := time.Now()
	return EnhancedFinding{
		Finding:         baseFinding,
		MissionID:       missionID,
		AgentName:       agentName,
		Status:          StatusOpen,
		RiskScore:       0.0,
		References:      []string{},
		ReproSteps:      []ReproStep{},
		RelatedIDs:      []types.ID{},
		OccurrenceCount: 1,
		UpdatedAt:       now,
	}
}

// WithClassification applies classification results to the finding
func (f EnhancedFinding) WithClassification(c Classification) EnhancedFinding {
	f.Category = string(c.Category)
	f.Subcategory = c.Subcategory
	f.Severity = c.Severity
	f.Confidence = c.Confidence
	f.RiskScore = c.RiskScore
	f.Remediation = c.Remediation

	// Store MITRE mappings in Metadata
	if len(c.MitreAttack) > 0 {
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		f.Metadata["mitre_attack"] = c.MitreAttack
	}
	if len(c.MitreAtlas) > 0 {
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		f.Metadata["mitre_atlas"] = c.MitreAtlas
	}

	f.UpdatedAt = time.Now()
	return f
}

// WithStatus sets the finding status
func (f EnhancedFinding) WithStatus(status FindingStatus) EnhancedFinding {
	f.Status = status
	f.UpdatedAt = time.Now()
	return f
}

// WithReproSteps sets the reproduction steps
func (f EnhancedFinding) WithReproSteps(steps []ReproStep) EnhancedFinding {
	f.ReproSteps = steps
	f.UpdatedAt = time.Now()
	return f
}

// WithReferences sets the reference URLs
func (f EnhancedFinding) WithReferences(refs ...string) EnhancedFinding {
	f.References = refs
	f.UpdatedAt = time.Now()
	return f
}

// WithRelatedFindings sets related finding IDs
func (f EnhancedFinding) WithRelatedFindings(ids ...types.ID) EnhancedFinding {
	f.RelatedIDs = ids
	f.UpdatedAt = time.Now()
	return f
}

// WithDelegation marks the finding as delegated from another agent
func (f EnhancedFinding) WithDelegation(fromAgent string) EnhancedFinding {
	f.DelegatedFrom = &fromAgent
	f.UpdatedAt = time.Now()
	return f
}

// IncrementOccurrence increments the occurrence count
func (f *EnhancedFinding) IncrementOccurrence() {
	f.OccurrenceCount++
	f.UpdatedAt = time.Now()
}

// IsConfirmed returns true if the finding has been confirmed
func (f EnhancedFinding) IsConfirmed() bool {
	return f.Status == StatusConfirmed
}

// IsResolved returns true if the finding has been resolved
func (f EnhancedFinding) IsResolved() bool {
	return f.Status == StatusResolved
}

// IsFalsePositive returns true if the finding is marked as a false positive
func (f EnhancedFinding) IsFalsePositive() bool {
	return f.Status == StatusFalsePositive
}

// IsCritical returns true if the finding is critical severity
func (f EnhancedFinding) IsCritical() bool {
	return f.Severity == agent.SeverityCritical
}

// NeedsAttention returns true if the finding needs immediate attention
func (f EnhancedFinding) NeedsAttention() bool {
	return (f.Severity == agent.SeverityCritical || f.Severity == agent.SeverityHigh) &&
		(f.Status == StatusOpen || f.Status == StatusConfirmed)
}

// GetMitreAttack retrieves the MITRE ATT&CK mappings from Metadata
func (f EnhancedFinding) GetMitreAttack() []SimpleMitreMapping {
	if f.Metadata == nil {
		return nil
	}

	val, ok := f.Metadata[security.MetaKeyMitreAttack]
	if !ok {
		return nil
	}

	// Handle various types from JSON deserialization
	return convertToSimpleMappings(val)
}

// GetMitreAtlas retrieves the MITRE ATLAS mappings from Metadata
func (f EnhancedFinding) GetMitreAtlas() []SimpleMitreMapping {
	if f.Metadata == nil {
		return nil
	}

	val, ok := f.Metadata[security.MetaKeyMitreAtlas]
	if !ok {
		return nil
	}

	// Handle various types from JSON deserialization
	return convertToSimpleMappings(val)
}

// convertToSimpleMappings handles conversion from various MITRE mapping formats
// to SimpleMitreMapping. Supports security.MitreMapping, SimpleMitreMapping,
// and generic map[string]interface{} (from JSON deserialization).
func convertToSimpleMappings(val any) []SimpleMitreMapping {
	switch v := val.(type) {
	case SimpleMitreMapping:
		// Single SimpleMitreMapping
		return []SimpleMitreMapping{v}
	case []SimpleMitreMapping:
		return v
	case security.MitreMapping:
		// Single security.MitreMapping
		return []SimpleMitreMapping{{
			TechniqueID:   v.TechniqueID,
			TechniqueName: v.TechniqueName,
			Tactic:        v.TacticName,
		}}
	case []security.MitreMapping:
		mappings := make([]SimpleMitreMapping, len(v))
		for i, m := range v {
			mappings[i] = SimpleMitreMapping{
				TechniqueID:   m.TechniqueID,
				TechniqueName: m.TechniqueName,
				Tactic:        m.TacticName,
			}
		}
		return mappings
	case map[string]interface{}:
		// Single map from JSON deserialization
		mapping := SimpleMitreMapping{}
		if tid, ok := v["technique_id"].(string); ok {
			mapping.TechniqueID = tid
		}
		if tn, ok := v["technique_name"].(string); ok {
			mapping.TechniqueName = tn
		}
		if tactic, ok := v["tactic"].(string); ok {
			mapping.Tactic = tactic
		} else if tacticName, ok := v["tactic_name"].(string); ok {
			mapping.Tactic = tacticName
		}
		return []SimpleMitreMapping{mapping}
	case []interface{}:
		// Convert from generic interface slice (JSON deserialization)
		mappings := make([]SimpleMitreMapping, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				mapping := SimpleMitreMapping{}
				if tid, ok := m["technique_id"].(string); ok {
					mapping.TechniqueID = tid
				}
				if tn, ok := m["technique_name"].(string); ok {
					mapping.TechniqueName = tn
				}
				// Try both "tactic" and "tactic_name" keys
				if tactic, ok := m["tactic"].(string); ok {
					mapping.Tactic = tactic
				} else if tacticName, ok := m["tactic_name"].(string); ok {
					mapping.Tactic = tacticName
				}
				mappings = append(mappings, mapping)
			}
		}
		return mappings
	default:
		return nil
	}
}

// GetCVSS retrieves the CVSS score from Metadata
func (f EnhancedFinding) GetCVSS() *agent.CVSSScore {
	if f.CVSS != nil {
		return f.CVSS
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling to maintain backward compatibility
// by including mitre_attack and mitre_atlas as top-level fields in the JSON output
func (f EnhancedFinding) MarshalJSON() ([]byte, error) {
	// Create an alias type to avoid recursion
	type Alias EnhancedFinding

	// Create a custom struct that includes both the base fields and MITRE fields
	return json.Marshal(&struct {
		*Alias
		MitreAttack []SimpleMitreMapping `json:"mitre_attack,omitempty"`
		MitreAtlas  []SimpleMitreMapping `json:"mitre_atlas,omitempty"`
	}{
		Alias:       (*Alias)(&f),
		MitreAttack: f.GetMitreAttack(),
		MitreAtlas:  f.GetMitreAtlas(),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling to maintain backward compatibility
// by reading mitre_attack and mitre_atlas from either top-level fields or metadata
func (f *EnhancedFinding) UnmarshalJSON(data []byte) error {
	// Create an alias type to avoid recursion
	type Alias EnhancedFinding

	// First unmarshal into the base structure
	aux := &struct {
		*Alias
		MitreAttack []SimpleMitreMapping `json:"mitre_attack,omitempty"`
		MitreAtlas  []SimpleMitreMapping `json:"mitre_atlas,omitempty"`
	}{
		Alias: (*Alias)(f),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If MITRE fields were in the JSON, store them in Metadata
	if len(aux.MitreAttack) > 0 {
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		f.Metadata["mitre_attack"] = aux.MitreAttack
	}
	if len(aux.MitreAtlas) > 0 {
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		f.Metadata["mitre_atlas"] = aux.MitreAtlas
	}

	return nil
}
