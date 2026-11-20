// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
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
	CategoryPrivilegeEscalation   FindingCategory = "privilege_escalation"
	CategoryDoS                   FindingCategory = "dos"
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
	case CategoryPrivilegeEscalation, CategoryDoS,
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
	TechniqueID   string `json:"technique_id"`     // e.g., "T1566"
	TechniqueName string `json:"technique_name"`   // Human-readable name
	Tactic        string `json:"tactic,omitempty"` // e.g., "Initial Access"
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
// by including mitre_attack as a top-level field in the JSON output
func (f EnhancedFinding) MarshalJSON() ([]byte, error) {
	// Create an alias type to avoid recursion
	type Alias EnhancedFinding

	// Create a custom struct that includes both the base fields and MITRE fields
	return json.Marshal(&struct {
		*Alias
		MitreAttack []SimpleMitreMapping `json:"mitre_attack,omitempty"`
	}{
		Alias:       (*Alias)(&f),
		MitreAttack: f.GetMitreAttack(),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling to maintain backward compatibility
// by reading mitre_attack from either top-level fields or metadata
func (f *EnhancedFinding) UnmarshalJSON(data []byte) error {
	// Create an alias type to avoid recursion
	type Alias EnhancedFinding

	// First unmarshal into the base structure
	aux := &struct {
		*Alias
		MitreAttack []SimpleMitreMapping `json:"mitre_attack,omitempty"`
	}{
		Alias: (*Alias)(f),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If the MITRE field was in the JSON, store them in Metadata
	if len(aux.MitreAttack) > 0 {
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		f.Metadata["mitre_attack"] = aux.MitreAttack
	}

	return nil
}
