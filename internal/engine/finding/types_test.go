// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestEnhancedFinding_NewEnhancedFinding(t *testing.T) {
	baseFinding := agent.NewFinding("Test Finding", "Test Description", agent.SeverityHigh)
	missionID := types.NewID()
	agentName := "test-agent"

	enhanced := NewEnhancedFinding(baseFinding, missionID, agentName)

	assert.Equal(t, baseFinding.ID, enhanced.ID)
	assert.Equal(t, missionID, enhanced.MissionID)
	assert.Equal(t, agentName, enhanced.AgentName)
	assert.Equal(t, StatusOpen, enhanced.Status)
	assert.Equal(t, 0.0, enhanced.RiskScore)
	assert.Equal(t, 1, enhanced.OccurrenceCount)
	assert.NotZero(t, enhanced.UpdatedAt)
	assert.Empty(t, enhanced.References)
	assert.Empty(t, enhanced.ReproSteps)
	assert.Empty(t, enhanced.GetMitreAttack())
	assert.Empty(t, enhanced.GetMitreAtlas())
	assert.Empty(t, enhanced.RelatedIDs)
}

func TestEnhancedFinding_WithClassification(t *testing.T) {
	baseFinding := agent.NewFinding("Test Finding", "Test Description", agent.SeverityMedium)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "test-agent")

	classification := Classification{
		Category:    CategoryJailbreak,
		Subcategory: "instruction_override",
		Severity:    agent.SeverityCritical,
		Confidence:  0.95,
		RiskScore:   9.5,
		Remediation: "Implement input validation",
		MitreAttack: []SimpleMitreMapping{
			{
				TechniqueID:   "AML.T0015",
				TechniqueName: "Jailbreak",
				Tactic:        "ML Attack Staging",
			},
		},
	}

	enhanced = enhanced.WithClassification(classification)

	assert.Equal(t, "jailbreak", enhanced.Category)
	assert.Equal(t, "instruction_override", enhanced.Subcategory)
	assert.Equal(t, agent.SeverityCritical, enhanced.Severity)
	assert.Equal(t, 0.95, enhanced.Confidence)
	assert.Equal(t, 9.5, enhanced.RiskScore)
	assert.Equal(t, "Implement input validation", enhanced.Remediation)

	// Check MITRE mappings from Metadata
	mitreAttack := enhanced.GetMitreAttack()
	assert.Len(t, mitreAttack, 1)
	assert.Equal(t, "AML.T0015", mitreAttack[0].TechniqueID)
}

func TestEnhancedFinding_WithStatus(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityLow)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")

	enhanced = enhanced.WithStatus(StatusConfirmed)
	assert.Equal(t, StatusConfirmed, enhanced.Status)
	assert.True(t, enhanced.IsConfirmed())
	assert.False(t, enhanced.IsResolved())

	enhanced = enhanced.WithStatus(StatusResolved)
	assert.Equal(t, StatusResolved, enhanced.Status)
	assert.True(t, enhanced.IsResolved())
	assert.False(t, enhanced.IsConfirmed())

	enhanced = enhanced.WithStatus(StatusFalsePositive)
	assert.True(t, enhanced.IsFalsePositive())
}

func TestEnhancedFinding_WithReproSteps(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityHigh)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")

	steps := []ReproStep{
		{
			StepNumber:     1,
			Description:    "Send malicious prompt",
			ExpectedResult: "Model responds with harmful content",
			EvidenceRef:    "conversation-1",
		},
		{
			StepNumber:     2,
			Description:    "Verify response",
			ExpectedResult: "Response contains sensitive data",
		},
	}

	enhanced = enhanced.WithReproSteps(steps)
	assert.Len(t, enhanced.ReproSteps, 2)
	assert.Equal(t, "Send malicious prompt", enhanced.ReproSteps[0].Description)
	assert.Equal(t, "conversation-1", enhanced.ReproSteps[0].EvidenceRef)
}

func TestEnhancedFinding_WithReferences(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityMedium)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")

	refs := []string{
		"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		"https://atlas.mitre.org/techniques/AML.T0015",
	}

	enhanced = enhanced.WithReferences(refs...)
	assert.Len(t, enhanced.References, 2)
	assert.Contains(t, enhanced.References, refs[0])
	assert.Contains(t, enhanced.References, refs[1])
}

func TestEnhancedFinding_WithRelatedFindings(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityLow)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")

	relatedID1 := types.NewID()
	relatedID2 := types.NewID()

	enhanced = enhanced.WithRelatedFindings(relatedID1, relatedID2)
	assert.Len(t, enhanced.RelatedIDs, 2)
	assert.Contains(t, enhanced.RelatedIDs, relatedID1)
	assert.Contains(t, enhanced.RelatedIDs, relatedID2)
}

func TestEnhancedFinding_WithDelegation(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityMedium)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent-2")

	enhanced = enhanced.WithDelegation("agent-1")
	require.NotNil(t, enhanced.DelegatedFrom)
	assert.Equal(t, "agent-1", *enhanced.DelegatedFrom)
}

func TestEnhancedFinding_IncrementOccurrence(t *testing.T) {
	baseFinding := agent.NewFinding("Test", "Test", agent.SeverityLow)
	enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")

	assert.Equal(t, 1, enhanced.OccurrenceCount)

	enhanced.IncrementOccurrence()
	assert.Equal(t, 2, enhanced.OccurrenceCount)

	enhanced.IncrementOccurrence()
	assert.Equal(t, 3, enhanced.OccurrenceCount)
}

func TestEnhancedFinding_IsCritical(t *testing.T) {
	criticalFinding := agent.NewFinding("Critical", "Test", agent.SeverityCritical)
	enhanced := NewEnhancedFinding(criticalFinding, types.NewID(), "agent")
	assert.True(t, enhanced.IsCritical())

	highFinding := agent.NewFinding("High", "Test", agent.SeverityHigh)
	enhanced = NewEnhancedFinding(highFinding, types.NewID(), "agent")
	assert.False(t, enhanced.IsCritical())
}

func TestEnhancedFinding_NeedsAttention(t *testing.T) {
	tests := []struct {
		name     string
		severity agent.FindingSeverity
		status   FindingStatus
		expected bool
	}{
		{"critical open", agent.SeverityCritical, StatusOpen, true},
		{"critical confirmed", agent.SeverityCritical, StatusConfirmed, true},
		{"critical resolved", agent.SeverityCritical, StatusResolved, false},
		{"high open", agent.SeverityHigh, StatusOpen, true},
		{"high confirmed", agent.SeverityHigh, StatusConfirmed, true},
		{"medium open", agent.SeverityMedium, StatusOpen, false},
		{"low open", agent.SeverityLow, StatusOpen, false},
		{"high false positive", agent.SeverityHigh, StatusFalsePositive, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseFinding := agent.NewFinding("Test", "Test", tt.severity)
			enhanced := NewEnhancedFinding(baseFinding, types.NewID(), "agent")
			enhanced = enhanced.WithStatus(tt.status)
			assert.Equal(t, tt.expected, enhanced.NeedsAttention())
		})
	}
}

func TestEnhancedFinding_JSONSerialization(t *testing.T) {
	baseFinding := agent.NewFinding("Test Finding", "Test Description", agent.SeverityHigh)
	baseFinding = baseFinding.WithCategory("security")

	missionID := types.NewID()
	enhanced := NewEnhancedFinding(baseFinding, missionID, "test-agent")
	enhanced = enhanced.WithStatus(StatusConfirmed)
	enhanced = enhanced.WithReferences("https://example.com/ref1")

	// Marshal to JSON
	data, err := json.Marshal(enhanced)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled EnhancedFinding
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify key fields
	assert.Equal(t, enhanced.ID, unmarshaled.ID)
	assert.Equal(t, enhanced.Title, unmarshaled.Title)
	assert.Equal(t, enhanced.MissionID, unmarshaled.MissionID)
	assert.Equal(t, enhanced.AgentName, unmarshaled.AgentName)
	assert.Equal(t, enhanced.Status, unmarshaled.Status)
	assert.Equal(t, enhanced.Severity, unmarshaled.Severity)
	assert.Len(t, unmarshaled.References, 1)
}

func TestFindingStatus_Values(t *testing.T) {
	assert.Equal(t, FindingStatus("open"), StatusOpen)
	assert.Equal(t, FindingStatus("confirmed"), StatusConfirmed)
	assert.Equal(t, FindingStatus("resolved"), StatusResolved)
	assert.Equal(t, FindingStatus("false_positive"), StatusFalsePositive)
}

func TestFindingCategory_Values(t *testing.T) {
	assert.Equal(t, FindingCategory("jailbreak"), CategoryJailbreak)
	assert.Equal(t, FindingCategory("prompt_injection"), CategoryPromptInjection)
	assert.Equal(t, FindingCategory("data_extraction"), CategoryDataExtraction)
	assert.Equal(t, FindingCategory("privilege_escalation"), CategoryPrivilegeEscalation)
	assert.Equal(t, FindingCategory("dos"), CategoryDoS)
	assert.Equal(t, FindingCategory("model_manipulation"), CategoryModelManipulation)
	assert.Equal(t, FindingCategory("information_disclosure"), CategoryInformationDisclosure)
}

func TestClassification(t *testing.T) {
	classification := Classification{
		Category:    CategoryPromptInjection,
		Subcategory: "indirect_injection",
		Severity:    agent.SeverityHigh,
		Confidence:  0.88,
		RiskScore:   8.5,
		Remediation: "Sanitize user inputs",
		NeedsReview: false,
		MitreAtlas: []SimpleMitreMapping{
			{
				TechniqueID:   "AML.T0051",
				TechniqueName: "Prompt Injection",
				Tactic:        "ML Attack Staging",
			},
		},
	}

	assert.Equal(t, CategoryPromptInjection, classification.Category)
	assert.Equal(t, 0.88, classification.Confidence)
	assert.False(t, classification.NeedsReview)
	assert.Len(t, classification.MitreAtlas, 1)
}

func TestFindingErrorCode_Constants(t *testing.T) {
	assert.Equal(t, FindingErrorCode("classification_failed"), ErrorClassificationFailed)
	assert.Equal(t, FindingErrorCode("llm_timeout"), ErrorLLMTimeout)
	assert.Equal(t, FindingErrorCode("store_failed"), ErrorStoreFailed)
	assert.Equal(t, FindingErrorCode("export_failed"), ErrorExportFailed)
	assert.Equal(t, FindingErrorCode("duplicate_conflict"), ErrorDuplicateConflict)
	assert.Equal(t, FindingErrorCode("mitre_not_found"), ErrorMitreNotFound)
	assert.Equal(t, FindingErrorCode("invalid_finding"), ErrorInvalidFinding)
}
