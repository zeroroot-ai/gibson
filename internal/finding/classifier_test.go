package finding

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
)

// ────────────────────────────────────────────────────────────────────────────
// Mock Implementations
// ────────────────────────────────────────────────────────────────────────────

// MockLLMCaller implements LLMCaller for testing
type MockLLMCaller struct {
	mu        sync.Mutex
	responses []*llm.CompletionResponse
	errors    []error
	callCount int
}

func NewMockLLMCaller() *MockLLMCaller {
	return &MockLLMCaller{
		responses: []*llm.CompletionResponse{},
		errors:    []error{},
	}
}

func (m *MockLLMCaller) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.callCount >= len(m.responses) {
		return nil, errors.New("no more mock responses")
	}

	resp := m.responses[m.callCount]
	err := m.errors[m.callCount]
	m.callCount++

	return resp, err
}

func (m *MockLLMCaller) AddResponse(category, subcategory, rationale string, confidence float64) {
	jsonResponse := `{
  "category": "` + category + `",
  "subcategory": "` + subcategory + `",
  "confidence": ` + fmt.Sprintf("%.2f", confidence) + `,
  "rationale": "` + rationale + `"
}`

	m.responses = append(m.responses, &llm.CompletionResponse{
		ID:    "test-completion",
		Model: "test-model",
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: jsonResponse,
		},
		FinishReason: llm.FinishReasonStop,
	})
	m.errors = append(m.errors, nil)
}

func (m *MockLLMCaller) AddError(err error) {
	m.responses = append(m.responses, nil)
	m.errors = append(m.errors, err)
}

func (m *MockLLMCaller) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// ────────────────────────────────────────────────────────────────────────────
// HeuristicClassifier Tests
// ────────────────────────────────────────────────────────────────────────────

func TestHeuristicClassifier_Classify_Jailbreak(t *testing.T) {
	tests := []struct {
		name                string
		title               string
		description         string
		expectedCategory    FindingCategory
		expectedSubcategory string
		minConfidence       float64
	}{
		{
			name:                "Explicit jailbreak",
			title:               "Jailbreak Attempt Detected",
			description:         "User tried to jailbreak the model",
			expectedCategory:    CategoryJailbreak,
			expectedSubcategory: "jailbreak",
			minConfidence:       0.90,
		},
		{
			name:                "Guardrail bypass",
			title:               "Guardrail Bypass",
			description:         "Attempt to bypass safety guardrails",
			expectedCategory:    CategoryJailbreak,
			expectedSubcategory: "guardrail_bypass",
			minConfidence:       0.85,
		},
		{
			name:                "Instruction override",
			title:               "Instruction Override",
			description:         "User attempted to override system instructions",
			expectedCategory:    CategoryJailbreak,
			expectedSubcategory: "instruction_override",
			minConfidence:       0.85,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := NewHeuristicClassifier()

			finding := agent.NewFinding(
				tt.title,
				tt.description,
				agent.SeverityHigh,
			)

			classification, err := classifier.Classify(context.Background(), finding)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedCategory, classification.Category)
			assert.Equal(t, tt.expectedSubcategory, classification.Subcategory)
			assert.GreaterOrEqual(t, classification.Confidence, tt.minConfidence)
			assert.Equal(t, MethodHeuristic, classification.Method)
			assert.NotEmpty(t, classification.Rationale)
		})
	}
}

func TestHeuristicClassifier_Classify_PromptInjection(t *testing.T) {
	tests := []struct {
		name                string
		title               string
		description         string
		expectedCategory    FindingCategory
		expectedSubcategory string
	}{
		{
			name:                "Direct prompt injection",
			title:               "Prompt Injection Attack",
			description:         "Malicious prompt injection detected",
			expectedCategory:    CategoryPromptInjection,
			expectedSubcategory: "prompt_injection",
		},
		{
			name:                "Indirect injection",
			title:               "Indirect Injection",
			description:         "Indirect prompt manipulation via context",
			expectedCategory:    CategoryPromptInjection,
			expectedSubcategory: "prompt_injection", // Heuristic doesn't distinguish indirect
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := NewHeuristicClassifier()

			finding := agent.NewFinding(
				tt.title,
				tt.description,
				agent.SeverityHigh,
			)

			classification, err := classifier.Classify(context.Background(), finding)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedCategory, classification.Category)
			assert.Equal(t, tt.expectedSubcategory, classification.Subcategory)
		})
	}
}

func TestHeuristicClassifier_Classify_DataExtraction(t *testing.T) {
	tests := []struct {
		name                string
		title               string
		description         string
		expectedSubcategory string
	}{
		{
			name:                "Data leak",
			title:               "Data Leak Detected",
			description:         "Sensitive data leaked in response",
			expectedSubcategory: "data_leak",
		},
		{
			name:                "PII disclosure",
			title:               "PII Disclosure",
			description:         "Personal identifiable information disclosed",
			expectedSubcategory: "pii_disclosure",
		},
		{
			name:                "Credential leak",
			title:               "Credential Leak",
			description:         "API credentials leaked in output",
			expectedSubcategory: "credential_leak",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := NewHeuristicClassifier()

			finding := agent.NewFinding(
				tt.title,
				tt.description,
				agent.SeverityCritical,
			)

			classification, err := classifier.Classify(context.Background(), finding)

			require.NoError(t, err)
			assert.Equal(t, CategoryDataExtraction, classification.Category)
			assert.Equal(t, tt.expectedSubcategory, classification.Subcategory)
		})
	}
}

func TestHeuristicClassifier_Classify_InformationDisclosure(t *testing.T) {
	tests := []struct {
		name                string
		title               string
		description         string
		expectedSubcategory string
	}{
		{
			name:                "System prompt disclosure",
			title:               "System Prompt Revealed",
			description:         "Model disclosed its system prompt",
			expectedSubcategory: "system_prompt",
		},
		{
			name:                "Config disclosure",
			title:               "Configuration Leak",
			description:         "Configuration settings disclosed",
			expectedSubcategory: "config_disclosure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := NewHeuristicClassifier()

			finding := agent.NewFinding(
				tt.title,
				tt.description,
				agent.SeverityMedium,
			)

			classification, err := classifier.Classify(context.Background(), finding)

			require.NoError(t, err)
			assert.Equal(t, CategoryInformationDisclosure, classification.Category)
			assert.Equal(t, tt.expectedSubcategory, classification.Subcategory)
		})
	}
}

func TestHeuristicClassifier_Classify_Uncategorized(t *testing.T) {
	classifier := NewHeuristicClassifier()

	finding := agent.NewFinding(
		"Unknown Issue",
		"Something unusual happened",
		agent.SeverityLow,
	)

	classification, err := classifier.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryUncategorized, classification.Category)
	assert.Equal(t, "unknown", classification.Subcategory)
	assert.LessOrEqual(t, classification.Confidence, 0.6)
}

func TestHeuristicClassifier_BulkClassify(t *testing.T) {
	classifier := NewHeuristicClassifier()

	findings := []agent.Finding{
		agent.NewFinding("Jailbreak", "jailbreak attempt", agent.SeverityHigh),
		agent.NewFinding("Prompt Injection", "prompt injection attack", agent.SeverityHigh),
		agent.NewFinding("Data Leak", "data leaked", agent.SeverityCritical),
	}

	classifications, err := classifier.BulkClassify(context.Background(), findings)

	require.NoError(t, err)
	require.Len(t, classifications, 3)
	assert.Equal(t, CategoryJailbreak, classifications[0].Category)
	assert.Equal(t, CategoryPromptInjection, classifications[1].Category)
	assert.Equal(t, CategoryDataExtraction, classifications[2].Category)
}

func TestHeuristicClassifier_AddCustomPattern(t *testing.T) {
	classifier := NewHeuristicClassifier()

	initialCount := classifier.GetPatternCount()

	err := classifier.AddCustomPattern(
		CategoryJailbreak,
		"custom_attack",
		`\b(?i)custom.*attack\b`,
		0.85,
		75,
	)

	require.NoError(t, err)
	assert.Equal(t, initialCount+1, classifier.GetPatternCount())

	// Test the custom pattern
	finding := agent.NewFinding(
		"Custom Attack",
		"This is a custom attack pattern",
		agent.SeverityHigh,
	)

	classification, err := classifier.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryJailbreak, classification.Category)
	assert.Equal(t, "custom_attack", classification.Subcategory)
}

func TestHeuristicClassifier_ContextCancellation(t *testing.T) {
	classifier := NewHeuristicClassifier()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	finding := agent.NewFinding(
		"Test",
		"Test finding",
		agent.SeverityLow,
	)

	_, err := classifier.Classify(ctx, finding)

	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// ────────────────────────────────────────────────────────────────────────────
// LLMClassifier Tests
// ────────────────────────────────────────────────────────────────────────────

func TestLLMClassifier_Classify_Success(t *testing.T) {
	mockCaller := NewMockLLMCaller()
	mockCaller.AddResponse("jailbreak", "role_manipulation", "User attempted role-play attack", 0.92)

	classifier := NewLLMClassifier(mockCaller, "primary")

	finding := agent.NewFinding(
		"Role Play Attack",
		"User asked model to pretend to be evil",
		agent.SeverityHigh,
	)

	classification, err := classifier.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryJailbreak, classification.Category)
	assert.Equal(t, "role_manipulation", classification.Subcategory)
	assert.Equal(t, 0.92, classification.Confidence)
	assert.Equal(t, MethodLLM, classification.Method)
	assert.NotEmpty(t, classification.Rationale)
	assert.Equal(t, 1, mockCaller.GetCallCount())
}

func TestLLMClassifier_Classify_WithMitreDB(t *testing.T) {
	mockCaller := NewMockLLMCaller()
	mockCaller.AddResponse("jailbreak", "instruction_override", "Instruction override attempt", 0.88)

	mockDB := NewMitreDatabase()
	classifier := NewLLMClassifier(mockCaller, "primary", WithMitreDatabase(mockDB))

	finding := agent.NewFinding(
		"Instruction Override",
		"Override system instructions",
		agent.SeverityHigh,
	)

	classification, err := classifier.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.NotEmpty(t, classification.MitreAttack)
	assert.Equal(t, "AML.T0015", classification.MitreAttack[0].TechniqueID)
}

func TestLLMClassifier_Classify_LLMError(t *testing.T) {
	mockCaller := NewMockLLMCaller()
	mockCaller.AddError(errors.New("LLM API error"))

	classifier := NewLLMClassifier(mockCaller, "primary")

	finding := agent.NewFinding(
		"Test",
		"Test finding",
		agent.SeverityLow,
	)

	_, err := classifier.Classify(context.Background(), finding)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LLM completion failed")
}

func TestLLMClassifier_Classify_InvalidCategory(t *testing.T) {
	mockCaller := NewMockLLMCaller()
	mockCaller.AddResponse("invalid_category", "unknown", "Not a valid category", 0.5)

	classifier := NewLLMClassifier(mockCaller, "primary")

	finding := agent.NewFinding(
		"Test",
		"Test finding",
		agent.SeverityLow,
	)

	classification, err := classifier.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryUncategorized, classification.Category)
	assert.Equal(t, 0.5, classification.Confidence)
}

func TestLLMClassifier_BulkClassify(t *testing.T) {
	mockCaller := NewMockLLMCaller()
	// Note: responses are consumed in the order goroutines acquire the lock,
	// which may not match the order findings were submitted due to concurrency.
	mockCaller.AddResponse("jailbreak", "jailbreak", "Jailbreak attempt", 0.95)
	mockCaller.AddResponse("prompt_injection", "prompt_injection", "Prompt injection", 0.90)

	classifier := NewLLMClassifier(mockCaller, "primary")

	findings := []agent.Finding{
		agent.NewFinding("Jailbreak", "jailbreak", agent.SeverityHigh),
		agent.NewFinding("Injection", "prompt injection", agent.SeverityHigh),
	}

	classifications, err := classifier.BulkClassify(context.Background(), findings)

	require.NoError(t, err)
	require.Len(t, classifications, 2)
	// Check that both expected categories are present (order may vary due to concurrency)
	categories := []FindingCategory{classifications[0].Category, classifications[1].Category}
	assert.Contains(t, categories, CategoryJailbreak, "should contain jailbreak category")
	assert.Contains(t, categories, CategoryPromptInjection, "should contain prompt_injection category")
	assert.Equal(t, 2, mockCaller.GetCallCount())
}

// ────────────────────────────────────────────────────────────────────────────
// CompositeClassifier Tests
// ────────────────────────────────────────────────────────────────────────────

func TestCompositeClassifier_Classify_HighConfidenceHeuristic(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	mockCaller := NewMockLLMCaller()
	llmClassifier := NewLLMClassifier(mockCaller, "primary")

	// Set threshold to 0.8, heuristic will return 0.95 for jailbreak
	composite := NewCompositeClassifier(heuristic, llmClassifier, WithConfidenceThreshold(0.8))

	finding := agent.NewFinding(
		"Jailbreak Attempt",
		"User tried to jailbreak the model",
		agent.SeverityHigh,
	)

	classification, err := composite.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryJailbreak, classification.Category)
	assert.Equal(t, MethodComposite, classification.Method)
	assert.Contains(t, classification.Rationale, "Heuristic")
	assert.Equal(t, 0, mockCaller.GetCallCount()) // LLM should not be called
}

func TestCompositeClassifier_Classify_LowConfidenceFallback(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	mockCaller := NewMockLLMCaller()
	mockCaller.AddResponse("prompt_injection", "subtle_injection", "Subtle prompt manipulation", 0.88)
	llmClassifier := NewLLMClassifier(mockCaller, "primary")

	// Set threshold to 0.9, uncategorized findings have confidence 0.5
	composite := NewCompositeClassifier(heuristic, llmClassifier, WithConfidenceThreshold(0.9))

	finding := agent.NewFinding(
		"Subtle Attack",
		"Something unusual in user input",
		agent.SeverityMedium,
	)

	classification, err := composite.Classify(context.Background(), finding)

	require.NoError(t, err)
	assert.Equal(t, CategoryPromptInjection, classification.Category)
	assert.Equal(t, MethodComposite, classification.Method)
	assert.Contains(t, classification.Rationale, "LLM analysis")
	assert.Equal(t, 1, mockCaller.GetCallCount()) // LLM should be called
}

func TestCompositeClassifier_BulkClassify(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	mockCaller := NewMockLLMCaller()
	mockCaller.AddResponse("prompt_injection", "unknown", "Unknown attack", 0.85)
	llmClassifier := NewLLMClassifier(mockCaller, "primary")

	composite := NewCompositeClassifier(heuristic, llmClassifier, WithConfidenceThreshold(0.8))

	findings := []agent.Finding{
		// High confidence - no LLM needed
		agent.NewFinding("Jailbreak", "jailbreak attempt", agent.SeverityHigh),
		// Low confidence - needs LLM
		agent.NewFinding("Unknown", "strange behavior", agent.SeverityMedium),
	}

	classifications, err := composite.BulkClassify(context.Background(), findings)

	require.NoError(t, err)
	require.Len(t, classifications, 2)
	assert.Equal(t, CategoryJailbreak, classifications[0].Category)
	assert.Equal(t, 1, mockCaller.GetCallCount()) // Only called for second finding
}

func TestCompositeClassifier_SetThreshold(t *testing.T) {
	heuristic := NewHeuristicClassifier()
	mockCaller := NewMockLLMCaller()
	llmClassifier := NewLLMClassifier(mockCaller, "primary")

	composite := NewCompositeClassifier(heuristic, llmClassifier, WithConfidenceThreshold(0.7))

	assert.Equal(t, 0.7, composite.GetThreshold())

	composite.SetThreshold(0.9)
	assert.Equal(t, 0.9, composite.GetThreshold())

	// Test boundary clamping
	composite.SetThreshold(-0.1)
	assert.Equal(t, 0.0, composite.GetThreshold())

	composite.SetThreshold(1.5)
	assert.Equal(t, 1.0, composite.GetThreshold())
}

// ────────────────────────────────────────────────────────────────────────────
// FindingCategory Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFindingCategory_String(t *testing.T) {
	assert.Equal(t, "jailbreak", CategoryJailbreak.String())
	assert.Equal(t, "prompt_injection", CategoryPromptInjection.String())
	assert.Equal(t, "data_extraction", CategoryDataExtraction.String())
	assert.Equal(t, "information_disclosure", CategoryInformationDisclosure.String())
	assert.Equal(t, "uncategorized", CategoryUncategorized.String())
}

func TestFindingCategory_IsValid(t *testing.T) {
	assert.True(t, CategoryJailbreak.IsValid())
	assert.True(t, CategoryPromptInjection.IsValid())
	assert.True(t, CategoryDataExtraction.IsValid())
	assert.True(t, CategoryInformationDisclosure.IsValid())
	assert.True(t, CategoryUncategorized.IsValid())
	assert.False(t, FindingCategory("invalid").IsValid())
}

// ────────────────────────────────────────────────────────────────────────────
// ClassificationMethod Tests
// ────────────────────────────────────────────────────────────────────────────

func TestClassificationMethod_String(t *testing.T) {
	assert.Equal(t, "heuristic", MethodHeuristic.String())
	assert.Equal(t, "llm", MethodLLM.String())
	assert.Equal(t, "composite", MethodComposite.String())
	assert.Equal(t, "manual", MethodManual.String())
}
