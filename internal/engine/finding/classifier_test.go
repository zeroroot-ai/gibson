// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
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

// ────────────────────────────────────────────────────────────────────────────
// LLMClassifier Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// CompositeClassifier Tests
// ────────────────────────────────────────────────────────────────────────────

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
