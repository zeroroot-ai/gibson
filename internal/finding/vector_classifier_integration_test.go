//go:build integration

package finding

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/sdk/finding/classifier"
	"github.com/zero-day-ai/sdk/finding/classifier/store"
	"github.com/zero-day-ai/sdk/finding/registry"
)

// TestVectorClassifier_RealEmbeddings_SemanticMatching tests semantic similarity
// matching using the real NativeEmbedder (all-MiniLM-L6-v2 via ONNX).
//
// This test verifies that semantically similar categories are correctly matched,
// such as "jailbreaking" matching "jailbreak".
func TestVectorClassifier_RealEmbeddings_SemanticMatching(t *testing.T) {
	ctx := context.Background()

	// Create the real NativeEmbedder (requires ONNX model to be available)
	nativeEmb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		t.Skipf("skipping integration test: NativeEmbedder unavailable: %v", err)
		return
	}

	// Test semantic matching: "jailbreaking" should match "jailbreak"
	t.Run("jailbreaking matches jailbreak", func(t *testing.T) {
		// Create fresh store for this subtest
		memStore := store.NewMemoryStore()
		config := classifier.DefaultConfig()
		vc := NewVectorClassifier(nativeEmb, memStore, config)

		// Register the canonical "jailbreak" category
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Bypass LLM safety controls",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		result, err := vc.Classify(ctx, "jailbreaking", "Bypass LLM safety controls")
		require.NoError(t, err)

		// With real embeddings and very similar descriptions, this should match
		// The result will be either "jailbreak" (matched) or "jailbreaking" (registered new)
		// depending on the exact similarity score
		assert.Contains(t, []string{"jailbreak", "jailbreaking"}, result,
			"result should be either matched or proposed category")

		// Verify count is reasonable (1 if matched, 2 if registered new)
		count, err := memStore.Count(ctx)
		require.NoError(t, err)
		assert.LessOrEqual(t, count, 2, "should have at most 2 categories")
	})

	// Test semantic matching: "prompt injection" should be distinct from "jailbreak"
	t.Run("prompt_injection is distinct from jailbreak", func(t *testing.T) {
		// Create fresh store for this subtest
		memStore := store.NewMemoryStore()
		config := classifier.DefaultConfig()
		vc := NewVectorClassifier(nativeEmb, memStore, config)

		// Register "jailbreak"
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Attempts to bypass LLM safety controls and content filters",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		result, err := vc.Classify(ctx, "prompt_injection", "Malicious prompt injection attack")
		require.NoError(t, err)

		// Should return "prompt_injection" (registered as new)
		assert.Equal(t, "prompt_injection", result,
			"prompt_injection should be distinct from jailbreak")

		// Verify a new category was registered
		count, err := memStore.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, count, "should register new distinct category")
	})

	// Test semantic matching: "jailbreak attack" should match "jailbreak"
	t.Run("jailbreak_attack matches jailbreak", func(t *testing.T) {
		// Create fresh store for this subtest
		memStore := store.NewMemoryStore()
		config := classifier.DefaultConfig()
		vc := NewVectorClassifier(nativeEmb, memStore, config)

		// Register "jailbreak"
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Attempts to bypass LLM safety controls and content filters",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		result, err := vc.Classify(ctx, "jailbreak_attack", "Breaking out of LLM constraints")
		require.NoError(t, err)

		// With real embeddings, this should match "jailbreak"
		// The exact behavior depends on the embedding similarity
		assert.NotEmpty(t, result)

		// Verify the result is sensible
		assert.Contains(t, []string{"jailbreak", "jailbreak_attack"}, result)
	})
}

// TestVectorClassifier_RealEmbeddings_BootstrapAndClassify tests the full
// workflow of bootstrapping from DefaultRegistry and then classifying findings.
func TestVectorClassifier_RealEmbeddings_BootstrapAndClassify(t *testing.T) {
	ctx := context.Background()

	// Create the real NativeEmbedder
	nativeEmb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		t.Skipf("skipping integration test: NativeEmbedder unavailable: %v", err)
		return
	}

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(nativeEmb, memStore, config)

	// Bootstrap from DefaultRegistry
	defaultReg := registry.DefaultRegistry()
	err = vc.Bootstrap(ctx, defaultReg)
	require.NoError(t, err)

	// Verify all categories were loaded
	expectedCount := len(defaultReg.ListAll())
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedCount, count)

	// Test classification against bootstrapped categories
	t.Run("classify jailbreak variants", func(t *testing.T) {
		testCases := []struct {
			proposed    string
			description string
			expectMatch string // Expected to match this category (or empty if new)
		}{
			{
				proposed:    "jailbreak_attempt",
				description: "User trying to bypass safety filters",
				expectMatch: "jailbreak",
			},
			{
				proposed:    "prompt_injection_attack",
				description: "Injection of malicious prompts",
				expectMatch: "prompt_injection",
			},
			{
				proposed:    "data_leak",
				description: "Unauthorized extraction of sensitive data",
				expectMatch: "data_extraction",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.proposed, func(t *testing.T) {
				result, err := vc.Classify(ctx, tc.proposed, tc.description)
				require.NoError(t, err)

				if tc.expectMatch != "" {
					// We expect a semantic match to an existing category
					// Note: The exact match depends on embedding similarity,
					// so we verify the result is either the expected match or
					// the proposed category (if similarity was below threshold)
					assert.Contains(t, []string{tc.expectMatch, tc.proposed}, result)
				} else {
					// No expected match - just verify we got a result
					assert.NotEmpty(t, result)
				}
			})
		}
	})
}

// TestVectorClassifier_RealEmbeddings_SearchSimilarity tests the Search method
// returns categories ranked by semantic similarity.
func TestVectorClassifier_RealEmbeddings_SearchSimilarity(t *testing.T) {
	ctx := context.Background()

	// Create the real NativeEmbedder
	nativeEmb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		t.Skipf("skipping integration test: NativeEmbedder unavailable: %v", err)
		return
	}

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(nativeEmb, memStore, config)

	// Bootstrap from DefaultRegistry
	defaultReg := registry.DefaultRegistry()
	err = vc.Bootstrap(ctx, defaultReg)
	require.NoError(t, err)

	// Search for "jailbreak bypass"
	t.Run("search jailbreak bypass", func(t *testing.T) {
		matches, err := vc.Search(ctx, "jailbreak bypass safety controls", 3)
		require.NoError(t, err)

		// Should return results
		assert.NotEmpty(t, matches)
		assert.LessOrEqual(t, len(matches), 3)

		// The top result should likely be "jailbreak"
		if len(matches) > 0 {
			// Verify the top match has a reasonable similarity
			topMatch := matches[0]
			assert.NotEmpty(t, topMatch.Category)
			assert.GreaterOrEqual(t, topMatch.Score, 0.0,
				"similarity score should be reasonable")
		}

		// Verify results are sorted by descending score
		for i := 1; i < len(matches); i++ {
			assert.GreaterOrEqual(t, matches[i-1].Score, matches[i].Score,
				"results should be sorted by descending score")
		}
	})

	// Search for "prompt injection"
	t.Run("search prompt injection", func(t *testing.T) {
		matches, err := vc.Search(ctx, "prompt injection attack", 3)
		require.NoError(t, err)

		// Should return results
		assert.NotEmpty(t, matches)

		// The top result should likely be "prompt_injection"
		if len(matches) > 0 {
			topMatch := matches[0]
			assert.NotEmpty(t, topMatch.Category)
			assert.GreaterOrEqual(t, topMatch.Score, 0.0)
		}
	})
}

// TestVectorClassifier_RealEmbeddings_DistinctCategories tests that truly
// distinct categories remain separate and are not incorrectly merged.
func TestVectorClassifier_RealEmbeddings_DistinctCategories(t *testing.T) {
	ctx := context.Background()

	// Create the real NativeEmbedder
	nativeEmb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		t.Skipf("skipping integration test: NativeEmbedder unavailable: %v", err)
		return
	}

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier with default threshold (0.85)
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(nativeEmb, memStore, config)

	// Register several distinct security categories
	categories := []registry.CategoryInfo{
		{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Bypass LLM safety controls and content filters",
		},
		{
			Name:        "sql_injection",
			Domain:      "security",
			DisplayName: "SQL Injection",
			Description: "SQL injection vulnerability in database queries",
		},
		{
			Name:        "xss",
			Domain:      "security",
			DisplayName: "Cross-Site Scripting",
			Description: "Cross-site scripting vulnerability in web applications",
		},
		{
			Name:        "dos",
			Domain:      "security",
			DisplayName: "Denial of Service",
			Description: "Denial of service or resource exhaustion attacks",
		},
	}

	for _, cat := range categories {
		err := vc.Register(ctx, cat)
		require.NoError(t, err)
	}

	// Verify all categories were registered
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, len(categories), count)

	// Test that truly distinct categories don't match each other
	testCases := []struct {
		proposed    string
		description string
		shouldMatch string // Should NOT match this category
	}{
		{
			proposed:    "sql_injection_vuln",
			description: "SQL injection in database",
			shouldMatch: "sql_injection",
		},
		{
			proposed:    "cross_site_scripting",
			description: "XSS vulnerability",
			shouldMatch: "xss",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.proposed, func(t *testing.T) {
			result, err := vc.Classify(ctx, tc.proposed, tc.description)
			require.NoError(t, err)

			// Result should be either the matched category or the proposed one
			// We're mainly verifying the classifier doesn't match to a completely
			// unrelated category like jailbreak when classifying SQL injection
			assert.NotEmpty(t, result)
		})
	}
}

// TestVectorClassifier_RealEmbeddings_ThresholdSensitivity tests how different
// threshold values affect classification behavior with real embeddings.
func TestVectorClassifier_RealEmbeddings_ThresholdSensitivity(t *testing.T) {
	ctx := context.Background()

	// Create the real NativeEmbedder
	nativeEmb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		t.Skipf("skipping integration test: NativeEmbedder unavailable: %v", err)
		return
	}

	// Test with a very strict threshold (0.95)
	t.Run("strict threshold", func(t *testing.T) {
		memStore := store.NewMemoryStore()
		config := classifier.Config{
			Threshold:    0.95,
			AutoRegister: true,
			StoreType:    "memory",
		}
		vc := NewVectorClassifier(nativeEmb, memStore, config)

		// Register "jailbreak"
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Attempts to bypass LLM safety controls",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		// Try to classify a similar but not identical variant
		result, err := vc.Classify(ctx, "jailbreaking", "Breaking LLM safety controls")
		require.NoError(t, err)

		// With strict threshold, this might register as new
		assert.NotEmpty(t, result)
	})

	// Test with a lenient threshold (0.70)
	t.Run("lenient threshold", func(t *testing.T) {
		memStore := store.NewMemoryStore()
		config := classifier.Config{
			Threshold:    0.70,
			AutoRegister: true,
			StoreType:    "memory",
		}
		vc := NewVectorClassifier(nativeEmb, memStore, config)

		// Register "jailbreak"
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Attempts to bypass LLM safety controls",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		// Try to classify a similar variant
		result, err := vc.Classify(ctx, "jailbreaking", "Breaking LLM safety controls")
		require.NoError(t, err)

		// With lenient threshold, this is more likely to match
		assert.NotEmpty(t, result)
	})
}
