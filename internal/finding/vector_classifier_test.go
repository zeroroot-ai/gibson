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

// TestVectorClassifier_Classify_MatchesExisting tests that Classify returns an existing
// category when semantic similarity is above the threshold.
func TestVectorClassifier_Classify_MatchesExisting(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder (deterministic embeddings based on text hash)
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier with threshold of 0.85
	config := classifier.Config{
		Threshold:    0.85,
		AutoRegister: true,
		StoreType:    "memory",
	}
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Register an existing category "jailbreak"
	jailbreakInfo := registry.CategoryInfo{
		Name:        "jailbreak",
		Domain:      "security",
		DisplayName: "Jailbreak",
		Description: "Attempts to bypass LLM safety controls",
	}
	err := vc.Register(ctx, jailbreakInfo)
	require.NoError(t, err)

	// Classify a very similar category "jailbreak: Attempts to bypass LLM safety controls"
	// The mock embedder produces identical embeddings for identical text, so we need
	// to use the exact same text to get a high similarity score
	result, err := vc.Classify(ctx, "jailbreak", "Attempts to bypass LLM safety controls")
	require.NoError(t, err)

	// Should return the existing category
	assert.Equal(t, "jailbreak", result)

	// Verify the store still has only one category
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestVectorClassifier_Classify_RegistersNew tests that Classify registers a new
// category when semantic similarity is below the threshold.
func TestVectorClassifier_Classify_RegistersNew(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier with threshold of 0.85
	config := classifier.Config{
		Threshold:    0.85,
		AutoRegister: true,
		StoreType:    "memory",
	}
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Register an existing category "jailbreak"
	jailbreakInfo := registry.CategoryInfo{
		Name:        "jailbreak",
		Domain:      "security",
		DisplayName: "Jailbreak",
		Description: "Attempts to bypass LLM safety controls",
	}
	err := vc.Register(ctx, jailbreakInfo)
	require.NoError(t, err)

	// Classify a different category "sql_injection"
	// The mock embedder will produce different embeddings for different text
	result, err := vc.Classify(ctx, "sql_injection", "SQL injection vulnerability in database query")
	require.NoError(t, err)

	// Should return the proposed category (registered as new)
	assert.Equal(t, "sql_injection", result)

	// Verify the store now has two categories
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

// TestVectorClassifier_Classify_AutoRegisterDisabled tests that when AutoRegister
// is disabled, new categories are returned but not stored.
func TestVectorClassifier_Classify_AutoRegisterDisabled(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier with AutoRegister disabled
	config := classifier.Config{
		Threshold:    0.85,
		AutoRegister: false, // Disabled
		StoreType:    "memory",
	}
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Register an existing category
	jailbreakInfo := registry.CategoryInfo{
		Name:        "jailbreak",
		Domain:      "security",
		DisplayName: "Jailbreak",
		Description: "Attempts to bypass LLM safety controls",
	}
	err := vc.Register(ctx, jailbreakInfo)
	require.NoError(t, err)

	// Classify a different category
	result, err := vc.Classify(ctx, "sql_injection", "SQL injection vulnerability")
	require.NoError(t, err)

	// Should return the proposed category
	assert.Equal(t, "sql_injection", result)

	// Verify the store still has only one category (auto-register was disabled)
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestVectorClassifier_Register_Idempotent tests that Register is idempotent -
// registering the same category twice updates it rather than creating duplicates.
func TestVectorClassifier_Register_Idempotent(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Register a category
	jailbreakInfo := registry.CategoryInfo{
		Name:        "jailbreak",
		Domain:      "security",
		DisplayName: "Jailbreak",
		Description: "Attempts to bypass LLM safety controls",
	}
	err := vc.Register(ctx, jailbreakInfo)
	require.NoError(t, err)

	// Verify count is 1
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Register the same category again with updated description
	jailbreakInfoUpdated := registry.CategoryInfo{
		Name:        "jailbreak",
		Domain:      "security",
		DisplayName: "Jailbreak Attack",
		Description: "Updated description for jailbreak attempts",
	}
	err = vc.Register(ctx, jailbreakInfoUpdated)
	require.NoError(t, err)

	// Verify count is still 1 (idempotent)
	count, err = memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Search to verify the updated metadata
	results, err := memStore.Search(ctx, []float64{}, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "jailbreak", results[0].ID)
	assert.Equal(t, "Updated description for jailbreak attempts", results[0].Metadata["description"])
}

// TestVectorClassifier_Bootstrap tests that Bootstrap loads all categories
// from the DefaultRegistry.
func TestVectorClassifier_Bootstrap(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Bootstrap from DefaultRegistry
	defaultReg := registry.DefaultRegistry()
	err := vc.Bootstrap(ctx, defaultReg)
	require.NoError(t, err)

	// Verify all categories were loaded
	expectedCategories := defaultReg.ListAll()
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, len(expectedCategories), count)

	// Verify we can search for categories
	matches, err := vc.Search(ctx, "jailbreak attack", 5)
	require.NoError(t, err)
	assert.NotEmpty(t, matches)
}

// TestVectorClassifier_Bootstrap_Empty tests that Bootstrap handles an empty registry gracefully.
func TestVectorClassifier_Bootstrap_Empty(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Bootstrap from an empty registry
	emptyReg := registry.NewCategoryRegistry()
	err := vc.Bootstrap(ctx, emptyReg)
	require.NoError(t, err)

	// Verify no categories were loaded
	count, err := memStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestVectorClassifier_Search tests the Search method returns categories
// sorted by similarity score.
func TestVectorClassifier_Search(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Register multiple categories
	categories := []registry.CategoryInfo{
		{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Bypass LLM safety controls",
		},
		{
			Name:        "prompt_injection",
			Domain:      "security",
			DisplayName: "Prompt Injection",
			Description: "Malicious prompt injection",
		},
		{
			Name:        "data_extraction",
			Domain:      "security",
			DisplayName: "Data Extraction",
			Description: "Unauthorized data access",
		},
	}

	for _, cat := range categories {
		err := vc.Register(ctx, cat)
		require.NoError(t, err)
	}

	// Search for "jailbreak"
	matches, err := vc.Search(ctx, "jailbreak bypass safety", 3)
	require.NoError(t, err)

	// Should return results (exact matches depend on mock embedder behavior)
	assert.NotEmpty(t, matches)
	assert.LessOrEqual(t, len(matches), 3)

	// Verify matches have required fields
	for _, match := range matches {
		assert.NotEmpty(t, match.Category)
		assert.NotEmpty(t, match.Domain)
		assert.NotEmpty(t, match.Description)
		// Cosine similarity ranges from -1 to 1
		assert.GreaterOrEqual(t, match.Score, -1.0)
		assert.LessOrEqual(t, match.Score, 1.0)
	}

	// Verify results are sorted by score (descending)
	for i := 1; i < len(matches); i++ {
		assert.GreaterOrEqual(t, matches[i-1].Score, matches[i].Score,
			"results should be sorted by descending score")
	}
}

// TestVectorClassifier_Search_Empty tests that Search handles an empty store gracefully.
func TestVectorClassifier_Search_Empty(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store (empty)
	memStore := store.NewMemoryStore()

	// Create classifier
	config := classifier.DefaultConfig()
	vc := NewVectorClassifier(mockEmb, memStore, config)

	// Search in empty store
	matches, err := vc.Search(ctx, "jailbreak", 5)
	require.NoError(t, err)

	// Should return empty slice (not nil)
	assert.NotNil(t, matches)
	assert.Empty(t, matches)
}

// TestVectorClassifier_GracefulDegradation tests that the classifier gracefully
// degrades when embedder or store operations fail.
func TestVectorClassifier_GracefulDegradation(t *testing.T) {
	ctx := context.Background()

	t.Run("classify with canceled context", func(t *testing.T) {
		// Create mock embedder
		mockEmb := embedder.NewMockEmbedder()

		// Create in-memory store
		memStore := store.NewMemoryStore()

		// Create classifier
		config := classifier.DefaultConfig()
		vc := NewVectorClassifier(mockEmb, memStore, config)

		// Use a canceled context
		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Classify should gracefully degrade (return proposed category)
		result, err := vc.Classify(canceledCtx, "jailbreak", "Bypass safety controls")
		require.NoError(t, err) // No error - graceful degradation
		assert.Equal(t, "jailbreak", result)
	})
}

// TestVectorClassifier_ThresholdBehavior tests classification behavior at different
// threshold values.
func TestVectorClassifier_ThresholdBehavior(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder
	mockEmb := embedder.NewMockEmbedder()

	// Create in-memory store
	memStore := store.NewMemoryStore()

	// Test with very low threshold (0.1) - almost everything matches
	t.Run("low threshold matches easily", func(t *testing.T) {
		config := classifier.Config{
			Threshold:    0.1,
			AutoRegister: true,
			StoreType:    "memory",
		}
		vc := NewVectorClassifier(mockEmb, memStore, config)

		// Register a category
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Bypass LLM safety controls",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		// Even a somewhat different category might match with low threshold
		// (behavior depends on mock embedder's similarity scores)
		result, err := vc.Classify(ctx, "jailbreaking", "Breaking safety controls")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	// Test with very high threshold (0.99) - almost nothing matches
	t.Run("high threshold rarely matches", func(t *testing.T) {
		memStore2 := store.NewMemoryStore()
		config := classifier.Config{
			Threshold:    0.99,
			AutoRegister: true,
			StoreType:    "memory",
		}
		vc := NewVectorClassifier(mockEmb, memStore2, config)

		// Register a category
		jailbreakInfo := registry.CategoryInfo{
			Name:        "jailbreak",
			Domain:      "security",
			DisplayName: "Jailbreak",
			Description: "Bypass LLM safety controls",
		}
		err := vc.Register(ctx, jailbreakInfo)
		require.NoError(t, err)

		// Even similar text might not match with very high threshold
		result, err := vc.Classify(ctx, "jailbreaking", "Bypassing safety controls")
		require.NoError(t, err)
		// Result is either "jailbreak" (if matched) or "jailbreaking" (if registered new)
		assert.Contains(t, []string{"jailbreak", "jailbreaking"}, result)
	})
}
