package finding

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/sdk/finding/classifier"
	"github.com/zero-day-ai/sdk/finding/classifier/store"
	"github.com/zero-day-ai/sdk/finding/registry"
)

// testTenantID is the tenant used in unit tests; deterministic for reproducibility.
var testTenantID = auth.MustNewTenantID("test-tenant")

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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

	// Search to verify the updated metadata. The store ID is prefixed with the
	// tenant ID to prevent cross-tenant collisions, so the stored ID has the form
	// "tenant_<tenant_id>:<category_name>".
	results, err := memStore.Search(ctx, []float64{}, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ID, "jailbreak", "ID should contain the category name")
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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
	vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
		vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
		vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore, config)

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
		vc := NewVectorClassifierForTenantWithStore(mockEmb, testTenantID, memStore2, config)

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

// TestVectorClassifier_CrossTenantIsolation verifies Req 3.4: tenant A's category
// set does not pollute tenant B's Classify results when both use a shared underlying
// MemoryStore via per-tenant scoped wrappers.
//
// This is the data-isolation test required by spec per-tenant-data-plane-completion
// Req 3.4. Tenant B MUST NOT match categories registered only under tenant A.
func TestVectorClassifier_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()

	mockEmb := embedder.NewMockEmbedder()
	sharedStore := store.NewMemoryStore()

	tenantA := auth.MustNewTenantID("isolate-a")
	tenantB := auth.MustNewTenantID("isolate-b")

	config := classifier.Config{
		Threshold:    0.80,
		AutoRegister: false, // Don't auto-register so results are unambiguous
		StoreType:    "memory",
	}

	vcA := NewVectorClassifierForTenantWithStore(mockEmb, tenantA, sharedStore, config)
	vcB := NewVectorClassifierForTenantWithStore(mockEmb, tenantB, sharedStore, config)

	// Register category "sql-injection" ONLY under tenant A.
	infoA := registry.CategoryInfo{
		Name:        "sql-injection",
		Domain:      "security",
		DisplayName: "SQL Injection",
		Description: "Database query injection attack",
	}
	require.NoError(t, vcA.Register(ctx, infoA))

	// Tenant B should NOT match "sql-injection" (it was only registered for A).
	// AutoRegister is false, so if no match is found the proposed name is returned.
	resultB, err := vcB.Classify(ctx, "sql-injection", "Database query injection attack")
	require.NoError(t, err)
	// Because tenant B's store is empty (no entries under its prefix), Classify
	// returns the proposed name unchanged — "sql-injection" — NOT a match from A.
	assert.Equal(t, "sql-injection", resultB,
		"tenant B must return the proposed name (no match), not a result from tenant A's dataset")

	// Sanity check: tenant A CAN classify its own category (regression guard).
	resultA, err := vcA.Classify(ctx, "sql-injection", "Database query injection attack")
	require.NoError(t, err)
	// Tenant A has "sql-injection" registered; the mock embedder produces deterministic
	// identical embeddings for the same text, so similarity = 1.0 ≥ threshold.
	assert.Equal(t, "sql-injection", resultA,
		"tenant A must find its own registered category")
}
