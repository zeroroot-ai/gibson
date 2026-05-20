package finding

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/sdk/finding/classifier"
	classifierstore "github.com/zero-day-ai/sdk/finding/classifier/store"
	"github.com/zero-day-ai/sdk/finding/registry"
)

// VectorClassifier implements the SDK CategoryClassifier interface using vector embeddings
// for semantic category matching. It uses the daemon's NativeEmbedder (all-MiniLM-L6-v2)
// for generating embeddings and a VectorStore for similarity search.
//
// The classifier embeds category names and descriptions as "category: description" strings,
// searches for similar existing categories, and either returns a match (if similarity >= threshold)
// or registers the proposed category as new (if similarity < threshold).
//
// Thread-safety: All methods are safe for concurrent use.
type VectorClassifier struct {
	embedder embedder.Embedder
	store    classifier.VectorStore
	config   classifier.Config
}

// classifierSanitizeRE matches characters safe in a key prefix.
var classifierSanitizeRE = regexp.MustCompile(`[^a-z0-9_]`)

// sanitizeClassifierTenantID converts a tenant ID to a safe prefix component.
func sanitizeClassifierTenantID(id string) string {
	replaced := strings.ReplaceAll(id, "-", "_")
	return classifierSanitizeRE.ReplaceAllString(replaced, "")
}

// tenantClassifierStore wraps a classifier.VectorStore with per-tenant key
// prefixing. All category IDs are namespaced as "tenant_<sanitized>:<id>" so
// that tenant A's categories never collide with tenant B's in a shared store.
//
// This implements the per-tenant isolation requirement for the finding
// classifier without spinning up per-tenant store instances (D4).
// Spec: per-tenant-data-plane-completion Req 3.2, 3.4.
type tenantClassifierStore struct {
	prefix     string
	underlying classifier.VectorStore
}

func (t *tenantClassifierStore) prefixID(id string) string   { return t.prefix + id }
func (t *tenantClassifierStore) unprefixID(id string) string { return strings.TrimPrefix(id, t.prefix) }

func (t *tenantClassifierStore) Upsert(ctx context.Context, id string, embedding []float64, metadata map[string]any) error {
	return t.underlying.Upsert(ctx, t.prefixID(id), embedding, metadata)
}

func (t *tenantClassifierStore) Search(ctx context.Context, embedding []float64, topK int) ([]classifier.SearchResult, error) {
	// Request extra results to account for cross-tenant filtering.
	results, err := t.underlying.Search(ctx, embedding, topK*2)
	if err != nil {
		return nil, err
	}
	// Filter to only this tenant's results (IDs that start with our prefix),
	// then strip the prefix so callers see original category names.
	own := results[:0]
	for _, r := range results {
		if strings.HasPrefix(r.ID, t.prefix) {
			r.ID = t.unprefixID(r.ID)
			own = append(own, r)
		}
	}
	// Trim to the requested topK.
	if len(own) > topK {
		own = own[:topK]
	}
	return own, nil
}

func (t *tenantClassifierStore) Delete(ctx context.Context, id string) error {
	return t.underlying.Delete(ctx, t.prefixID(id))
}

func (t *tenantClassifierStore) Count(ctx context.Context) (int, error) {
	// NOTE: Count returns the total count of ALL keys in the underlying store,
	// not just this tenant's keys. This is a known limitation of the shared-store
	// D4 design with the MemoryStore backend; it is acceptable for the current
	// use case (classifier warm-up checks) where a higher-than-actual count is
	// safe (never causes incorrect classification decisions).
	return t.underlying.Count(ctx)
}

// NewVectorClassifierForTenant creates a VectorClassifier scoped to the given
// tenant. All category embeddings stored by this classifier are namespaced under
// "tenant_<sanitized>:" so they cannot collide with another tenant's categories.
//
// An in-memory (shared) MemoryStore is created per call. For production paths
// that need a process-wide shared store, pass a pre-constructed store via the
// internal constructor or use NewVectorClassifierForTenantWithStore (if added).
//
// The old NewVectorClassifier (without tenantID) has been removed. Every caller
// MUST pass a tenant ID — this is enforced at compile time.
// Spec: per-tenant-data-plane-completion Req 3.2, 3.4.
func NewVectorClassifierForTenant(emb embedder.Embedder, tenantID auth.TenantID, cfg classifier.Config) *VectorClassifier {
	sanitized := sanitizeClassifierTenantID(tenantID.String())
	prefix := "tenant_" + sanitized + ":"
	underlying := classifierstore.NewMemoryStore()
	scopedStore := &tenantClassifierStore{
		prefix:     prefix,
		underlying: underlying,
	}
	return &VectorClassifier{
		embedder: emb,
		store:    scopedStore,
		config:   cfg,
	}
}

// NewVectorClassifierForTenantWithStore creates a VectorClassifier scoped to
// the given tenant, wrapping an existing classifier.VectorStore. Use this
// when sharing a store across multiple classifiers in the same process.
func NewVectorClassifierForTenantWithStore(emb embedder.Embedder, tenantID auth.TenantID, store classifier.VectorStore, cfg classifier.Config) *VectorClassifier {
	sanitized := sanitizeClassifierTenantID(tenantID.String())
	prefix := "tenant_" + sanitized + ":"
	scopedStore := &tenantClassifierStore{
		prefix:     prefix,
		underlying: store,
	}
	return &VectorClassifier{
		embedder: emb,
		store:    scopedStore,
		config:   cfg,
	}
}

// Classify normalizes a category via semantic matching.
//
// It embeds the proposed category and description as "category: description",
// searches for similar existing categories in the vector store, and either:
//   - Returns the most similar category if similarity >= threshold
//   - Registers and returns the proposed category if similarity < threshold (and AutoRegister is true)
//   - Returns the proposed category without registration if AutoRegister is false
//
// Graceful degradation: If embedding or search fails, logs a warning and returns
// the proposed category unchanged.
//
// Parameters:
//   - ctx: Context for cancellation and tracing
//   - proposed: The proposed category name (e.g., "jailbreaking")
//   - description: Additional context about the category
//
// Returns the normalized category name and an error only if the operation fails critically.
func (v *VectorClassifier) Classify(ctx context.Context, proposed, description string) (string, error) {
	// Build the text to embed: "category: description"
	text := fmt.Sprintf("%s: %s", proposed, description)

	// Embed the text
	embedding, err := v.embedder.Embed(ctx, text)
	if err != nil {
		// Graceful degradation: log warning and return proposed category
		slog.WarnContext(ctx, "failed to embed category for classification",
			"category", proposed,
			"error", err)
		return proposed, nil
	}

	// Search for similar categories
	results, err := v.store.Search(ctx, embedding, 1)
	if err != nil {
		// Graceful degradation: log warning and return proposed category
		slog.WarnContext(ctx, "failed to search vector store for similar categories",
			"category", proposed,
			"error", err)
		return proposed, nil
	}

	// Check if we found a similar category above the threshold
	if len(results) > 0 && results[0].Score >= v.config.Threshold {
		// Match found - return the existing category
		existingCategory := results[0].ID
		slog.InfoContext(ctx, "matched category to existing via semantic similarity",
			"proposed", proposed,
			"matched", existingCategory,
			"score", results[0].Score)
		return existingCategory, nil
	}

	// No match found - register new category if auto-register is enabled
	if v.config.AutoRegister {
		categoryInfo := registry.CategoryInfo{
			Name:        proposed,
			Domain:      "unknown", // Domain not provided in Classify - could be enhanced
			DisplayName: proposed,
			Description: description,
		}

		if err := v.Register(ctx, categoryInfo); err != nil {
			// Graceful degradation: log warning and return proposed category
			slog.WarnContext(ctx, "failed to register new category",
				"category", proposed,
				"error", err)
			return proposed, nil
		}

		slog.InfoContext(ctx, "registered new category",
			"category", proposed,
			"description", description)
	}

	return proposed, nil
}

// Register explicitly adds a category to the classifier's index.
//
// This method embeds the category information as "name: description" and stores
// it in the vector store for future matching. Registration is idempotent - if
// the category already exists in the store, it is updated.
//
// Parameters:
//   - ctx: Context for cancellation and tracing
//   - info: Category metadata including name, domain, and description
//
// Returns an error if embedding or storage fails.
func (v *VectorClassifier) Register(ctx context.Context, info registry.CategoryInfo) error {
	// Build the text to embed: "category: description"
	text := fmt.Sprintf("%s: %s", info.Name, info.Description)

	// Embed the category
	embedding, err := v.embedder.Embed(ctx, text)
	if err != nil {
		return fmt.Errorf("failed to embed category %q: %w", info.Name, err)
	}

	// Store metadata
	metadata := map[string]any{
		"domain":       info.Domain,
		"description":  info.Description,
		"display_name": info.DisplayName,
	}

	// Upsert into vector store (idempotent)
	if err := v.store.Upsert(ctx, info.Name, embedding, metadata); err != nil {
		return fmt.Errorf("failed to store category %q in vector store: %w", info.Name, err)
	}

	return nil
}

// Search finds similar categories using semantic similarity.
//
// It embeds the query text and returns the top-K most similar categories
// from the vector store, sorted by descending similarity score.
//
// Parameters:
//   - ctx: Context for cancellation and tracing
//   - query: The search query text
//   - topK: Maximum number of results to return
//
// Returns a slice of CategoryMatch results sorted by score (highest first)
// and an error if search fails. Returns an empty slice if no matches found.
func (v *VectorClassifier) Search(ctx context.Context, query string, topK int) ([]classifier.CategoryMatch, error) {
	// Embed the query
	embedding, err := v.embedder.Embed(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to embed search query: %w", err)
	}

	// Search the vector store
	results, err := v.store.Search(ctx, embedding, topK)
	if err != nil {
		return nil, fmt.Errorf("failed to search vector store: %w", err)
	}

	// Convert SearchResult to CategoryMatch
	matches := make([]classifier.CategoryMatch, len(results))
	for i, result := range results {
		matches[i] = classifier.CategoryMatch{
			Category:    result.ID,
			Domain:      getStringFromMetadata(result.Metadata, "domain"),
			Description: getStringFromMetadata(result.Metadata, "description"),
			Score:       result.Score,
		}
	}

	return matches, nil
}

// Bootstrap loads categories from a registry into the classifier's index.
//
// This method efficiently embeds and stores all categories from the provided
// registry using batch embedding. Categories already in the store are updated
// (idempotent operation).
//
// Parameters:
//   - ctx: Context for cancellation and tracing
//   - reg: CategoryRegistry containing categories to index
//
// Returns an error if bootstrap fails. If individual categories fail to embed
// or store, the error includes details about which categories failed.
func (v *VectorClassifier) Bootstrap(ctx context.Context, reg *registry.CategoryRegistry) error {
	// Get all categories from the registry
	categories := reg.ListAll()
	if len(categories) == 0 {
		slog.InfoContext(ctx, "no categories to bootstrap")
		return nil
	}

	// Build texts for batch embedding
	texts := make([]string, len(categories))
	for i, cat := range categories {
		texts[i] = fmt.Sprintf("%s: %s", cat.Name, cat.Description)
	}

	// Batch embed all categories
	embeddings, err := v.embedder.EmbedBatch(ctx, texts)
	if err != nil {
		return fmt.Errorf("failed to batch embed categories: %w", err)
	}

	// Store all embeddings
	var failedCategories []string
	for i, cat := range categories {
		metadata := map[string]any{
			"domain":       cat.Domain,
			"description":  cat.Description,
			"display_name": cat.DisplayName,
		}

		if err := v.store.Upsert(ctx, cat.Name, embeddings[i], metadata); err != nil {
			slog.WarnContext(ctx, "failed to store category during bootstrap",
				"category", cat.Name,
				"error", err)
			failedCategories = append(failedCategories, cat.Name)
		}
	}

	if len(failedCategories) > 0 {
		return fmt.Errorf("failed to bootstrap %d categories: %v", len(failedCategories), failedCategories)
	}

	slog.InfoContext(ctx, "successfully bootstrapped categories",
		"count", len(categories))

	return nil
}

// getStringFromMetadata safely extracts a string value from metadata map.
// Returns empty string if key doesn't exist or value is not a string.
func getStringFromMetadata(metadata map[string]any, key string) string {
	if val, ok := metadata[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
