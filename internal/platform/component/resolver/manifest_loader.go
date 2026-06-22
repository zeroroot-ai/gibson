package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// DefaultManifestLoader implements ManifestLoader using a ComponentStore
// with an in-memory cache for improved performance.
// It provides caching to avoid repeated file system access and improves
// performance during dependency resolution.
type DefaultManifestLoader struct {
	store component.ComponentStore
	mu    sync.RWMutex
	cache map[string]*component.Manifest
}

// NewManifestLoader creates a new manifest loader backed by the given component store.
func NewManifestLoader(store component.ComponentStore) *DefaultManifestLoader {
	return &DefaultManifestLoader{
		store: store,
		cache: make(map[string]*component.Manifest),
	}
}

// cacheKey constructs a unique cache key for a component.
// Format: "kind:name"
func (l *DefaultManifestLoader) cacheKey(kind component.ComponentKind, name string) string {
	return fmt.Sprintf("%s:%s", kind, name)
}

// LoadManifest loads a component's manifest from the store or cache.
// This method is safe for concurrent use.
//
// Returns:
//   - (*Manifest, nil) if the manifest was found and loaded successfully
//   - (nil, nil) if the component or manifest was not found (graceful degradation)
//   - (nil, error) only for unexpected failures like parse errors
func (l *DefaultManifestLoader) LoadManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error) {
	key := l.cacheKey(kind, name)

	// Check cache first (read lock)
	l.mu.RLock()
	if cached, exists := l.cache[key]; exists {
		l.mu.RUnlock()
		return cached, nil
	}
	l.mu.RUnlock()

	// Not in cache, query the component store
	comp, err := l.store.GetByName(ctx, kind, name)
	if err != nil {
		// Store error - this is unexpected, return error
		return nil, fmt.Errorf("failed to query component store for %s/%s: %w", kind, name, err)
	}

	// Component not found - graceful degradation (not an error)
	if comp == nil {
		slog.Warn("component not found in store during manifest load",
			"kind", kind,
			"name", name,
		)
		return nil, nil
	}

	// Component has no RepoPath - cannot load manifest
	if comp.RepoPath == "" {
		slog.Debug("component has no repo path, cannot load manifest",
			"kind", kind,
			"name", name,
			"component", comp,
		)
		// Cache nil result to avoid repeated lookups
		l.mu.Lock()
		l.cache[key] = nil
		l.mu.Unlock()
		return nil, nil
	}

	// Load manifest from repo path
	manifestPath := filepath.Join(comp.RepoPath, "component.yaml")
	manifest, err := component.LoadManifest(manifestPath)
	if err != nil {
		// Manifest file missing or invalid - warn but don't fail
		// This is expected for components without manifests
		slog.Warn("failed to load manifest for component",
			"kind", kind,
			"name", name,
			"path", manifestPath,
			"error", err,
		)
		// Cache nil result to avoid repeated failed loads
		l.mu.Lock()
		l.cache[key] = nil
		l.mu.Unlock()
		return nil, nil
	}

	// Successfully loaded manifest - cache it
	l.mu.Lock()
	l.cache[key] = manifest
	l.mu.Unlock()

	// Log debug info (handle nil dependencies gracefully)
	depCount := 0
	if manifest.Dependencies != nil {
		depCount = len(manifest.Dependencies.GetComponents())
	}
	slog.Debug("loaded and cached manifest",
		"kind", kind,
		"name", name,
		"version", manifest.Version,
		"dependencies", depCount,
	)

	return manifest, nil
}

// ClearCache invalidates all cached manifests.
// This should be called when components are installed, updated, or uninstalled
// to ensure the cache stays in sync with the component store.
func (l *DefaultManifestLoader) ClearCache() {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create a new map instead of clearing the old one
	// This is more efficient for large caches
	l.cache = make(map[string]*component.Manifest)

	slog.Debug("manifest cache cleared")
}
