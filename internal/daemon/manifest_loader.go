package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/component/resolver"
)

// manifestLoader implements the resolver.ManifestLoader interface.
// It loads component manifests from the component store.
type manifestLoader struct {
	componentStore component.ComponentStore
}

// newManifestLoader creates a new manifest loader that reads from the component store.
func newManifestLoader(store component.ComponentStore) resolver.ManifestLoader {
	return &manifestLoader{
		componentStore: store,
	}
}

// LoadManifest loads a component manifest by kind and name from the component store.
// Returns nil, nil if the component is not found (not an error).
func (m *manifestLoader) LoadManifest(ctx context.Context, kind component.ComponentKind, name string) (*component.Manifest, error) {
	// Get component from store
	comp, err := m.componentStore.GetByName(ctx, kind, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get component from store: %w", err)
	}

	// Component not found - return nil, nil (not an error per interface contract)
	if comp == nil {
		return nil, nil
	}

	// Return the manifest (may be nil if component has no manifest)
	return comp.Manifest, nil
}
