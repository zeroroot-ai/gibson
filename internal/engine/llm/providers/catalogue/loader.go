// Package catalogue provides provider-catalogue.yaml as the source of truth
// for which models each provider exposes.  The embedded YAML is used when no
// external path is configured; an operator-supplied file can be hot-reloaded
// via the Loader so catalogue updates are visible without a daemon restart.
package catalogue

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed provider-catalogue.yaml
var catalogueData []byte

// Model describes a single model entry in the catalogue.
type Model struct {
	ID            string   `yaml:"id"`
	ContextWindow int      `yaml:"context_window"`
	Capabilities  []string `yaml:"capabilities"`
	Deprecated    bool     `yaml:"deprecated"`
}

// ProviderEntry describes a provider and its static model list.
type ProviderEntry struct {
	Type           string  `yaml:"type"`
	DisplayName    string  `yaml:"display_name"`
	UpdateStrategy string  `yaml:"update_strategy"`
	Models         []Model `yaml:"models"`
}

// Catalogue is the top-level structure of provider-catalogue.yaml.
type Catalogue struct {
	Providers []ProviderEntry `yaml:"providers"`
}

// Loader holds a live, hot-reloadable provider catalogue.
//
// When path is empty the loader uses the embedded provider-catalogue.yaml
// and never polls the filesystem (Start is a no-op in that case).  When
// path points at an operator-managed file (e.g. mounted from a ConfigMap),
// Start runs a background ticker that reloads the file on every mtime change.
//
// All public methods are safe for concurrent use.
type Loader struct {
	mu        sync.RWMutex
	catalogue *Catalogue
	path      string    // empty = use embedded bytes
	mtime     time.Time // mtime of the last successfully-loaded file
}

// NewLoader creates a Loader and performs the initial catalogue load.
//
// When path is empty the embedded provider-catalogue.yaml is parsed; a
// malformed embedded YAML is treated as a startup failure and the function
// panics (identical to the previous sync.Once behaviour).
//
// When path is set, the named file is parsed instead.  A missing or
// malformed file at startup is also a hard failure (the daemon ships the
// embedded copy as a fallback only when path is empty).
func NewLoader(path string) *Loader {
	l := &Loader{path: path}
	if path == "" {
		// Embedded path: parse once, never poll.
		var c Catalogue
		if err := yaml.Unmarshal(catalogueData, &c); err != nil {
			panic("provider-catalogue.yaml (embedded) parse error: " + err.Error())
		}
		l.catalogue = &c
		return l
	}

	// External file path: load now so callers receive a valid catalogue
	// immediately and the process fails loudly on a bad file at startup.
	c, mtime, err := loadFile(path)
	if err != nil {
		panic(fmt.Sprintf("provider-catalogue.yaml (%s) load error: %v", path, err))
	}
	l.catalogue = c
	l.mtime = mtime
	return l
}

// Start launches a background goroutine that reloads the catalogue file
// whenever its mtime changes.  It is a no-op when the Loader was created
// with an empty path (embedded-only mode).
//
// The goroutine stops when ctx is cancelled.  interval is the poll cadence;
// pass 5*time.Minute for production use.
func (l *Loader) Start(ctx context.Context, interval time.Duration) {
	if l.path == "" {
		return
	}
	go l.poll(ctx, interval)
}

// ModelsFor returns the model list for the given provider type string, or nil
// if the provider is not present in the catalogue.
func (l *Loader) ModelsFor(providerType string) []Model {
	l.mu.RLock()
	c := l.catalogue
	l.mu.RUnlock()
	for _, p := range c.Providers {
		if p.Type == providerType {
			return p.Models
		}
	}
	return nil
}

// poll is the background reload loop.
func (l *Loader) poll(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.tryReload()
		}
	}
}

// tryReload stats the file and, if mtime has changed, parses and swaps in the
// new catalogue.  On any error it logs and retains the old catalogue.
func (l *Loader) tryReload() {
	info, err := os.Stat(l.path)
	if err != nil {
		slog.Error("provider catalogue stat error; retaining previous catalogue",
			"path", l.path, "err", err)
		return
	}
	newMtime := info.ModTime()

	l.mu.RLock()
	unchanged := !newMtime.After(l.mtime)
	l.mu.RUnlock()
	if unchanged {
		return
	}

	c, mtime, err := loadFile(l.path)
	if err != nil {
		slog.Error("provider catalogue reload error; retaining previous catalogue",
			"path", l.path, "err", err)
		return
	}

	// Count models per provider for the log line.
	counts := make(map[string]int, len(c.Providers))
	for _, p := range c.Providers {
		counts[p.Type] = len(p.Models)
	}

	l.mu.Lock()
	l.catalogue = c
	l.mtime = mtime
	l.mu.Unlock()

	slog.Info("provider catalogue reloaded",
		"path", l.path,
		"providers", len(c.Providers),
		"model_counts", counts)
}

// loadFile reads, stats, and parses the YAML file at path.
func loadFile(path string) (*Catalogue, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("stat: %w", err)
	}
	var c Catalogue
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse: %w", err)
	}
	return &c, info.ModTime(), nil
}

// ---------------------------------------------------------------------------
// Package-level singleton — retained so existing call-sites continue to work.
// SetLoader replaces the singleton with a hot-reload-capable *Loader; call it
// once during daemon startup (before any RPC handler runs) so all subsequent
// package-level Load()/ModelsFor() calls reflect live catalogue updates.
// ---------------------------------------------------------------------------

var (
	pkgMu       sync.RWMutex
	pkgOnce     sync.Once
	pkgInstance *Loader
)

// SetLoader replaces the package-level catalogue singleton with loader.
// It must be called before any concurrent Load() / ModelsFor() callers.
// Typical usage: call once from daemon startup after creating a *Loader with
// the operator-supplied path and starting its background goroutine.
func SetLoader(loader *Loader) {
	pkgMu.Lock()
	// Force pkgOnce to consider itself done so the lazy init in Load() /
	// ModelsFor() never overwrites our explicit loader.
	pkgOnce.Do(func() {})
	pkgInstance = loader
	pkgMu.Unlock()
}

// Load returns the current package-level catalogue.  Panics on a corrupt
// embedded YAML when the embedded loader has not yet been initialised.
//
// Deprecated: inject *Loader via NewLoader for testability and hot-reload.
func Load() *Catalogue {
	pkgMu.Lock()
	pkgOnce.Do(func() {
		pkgInstance = NewLoader("")
	})
	pkgMu.Unlock()

	pkgMu.RLock()
	l := pkgInstance
	pkgMu.RUnlock()

	l.mu.RLock()
	c := l.catalogue
	l.mu.RUnlock()
	return c
}

// ModelsFor returns the model list for the given provider type string from the
// package-level catalogue, or nil if the provider is not present.
//
// Deprecated: use (*Loader).ModelsFor for testability and hot-reload.
func ModelsFor(providerType string) []Model {
	pkgMu.Lock()
	pkgOnce.Do(func() {
		pkgInstance = NewLoader("")
	})
	pkgMu.Unlock()

	pkgMu.RLock()
	l := pkgInstance
	pkgMu.RUnlock()
	return l.ModelsFor(providerType)
}
