// Package reservednames reads the chart-mounted gibson-reserved-names
// denylist files and exposes the (exact, prefix) lists used by:
//
//   - the dashboard signup form (via PlatformOperatorService.GetReservedNames)
//   - the K8s admission webhook (via the operator's own reader)
//
// Per ADR-0023, the daemon does not consume the Kubernetes API at runtime.
// The chart projects the `gibson-reserved-names` ConfigMap as a volume at
// /etc/gibson/reserved-names/; the provider reads the files on disk and
// watches them with fsnotify so kubelet's in-place projection updates
// (symlink swap) reload the denylist without a daemon restart.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 4.5 +
// ADR-0023 (gibson daemon does not consume the Kubernetes API).
package reservednames

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// DefaultMountDir is the chart's projected ConfigMap mount path.
const DefaultMountDir = "/etc/gibson/reserved-names"

// File names inside the mount directory. The chart writes one file per
// ConfigMap data key.
const (
	fileExact  = "exact"
	filePrefix = "prefix"
)

// Provider holds the in-memory snapshot of the denylist files and a
// background fsnotify watcher that reloads on disk-change events.
//
// Construction does an initial synchronous read so callers see populated
// data immediately. Subsequent reads from ReservedNames are lock-free in
// the steady state; updates from the watcher swap the snapshot under a
// brief lock.
//
// Safe for concurrent use.
type Provider struct {
	dir    string
	logger *slog.Logger

	mu     sync.RWMutex
	exact  []string
	prefix []string

	watcher  *fsnotify.Watcher
	stopOnce sync.Once
	stopCh   chan struct{}
}

// New constructs a Provider that reads <dir>/exact and <dir>/prefix.
// logger may be nil (uses slog.Default()). The returned Provider has
// performed its initial read; callers can call ReservedNames immediately.
//
// Missing files are tolerated (treated as empty denylist). A malformed
// file is logged at WARN and the previous good state is retained — this
// mirrors the K8s ConfigMap path's tolerance for partially-written data.
func New(dir string, logger *slog.Logger) (*Provider, error) {
	if dir == "" {
		dir = DefaultMountDir
	}
	if logger == nil {
		logger = slog.Default()
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("reservednames: fsnotify watcher: %w", err)
	}

	p := &Provider{
		dir:     dir,
		logger:  logger,
		watcher: w,
		stopCh:  make(chan struct{}),
	}

	// Initial synchronous read so callers see populated data immediately.
	// Errors are surfaced via the logger but do not block construction —
	// the daemon must boot even when the chart hasn't projected the
	// ConfigMap yet.
	p.reload()

	// Watch the directory (not the individual files) so kubelet's
	// symlink-swap projection updates fire INotify events the watcher
	// can pick up. Watching the files directly misses the events because
	// kubelet replaces the entire `..data/` symlink target on update.
	if err := w.Add(dir); err != nil {
		// Watch failure is non-fatal: the initial snapshot still works,
		// it just won't auto-reload. Log loud and continue.
		p.logger.Warn("reservednames: failed to add directory to watcher; auto-reload disabled",
			"dir", dir, "error", err)
	}

	go p.watchLoop()
	return p, nil
}

// ReservedNames returns the cached (exact, prefix) lists. Reads are
// lock-free in the steady state; the only contention is when the
// fsnotify watcher swaps the snapshot.
//
// The ctx parameter is preserved for interface compatibility with the
// previous K8s-backed Provider — the file-mount path has no I/O so ctx
// is unused.
func (p *Provider) ReservedNames(_ context.Context) (exact, prefix []string, err error) {
	if p == nil {
		return nil, nil, errors.New("reservednames: nil Provider")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Return defensive copies so callers cannot mutate the cached state.
	return cloneSlice(p.exact), cloneSlice(p.prefix), nil
}

// Close stops the background watcher. Safe to call multiple times.
func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	if p.watcher != nil {
		return p.watcher.Close()
	}
	return nil
}

// reload reads both files and atomically swaps the in-memory snapshot.
// On a per-file read error, the previous good slice for that file is
// retained (and a WARN is logged). Missing files are treated as empty.
func (p *Provider) reload() {
	newExact, exactErr := readListFile(filepath.Join(p.dir, fileExact))
	newPrefix, prefixErr := readListFile(filepath.Join(p.dir, filePrefix))

	p.mu.Lock()
	defer p.mu.Unlock()

	if exactErr == nil {
		p.exact = newExact
	} else if !errors.Is(exactErr, os.ErrNotExist) {
		p.logger.Warn("reservednames: failed to read exact denylist; retaining previous snapshot",
			"file", filepath.Join(p.dir, fileExact), "error", exactErr)
	} else {
		// Missing file → empty list. Matches the K8s NotFound semantics.
		p.exact = nil
	}

	if prefixErr == nil {
		p.prefix = newPrefix
	} else if !errors.Is(prefixErr, os.ErrNotExist) {
		p.logger.Warn("reservednames: failed to read prefix denylist; retaining previous snapshot",
			"file", filepath.Join(p.dir, filePrefix), "error", prefixErr)
	} else {
		p.prefix = nil
	}
}

// watchLoop pumps fsnotify events. Any event on either denylist file
// triggers a full reload. We deliberately do NOT filter by event type —
// kubelet's ConfigMap projection involves Create/Remove/Rename events on
// the `..data` symlink, and the safest reaction to "something happened"
// is to re-read both files.
func (p *Provider) watchLoop() {
	if p.watcher == nil {
		return
	}
	for {
		select {
		case <-p.stopCh:
			return
		case event, ok := <-p.watcher.Events:
			if !ok {
				return
			}
			// React to events touching the projected files. kubelet's
			// ConfigMap projection lands as a symlink swap on `..data`,
			// which manifests as Create/Remove/Rename events in the
			// parent directory; the per-file paths through the symlink
			// then resolve to the new content.
			base := filepath.Base(event.Name)
			if base == fileExact || base == filePrefix || strings.HasPrefix(base, "..") {
				p.reload()
			}
		case err, ok := <-p.watcher.Errors:
			if !ok {
				return
			}
			p.logger.Warn("reservednames: fsnotify error", "error", err)
		}
	}
}

// readListFile reads a newline-separated denylist file, ignoring blank
// lines and comment lines that start with '#'. Returns nil for an empty
// file. Returns os.ErrNotExist (wrapped) when the file does not exist.
func readListFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseList(string(raw)), nil
}

// parseList trims whitespace and skips blank or comment ('#') lines.
func parseList(raw string) []string {
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cloneSlice returns a copy of s. Callers of ReservedNames must not be
// able to mutate the cached snapshot.
func cloneSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
