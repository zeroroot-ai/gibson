// Package identityresolver maps Zitadel-issued numeric service-account
// subjects to their readable platform-SA names (e.g. "370767967299829765"
// → "gibson-tenant-operator").
//
// Spec: canonical-service-identity Req 8.
//
// The canonical service-account identifier across the platform is the
// numeric sub. Auth decisions everywhere use that form. This helper
// provides the reverse mapping for ONE purpose only: making log lines and
// audit trails human-readable.
//
// INVARIANT: callers MUST NOT use Resolve in a code path that reaches an
// allow/deny decision. A `gibsoncheck` static analyzer (when added under
// canonical-service-identity Task 12) flags any call from a function whose
// name matches /(?i)^(check|authorize|authz|verify|allow|deny|permission|ensure)/.
//
// Source-of-truth: gibson-sa-identity-map ConfigMap, mounted into the
// daemon Pod by the chart at the path returned by DefaultPath().
//
// Mount layout: kubelet projects each ConfigMap key as a file under the
// mount path. The resolver reads the directory and treats filenames as
// readable SA names (e.g. "gibson-tenant-operator") and file contents as
// the numeric sub. A `.json` file at the path is also accepted (single
// JSON object with the same {readable: numeric} shape) for compatibility
// with the dashboard's init-container-produced /shared/sa-identity-map.json.
package identityresolver

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultPath is the on-disk location of the projected identity map.
// Override via GIBSON_SA_IDENTITY_MAP_PATH env var. Either a directory of
// per-key files (kubelet ConfigMap projection) or a JSON file is accepted.
const DefaultPath = "/etc/gibson/sa-identity-map"

// DefaultRefreshInterval is how often the background refresher polls the
// file mtime. Reads on every Resolve also check mtime, so this interval
// only matters for callers that hold a long-lived Resolver and never call
// Resolve.
const DefaultRefreshInterval = 60 * time.Second

// Resolver holds the in-memory map and watches the source file for
// updates. Safe for concurrent use.
type Resolver struct {
	path string

	mu       sync.RWMutex
	cache    map[string]string
	cacheMTS int64 // mtime in nanoseconds since epoch
}

// New constructs a Resolver that reads from path. If path is empty,
// DefaultPath (or the GIBSON_SA_IDENTITY_MAP_PATH env override) is used.
// The returned Resolver lazily loads on first Resolve and re-reads on
// every subsequent call when the file mtime has advanced.
func New(path string) *Resolver {
	if path == "" {
		if env := os.Getenv("GIBSON_SA_IDENTITY_MAP_PATH"); env != "" {
			path = env
		} else {
			path = DefaultPath
		}
	}
	return &Resolver{path: path, cache: map[string]string{}}
}

// Resolve maps numericSub to its readable platform-SA name.
//
// Returns ("", false) for an empty input, an unknown sub (e.g. a human
// user, who isn't in the SA map), or when the underlying file is
// unreadable. Callers handle the false case by logging the bare numeric
// sub.
func (r *Resolver) Resolve(numericSub string) (string, bool) {
	if numericSub == "" {
		return "", false
	}
	r.loadIfChanged()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for readable, num := range r.cache {
		if num == numericSub {
			return readable, true
		}
	}
	return "", false
}

// loadIfChanged stats the source path and re-reads it if the mtime has
// advanced since the last load. Errors silently keep the last-known-good
// cache (callers fail open with an unknown-sub answer).
func (r *Resolver) loadIfChanged() {
	st, err := os.Stat(r.path)
	if err != nil {
		return
	}
	mts := st.ModTime().UnixNano()

	r.mu.RLock()
	if mts == r.cacheMTS {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()

	var m map[string]string
	if st.IsDir() {
		m, err = readDirMap(r.path)
	} else {
		m, err = readJSONMap(r.path)
	}
	if err != nil {
		return
	}

	r.mu.Lock()
	r.cache = m
	r.cacheMTS = mts
	r.mu.Unlock()
}

// readDirMap reads kubelet's ConfigMap projection — one file per key.
// Filenames starting with "." are skipped (kubelet writes ..data and
// ..<timestamp> directories there for atomic updates).
func readDirMap(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		v := strings.TrimRight(string(data), "\n\r ")
		if v == "" || v == "<unset>" {
			continue
		}
		m[name] = v
	}
	return m, nil
}

// readJSONMap reads a {readable: numeric} object from a JSON file —
// matches the dashboard's /shared/sa-identity-map.json format.
func readJSONMap(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// errMissing is exported only for test use.
var errMissing = errors.New("identityresolver: source file missing")
