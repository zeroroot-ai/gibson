// source.go — golang-migrate source.Driver constructors over the
// embedded Tenant and Platform FSs, plus MaxVersion helpers used by
// the daemon's startup-gate (R5).

package migrations

import (
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// tenantDir is the subdirectory of the embedded FS that holds the
// per-tenant migrations. Keep in sync with the //go:embed directive.
const tenantDir = "postgres/tenant"

// platformDir is the subdirectory holding the dashboard-DB
// migrations.
const platformDir = "postgres/platform"

// NewTenantSource returns a golang-migrate source.Driver rooted at
// the embedded tenant migration set. Callers MUST call .Close() on
// the returned driver when done.
func NewTenantSource() (source.Driver, error) {
	d, err := iofs.New(Tenant, tenantDir)
	if err != nil {
		return nil, fmt.Errorf("migrations: tenant source: %w", err)
	}
	return d, nil
}

// NewPlatformSource returns a golang-migrate source.Driver rooted
// at the embedded platform migration set. Callers MUST call
// .Close() on the returned driver when done.
func NewPlatformSource() (source.Driver, error) {
	d, err := iofs.New(Platform, platformDir)
	if err != nil {
		return nil, fmt.Errorf("migrations: platform source: %w", err)
	}
	return d, nil
}

// TenantMaxVersion returns the highest migration version present in
// the embedded tenant set. Cached after first call.
func TenantMaxVersion() (uint, error) {
	return tenantMaxOnce.value()
}

// PlatformMaxVersion is the platform equivalent.
func PlatformMaxVersion() (uint, error) {
	return platformMaxOnce.value()
}

// maxVersionCache wraps sync.Once + a memoized scan result.
type maxVersionCache struct {
	once   sync.Once
	value_ uint
	err    error
	scan   func() (uint, error)
}

func (m *maxVersionCache) value() (uint, error) {
	m.once.Do(func() { m.value_, m.err = m.scan() })
	return m.value_, m.err
}

var (
	tenantMaxOnce = &maxVersionCache{scan: func() (uint, error) {
		return scanMaxVersion(Tenant, tenantDir)
	}}
	platformMaxOnce = &maxVersionCache{scan: func() (uint, error) {
		return scanMaxVersion(Platform, platformDir)
	}}
)

// scanMaxVersion walks dir within fsys, parses leading NNN_ prefix
// from each *.up.sql filename, returns the largest. Returns 0 with
// nil error when the directory contains no up files (legitimate
// state for a not-yet-populated subset).
func scanMaxVersion(fsys fs.FS, dir string) (uint, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return 0, fmt.Errorf("migrations: read %s: %w", dir, err)
	}
	var max uint
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		v, err := parseVersionPrefix(name)
		if err != nil {
			// Skip files that don't match the NNN_ pattern; they
			// might be README.md or similar metadata.
			continue
		}
		if v > max {
			max = v
		}
	}
	return max, nil
}

// parseVersionPrefix extracts the leading NNN_ uint from a
// migration filename.
func parseVersionPrefix(name string) (uint, error) {
	base := path.Base(name)
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("no leading version in %q", base)
	}
	v, err := strconv.ParseUint(base[:idx], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse version from %q: %w", base, err)
	}
	return uint(v), nil
}
