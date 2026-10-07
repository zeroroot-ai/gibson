// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// source.go — golang-migrate source.Driver constructors over the
// embedded Tenant and Platform FSs, plus MaxVersion helpers used by
// the daemon's startup-gate (R5).

package migrations

import (
	"errors"
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

// scanMaxVersion returns the largest version of the *.up.sql files in dir
// within fsys, after CheckVersions accepts the set. It returns 0 with a nil
// error when the directory holds no up files (legitimate for a
// not-yet-populated subset).
func scanMaxVersion(fsys fs.FS, dir string) (uint, error) {
	if err := CheckVersions(fsys, dir); err != nil {
		return 0, err
	}
	versions, err := upVersions(fsys, dir)
	if err != nil {
		return 0, err
	}
	return highestVersion(versions), nil
}

// highestVersion returns the highest version of the set, or 0 for an empty set.
func highestVersion(versions map[uint][]string) uint {
	var highest uint
	for v := range versions {
		highest = max(highest, v)
	}
	return highest
}

// ErrDuplicateVersion reports two up migrations with one version number.
var ErrDuplicateVersion = errors.New("migrations: two up migrations have the same version")

// ErrVersionGap reports a version number between 1 and the highest version
// that no up migration has.
var ErrVersionGap = errors.New("migrations: the version sequence has a gap")

// CheckVersions refuses a set of migrations that golang-migrate would not
// apply as written. golang-migrate records one integer version and only
// moves forward, so:
//
//   - two up files with one version: one of them never runs, or the source
//     refuses to open, depending on the order of the files;
//   - a gap: a migration that later fills it is never applied on a database
//     that is already past it.
//
// Each error names the files and says what to do. Files whose name does not
// start with a version (README.md and the like) are ignored.
func CheckVersions(fsys fs.FS, dir string) error {
	versions, err := upVersions(fsys, dir)
	if err != nil {
		return err
	}
	highest := highestVersion(versions)
	var errs []error
	for v := uint(1); v <= highest; v++ {
		names := versions[v]
		switch {
		case len(names) == 0:
			errs = append(errs, fmt.Errorf("%w: %s has no up migration %03d; number the migrations 1 to %d with no hole",
				ErrVersionGap, dir, v, highest))
		case len(names) > 1:
			errs = append(errs, fmt.Errorf("%w: %s and %s in %s both have version %03d; give the newer one the next free number, %03d",
				ErrDuplicateVersion, names[0], names[1], dir, v, highest+1))
		}
	}
	return errors.Join(errs...)
}

// upVersions maps each version to the names of its *.up.sql files in dir,
// in name order.
func upVersions(fsys fs.FS, dir string) (map[uint][]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrations: read %s: %w", dir, err)
	}
	versions := map[uint][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		v, perr := parseVersionPrefix(name)
		if perr != nil {
			continue
		}
		versions[v] = append(versions[v], name)
	}
	return versions, nil
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
