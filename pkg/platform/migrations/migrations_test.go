package migrations

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbed_TenantHasExpectedFiles(t *testing.T) {
	t.Parallel()
	upCount, downCount := countSQL(t, Tenant, tenantDir)
	if upCount != 7 {
		t.Errorf("tenant: expected 7 up.sql files, got %d", upCount)
	}
	if downCount != 7 {
		t.Errorf("tenant: expected 7 down.sql files, got %d", downCount)
	}
}

func TestEmbed_PlatformHasExpectedFiles(t *testing.T) {
	t.Parallel()
	upCount, downCount := countSQL(t, Platform, platformDir)
	if upCount != 9 {
		t.Errorf("platform: expected 9 up.sql files, got %d", upCount)
	}
	if downCount != 9 {
		t.Errorf("platform: expected 9 down.sql files, got %d", downCount)
	}
}

func TestEmbed_UpDownPairing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		fsys fs.FS
		dir  string
	}{
		{"tenant", Tenant, tenantDir},
		{"platform", Platform, platformDir},
	} {
		entries, err := fs.ReadDir(c.fsys, c.dir)
		if err != nil {
			t.Fatalf("%s: read dir: %v", c.name, err)
		}
		ups, downs := map[string]bool{}, map[string]bool{}
		for _, e := range entries {
			n := e.Name()
			switch {
			case strings.HasSuffix(n, ".up.sql"):
				ups[strings.TrimSuffix(n, ".up.sql")] = true
			case strings.HasSuffix(n, ".down.sql"):
				downs[strings.TrimSuffix(n, ".down.sql")] = true
			}
		}
		for stem := range ups {
			if !downs[stem] {
				t.Errorf("%s: missing %s.down.sql for %s.up.sql", c.name, stem, stem)
			}
		}
		for stem := range downs {
			if !ups[stem] {
				t.Errorf("%s: missing %s.up.sql for %s.down.sql", c.name, stem, stem)
			}
		}
	}
}

func TestTenantMaxVersion(t *testing.T) {
	t.Parallel()
	v, err := TenantMaxVersion()
	if err != nil {
		t.Fatalf("TenantMaxVersion: %v", err)
	}
	if v != 7 {
		t.Errorf("TenantMaxVersion: got %d, want 7", v)
	}
}

// PlatformMaxVersion must match the highest NNN in
// postgres/platform/*.up.sql. Bump alongside any added migration:
//
//	001 — tenant_secrets_broker_config
//	002 — plugin_install
//	003 — tenant_quotas_simplify
//	004 — tenant_id_text (UUID → TEXT, gibson#99)
func TestPlatformMaxVersion(t *testing.T) {
	t.Parallel()
	v, err := PlatformMaxVersion()
	if err != nil {
		t.Fatalf("PlatformMaxVersion: %v", err)
	}
	if v != 9 {
		t.Errorf("PlatformMaxVersion: got %d, want 9", v)
	}
}

func TestNewTenantSource_OpensAndCloses(t *testing.T) {
	t.Parallel()
	d, err := NewTenantSource()
	if err != nil {
		t.Fatalf("NewTenantSource: %v", err)
	}
	defer d.Close()
	first, err := d.First()
	if err != nil {
		t.Fatalf("First: %v", err)
	}
	if first != 1 {
		t.Errorf("first version: got %d, want 1", first)
	}
}

func TestNewPlatformSource_OpensAndCloses(t *testing.T) {
	t.Parallel()
	d, err := NewPlatformSource()
	if err != nil {
		t.Fatalf("NewPlatformSource: %v", err)
	}
	defer d.Close()
	first, err := d.First()
	if err != nil {
		t.Fatalf("First: %v", err)
	}
	if first != 1 {
		t.Errorf("first version: got %d, want 1", first)
	}
}

func TestParseVersionPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    uint
		wantErr bool
	}{
		{"001_credentials.up.sql", 1, false},
		{"042_foo.up.sql", 42, false},
		{"README.md", 0, true},
		{"_no_prefix.sql", 0, true},
		{"abc_not_numeric.sql", 0, true},
	}
	for _, c := range cases {
		got, err := parseVersionPrefix(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseVersionPrefix(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parseVersionPrefix(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func countSQL(t *testing.T, fsys fs.FS, dir string) (up, down int) {
	t.Helper()
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".up.sql"):
			up++
		case strings.HasSuffix(e.Name(), ".down.sql"):
			down++
		}
	}
	return up, down
}
