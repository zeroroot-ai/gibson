// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package migrations

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// A table a migration creates and no Go code names is a producer with no
// consumer (ADR-0094, gibson#506). connector_sandbox lived that way for
// months with COMMENT text describing a reader that was never built. This
// guard fails the build for the next one.

var (
	createTableRE = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	dropTableRE   = regexp.MustCompile(`(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
)

// liveTables returns the tables the up migrations in dir leave in place:
// every CREATE TABLE minus every table a later up migration drops. Files are
// read in name order, which is version order.
func liveTables(sqlFS fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(sqlFS, dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	live := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := fs.ReadFile(sqlFS, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		for _, m := range createTableRE.FindAllStringSubmatch(string(b), -1) {
			live[strings.ToLower(m[1])] = true
		}
		for _, m := range dropTableRE.FindAllStringSubmatch(string(b), -1) {
			delete(live, strings.ToLower(m[1]))
		}
	}
	out := make([]string, 0, len(live))
	for t := range live {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// unreadTables returns the live tables that no production Go file under goFS
// names as a whole word. Test files, generated protobuf bindings and the
// migrations package itself (which names every table in its SQL) do not
// count as readers.
func unreadTables(sqlFS fs.FS, dir string, goFS fs.FS) ([]string, error) {
	tables, err := liveTables(sqlFS, dir)
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	err = fs.WalkDir(goFS, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := d.Name()
			if p != "." && (strings.HasPrefix(base, ".") || base == "vendor" || base == "node_modules" || p == "pkg/platform/migrations") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, ".pb.go") {
			return nil
		}
		b, err := fs.ReadFile(goFS, p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		src := string(b)
		for _, t := range tables {
			if named[t] {
				continue
			}
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(t) + `\b`).MatchString(src) {
				named[t] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk go sources: %w", err)
	}
	var unread []string
	for _, t := range tables {
		if !named[t] {
			unread = append(unread, t)
		}
	}
	return unread, nil
}

// moduleRoot walks up from this file to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above " + file)
		}
		dir = parent
	}
}

func TestLiveTablesHaveAGoReader(t *testing.T) {
	t.Parallel()
	goFS := os.DirFS(moduleRoot(t))
	for _, c := range []struct {
		name string
		fsys fs.FS
		dir  string
	}{
		{"platform", Platform, platformDir},
		{"tenant", Tenant, tenantDir},
	} {
		unread, err := unreadTables(c.fsys, c.dir, goFS)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(unread) > 0 {
			t.Errorf("%s migrations create tables no production Go file names: %v\n"+
				"Give each a reader, or drop it in a new migration (gibson#506).", c.name, unread)
		}
	}
}

// The fixture: a planted table with no reader is reported, a reader clears it,
// and a later DROP TABLE clears it too.
func TestUnreadTables_Fixture(t *testing.T) {
	t.Parallel()
	sqlFS := fstest.MapFS{
		"m/001_ghost.up.sql":   {Data: []byte("CREATE TABLE IF NOT EXISTS ghost_table (id TEXT PRIMARY KEY);\nCREATE TABLE read_table (id TEXT);")},
		"m/001_ghost.down.sql": {Data: []byte("DROP TABLE ghost_table; DROP TABLE read_table;")},
	}
	noReader := fstest.MapFS{
		"internal/x/x.go":      {Data: []byte("package x\n\nconst q = `SELECT 1 FROM read_table`\n")},
		"internal/x/x_test.go": {Data: []byte("package x\n\nconst q2 = `SELECT 1 FROM ghost_table`\n")},
		"api/y.pb.go":          {Data: []byte("package y\n\n// ghost_table\n")},
	}
	got, err := unreadTables(sqlFS, "m", noReader)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"ghost_table"}) {
		t.Fatalf("unread = %v, want [ghost_table]: a test file and a .pb.go are not readers", got)
	}

	withReader := fstest.MapFS{
		"internal/x/x.go": {Data: []byte("package x\n\nconst q = `SELECT 1 FROM ghost_table JOIN read_table`\n")},
	}
	if got, err = unreadTables(sqlFS, "m", withReader); err != nil || len(got) != 0 {
		t.Fatalf("unread = %v (err %v), want none once a Go file names the table", got, err)
	}

	sqlFS["m/002_drop.up.sql"] = &fstest.MapFile{Data: []byte("DROP TABLE IF EXISTS ghost_table;")}
	if got, err = unreadTables(sqlFS, "m", noReader); err != nil || len(got) != 0 {
		t.Fatalf("unread = %v (err %v), want none once a later migration drops the table", got, err)
	}
}
