package identityresolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMap(t *testing.T, path string, m map[string]string) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func touchFuture(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(5 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func TestResolve_KnownSub(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "map.json")
	writeMap(t, p, map[string]string{
		"gibson-tenant-operator": "370767967299829765",
		"gibson-dashboard-sa":    "370767968507789317",
	})
	r := New(p)

	if name, ok := r.Resolve("370767967299829765"); !ok || name != "gibson-tenant-operator" {
		t.Fatalf("got (%q, %v); want (gibson-tenant-operator, true)", name, ok)
	}
	if name, ok := r.Resolve("370767968507789317"); !ok || name != "gibson-dashboard-sa" {
		t.Fatalf("got (%q, %v); want (gibson-dashboard-sa, true)", name, ok)
	}
}

func TestResolve_UnknownSub(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "map.json")
	writeMap(t, p, map[string]string{"sa-one": "111"})
	r := New(p)
	if name, ok := r.Resolve("999999"); ok {
		t.Fatalf("expected unknown sub to return false; got (%q, true)", name)
	}
}

func TestResolve_EmptyInput(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "missing.json"))
	if name, ok := r.Resolve(""); ok || name != "" {
		t.Fatalf("expected empty input to return (\"\", false); got (%q, %v)", name, ok)
	}
}

func TestResolve_MissingFileReturnsFalse(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "absent.json"))
	if name, ok := r.Resolve("anything"); ok || name != "" {
		t.Fatalf("expected missing file to return (\"\", false); got (%q, %v)", name, ok)
	}
}

func TestResolve_RefreshOnMTimeChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "map.json")
	writeMap(t, p, map[string]string{"sa-one": "111"})
	r := New(p)

	if name, ok := r.Resolve("111"); !ok || name != "sa-one" {
		t.Fatalf("first resolve: got (%q, %v)", name, ok)
	}

	writeMap(t, p, map[string]string{"sa-two": "222"})
	touchFuture(t, p)

	if name, ok := r.Resolve("222"); !ok || name != "sa-two" {
		t.Fatalf("after rewrite: got (%q, %v)", name, ok)
	}
	if _, ok := r.Resolve("111"); ok {
		t.Fatalf("stale entry still resolved after refresh")
	}
}

func TestResolve_SurvivesFileDisappear(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "map.json")
	writeMap(t, p, map[string]string{"sa-one": "111"})
	r := New(p)

	// Prime the cache.
	if _, ok := r.Resolve("111"); !ok {
		t.Fatalf("prime: missing")
	}
	// Delete the file. Cache should still serve the last-known-good.
	if err := os.Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if name, ok := r.Resolve("111"); !ok || name != "sa-one" {
		t.Fatalf("after delete: got (%q, %v); want last-known-good", name, ok)
	}
}

func TestNew_DefaultsAndEnvOverride(t *testing.T) {
	r1 := New("")
	if r1.path != DefaultPath {
		t.Fatalf("default path: got %q want %q", r1.path, DefaultPath)
	}
	t.Setenv("GIBSON_SA_IDENTITY_MAP_PATH", "/tmp/override.json")
	r2 := New("")
	if r2.path != "/tmp/override.json" {
		t.Fatalf("env override: got %q want /tmp/override.json", r2.path)
	}
}

// kubelet's ConfigMap projection writes one file per key. The resolver
// should treat each filename as a readable SA name and the file content
// as the numeric sub. Hidden entries (..data, ..<timestamp>) must be
// skipped — they're kubelet's atomic-update plumbing.
func TestResolve_DirectoryMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gibson-tenant-operator"), []byte("370767967299829765"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gibson-dashboard-sa"), []byte("370767968507789317\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Kubelet plumbing — must be ignored.
	if err := os.MkdirAll(filepath.Join(dir, "..data_2026"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..hidden"), []byte("ignore"), 0o644); err != nil {
		t.Fatalf("write hidden: %v", err)
	}
	// Unset placeholder — should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "gibson-iam-admin"), []byte("<unset>"), 0o644); err != nil {
		t.Fatalf("write unset: %v", err)
	}

	r := New(dir)
	if name, ok := r.Resolve("370767967299829765"); !ok || name != "gibson-tenant-operator" {
		t.Fatalf("operator: got (%q, %v)", name, ok)
	}
	if name, ok := r.Resolve("370767968507789317"); !ok || name != "gibson-dashboard-sa" {
		t.Fatalf("dashboard: got (%q, %v) — trailing newline not trimmed?", name, ok)
	}
	if _, ok := r.Resolve("<unset>"); ok {
		t.Fatalf("placeholder value should not match")
	}
	if _, ok := r.Resolve("ignore"); ok {
		t.Fatalf("hidden entries leaked into the cache")
	}
}
