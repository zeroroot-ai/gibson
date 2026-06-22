package reservednames

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// writeFiles populates a temp dir with the given file contents. Used as
// a kubelet-projection stand-in.
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// TestProvider_MissingDir_ReturnsEmpty covers the dev-environment path:
// the chart hasn't projected the ConfigMap volume yet, so the directory
// is missing. Provider must still construct and return empty lists.
func TestProvider_MissingDir_ReturnsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	p, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatalf("ReservedNames: %v", err)
	}
	if len(exact) != 0 || len(prefix) != 0 {
		t.Fatalf("expected empty lists for missing dir, got exact=%v prefix=%v", exact, prefix)
	}
}

// TestProvider_ColdLoad covers the steady-state path: both files exist
// at construction time, provider reads them, ReservedNames returns
// trimmed + comment-stripped lists.
func TestProvider_ColdLoad(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		fileExact:  "default\nkube-system\n# a comment\n\ngibson",
		filePrefix: "kube-\nsystem-",
	})

	p, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	wantExact := []string{"default", "gibson", "kube-system"}
	wantPrefix := []string{"kube-", "system-"}
	sort.Strings(exact)
	sort.Strings(prefix)
	sort.Strings(wantExact)
	sort.Strings(wantPrefix)
	if !slicesEqual(exact, wantExact) {
		t.Fatalf("exact: want %v, got %v", wantExact, exact)
	}
	if !slicesEqual(prefix, wantPrefix) {
		t.Fatalf("prefix: want %v, got %v", wantPrefix, prefix)
	}
}

// TestProvider_LiveReload exercises the fsnotify path: the provider
// picks up a file-rewrite without restart. This mirrors kubelet's
// in-place ConfigMap projection update.
func TestProvider_LiveReload(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		fileExact: "alpha",
	})

	p, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	exact, _, _ := p.ReservedNames(context.Background())
	if !slicesEqual(exact, []string{"alpha"}) {
		t.Fatalf("initial: want [alpha], got %v", exact)
	}

	// Rewrite the file. fsnotify should fire and the watchLoop will reload.
	writeFiles(t, dir, map[string]string{
		fileExact: "alpha\nbeta\ngamma",
	})

	// Poll for up to 2s waiting for the reload to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		exact, _, _ = p.ReservedNames(context.Background())
		sort.Strings(exact)
		if slicesEqual(exact, []string{"alpha", "beta", "gamma"}) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("live reload did not pick up file change; final exact=%v", exact)
}

// TestProvider_MissingOneFile covers the half-projected path: kubelet
// has written `exact` but not `prefix`. The provider returns the
// readable list and an empty list for the missing file — no error.
func TestProvider_MissingOneFile(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		fileExact: "only-exact-here",
	})

	p, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slicesEqual(exact, []string{"only-exact-here"}) {
		t.Fatalf("exact: want [only-exact-here], got %v", exact)
	}
	if len(prefix) != 0 {
		t.Fatalf("prefix: want empty, got %v", prefix)
	}
}

// TestProvider_DefensiveCopy verifies that callers cannot mutate the
// cached snapshot through the returned slices.
func TestProvider_DefensiveCopy(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		fileExact: "untouchable",
	})

	p, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	exact, _, _ := p.ReservedNames(context.Background())
	if len(exact) != 1 {
		t.Fatalf("setup: expected 1 element, got %v", exact)
	}
	// Mutate the returned slice. Subsequent reads must see the original.
	exact[0] = "tampered"

	exact2, _, _ := p.ReservedNames(context.Background())
	if exact2[0] != "untouchable" {
		t.Fatalf("cache was mutated through returned slice; got %v", exact2)
	}
}

// TestProvider_Close_Idempotent confirms Close can be called more than
// once without panic.
func TestProvider_Close_Idempotent(t *testing.T) {
	p, err := New(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestProvider_NilReceiver_ReturnsError covers the defence-in-depth
// nil-receiver guard: callers that accidentally drop a constructor
// error and use a nil *Provider should not panic.
func TestProvider_NilReceiver_ReturnsError(t *testing.T) {
	var p *Provider
	_, _, err := p.ReservedNames(context.Background())
	if err == nil {
		t.Fatal("expected error on nil receiver")
	}
}

// slicesEqual is a tiny string-slice equality helper to avoid pulling in
// reflect.DeepEqual or testify just for this package.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
