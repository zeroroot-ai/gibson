package catalogue

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Package-level API (backward-compat shims)
// ---------------------------------------------------------------------------

func TestLoad_Canonical(t *testing.T) {
	l := NewLoader("")
	c := l.catalogue
	if len(c.Providers) == 0 {
		t.Fatal("catalogue has no providers")
	}
	wantTypes := []string{"anthropic", "openai", "bedrock", "google", "mistral", "cohere", "cloudflare", "huggingface", "ollama", "llamafile"}
	found := map[string]bool{}
	for _, p := range c.Providers {
		found[p.Type] = true
	}
	for _, want := range wantTypes {
		if !found[want] {
			t.Errorf("missing provider type: %s", want)
		}
	}
}

func TestLoad_Idempotent(t *testing.T) {
	c1 := Load()
	c2 := Load()
	if c1 != c2 {
		t.Fatal("Load() must return the same singleton pointer")
	}
}

func TestModelsFor_KnownProvider(t *testing.T) {
	models := ModelsFor("anthropic")
	if len(models) == 0 {
		t.Fatal("expected at least one anthropic model")
	}
	for _, m := range models {
		if m.ID == "" {
			t.Error("model entry has empty ID")
		}
		if m.ContextWindow <= 0 {
			t.Errorf("model %s has non-positive context_window: %d", m.ID, m.ContextWindow)
		}
	}
}

func TestModelsFor_UnknownProvider(t *testing.T) {
	models := ModelsFor("nonexistent-provider-xyz")
	if models != nil {
		t.Fatalf("expected nil for unknown provider, got %v", models)
	}
}

func TestModelsFor_DynamicProviders(t *testing.T) {
	// ollama and llamafile have update_strategy: dynamic and an empty model list.
	// ModelsFor should return an empty (non-nil? nil? — catalogue returns the slice
	// from the YAML, which yaml.v3 decodes as nil for "models: []"). Either nil or
	// empty is fine; what must NOT happen is a panic.
	for _, provider := range []string{"ollama", "llamafile"} {
		models := ModelsFor(provider)
		_ = models // nil or empty slice, both valid
	}
}

// ---------------------------------------------------------------------------
// Loader struct tests
// ---------------------------------------------------------------------------

func TestNewLoader_Embedded(t *testing.T) {
	l := NewLoader("")
	if l.catalogue == nil {
		t.Fatal("embedded loader has nil catalogue")
	}
	if len(l.catalogue.Providers) == 0 {
		t.Fatal("embedded catalogue has no providers")
	}
	if l.path != "" {
		t.Fatalf("expected empty path, got %q", l.path)
	}
}

func TestNewLoader_PanicsOnCorruptEmbedded(t *testing.T) {
	// We test the external-file panic path instead (easier to trigger without
	// patching the embed).
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte(": not: valid: yaml::"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for corrupt YAML, got none")
		}
	}()
	NewLoader(bad)
}

func TestLoader_Start_Noop_WhenEmbedded(t *testing.T) {
	l := NewLoader("")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Should return immediately without starting a goroutine (no ticker); we
	// just verify it does not block or panic.
	l.Start(ctx, 10*time.Millisecond)
}

func TestLoader_HotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalogue.yaml")

	// Initial catalogue: one provider with one model.
	initial := `
providers:
  - type: testprovider
    update_strategy: manual
    models:
      - id: model-v1
        context_window: 4096
        deprecated: false
`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	l := NewLoader(path)

	// Verify initial load.
	models := l.ModelsFor("testprovider")
	if len(models) != 1 || models[0].ID != "model-v1" {
		t.Fatalf("expected [model-v1], got %v", models)
	}

	// Sleep briefly so the mtime of the rewritten file is strictly newer.
	time.Sleep(10 * time.Millisecond)

	// Overwrite with a new catalogue: model-v2 added.
	updated := `
providers:
  - type: testprovider
    update_strategy: manual
    models:
      - id: model-v1
        context_window: 4096
        deprecated: false
      - id: model-v2
        context_window: 8192
        deprecated: false
`
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use a short interval and let the background goroutine fire.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l.Start(ctx, 20*time.Millisecond)

	// Poll until the hot-reload fires or the timeout expires.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got := l.ModelsFor("testprovider")
		if len(got) == 2 {
			// Both models present — reload succeeded.
			if got[1].ID != "model-v2" {
				t.Fatalf("expected model-v2 as second entry, got %q", got[1].ID)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for hot-reload to pick up updated catalogue")
}

func TestLoader_ParseError_RetainsOld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalogue.yaml")

	// Initial catalogue.
	initial := `
providers:
  - type: myprovider
    update_strategy: manual
    models:
      - id: model-a
        context_window: 1024
        deprecated: false
`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(path)

	// Verify initial state.
	if got := l.ModelsFor("myprovider"); len(got) != 1 {
		t.Fatalf("expected 1 model, got %v", got)
	}

	// Sleep so the corrupt file's mtime is strictly newer.
	time.Sleep(10 * time.Millisecond)

	// Corrupt the file.
	if err := os.WriteFile(path, []byte(": NOT VALID YAML ::"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Trigger reload directly (bypass ticker for determinism).
	l.tryReload()

	// Old catalogue must still be intact.
	got := l.ModelsFor("myprovider")
	if len(got) != 1 || got[0].ID != "model-a" {
		t.Fatalf("expected old catalogue [model-a] retained after parse error, got %v", got)
	}
}
