package catalogue

import (
	"testing"
)

func TestLoad_Canonical(t *testing.T) {
	c := Load()
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
