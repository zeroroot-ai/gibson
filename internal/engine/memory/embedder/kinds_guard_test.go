package embedder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoStaleEmbedderKinds is a regression guard for gibson#1011: the local-model
// embedder apparatus (the deleted graphrag.EmbedderConfig with its
// native/huggingface/local "kinds" and a hardcoded 384 dimension) must not creep
// back in. Embeddings are bring-your-own per tenant (ADR-0059); the only valid
// embedder backends are the Kind constants in factory.go (openai,
// openai-compatible, tei, bedrock, cohere, voyage).
//
// The guard scans the non-test Go source of the embedder and graphrag packages
// for the deleted kind string-literals.
//
// Scoping notes (to avoid false positives — these are legitimate, unrelated uses
// and are NOT embedder kinds):
//   - "HuggingFace" (capitalised, unquoted) is the company behind Text-
//     Embeddings-Inference (TEI), referenced in factory.go/tei.go comments. Only
//     the quoted lower-case kind literal "huggingface" is forbidden.
//   - "local" is a GraphRAG *provider* type (graphrag.ProviderTypeLocal =
//     "local") and a substring of localhost etc. It is forbidden as an embedder
//     kind only inside the embedder package; it is allowed in graphrag.
func TestNoStaleEmbedderKinds(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	embedderDir := filepath.Dir(thisFile)                             // .../internal/engine/memory/embedder
	graphragDir := filepath.Join(embedderDir, "..", "..", "graphrag") // .../internal/engine/graphrag

	cases := []struct {
		dir       string
		forbidden []string
	}{
		// The embedder package defines the canonical Kind set — none of the
		// deleted kinds may appear here as quoted literals. (The package keeps its
		// own transport-level embedder.EmbedderConfig, which is unrelated and
		// therefore NOT forbidden here.)
		{dir: embedderDir, forbidden: []string{`"native"`, `"huggingface"`, `"local"`}},
		// The graphrag package previously carried the stale graphrag.EmbedderConfig
		// (deleted in gibson#1011). "local" is excluded here (legitimate GraphRAG
		// provider type, graphrag.ProviderTypeLocal).
		{dir: graphragDir, forbidden: []string{`"native"`, `"huggingface"`, "EmbedderConfig"}},
	}

	for _, tc := range cases {
		entries, err := os.ReadDir(tc.dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", tc.dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(tc.dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			src := string(data)
			for _, tok := range tc.forbidden {
				if strings.Contains(src, tok) {
					t.Errorf("stale embedder-kind reference %q found in %s — embeddings are BYO per tenant (ADR-0059); native/huggingface/local kinds were removed in gibson#1011", tok, path)
				}
			}
		}
	}
}
