package ontology

import (
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/taxonomy"
)

// Loader reads ontology files and registers them with a Reasoner.
type Loader struct {
	reasoner *Reasoner
	logger   *slog.Logger
}

// NewLoader creates a Loader backed by the given reasoner.
func NewLoader(r *Reasoner, logger *slog.Logger) *Loader {
	if logger == nil {
		logger = slog.Default()
	}
	return &Loader{reasoner: r, logger: logger.With("component", "ontology_loader")}
}

// LoadCore reads all *.yaml files from the SDK's embedded ontology FS and
// registers them with the Reasoner. Files named *.yaml.example or *.example
// are skipped. Errors for individual files are logged and skipped — the method
// returns an error only if no files were successfully processed AND at least
// one YAML file was present.
func (l *Loader) LoadCore() error {
	fsys := taxonomy.EmbeddedOntology()
	return l.loadFromFS(fsys, "core")
}

// LoadFromFS reads all *.yaml files from the given FS rooted at "ontology/"
// and registers them. The namePrefix is prepended to each file's base name to
// form the extension registration key, ensuring vendor-supplied ontologies
// don't collide with the core vocab.
func (l *Loader) LoadFromFS(fsys fs.FS, namePrefix string) error {
	return l.loadFromFS(fsys, namePrefix)
}

func (l *Loader) loadFromFS(fsys fs.FS, namePrefix string) error {
	const dir = "ontology"

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		// If the directory doesn't exist (e.g., empty FS), that's fine.
		l.logger.Warn("ontology directory not found in FS", slog.String("prefix", namePrefix))
		return nil
	}

	var loaded, skipped int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip example files.
		if strings.HasSuffix(name, ".example") || strings.Contains(name, ".yaml.example") {
			skipped++
			continue
		}
		// Only process YAML files.
		if !strings.HasSuffix(name, ".yaml") {
			// Turtle files: store raw bytes as RawTriples (not parsed yet —
			// spec defers full Turtle ingestion to a future milestone).
			if strings.HasSuffix(name, ".ttl") {
				data, readErr := fs.ReadFile(fsys, dir+"/"+name)
				if readErr != nil {
					l.logger.Warn("failed to read ttl file", slog.String("file", name), slog.Any("err", readErr))
					continue
				}
				extName := namePrefix + "/" + strings.TrimSuffix(name, ".ttl")
				ext := sdkgraphrag.OntologyExtension{
					RawTriples: data,
					Prefixes:   make(map[string]string),
				}
				if regErr := l.reasoner.RegisterExtension(extName, ext); regErr != nil {
					l.logger.Warn("failed to register ttl extension",
						slog.String("file", name), slog.Any("err", regErr))
				} else {
					loaded++
					l.logger.Info("registered ttl extension (raw triples only)",
						slog.String("ext", extName))
				}
			}
			continue
		}

		data, readErr := fs.ReadFile(fsys, dir+"/"+name)
		if readErr != nil {
			l.logger.Warn("failed to read yaml file", slog.String("file", name), slog.Any("err", readErr))
			skipped++
			continue
		}

		o, parseErr := taxonomy.Parse(data)
		if parseErr != nil {
			l.logger.Warn("failed to parse yaml ontology",
				slog.String("file", name), slog.Any("err", parseErr))
			skipped++
			continue
		}

		ext := ontologyToExtension(o)
		extName := namePrefix + "/" + strings.TrimSuffix(name, ".yaml")
		if regErr := l.reasoner.RegisterExtension(extName, ext); regErr != nil {
			l.logger.Warn("failed to register yaml extension",
				slog.String("file", name), slog.Any("err", regErr))
			skipped++
			continue
		}
		loaded++
		l.logger.Info("registered yaml ontology extension", slog.String("ext", extName))
	}

	l.logger.Info("ontology loader finished",
		slog.String("prefix", namePrefix),
		slog.Int("loaded", loaded),
		slog.Int("skipped", skipped),
	)
	return nil
}

// ontologyToExtension converts the taxonomy.Ontology (YAML-parsed) value into
// the sdk/graphrag.OntologyExtension that the Reasoner consumes.
func ontologyToExtension(o taxonomy.Ontology) sdkgraphrag.OntologyExtension {
	prefixes := make(map[string]string, len(o.Prefixes))
	for k, v := range o.Prefixes {
		prefixes[k] = v
	}

	hierarchies := make([]sdkgraphrag.HierarchyDef, 0, len(o.Hierarchies))
	for _, h := range o.Hierarchies {
		hierarchies = append(hierarchies, sdkgraphrag.HierarchyDef{
			NodeType:   h.NodeType,
			Label:      h.Label,
			SubClassOf: h.SubClassOf,
		})
	}

	equivs := make([][2]string, 0, len(o.Equivalences))
	for _, pair := range o.Equivalences {
		equivs = append(equivs, [2]string{pair[0], pair[1]})
	}

	ifps := make([]sdkgraphrag.IFPDef, 0, len(o.IFPs))
	for _, ifp := range o.IFPs {
		ifps = append(ifps, sdkgraphrag.IFPDef{
			NodeType: ifp.NodeType,
			Property: ifp.Property,
		})
	}

	return sdkgraphrag.OntologyExtension{
		Prefixes:     prefixes,
		Hierarchies:  hierarchies,
		Equivalences: equivs,
		IFPs:         ifps,
	}
}

// RegisterExtensionFromYAML parses raw YAML bytes and registers the resulting
// extension under name. Convenience helper for runtime-supplied extensions
// (e.g., from a plugin or a tenant config upload).
func (l *Loader) RegisterExtensionFromYAML(name string, data []byte) error {
	o, err := taxonomy.Parse(data)
	if err != nil {
		return fmt.Errorf("ontology: parse extension YAML: %w", err)
	}
	ext := ontologyToExtension(o)
	return l.reasoner.RegisterExtension(name, ext)
}
