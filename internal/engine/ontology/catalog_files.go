// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// catalog_files.go: the content of each catalog Domain Pack is a data file
// (ADR-0133, gibson#710). A pack is data only, so a new catalog pack is a
// new file in packs/ and needs no Go change.
//
// Each file is one JSON document with the fields of DomainPack. The file
// name is the pack name: packs/<name>.json. The binary embeds the files, so
// a catalog never changes under a running daemon (no hot reload).

// MainDomainPackName is the catalog name of the platform's seed pack. It is
// default-off (ADR-0133): the catalog makes it visible and enable-able,
// never enabled.
const MainDomainPackName = "main"

// packFileExt is the extension of a catalog pack file.
const packFileExt = ".json"

//go:embed packs/*.json
var embeddedPackFiles embed.FS

// LoadCatalog reads each packs/*.json file of fsys and returns the catalog
// of those packs. It refuses:
//   - a file that is not valid JSON, or that has a field DomainPack does
//     not have (a typo must not drop content in silence);
//   - a file with more than one JSON document;
//   - a file whose name is not the name of its pack;
//   - a pack that fails DomainPack.Validate;
//   - a directory with no pack file.
func LoadCatalog(fsys fs.FS) (*DomainPackCatalog, error) {
	names, err := fs.Glob(fsys, "packs/*"+packFileExt)
	if err != nil {
		return nil, fmt.Errorf("ontology: list catalog pack files: %w", err)
	}
	if len(names) == 0 {
		return nil, errors.New("ontology: no catalog pack file in packs/")
	}
	sort.Strings(names)

	packs := make([]DomainPack, 0, len(names))
	for _, name := range names {
		pack, err := decodePackFile(fsys, name)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	return newCheckedCatalog(packs)
}

// decodePackFile reads one pack file and checks its name.
func decodePackFile(fsys fs.FS, name string) (DomainPack, error) {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return DomainPack{}, fmt.Errorf("ontology: read catalog pack file %s: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pack DomainPack
	if err := dec.Decode(&pack); err != nil {
		return DomainPack{}, fmt.Errorf("ontology: catalog pack file %s: %w", name, err)
	}
	if dec.More() {
		return DomainPack{}, fmt.Errorf("ontology: catalog pack file %s: more than one JSON document", name)
	}
	if want := strings.TrimSuffix(path.Base(name), packFileExt); pack.Name != want {
		return DomainPack{}, fmt.Errorf("ontology: catalog pack file %s: the pack name is %q, want %q (the file name)",
			name, pack.Name, want)
	}
	return pack, nil
}

// newCheckedCatalog is NewDomainPackCatalog with an error in place of a
// panic, for content that comes from a file.
func newCheckedCatalog(packs []DomainPack) (*DomainPackCatalog, error) {
	seen := make(map[string]struct{}, len(packs))
	for i := range packs {
		if _, dup := seen[packs[i].Name]; dup {
			return nil, fmt.Errorf("ontology: catalog pack %q: duplicate name", packs[i].Name)
		}
		seen[packs[i].Name] = struct{}{}
		if err := packs[i].Validate(); err != nil {
			return nil, fmt.Errorf("ontology: catalog pack %q: %w", packs[i].Name, err)
		}
	}
	return NewDomainPackCatalog(packs...), nil
}

// EmbeddedCatalog returns the catalog of the pack files that the binary
// embeds. The daemon calls it at start. A bad pack file is a build defect,
// so EmbeddedCatalog panics with the reason; the unit tests load the same
// files, so the panic cannot reach a release.
func EmbeddedCatalog() *DomainPackCatalog {
	c, err := LoadCatalog(embeddedPackFiles)
	if err != nil {
		panic(err.Error())
	}
	return c
}
