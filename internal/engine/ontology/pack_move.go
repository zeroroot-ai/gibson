// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// pack_move.go: a Domain Pack moves between installs (ADR-0133,
// gibson#712). One install exports the live extensions of a tenant as pack
// JSON. The platform owner of a second install imports that JSON. The
// imported pack joins the catalog of that install at its next start: a
// catalog never changes under a running daemon (ADR-0133).

// MaxPackJSONBytes bounds the JSON of one imported pack.
const MaxPackJSONBytes = 1 << 20

// ErrPackExists is returned by ImportStore.Save for a pack whose name the
// install already has, at the same or a higher version.
var ErrPackExists = errors.New("ontology: the install already has this pack at the same or a higher version")

// coreReasoner returns a Reasoner with the core ontology of the platform.
func coreReasoner() (*Reasoner, error) {
	r := NewReasoner(NewMetrics())
	if err := NewLoader(r, slog.Default()).LoadCore(); err != nil {
		return nil, fmt.Errorf("ontology: load core ontology: %w", err)
	}
	return r, nil
}

// ExportTenantExtensions returns the live extensions of one tenant as a
// pack: the node labels and the relationship types that the tenant promoted
// on top of the core taxonomy. It uses ExportDomainPack with the core
// taxonomy as the base and the core ontology excluded, so the pack holds
// only what the tenant added. Each node label keeps the key form that the
// promotion registry recorded for it.
func ExportTenantExtensions(name string, version int, author string, nodeLabels, relTypes []string) (*DomainPack, error) {
	if err := taxonomy.ValidIdentifier(name); err != nil {
		return nil, fmt.Errorf("ontology: export: pack name: %w", err)
	}
	if version < 1 {
		return nil, errors.New("ontology: export: version must be 1 or more")
	}
	base := taxonomy.Global
	now, err := taxonomy.New(base.Version()+1,
		unionNew(base.NodeLabels(), nodeLabels), unionNew(base.RelationshipTypes(), relTypes))
	if err != nil {
		return nil, fmt.Errorf("ontology: export: %w", err)
	}
	reasoner, err := coreReasoner()
	if err != nil {
		return nil, err
	}
	core := make([]string, 0, len(reasoner.Extensions()))
	for n := range reasoner.Extensions() {
		core = append(core, n)
	}
	pack, err := ExportDomainPack(name, version, base, now, reasoner, core...)
	if err != nil {
		return nil, err
	}
	for label := range pack.TaxonomyNodeIdentity {
		if prop, ok := taxonomy.IdentityProperty(label); ok {
			pack.TaxonomyNodeIdentity[label] = prop
		}
	}
	pack.Author = author
	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("ontology: export: %w", err)
	}
	return pack, nil
}

// CheckImport proves that pack applies to this install: Import layers it
// onto the core taxonomy and a reasoner with the core ontology, with the
// same checks that gate content at discovery time. It changes nothing.
func CheckImport(pack *DomainPack) error {
	reasoner, err := coreReasoner()
	if err != nil {
		return err
	}
	if _, err := pack.Import(taxonomy.Global, reasoner); err != nil {
		return err
	}
	return nil
}

// DecodePackJSON decodes one pack from JSON. It refuses an unknown field and
// a second JSON document, as the catalog loader does.
func DecodePackJSON(raw []byte) (DomainPack, error) {
	if len(raw) > MaxPackJSONBytes {
		return DomainPack{}, fmt.Errorf("ontology: pack JSON is %d bytes, over the %d-byte cap", len(raw), MaxPackJSONBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pack DomainPack
	if err := dec.Decode(&pack); err != nil {
		return DomainPack{}, fmt.Errorf("ontology: decode pack JSON: %w", err)
	}
	if dec.More() {
		return DomainPack{}, errors.New("ontology: pack JSON holds more than one JSON document")
	}
	return pack, nil
}

// EncodePackJSON encodes one pack as JSON.
func EncodePackJSON(pack *DomainPack) ([]byte, error) {
	raw, err := json.Marshal(pack)
	if err != nil {
		return nil, fmt.Errorf("ontology: encode pack JSON: %w", err)
	}
	return raw, nil
}

// ImportStore keeps the imported packs of an install in the platform
// database (table domain_pack_imports).
type ImportStore struct {
	db *sql.DB
}

// NewImportStore returns the store. db must not be nil.
func NewImportStore(db *sql.DB) (*ImportStore, error) {
	if db == nil {
		return nil, errors.New("ontology: NewImportStore: db is required")
	}
	return &ImportStore{db: db}, nil
}

// Save stores pack. A pack with a name the install has at the same or a
// higher version is refused with ErrPackExists. A higher version replaces
// the stored one.
func (s *ImportStore) Save(ctx context.Context, pack *DomainPack, importedBy string) error {
	raw, err := EncodePackJSON(pack)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO domain_pack_imports (name, version, pack_json, imported_by, imported_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (name) DO UPDATE
SET version = EXCLUDED.version, pack_json = EXCLUDED.pack_json,
    imported_by = EXCLUDED.imported_by, imported_at = EXCLUDED.imported_at
WHERE domain_pack_imports.version < EXCLUDED.version`, pack.Name, pack.Version, raw, importedBy)
	if err != nil {
		return fmt.Errorf("ontology: save imported pack %q: %w", pack.Name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("ontology: save imported pack %q: %w", pack.Name, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %q version %d", ErrPackExists, pack.Name, pack.Version)
	}
	return nil
}

// List returns the imported packs, sorted by name.
func (s *ImportStore) List(ctx context.Context) ([]DomainPack, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, pack_json FROM domain_pack_imports ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("ontology: list imported packs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DomainPack
	for rows.Next() {
		var (
			name string
			raw  []byte
		)
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, fmt.Errorf("ontology: scan imported pack: %w", err)
		}
		pack, err := DecodePackJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("ontology: imported pack %q: %w", name, err)
		}
		out = append(out, pack)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ontology: list imported packs: %w", err)
	}
	return out, nil
}

// CatalogWithImports returns the catalog of the embedded pack files and the
// imported packs of the install. An imported pack with the name of an
// embedded pack is refused: the embedded catalog is first-party, and an
// import never replaces a first-party pack.
func CatalogWithImports(ctx context.Context, store *ImportStore) (*DomainPackCatalog, error) {
	embedded, err := LoadCatalog(embeddedPackFiles)
	if err != nil {
		return nil, err
	}
	imported, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	packs := embedded.List()
	for _, p := range imported {
		if _, ok := embedded.Get(p.Name); ok {
			return nil, fmt.Errorf("ontology: imported pack %q has the name of an embedded catalog pack", p.Name)
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return newCheckedCatalog(packs)
}

// InstallCatalog returns the catalog of this install: the embedded pack
// files and the imported packs in db. The daemon calls it at start.
func InstallCatalog(ctx context.Context, db *sql.DB) (*DomainPackCatalog, error) {
	store, err := NewImportStore(db)
	if err != nil {
		return nil, err
	}
	return CatalogWithImports(ctx, store)
}
