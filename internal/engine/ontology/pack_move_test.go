// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportTenantExtensions(t *testing.T) {
	pack, err := ExportTenantExtensions("k8s", 2, "acme", []string{"Container"}, []string{"RUNS_IN"})
	require.NoError(t, err)
	assert.Equal(t, "k8s", pack.Name)
	assert.Equal(t, 2, pack.Version)
	assert.Equal(t, "acme", pack.Author)
	assert.Equal(t, []string{"Container"}, pack.TaxonomyNodeLabels)
	assert.Equal(t, []string{"RUNS_IN"}, pack.TaxonomyRelationshipTypes)
	assert.NotEmpty(t, pack.TaxonomyNodeIdentity["Container"])
	assert.Empty(t, pack.Ontology, "the core ontology is not exported")

	// The export applies on a second install.
	require.NoError(t, CheckImport(pack))

	for name, args := range map[string]struct {
		name    string
		version int
	}{
		"bad name":     {"bad name", 1},
		"zero version": {"k8s", 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ExportTenantExtensions(args.name, args.version, "acme", nil, nil)
			require.Error(t, err)
		})
	}
}

func TestCheckImport_RefusesALabelWithNoKeyForm(t *testing.T) {
	require.Error(t, CheckImport(&DomainPack{Name: "p", TaxonomyNodeLabels: []string{"Pod"}}))
}

func TestDecodePackJSON(t *testing.T) {
	p, err := DecodePackJSON([]byte(`{"name":"p","version":1}`))
	require.NoError(t, err)
	assert.Equal(t, "p", p.Name)
	for name, raw := range map[string]string{
		"unknown field": `{"name":"p","x":1}`,
		"two documents": `{"name":"p"} {"name":"q"}`,
		"not JSON":      `{`,
		"too large":     `{"name":"` + strings.Repeat("a", MaxPackJSONBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodePackJSON([]byte(raw))
			require.Error(t, err)
		})
	}
}

func TestImportStore_Save(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	s, err := NewImportStore(db)
	require.NoError(t, err)
	pack := &DomainPack{Name: "p", Version: 2}

	mock.ExpectExec("INSERT INTO domain_pack_imports").WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, s.Save(context.Background(), pack, "owner"))

	mock.ExpectExec("INSERT INTO domain_pack_imports").WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, s.Save(context.Background(), pack, "owner"), ErrPackExists)

	mock.ExpectExec("INSERT INTO domain_pack_imports").WillReturnError(assert.AnError)
	require.Error(t, s.Save(context.Background(), pack, "owner"))

	_, err = NewImportStore(nil)
	require.Error(t, err)
}

func TestCatalogWithImports(t *testing.T) {
	newStore := func(t *testing.T, rows ...[2]string) *ImportStore {
		t.Helper()
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		r := sqlmock.NewRows([]string{"name", "pack_json"})
		for _, row := range rows {
			r.AddRow(row[0], []byte(row[1]))
		}
		mock.ExpectQuery("FROM domain_pack_imports").WillReturnRows(r)
		s, err := NewImportStore(db)
		require.NoError(t, err)
		return s
	}
	t.Run("an imported pack joins the catalog", func(t *testing.T) {
		c, err := CatalogWithImports(context.Background(), newStore(t, [2]string{"k8s", `{"name":"k8s","version":1}`}))
		require.NoError(t, err)
		_, ok := c.Get("k8s")
		assert.True(t, ok)
		_, ok = c.Get(MainDomainPackName)
		assert.True(t, ok, "the embedded packs stay")
	})
	t.Run("an import never replaces an embedded pack", func(t *testing.T) {
		_, err := CatalogWithImports(context.Background(), newStore(t, [2]string{"main", `{"name":"main","version":9}`}))
		require.ErrorContains(t, err, "embedded catalog pack")
	})
	t.Run("a stored pack that does not decode stops the start", func(t *testing.T) {
		_, err := CatalogWithImports(context.Background(), newStore(t, [2]string{"k8s", `{`}))
		require.Error(t, err)
	})
}
