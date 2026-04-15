package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestYAMLRegistryMatchesGo is the migration safety net for spec
// 21-yaml-rpc-authz-registry. It builds the registry both ways — from the
// embedded YAML (the new path) and from the legacy Go populate() body — and
// asserts byte-equivalence per method.
//
// This test is deleted in task 9 alongside newFgaRpcRegistryGoLegacy and
// populate(), but only after at least one full release cycle has run with
// the YAML path in production.
func TestYAMLRegistryMatchesGo(t *testing.T) {
	yamlReg, err := LoadRegistry(EmbeddedRpcRegistry, "")
	require.NoError(t, err, "loading embedded YAML must succeed")

	goReg := newFgaRpcRegistryGoLegacy()

	// Method sets must match exactly.
	yamlMethods := yamlReg.Methods()
	goMethods := goReg.Methods()
	sort.Strings(yamlMethods)
	sort.Strings(goMethods)
	assert.Equal(t, goMethods, yamlMethods,
		"YAML and Go-built registries must contain identical method sets")

	// Per-method comparison.
	for _, m := range goMethods {
		ys, yok := yamlReg.Lookup(m)
		gs, gok := goReg.Lookup(m)
		require.True(t, yok, "YAML registry missing %s", m)
		require.True(t, gok, "Go registry missing %s", m)

		assert.Equal(t, gs.Relation, ys.Relation,
			"%s: relation mismatch (go=%q yaml=%q)", m, gs.Relation, ys.Relation)
		assert.Equal(t, gs.Unauthenticated, ys.Unauthenticated,
			"%s: unauthenticated mismatch", m)
		assert.Equal(t, gs.Description, ys.Description,
			"%s: description mismatch", m)

		// Compare ObjectFrom by behavior. Function pointer equality won't work
		// across builders (each builds a fresh closure); instead, invoke the
		// resolver against a tenant-loaded context and compare the produced
		// FGA object string. For nil ObjectFrom (tenant-from-context fallback),
		// both must be nil.
		if gs.ObjectFrom == nil {
			assert.Nil(t, ys.ObjectFrom,
				"%s: ObjectFrom mismatch (go=nil yaml=non-nil)", m)
			continue
		}
		require.NotNil(t, ys.ObjectFrom,
			"%s: ObjectFrom mismatch (go=non-nil yaml=nil)", m)

		ctx := ContextWithTenant(context.Background(), "parity-test-tenant")
		goObj, goErr := gs.ObjectFrom(nil, ctx)
		yamlObj, yamlErr := ys.ObjectFrom(nil, ctx)

		// Errors must agree (both nil or both non-nil).
		switch {
		case goErr == nil && yamlErr == nil:
			assert.Equal(t, goObj, yamlObj,
				"%s: ObjectFrom returned different values (go=%q yaml=%q)",
				m, goObj, yamlObj)
		case goErr != nil && yamlErr != nil:
			// Both errored — acceptable as long as the resolver behavior is
			// equivalent; we don't pin the exact message.
		default:
			t.Errorf("%s: ObjectFrom error agreement failed (goErr=%v yamlErr=%v)",
				m, goErr, yamlErr)
		}
	}
}
