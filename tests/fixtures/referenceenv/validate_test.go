// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package referenceenv

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

func load(t *testing.T) (docs []Doc, flaws []Flaw) {
	t.Helper()
	docs, flaws, err := Load(os.DirFS("."))
	require.NoError(t, err)
	return docs, flaws
}

// TestReferenceEnvironment_IsValid: the real manifests pass the validator.
func TestReferenceEnvironment_IsValid(t *testing.T) {
	docs, flaws := load(t)
	assert.Empty(t, Validate(docs, flaws))
	assert.Len(t, flaws, 7)
}

// TestReferenceEnvironment_ReadmeNamesEachFlaw: the flaw table of the README
// and flaws.yaml name the same flaws.
func TestReferenceEnvironment_ReadmeNamesEachFlaw(t *testing.T) {
	_, flaws := load(t)
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	for _, f := range flaws {
		assert.Contains(t, string(readme), "`"+f.ID+"`", "README.md must name the flaw %s", f.ID)
	}
}

// TestReferenceEnvironment_EachAttackFlawHasAPredicate: the main pack binds the
// predicate of each attack flaw, with the category and the destructive state
// that flaws.yaml states (gibson#1512).
func TestReferenceEnvironment_EachAttackFlawHasAPredicate(t *testing.T) {
	_, flaws := load(t)
	pack, ok := ontology.EmbeddedCatalog().Get(ontology.MainDomainPackName)
	require.True(t, ok)
	for _, f := range flaws {
		if f.Check != CheckAttack {
			continue
		}
		assert.Contains(t, pack.Predicates, f.Predicate, "flaw %s", f.ID)
		assert.Equal(t, f.Category, pack.Techniques[f.Predicate], "flaw %s", f.ID)
		assert.Equal(t, !*f.Destructive, slices.Contains(pack.NonDestructivePredicates, f.Predicate), "flaw %s", f.ID)
	}
}

// The tests below are the failing fixtures of the validator. Each one breaks
// the real manifests in one way and expects the validator to refuse it.

func mutate(t *testing.T, edit func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw)) []error {
	t.Helper()
	docs, flaws := load(t)
	docs, flaws = edit(docs, flaws)
	return Validate(docs, flaws)
}

// assertRefused checks that one of the errors holds want.
func assertRefused(t *testing.T, errs []error, want string) {
	t.Helper()
	for _, err := range errs {
		if strings.Contains(err.Error(), want) {
			return
		}
	}
	t.Errorf("no error holds %q: %v", want, errs)
}

func deployment(docs []Doc, name string) Doc {
	for _, d := range docs {
		if d.Kind == "Deployment" && d.Name == name {
			return d
		}
	}
	return Doc{}
}

func firstContainer(d Doc) map[string]any {
	spec := get(d.Obj, "spec", "template", "spec").(map[string]any)
	return spec["containers"].([]any)[0].(map[string]any)
}

func TestValidate_RefusesAnImageWithNoDigest(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		firstContainer(deployment(docs, "payments"))["image"] = "busybox:1.37.0"
		return docs, flaws
	})
	assertRefused(t, errs, "not pinned by digest")
}

func TestValidate_RefusesAServiceWithNoHealthSignal(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		d := deployment(docs, "payments")
		delete(get(d.Obj, "metadata", "annotations").(map[string]any), HealthAnnotation)
		return docs, flaws
	})
	assertRefused(t, errs, HealthAnnotation)
}

func TestValidate_RefusesAProbeThatDiffersFromTheSignal(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		probe := get(firstContainer(deployment(docs, "payments")), "readinessProbe", "httpGet").(map[string]any)
		probe["path"] = "/other"
		return docs, flaws
	})
	assertRefused(t, errs, "readiness probe path")
}

func TestValidate_RefusesAFlawThatTheManifestFixed(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		sc := get(firstContainer(deployment(docs, "node-agent")), "securityContext").(map[string]any)
		sc["privileged"] = false
		return docs, flaws
	})
	assertRefused(t, errs, "does not hold the flaw")
}

func TestValidate_RefusesAnAttackWithNoPredicate(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		flaws[0].Predicate = ""
		return docs, flaws
	})
	assertRefused(t, errs, "needs predicate")
}

func TestValidate_RefusesAListWithoutEachKindOfCheck(t *testing.T) {
	errs := mutate(t, func(docs []Doc, flaws []Flaw) ([]Doc, []Flaw) {
		var attacks []Flaw
		for _, f := range flaws {
			if f.Check == CheckAttack {
				attacks = append(attacks, f)
			}
		}
		return docs, attacks
	})
	assertRefused(t, errs, `no flaw has the check "scan"`)
}
