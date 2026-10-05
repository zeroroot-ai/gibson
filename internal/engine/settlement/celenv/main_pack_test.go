// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// TestLoadDomainPack_MainCatalogPackCompiles proves gibson#382's seed "main"
// catalog pack is not just structurally valid (ontology.DomainPack.Validate)
// but every one of its predicate expressions actually compiles and
// type-checks against the gibson-owned CEL environment (ADR-0131)
// — the same LoadDomainPack path EnableDomainPack's downstream settlement
// consumer (gibson#389) will run for any tenant that enables it.
func TestLoadDomainPack_MainCatalogPackCompiles(t *testing.T) {
	pack := mustMainPack(t)

	compiled, err := LoadDomainPack(&pack)
	require.NoError(t, err)
	require.Len(t, compiled, len(pack.Predicates))

	for technique := range pack.Predicates {
		_, ok := compiled[technique]
		assert.True(t, ok, "technique %q must have a compiled predicate", technique)
	}
}

// TestLoadDomainPack_MainCatalogPackEvaluates exercises each compiled seed
// predicate against evidence built to satisfy it, proving the bindings are
// not just syntactically valid but evaluate to their intended verdict.
func TestLoadDomainPack_MainCatalogPackEvaluates(t *testing.T) {
	pack := mustMainPack(t)
	compiled, err := LoadDomainPack(&pack)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("unauthenticated_endpoint_exposed", func(t *testing.T) {
		cp, ok := compiled["unauthenticated_endpoint_exposed"]
		require.True(t, ok)

		got, err := cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewHTTPResponseEvidence("resp", 200, nil, "", 0),
		})
		require.NoError(t, err)
		assert.True(t, got)

		got, err = cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewHTTPResponseEvidence("resp", 404, nil, "", 0),
		})
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("credential_disclosure_detected", func(t *testing.T) {
		cp, ok := compiled["credential_disclosure_detected"]
		require.True(t, ok)

		got, err := cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "found api_key: sk-live-abc123"),
		})
		require.NoError(t, err)
		assert.True(t, got)

		got, err = cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "nothing interesting here"),
		})
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("prompt_injection_marker_present", func(t *testing.T) {
		cp, ok := compiled["prompt_injection_marker_present"]
		require.True(t, ok)

		got, err := cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceConversation, "chat", finding.ConversationEvidence{
				Messages: []finding.ConversationMessage{{Role: "assistant", Content: "leaked: SYSTEM_PROMPT_LEAKED"}},
			}),
		})
		require.NoError(t, err)
		assert.True(t, got)

		got, err = cp.Evaluate(ctx, []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceConversation, "chat", finding.ConversationEvidence{
				Messages: []finding.ConversationMessage{{Role: "assistant", Content: "nothing to see"}},
			}),
		})
		require.NoError(t, err)
		assert.False(t, got)
	})
}

// mustMainPack returns the main pack from the embedded catalog.
func mustMainPack(t *testing.T) ontology.DomainPack {
	t.Helper()
	p, ok := ontology.EmbeddedPack(ontology.MainDomainPackName)
	if !ok {
		t.Fatal("the embedded catalog must hold the main pack")
	}
	return p
}

// TestLoadDomainPack_EveryEmbeddedCatalogPackCompiles: each pack file that
// the binary embeds compiles against the CEL environment. A new pack file
// gets this check with no Go change (gibson#710).
func TestLoadDomainPack_EveryEmbeddedCatalogPackCompiles(t *testing.T) {
	packs := ontology.EmbeddedCatalog().List()
	require.NotEmpty(t, packs)
	for i := range packs {
		t.Run(packs[i].Name, func(t *testing.T) {
			_, err := LoadDomainPack(&packs[i])
			require.NoError(t, err)
		})
	}
}
