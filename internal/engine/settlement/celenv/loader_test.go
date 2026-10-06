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

func TestLoadDomainPack_NilPack(t *testing.T) {
	_, err := LoadDomainPack(nil)
	assert.ErrorIs(t, err, ErrNilDomainPack)
}

func TestLoadDomainPack_EmptyPredicates(t *testing.T) {
	pack := &ontology.DomainPack{Name: "k8s", Version: 1}
	compiled, err := LoadDomainPack(pack)
	require.NoError(t, err)
	assert.Empty(t, compiled)
}

func TestLoadDomainPack_RunsPackValidateFirst(t *testing.T) {
	// A technique key that is not a ValidIdentifier fails DomainPack.Validate
	// before celenv ever sees the expression — this must not surface as a
	// CEL compile error.
	pack := &ontology.DomainPack{
		Name:    "k8s",
		Version: 1,
		Predicates: map[string]string{
			"not a valid identifier!": `true`,
		},
	}
	_, err := LoadDomainPack(pack)
	require.Error(t, err)
}

func TestLoadDomainPack_CompilesEveryPredicate(t *testing.T) {
	pack := &ontology.DomainPack{
		Name:       "k8s",
		Version:    1,
		Techniques: map[string]string{"T1190": "reconnaissance", "T1059": "extraction"},
		Predicates: map[string]string{
			"T1190": `evidence.exists(e, httpStatus(e) == 200)`,
			"T1059": `markerPresent(evidence, "nonce")`,
		},
	}
	compiled, err := LoadDomainPack(pack)
	require.NoError(t, err)
	require.Len(t, compiled, 2)

	t1190, ok := compiled["T1190"]
	require.True(t, ok)
	ok1, err := t1190.Evaluate(context.Background(), []finding.EnhancedEvidence{
		httpResponseEvidence(200, ""),
	})
	require.NoError(t, err)
	assert.True(t, ok1)

	t1059, ok := compiled["T1059"]
	require.True(t, ok)
	ok2, err := t1059.Evaluate(context.Background(), []finding.EnhancedEvidence{
		finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "nonce seen here"),
	})
	require.NoError(t, err)
	assert.True(t, ok2)
}

func TestLoadDomainPack_FailsClosedOnOutOfEnvironmentReference(t *testing.T) {
	pack := &ontology.DomainPack{
		Name:       "k8s",
		Version:    1,
		Techniques: map[string]string{"T1190": "reconnaissance", "T1059": "extraction"},
		Predicates: map[string]string{
			"T1190": `evidence.exists(e, httpStatus(e) == 200)`, // good
			"T1059": `evidence.exists(e, cvssScore(e) > 7.0)`,   // out-of-environment function
		},
	}
	compiled, err := LoadDomainPack(pack)
	require.Error(t, err)
	assert.Nil(t, compiled)
	assert.Contains(t, err.Error(), "T1059")
	assert.Contains(t, err.Error(), "cvssScore")
}

func TestLoadDomainPack_FailsClosedOnSyntaxError(t *testing.T) {
	pack := &ontology.DomainPack{
		Name:       "k8s",
		Version:    1,
		Techniques: map[string]string{"T1190": "reconnaissance", "T1059": "extraction"},
		Predicates: map[string]string{
			"T1190": `evidence.exists(e, e.type ==`,
		},
	}
	compiled, err := LoadDomainPack(pack)
	require.Error(t, err)
	assert.Nil(t, compiled)
}

func TestLoadDomainPack_FailsClosedOnNonBoolPredicate(t *testing.T) {
	pack := &ontology.DomainPack{
		Name:       "k8s",
		Version:    1,
		Techniques: map[string]string{"T1190": "reconnaissance", "T1059": "extraction"},
		Predicates: map[string]string{
			"T1190": `evidence.size()`,
		},
	}
	compiled, err := LoadDomainPack(pack)
	require.Error(t, err)
	assert.Nil(t, compiled)
}
