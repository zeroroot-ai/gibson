// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package builtin

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

const testTechnique settlement.TechniqueID = "T1190"

func TestRegisterMarkerPresent(t *testing.T) {
	r := settlement.NewRegistry()
	require.NoError(t, RegisterMarkerPresent(r, testTechnique))
	assert.True(t, r.Registered(testTechnique, MarkerPresentType))

	t.Run("registering twice under the same technique fails closed", func(t *testing.T) {
		err := RegisterMarkerPresent(r, testTechnique)
		require.Error(t, err)
		assert.ErrorIs(t, err, settlement.ErrAlreadyRegistered)
	})
}

func TestMarkerPresent_Evaluate(t *testing.T) {
	ctx := context.Background()
	r := settlement.NewRegistry()
	require.NoError(t, RegisterMarkerPresent(r, testTechnique))

	newPredicate := func(t *testing.T, marker string, evType finding.EvidenceType) settlement.Predicate {
		t.Helper()
		p, err := r.NewPredicate(testTechnique, MarkerPresentType, MarkerPresentParams{
			Marker:       marker,
			EvidenceType: evType,
		})
		require.NoError(t, err)
		return p
	}

	tests := []struct {
		name     string
		marker   string
		evType   finding.EvidenceType
		evidence []finding.EnhancedEvidence
		want     bool
		wantErr  bool
	}{
		{
			name:   "marker present in a log entry",
			marker: "proof-token-9f3a",
			evidence: []finding.EnhancedEvidence{
				finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "saw proof-token-9f3a in output"),
			},
			want: true,
		},
		{
			name:   "marker absent",
			marker: "proof-token-9f3a",
			evidence: []finding.EnhancedEvidence{
				finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "nothing here"),
			},
			want: false,
		},
		{
			name:     "no evidence at all",
			marker:   "proof-token-9f3a",
			evidence: nil,
			want:     false,
		},
		{
			name:   "marker present in HTTP response body",
			marker: "proof-token-9f3a",
			evidence: []finding.EnhancedEvidence{
				finding.NewHTTPResponseEvidence("resp", 200, nil, "body contains proof-token-9f3a here", 0),
			},
			want: true,
		},
		{
			name:   "marker present but wrong evidence-type filter excludes it",
			marker: "proof-token-9f3a",
			evType: finding.EvidenceHTTPResponse,
			evidence: []finding.EnhancedEvidence{
				finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "proof-token-9f3a"),
			},
			want: false,
		},
		{
			name:   "marker present in conversation content",
			marker: "proof-token-9f3a",
			evidence: []finding.EnhancedEvidence{
				finding.NewConversationEvidence("chat", []finding.ConversationMessage{
					finding.NewConversationMessage("assistant", "here is proof-token-9f3a"),
				}),
			},
			want: true,
		},
		{
			name:   "substring match is exact, case-sensitive",
			marker: "Proof-Token",
			evidence: []finding.EnhancedEvidence{
				finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "proof-token"),
			},
			want: false,
		},
		{
			name:    "empty marker is rejected at evaluation time",
			marker:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPredicate(t, tt.marker, tt.evType)
			ok, err := r.Evaluate(ctx, p, tt.evidence)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestMarkerPresent_Evaluate_Deterministic(t *testing.T) {
	ctx := context.Background()
	r := settlement.NewRegistry()
	require.NoError(t, RegisterMarkerPresent(r, testTechnique))

	p, err := r.NewPredicate(testTechnique, MarkerPresentType, MarkerPresentParams{Marker: "nonce-1234"})
	require.NoError(t, err)

	evidence := []finding.EnhancedEvidence{
		finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "nonce-1234"),
	}

	for i := 0; i < 50; i++ {
		ok, err := r.Evaluate(ctx, p, evidence)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestRegisterHTTPStatusEquals(t *testing.T) {
	r := settlement.NewRegistry()
	require.NoError(t, RegisterHTTPStatusEquals(r, testTechnique))
	assert.True(t, r.Registered(testTechnique, HTTPStatusEqualsType))
}

func TestHTTPStatusEquals_Evaluate(t *testing.T) {
	ctx := context.Background()
	r := settlement.NewRegistry()
	require.NoError(t, RegisterHTTPStatusEquals(r, testTechnique))

	tests := []struct {
		name     string
		want     int
		evidence []finding.EnhancedEvidence
		wantOK   bool
		wantErr  bool
	}{
		{
			name: "matching status",
			want: 200,
			evidence: []finding.EnhancedEvidence{
				finding.NewHTTPResponseEvidence("resp", 200, nil, "ok", 10*time.Millisecond),
			},
			wantOK: true,
		},
		{
			name: "non-matching status",
			want: 200,
			evidence: []finding.EnhancedEvidence{
				finding.NewHTTPResponseEvidence("resp", 403, nil, "forbidden", 10*time.Millisecond),
			},
			wantOK: false,
		},
		{
			name: "ignores non-HTTP-response evidence",
			want: 200,
			evidence: []finding.EnhancedEvidence{
				finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "status 200 mentioned but not structured"),
			},
			wantOK: false,
		},
		{
			name: "matches the first of several responses",
			want: 500,
			evidence: []finding.EnhancedEvidence{
				finding.NewHTTPResponseEvidence("resp1", 200, nil, "ok", 0),
				finding.NewHTTPResponseEvidence("resp2", 500, nil, "err", 0),
			},
			wantOK: true,
		},
		{
			name:    "invalid want status is rejected at evaluation time",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := r.NewPredicate(testTechnique, HTTPStatusEqualsType, HTTPStatusEqualsParams{Want: tt.want})
			require.NoError(t, err)

			ok, err := r.Evaluate(ctx, p, tt.evidence)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}
