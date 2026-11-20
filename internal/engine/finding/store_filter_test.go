// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func filterSample() EnhancedFinding {
	f := NewEnhancedFinding(
		agent.NewFinding("Open SSH port", "Port 22 accepts password login", agent.SeverityHigh), types.NewID(), "recon")
	f.Category = string(CategoryPrivilegeEscalation)
	f.RiskScore = 5
	return f
}

func ptr[T any](v T) *T { return &v }

func TestFindingFilter_Matches(t *testing.T) {
	f := filterSample()
	tests := []struct {
		name   string
		filter *FindingFilter
		want   bool
	}{
		{"nil filter", nil, true},
		{"empty filter", &FindingFilter{}, true},
		{"same severity", &FindingFilter{Severity: ptr(agent.SeverityHigh)}, true},
		{"other severity", &FindingFilter{Severity: ptr(agent.SeverityLow)}, false},
		{"same category", &FindingFilter{Category: ptr(CategoryPrivilegeEscalation)}, true},
		{"other category", &FindingFilter{Category: ptr(FindingCategory("other"))}, false},
		{"same status", &FindingFilter{Status: ptr(StatusOpen)}, true},
		{"other status", &FindingFilter{Status: ptr(StatusFixed)}, false},
		{"risk at the minimum", &FindingFilter{MinRisk: ptr(5.0)}, true},
		{"risk under the minimum", &FindingFilter{MinRisk: ptr(5.1)}, false},
		{"risk at the maximum", &FindingFilter{MaxRisk: ptr(5.0)}, true},
		{"risk over the maximum", &FindingFilter{MaxRisk: ptr(4.9)}, false},
		{"same agent", &FindingFilter{AgentName: ptr("recon")}, true},
		{"other agent", &FindingFilter{AgentName: ptr("other")}, false},
		{"text in the title, other case", &FindingFilter{SearchText: ptr("SSH")}, true},
		{"text in the description", &FindingFilter{SearchText: ptr("PASSWORD")}, true},
		{"text in neither", &FindingFilter{SearchText: ptr("telnet")}, false},
		{"all fields match", &FindingFilter{
			Severity: ptr(agent.SeverityHigh), Status: ptr(StatusOpen), MinRisk: ptr(1.0), MaxRisk: ptr(9.0),
			AgentName: ptr("recon"), SearchText: ptr("ssh"),
		}, true},
		{"one field fails", &FindingFilter{Severity: ptr(agent.SeverityHigh), AgentName: ptr("other")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.filter.Matches(f))
		})
	}
}

func TestFindingError(t *testing.T) {
	cause := errors.New("disk full")
	withCause := &FindingError{Code: ErrorStoreFailed, Message: "write", Cause: cause}
	plain := &FindingError{Code: ErrorInvalidFinding, Message: "no title"}

	assert.Equal(t, "[store_failed] write: disk full", withCause.Error())
	assert.Equal(t, "[invalid_finding] no title", plain.Error())
	assert.Equal(t, cause, withCause.Unwrap())
	require.NoError(t, plain.Unwrap())
	require.ErrorIs(t, withCause, cause)

	require.ErrorIs(t, withCause, &FindingError{Code: ErrorStoreFailed}, "the code selects the match")
	require.NotErrorIs(t, withCause, &FindingError{Code: ErrorExportFailed})
	assert.False(t, withCause.Is(errors.New("other")), "an error of another type never matches")
}
