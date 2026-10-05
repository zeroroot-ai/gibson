// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// recordingMissionClient is the mission client behind the real adapter. It
// keeps the create request, so a test can read back the definition that the
// mission store gets.
type recordingMissionClient struct {
	MissionClientIface
	got *MissionClientCreateRequest
}

func (c *recordingMissionClient) CreateMission(_ context.Context, req *MissionClientCreateRequest) (*MissionClientInfo, error) {
	c.got = req
	return &MissionClientInfo{ID: types.NewID(), Name: req.Name}, nil
}

// storedConstraints creates a mission through the callback, with the real
// operator adapter, and reads back the constraints of the stored definition.
func storedConstraints(t *testing.T, req *harnesspb.CreateMissionRequest) *missionv1.MissionConstraints {
	t.Helper()
	client := &recordingMissionClient{}
	svc := newOriginService(t, NewMissionOperatorAdapter(client), originParentMissionID, "zerocool")

	resp, err := svc.CreateMission(originCtx(), req)
	require.NoError(t, err)
	require.Nil(t, resp.GetError(), "the mission must be created")
	require.NotNil(t, client.got, "the mission client must have been called")

	def, err := mission.UnmarshalDefinitionJSON([]byte(client.got.MissionDefinitionJSON))
	require.NoError(t, err)
	return def.GetConstraints()
}

// TestCreateMission_CanonicalConstraintsReachTheMission proves that a mission
// from the callback carries each field of the platform constraint type, not
// only the four fields of the deprecated message (gibson#683).
func TestCreateMission_CanonicalConstraintsReachTheMission(t *testing.T) {
	want := &missionv1.MissionConstraints{
		MaxDuration:       durationpb.New(30 * time.Minute),
		MaxTokens:         50000,
		MaxCost:           2.5,
		MaxFindings:       7,
		SeverityThreshold: "high",
		RequireEvidence:   true,
		BlockedTools:      []string{"native:masscan"},
		BlockedDomains:    []string{"prod.example.com"},
		MaxTurnsPerAgent:  12,
		AllowedTechniques: []string{"T1595"},
		BlockedTechniques: []string{"T1490"},
		MaxTokensPerCall:  4096,
	}
	req := originRequest()
	req.CanonicalConstraints = want

	got := storedConstraints(t, req)
	assert.True(t, proto.Equal(want, got), "stored constraints:\n got %v\nwant %v", got, want)
}

// A request with both fields uses the canonical one.
func TestCreateMission_CanonicalConstraintsWinOverTheDeprecatedMessage(t *testing.T) {
	req := originRequest()
	req.CanonicalConstraints = &missionv1.MissionConstraints{MaxTokens: 100, BlockedTools: []string{"native:nmap"}}
	req.Constraints = &harnesspb.MissionConstraints{MaxTokens: 999, MaxFindings: 5} //nolint:staticcheck // SA1019: the deprecated field under test

	got := storedConstraints(t, req)
	assert.EqualValues(t, 100, got.GetMaxTokens())
	assert.Zero(t, got.GetMaxFindings(), "the deprecated message must not be merged in")
	assert.Equal(t, []string{"native:nmap"}, got.GetBlockedTools())
}

// The sdk writes only the deprecated message until zeroroot-ai/sdk#180. Its
// four fields reach the mission.
func TestCreateMission_DeprecatedConstraintsStillReachTheMission(t *testing.T) {
	req := originRequest()
	req.Constraints = &harnesspb.MissionConstraints{ //nolint:staticcheck // SA1019: the deprecated field under test
		MaxDurationMs: 60000, MaxTokens: 42, MaxCost: 1.5, MaxFindings: 3,
	}

	got := storedConstraints(t, req)
	assert.Equal(t, time.Minute, got.GetMaxDuration().AsDuration())
	assert.EqualValues(t, 42, got.GetMaxTokens())
	assert.InDelta(t, 1.5, got.GetMaxCost(), 1e-9)
	assert.EqualValues(t, 3, got.GetMaxFindings())
}

// A request with no constraints leaves the constraints of the definition.
func TestCreateMission_NoRequestedConstraintsKeepsTheDefinition(t *testing.T) {
	req := originRequest()
	req.MissionDefinitionJson = []byte(`{"name":"scan","constraints":{"max_tokens":"77"}}`)

	got := storedConstraints(t, req)
	assert.EqualValues(t, 77, got.GetMaxTokens())
}
