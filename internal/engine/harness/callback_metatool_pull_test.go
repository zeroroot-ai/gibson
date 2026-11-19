// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// authzLookupStub answers Get with a fixed state or error.
type authzLookupStub struct {
	state *RunAuthzState
	err   error
}

func (a authzLookupStub) Get(context.Context, string) (*RunAuthzState, error) { return a.state, a.err }

// wiredService returns a service with the three parts that meta-tools need.
// The registry and the authorizer are empty, because the tests below stop
// before they call either one.
func wiredService(t *testing.T, store RunAuthzLookup) *HarnessCallbackService {
	t.Helper()
	s := newSvc(t)
	s.componentRegistry = struct{ component.ComponentRegistry }{}
	s.componentAuthorizer = struct{ authz.Authorizer }{}
	s.authzStore = store
	return s
}

func TestCallMetaTool_RefusesBeforeAnyDispatch(t *testing.T) {
	tests := []struct {
		name    string
		svc     func(t *testing.T) *HarnessCallbackService
		runID   string
		wantErr commonpb.ErrorCode
		wantMsg string
	}{
		{
			name:    "the catalog is not wired",
			svc:     newSvc,
			runID:   "run-1",
			wantErr: commonpb.ErrorCode_ERROR_CODE_INTERNAL,
			wantMsg: "meta-tools are not wired",
		},
		{
			name: "no run ID",
			svc: func(t *testing.T) *HarnessCallbackService {
				t.Helper()
				return wiredService(t, authzLookupStub{})
			},
			runID:   "",
			wantErr: commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
			wantMsg: "needs the work item of a mission run",
		},
		{
			name: "no authz state for the run",
			svc: func(t *testing.T) *HarnessCallbackService {
				t.Helper()
				return wiredService(t, authzLookupStub{err: ErrRunNotFound})
			},
			runID:   "run-1",
			wantErr: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
			wantMsg: "run authz state not found",
		},
		{
			name: "the run belongs to another tenant",
			svc: func(t *testing.T) *HarnessCallbackService {
				t.Helper()
				return wiredService(t, authzLookupStub{state: &RunAuthzState{TenantID: "other"}})
			},
			runID:   "run-1",
			wantErr: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
			wantMsg: "run authz state not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.svc(t).CallMetaTool(context.Background(), "acme", "m1", tt.runID, "search_tools", nil)

			require.NoError(t, err, "the refusal is the response")
			require.NotNil(t, resp.GetError())
			assert.Equal(t, tt.wantErr, resp.GetError().GetCode())
			assert.Contains(t, resp.GetError().GetMessage(), tt.wantMsg)
			assert.Empty(t, resp.GetOutputJson())
		})
	}
}

func TestCallMetaTool_StoreErrorIsNotLeaked(t *testing.T) {
	s := wiredService(t, authzLookupStub{err: errors.New("redis password is hunter2")})

	resp, err := s.CallMetaTool(context.Background(), "acme", "m1", "run-1", "search_tools", nil)

	require.NoError(t, err)
	assert.NotContains(t, resp.GetError().GetMessage(), "hunter2")
}

func TestMissionStatusProto_UnknownValues(t *testing.T) {
	assert.Equal(t, harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED, missionStatusToProto("nonsense"))
	assert.Equal(t, harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED, missionStatusToProto(""))
	assert.Equal(t, MissionStatus(""), missionStatusFromProto(harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED))
	assert.Equal(t, MissionStatus(""), missionStatusFromProto(harnesspb.MissionStatus(999)))
}
