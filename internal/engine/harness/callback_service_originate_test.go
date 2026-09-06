// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_service_originate_test.go covers the origination rule on
// CreateMission (ADR-0063, gibson#1657): an agent may originate a mission only
// from inside one it was dispatched to, and the parent, tenant and lineage come
// from the resolved mission record rather than from the request payload.

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// originMockHarness is a harness whose Mission() carries a full identity, so a
// test can assert what the handler copied off the parent.
type originMockHarness struct {
	DefaultAgentHarness
	mission MissionContext
}

func (m *originMockHarness) Mission() MissionContext { return m.mission }

// recordingMissionOperator captures the CreateMissionRequest the handler built.
type recordingMissionOperator struct {
	cbMockMissionOperator
	got *CreateMissionRequest
}

func (m *recordingMissionOperator) CreateMission(_ context.Context, req *CreateMissionRequest) (*MissionInfo, error) {
	m.got = req
	if m.createErr != nil {
		return nil, m.createErr
	}
	info := m.createInfo
	if info == nil {
		childID, _ := types.ParseID("11111111-2222-3333-4444-555555555555")
		info = &MissionInfo{ID: childID, Name: req.Name, TargetID: req.TargetID, ParentMissionID: req.ParentMissionID}
	}
	return info, nil
}

const (
	originParentMissionID = "0f0f0f0f-1111-2222-3333-444444444444"
	originTargetID        = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	originTenant          = "tenant-a"
)

// newOriginService wires a service with a live parent harness registered for
// (missionID, agentName), so getHarness resolves it.
func newOriginService(t *testing.T, mgr MissionOperator, missionID, agentName string) *HarnessCallbackService {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := NewCallbackHarnessRegistry()

	parentID, err := types.ParseID(originParentMissionID)
	require.NoError(t, err)
	registry.Register(missionID, agentName, &originMockHarness{
		mission: MissionContext{
			ID:              parentID,
			Name:            "watch-customer-portal",
			TenantID:        originTenant,
			MissionRunID:    "run-7",
			DelegationDepth: 2,
		},
	})
	return NewHarnessCallbackServiceWithRegistry(logger, registry, WithMissionManager(mgr))
}

func originRequest() *harnesspb.CreateMissionRequest {
	return &harnesspb.CreateMissionRequest{
		Context: &harnesspb.ContextInfo{
			MissionId: originParentMissionID,
			AgentName: "zerocool",
			TaskId:    "task-1",
		},
		TargetId: originTargetID,
		Name:     "scan-customer-portal",
		// These tests are about lineage, tenancy and the target, not about the
		// graph — but CreateMission now requires exactly one of a caller-supplied
		// graph or a named catalog mission (gibson#1688), so the fixture supplies
		// the simpler one. Origination with neither is refused, and
		// catalog_mission_origination_test.go covers that rule directly.
		MissionDefinitionJson: []byte(`{"name":"scan-customer-portal"}`),
	}
}

func originCtx() context.Context {
	return auth.ContextWithTenantString(context.Background(), originTenant)
}

// TestCreateMission_FromInsideItsParent_Succeeds is the happy path: the agent is
// running inside a live mission, so it may originate a child.
func TestCreateMission_FromInsideItsParent_Succeeds(t *testing.T) {
	mgr := &recordingMissionOperator{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

	resp, err := svc.CreateMission(originCtx(), originRequest())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error, "a mission originated from inside its parent must not error")
	require.NotNil(t, resp.Mission)
	assert.Equal(t, originParentMissionID, resp.Mission.ParentMissionId)

	require.NotNil(t, mgr.got, "the manager must have been called")
	require.NotNil(t, mgr.got.ParentMissionID)
	assert.Equal(t, originParentMissionID, mgr.got.ParentMissionID.String(),
		"the parent comes from the resolved mission record")
	assert.Equal(t, 2, mgr.got.ParentDepth, "the child inherits the parent's delegation depth")
}

// TestCreateMission_WithoutALiveParent_IsRefused is the ADR-0063 denial: a
// caller that is not inside a running mission cannot originate one. A bare
// component grant reaches this RPC and gets NotFound, because the registry
// holds no live harness for the mission it names.
func TestCreateMission_WithoutALiveParent_IsRefused(t *testing.T) {
	mgr := &recordingMissionOperator{}
	// A service whose registry holds a DIFFERENT mission: nothing is live for
	// the one the caller names.
	svc := newOriginService(t, mgr, "some-other-mission", "zerocool")

	resp, err := svc.CreateMission(originCtx(), originRequest())
	require.Error(t, err, "origination outside a live mission must be refused")
	assert.Nil(t, resp)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Nil(t, mgr.got, "no mission may be created when the parent cannot be proved")
}

// TestCreateMission_WithNoMissionContext_IsRefused: an empty context is the
// shape a caller outside any mission sends. It must never fall through to a
// parentless mission, because every bound origination has is relative to a
// parent.
func TestCreateMission_WithNoMissionContext_IsRefused(t *testing.T) {
	for name, ctxInfo := range map[string]*harnesspb.ContextInfo{
		"nil context":      nil,
		"empty mission id": {AgentName: "zerocool"},
		"empty agent name": {MissionId: originParentMissionID},
		"both empty":       {},
	} {
		t.Run(name, func(t *testing.T) {
			mgr := &recordingMissionOperator{}
			svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

			req := originRequest()
			req.Context = ctxInfo
			resp, err := svc.CreateMission(originCtx(), req)

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Nil(t, mgr.got, "a parentless mission must never be created")
		})
	}
}

// TestCreateMission_CrossTenantIsRefused: the caller's tenant must match the
// parent mission's. A child could otherwise be attributed into another tenant.
func TestCreateMission_CrossTenantIsRefused(t *testing.T) {
	mgr := &recordingMissionOperator{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-b")
	resp, err := svc.CreateMission(ctx, originRequest())

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, mgr.got, "no mission may cross a tenant boundary")
}

// TestCreateMission_LineageComesFromTheParentNotThePayload: the caller cannot
// launder attribution by sending its own lineage values.
func TestCreateMission_LineageComesFromTheParentNotThePayload(t *testing.T) {
	mgr := &recordingMissionOperator{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

	req := originRequest()
	req.Metadata = map[string]*commonpb.TypedValue{
		MetadataParentMissionID: {
			Kind: &commonpb.TypedValue_StringValue{StringValue: "somebody-elses-mission"},
		},
		MetadataOriginatingAgent: {
			Kind: &commonpb.TypedValue_StringValue{StringValue: "not-me"},
		},
		"application": {
			Kind: &commonpb.TypedValue_StringValue{StringValue: "customer-portal"},
		},
	}

	_, err := svc.CreateMission(originCtx(), req)
	require.NoError(t, err)
	require.NotNil(t, mgr.got)

	assert.Equal(t, originParentMissionID, mgr.got.Metadata[MetadataParentMissionID],
		"the payload's parent id must be overwritten by the resolved one")
	assert.Equal(t, "zerocool", mgr.got.Metadata[MetadataOriginatingAgent],
		"the originating agent comes from the proved context")
	assert.Equal(t, "run-7", mgr.got.Metadata[MetadataParentMissionRunID],
		"the child is attributable to one execution of the parent")
	assert.Equal(t, "customer-portal", mgr.got.Metadata["application"],
		"metadata the caller owns is preserved")
}

// TestCreateMission_NilManager_ReturnsUnavailable keeps the unconfigured case a
// clean error rather than a panic, and proves the manager check runs before the
// harness lookup so an unconfigured daemon does not look like a denial.
func TestCreateMission_NilManager_ReturnsUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewHarnessCallbackServiceWithRegistry(logger, NewCallbackHarnessRegistry())

	resp, err := svc.CreateMission(originCtx(), originRequest())
	require.NoError(t, err, "an unconfigured manager is reported in-band, not as a gRPC error")
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

// TestCreateMission_InvalidTargetIsRejected: the target is still the caller's to
// name, so a malformed one is an argument error rather than a denial.
func TestCreateMission_InvalidTargetIsRejected(t *testing.T) {
	mgr := &recordingMissionOperator{}
	svc := newOriginService(t, mgr, originParentMissionID, "zerocool")

	req := originRequest()
	req.TargetId = "not-a-uuid"
	resp, err := svc.CreateMission(originCtx(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
	assert.Nil(t, mgr.got)
}
