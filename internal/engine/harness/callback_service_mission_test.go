package harness

// callback_service_mission_test.go contains unit tests for the six mission
// callback RPCs on HarnessCallbackService:
//   RunMission, GetMissionStatus, WaitForMission, ListMissions,
//   CancelMission, GetMissionResults.
//
// Strategy:
//   - A minimal mockMissionOperator satisfies the MissionOperator interface.
//   - Nil-manager cases verify that responses carry the UNAVAILABLE error code
//     rather than panicking.
//   - Missing-field cases verify INVALID_ARGUMENT error codes.
//   - Happy-path cases verify the response payload is correctly populated.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var cbTestLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// newCallbackService returns a HarnessCallbackService with no mission manager.
func newCallbackService() *HarnessCallbackService {
	return NewHarnessCallbackService(cbTestLogger)
}

// newCallbackServiceWithMgr returns a service wired to mgr.
func newCBCallbackServiceWithMgr(mgr MissionOperator) *HarnessCallbackService {
	return NewHarnessCallbackService(cbTestLogger, WithMissionManager(mgr))
}

// validMissionID is a well-formed UUID string accepted by types.ParseID.
const validMissionID = "01234567-89ab-cdef-0123-456789abcdef"

// ---------------------------------------------------------------------------
// cbMockMissionOperator — a simple stub used only within this file to avoid
// naming collisions with the richer mockMissionOperator in mission_test.go.
// ---------------------------------------------------------------------------

type cbMockMissionOperator struct {
	runErr        error
	statusInfo    *MissionStatusInfo
	statusErr     error
	waitResult    *MissionResultInfo
	waitErr       error
	listRecords   []*MissionRecord
	listErr       error
	cancelErr     error
	getResultInfo *MissionResultInfo
	getResultErr  error
	createInfo    *MissionInfo
	createErr     error
}

func (m *cbMockMissionOperator) CreateMission(_ context.Context, _ *CreateMissionRequest) (*MissionInfo, error) {
	return m.createInfo, m.createErr
}
func (m *cbMockMissionOperator) Run(_ context.Context, _ string) error {
	return m.runErr
}
func (m *cbMockMissionOperator) GetStatus(_ context.Context, _ string) (*MissionStatusInfo, error) {
	return m.statusInfo, m.statusErr
}
func (m *cbMockMissionOperator) WaitForCompletion(_ context.Context, _ string, _ time.Duration) (*MissionResultInfo, error) {
	return m.waitResult, m.waitErr
}
func (m *cbMockMissionOperator) List(_ context.Context, _ *MissionFilter) ([]*MissionRecord, error) {
	return m.listRecords, m.listErr
}
func (m *cbMockMissionOperator) Cancel(_ context.Context, _ types.ID) error {
	return m.cancelErr
}
func (m *cbMockMissionOperator) GetResults(_ context.Context, _ types.ID) (*MissionResultInfo, error) {
	return m.getResultInfo, m.getResultErr
}

// ---------------------------------------------------------------------------
// RunMission
// ---------------------------------------------------------------------------

func TestRunMission_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.RunMission(context.Background(), &harnesspb.RunMissionRequest{MissionId: validMissionID})
	require.NoError(t, err, "RPC must not return a gRPC error")
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestRunMission_MissingMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.RunMission(context.Background(), &harnesspb.RunMissionRequest{MissionId: ""})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestRunMission_ManagerError_ReturnsInternal(t *testing.T) {
	mgr := &cbMockMissionOperator{runErr: errors.New("queue full")}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.RunMission(context.Background(), &harnesspb.RunMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}

func TestRunMission_Success(t *testing.T) {
	mgr := &cbMockMissionOperator{}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.RunMission(context.Background(), &harnesspb.RunMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	assert.Nil(t, resp.Error, "no error expected on success")
}

// ---------------------------------------------------------------------------
// GetMissionStatus
// ---------------------------------------------------------------------------

func TestGetMissionStatus_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.GetMissionStatus(context.Background(), &harnesspb.GetMissionStatusRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestGetMissionStatus_MissingMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.GetMissionStatus(context.Background(), &harnesspb.GetMissionStatusRequest{MissionId: ""})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestGetMissionStatus_Success(t *testing.T) {
	mgr := &cbMockMissionOperator{
		statusInfo: &MissionStatusInfo{
			Status:   MissionStatusRunning,
			Progress: 0.42,
			Phase:    "reconnaissance",
		},
	}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.GetMissionStatus(context.Background(), &harnesspb.GetMissionStatusRequest{MissionId: validMissionID})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.Status)
	assert.InDelta(t, 0.42, resp.Status.Progress, 0.001)
	assert.Equal(t, "reconnaissance", resp.Status.Phase)
}

// ---------------------------------------------------------------------------
// WaitForMission
// ---------------------------------------------------------------------------

func TestWaitForMission_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.WaitForMission(context.Background(), &harnesspb.WaitForMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestWaitForMission_MissingMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.WaitForMission(context.Background(), &harnesspb.WaitForMissionRequest{MissionId: ""})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestWaitForMission_Success(t *testing.T) {
	completed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := &cbMockMissionOperator{
		waitResult: &MissionResultInfo{
			MissionID:   validMissionID,
			Status:      MissionStatusCompleted,
			CompletedAt: completed,
		},
	}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.WaitForMission(context.Background(), &harnesspb.WaitForMissionRequest{
		MissionId: validMissionID, TimeoutMs: 30000,
	})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.Equal(t, validMissionID, resp.Result.MissionId)
	assert.Equal(t, harnesspb.MissionStatus_MISSION_STATUS_COMPLETED, resp.Result.Status)
}

// ---------------------------------------------------------------------------
// ListMissions
// ---------------------------------------------------------------------------

func TestListMissions_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.ListMissions(context.Background(), &harnesspb.ListMissionsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestListMissions_EmptyList(t *testing.T) {
	mgr := &cbMockMissionOperator{listRecords: []*MissionRecord{}}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.ListMissions(context.Background(), &harnesspb.ListMissionsRequest{})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	assert.Empty(t, resp.Missions)
}

func TestListMissions_Success(t *testing.T) {
	id1, _ := types.ParseID(validMissionID)
	mgr := &cbMockMissionOperator{
		listRecords: []*MissionRecord{
			{ID: id1, Status: MissionStatusRunning},
		},
	}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.ListMissions(context.Background(), &harnesspb.ListMissionsRequest{})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	require.Len(t, resp.Missions, 1)
	assert.Equal(t, validMissionID, resp.Missions[0].Id)
	assert.Equal(t, harnesspb.MissionStatus_MISSION_STATUS_RUNNING, resp.Missions[0].Status)
}

func TestListMissions_ManagerError_ReturnsInternal(t *testing.T) {
	mgr := &cbMockMissionOperator{listErr: errors.New("redis timeout")}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.ListMissions(context.Background(), &harnesspb.ListMissionsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}

// ---------------------------------------------------------------------------
// CancelMission
// ---------------------------------------------------------------------------

func TestCancelMission_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.CancelMission(context.Background(), &harnesspb.CancelMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestCancelMission_MissingMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.CancelMission(context.Background(), &harnesspb.CancelMissionRequest{MissionId: ""})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestCancelMission_InvalidMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.CancelMission(context.Background(), &harnesspb.CancelMissionRequest{MissionId: "not-a-uuid"})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestCancelMission_Success(t *testing.T) {
	mgr := &cbMockMissionOperator{}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.CancelMission(context.Background(), &harnesspb.CancelMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
}

func TestCancelMission_ManagerError_ReturnsInternal(t *testing.T) {
	mgr := &cbMockMissionOperator{cancelErr: errors.New("not found")}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.CancelMission(context.Background(), &harnesspb.CancelMissionRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}

// ---------------------------------------------------------------------------
// GetMissionResults
// ---------------------------------------------------------------------------

func TestGetMissionResults_NilManager_ReturnsUnavailable(t *testing.T) {
	svc := newCallbackService()
	resp, err := svc.GetMissionResults(context.Background(), &harnesspb.GetMissionResultsRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.Error.Code)
}

func TestGetMissionResults_MissingMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.GetMissionResults(context.Background(), &harnesspb.GetMissionResultsRequest{MissionId: ""})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestGetMissionResults_InvalidMissionID_ReturnsInvalidArgument(t *testing.T) {
	svc := newCBCallbackServiceWithMgr(&cbMockMissionOperator{})
	resp, err := svc.GetMissionResults(context.Background(), &harnesspb.GetMissionResultsRequest{MissionId: "bad-id"})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
}

func TestGetMissionResults_Success(t *testing.T) {
	completed := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	mgr := &cbMockMissionOperator{
		getResultInfo: &MissionResultInfo{
			MissionID:   validMissionID,
			Status:      MissionStatusCompleted,
			CompletedAt: completed,
		},
	}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.GetMissionResults(context.Background(), &harnesspb.GetMissionResultsRequest{MissionId: validMissionID})
	require.NoError(t, err)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.Equal(t, validMissionID, resp.Result.MissionId)
	assert.Equal(t, harnesspb.MissionStatus_MISSION_STATUS_COMPLETED, resp.Result.Status)
}

func TestGetMissionResults_ManagerError_ReturnsInternal(t *testing.T) {
	mgr := &cbMockMissionOperator{getResultErr: errors.New("not found")}
	svc := newCBCallbackServiceWithMgr(mgr)
	resp, err := svc.GetMissionResults(context.Background(), &harnesspb.GetMissionResultsRequest{MissionId: validMissionID})
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}
