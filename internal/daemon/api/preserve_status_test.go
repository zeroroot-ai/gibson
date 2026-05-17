package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/datapool"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// ---------------------------------------------------------------------------
// preserveStatus unit tests
// Spec: per-tenant-data-plane-completion Req 8.1–8.3
// ---------------------------------------------------------------------------

func TestPreserveStatus_AlreadyHasCode(t *testing.T) {
	// A FailedPrecondition status from MapPoolError must not be rewrapped.
	fpErr := status.Errorf(codes.FailedPrecondition, "tenant data-plane not provisioned: foo")
	result := preserveStatus(fpErr, "failed to list missions")
	st, ok := status.FromError(result)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code(), "FailedPrecondition should be preserved")
}

func TestPreserveStatus_PlainError(t *testing.T) {
	// A plain Go error (no gRPC status) should be wrapped as Internal.
	plainErr := fmt.Errorf("some storage failure")
	result := preserveStatus(plainErr, "failed to list missions")
	st, ok := status.FromError(result)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code(), "plain error should become Internal")
}

func TestPreserveStatus_NilError(t *testing.T) {
	// nil passed through preserveStatus should return nil-equivalent.
	// status.FromError(nil) is ok=true, code=OK — so nil stays nil.
	result := preserveStatus(nil, "should not matter")
	// nil input: status.FromError returns (OK status, true). We return that —
	// but the callers only invoke preserveStatus when err != nil, so this just
	// verifies no panic.
	_ = result
}

func TestPreserveStatus_UnavailableCode(t *testing.T) {
	// Unavailable (e.g. EvictedError mapping) must also be preserved.
	unavErr := status.Errorf(codes.Unavailable, "pool evicted: tenant123")
	result := preserveStatus(unavErr, "failed to list missions")
	st, ok := status.FromError(result)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

// ---------------------------------------------------------------------------
// End-to-end handler test: ListMissions with NotProvisionedError
//
// Verifies that DaemonServer.ListMissions returns codes.FailedPrecondition
// when the underlying daemon returns a NotProvisionedError via MapPoolError.
// This catches the rewrap bug fixed in this task.
// ---------------------------------------------------------------------------

// notProvisionedDaemon is a minimal DaemonInterface that returns a
// NotProvisionedError (mapped through MapPoolError) from ListMissions.
type notProvisionedDaemon struct {
	// embed minimal no-op stubs for all required DaemonInterface methods.
	nilDaemonStub
}

func (n *notProvisionedDaemon) ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error) {
	// Simulate what list_missions.go does: call pool.For, get NotProvisionedError,
	// return datapool.MapPoolError(err).
	notProvisioned := &datapool.NotProvisionedError{
		Tenant: "tenant-abc",
		Reason: "redis logical-db index not allocated for tenant",
	}
	return nil, 0, datapool.MapPoolError(notProvisioned)
}

func TestListMissions_NotProvisionedReturnsFailedPrecondition(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &DaemonServer{
		daemon: &notProvisionedDaemon{},
		logger: logger,
	}

	// Set env var to skip registry coverage check (not relevant to this test).
	t.Setenv("GIBSON_SKIP_REGISTRY_COVERAGE_CHECK", "true")

	_, err := srv.ListMissions(context.Background(), &daemonpb.ListMissionsRequest{})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status")
	assert.Equal(t, codes.FailedPrecondition, st.Code(),
		"NotProvisionedError must reach the client as FailedPrecondition, not Internal")
}

// ---------------------------------------------------------------------------
// nilDaemonStub satisfies DaemonInterface with no-op implementations so that
// test mocks only need to override the methods they care about.
// ---------------------------------------------------------------------------

type nilDaemonStub struct{}

func (n nilDaemonStub) Status() (DaemonStatus, error) { return DaemonStatus{}, nil }
func (n nilDaemonStub) ListAgents(_ context.Context, _ string) ([]AgentInfoInternal, error) {
	return nil, nil
}
func (n nilDaemonStub) GetAgentStatus(_ context.Context, _ string) (AgentStatusInternal, error) {
	return AgentStatusInternal{}, nil
}
func (n nilDaemonStub) ListTools(_ context.Context) ([]ToolInfoInternal, error) { return nil, nil }
func (n nilDaemonStub) ListPlugins(_ context.Context) ([]PluginInfoInternal, error) {
	return nil, nil
}
func (n nilDaemonStub) QueryPlugin(_ context.Context, _, _ string, _ map[string]any) (any, error) {
	return nil, nil
}
func (n nilDaemonStub) RunMission(_ context.Context, _, _ string, _ map[string]string, _ string) (<-chan MissionEventData, error) {
	ch := make(chan MissionEventData)
	close(ch)
	return ch, nil
}
func (n nilDaemonStub) StopMission(_ context.Context, _ string, _ bool) error { return nil }
func (n nilDaemonStub) ListMissions(_ context.Context, _ bool, _, _ string, _, _ int) ([]MissionData, int, error) {
	return nil, 0, nil
}
func (n nilDaemonStub) Subscribe(_ context.Context, _ []string, _ string) (<-chan EventData, error) {
	ch := make(chan EventData)
	close(ch)
	return ch, nil
}
func (n nilDaemonStub) StartComponent(_ context.Context, _, _ string) (StartComponentResult, error) {
	return StartComponentResult{}, nil
}
func (n nilDaemonStub) StopComponent(_ context.Context, _, _ string, _ bool) (StopComponentResult, error) {
	return StopComponentResult{}, nil
}
func (n nilDaemonStub) PauseMission(_ context.Context, _ string, _ bool) error { return nil }
func (n nilDaemonStub) ResumeMission(_ context.Context, _ string) (<-chan MissionEventData, error) {
	ch := make(chan MissionEventData)
	close(ch)
	return ch, nil
}
func (n nilDaemonStub) GetMissionHistory(_ context.Context, _ string, _, _ int) ([]MissionRunData, int, error) {
	return nil, 0, nil
}
func (n nilDaemonStub) GetMissionCheckpoints(_ context.Context, _ string) ([]CheckpointData, error) {
	return nil, nil
}
func (n nilDaemonStub) GetMissionCheckpointPayload(_ context.Context, _, _ string) (*CheckpointData, error) {
	return nil, nil
}
func (n nilDaemonStub) RewindMission(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (n nilDaemonStub) BuildComponent(_ context.Context, _, _ string) (BuildComponentResult, error) {
	return BuildComponentResult{}, nil
}
func (n nilDaemonStub) ShowComponent(_ context.Context, _, _ string) (ComponentInfoInternal, error) {
	return ComponentInfoInternal{}, nil
}
func (n nilDaemonStub) GetComponentLogs(_ context.Context, _, _ string, _ bool, _ int) (<-chan LogEntryData, error) {
	ch := make(chan LogEntryData)
	close(ch)
	return ch, nil
}
func (n nilDaemonStub) ListMissionDefinitions(_ context.Context, _, _ int) ([]MissionDefinitionData, int, error) {
	return nil, 0, nil
}
func (n nilDaemonStub) GetMissionDefinition(_ context.Context, _ string) (*missionpb.MissionDefinition, error) {
	return nil, nil
}
func (n nilDaemonStub) CreateMission(_ context.Context, _ CreateMissionData) (CreateMissionResultData, error) {
	return CreateMissionResultData{}, nil
}
func (n nilDaemonStub) CreateMissionDefinition(_ context.Context, _ CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error) {
	return CreateMissionDefinitionResultData{}, nil
}
func (n nilDaemonStub) RequestShutdown(_ context.Context, _ bool, _ int32) error { return nil }
func (n nilDaemonStub) RefreshToolCatalog(_ context.Context) (bool, string, error) {
	return false, "", nil
}
