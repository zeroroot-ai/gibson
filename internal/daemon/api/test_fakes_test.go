// Package api — test_fakes_test.go provides deterministic in-memory
// fakes for the DaemonInterface, authzIface, and audit writer that
// exercise the mission-checkpointing handlers (ListCheckpoints /
// GetCheckpoint / DiffCheckpoints / ResumeMission rewind path) without
// needing the production Redis + FGA stack.
//
// All fakes are confined to test compilation by living in a *_test.go
// file. They share the api package with the handlers so they can
// reference unexported types (CheckpointData, authzIface, etc.).
package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/authz"
	missionpb "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// fakeDaemon is a programmable DaemonInterface that records calls and
// returns scripted responses.
type fakeDaemon struct {
	mu sync.RWMutex

	checkpoints map[string][]CheckpointData // missionID -> checkpoints
	payloads    map[string]*CheckpointData  // missionID|checkpointID -> rich payload
	rewindCalls []rewindCall                // recorded RewindMission calls
	rewindError error                       // override error on RewindMission
}

type rewindCall struct {
	MissionID    string
	TargetID     string
	MarkerResult string
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{
		checkpoints: make(map[string][]CheckpointData),
		payloads:    make(map[string]*CheckpointData),
	}
}

func (f *fakeDaemon) withCheckpoint(missionID string, cp CheckpointData) *fakeDaemon {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkpoints[missionID] = append(f.checkpoints[missionID], cp)
	stored := cp
	f.payloads[fakePayloadKey(missionID, cp.CheckpointID)] = &stored
	return f
}

func (f *fakeDaemon) rewindRecorded() []rewindCall {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]rewindCall, len(f.rewindCalls))
	copy(out, f.rewindCalls)
	return out
}

func (f *fakeDaemon) Status() (DaemonStatus, error) { return DaemonStatus{}, nil }
func (f *fakeDaemon) ListAgents(_ context.Context, _ string) ([]AgentInfoInternal, error) {
	return nil, nil
}
func (f *fakeDaemon) GetAgentStatus(_ context.Context, _ string) (AgentStatusInternal, error) {
	return AgentStatusInternal{}, nil
}
func (f *fakeDaemon) ListTools(_ context.Context) ([]ToolInfoInternal, error) { return nil, nil }
func (f *fakeDaemon) ListPlugins(_ context.Context) ([]PluginInfoInternal, error) {
	return nil, nil
}
func (f *fakeDaemon) QueryPlugin(_ context.Context, _, _ string, _ map[string]any) (any, error) {
	return nil, nil
}
func (f *fakeDaemon) RunMission(_ context.Context, _, _ string, _ map[string]string, _ string) (<-chan MissionEventData, error) {
	ch := make(chan MissionEventData)
	close(ch)
	return ch, nil
}
func (f *fakeDaemon) StopMission(_ context.Context, _ string, _ bool) error { return nil }
func (f *fakeDaemon) ListMissions(_ context.Context, _ bool, _, _ string, _, _ int) ([]MissionData, int, error) {
	return nil, 0, nil
}
func (f *fakeDaemon) Subscribe(_ context.Context, _ []string, _ string) (<-chan EventData, error) {
	ch := make(chan EventData)
	close(ch)
	return ch, nil
}
func (f *fakeDaemon) StartComponent(_ context.Context, _, _ string) (StartComponentResult, error) {
	return StartComponentResult{}, nil
}
func (f *fakeDaemon) StopComponent(_ context.Context, _, _ string, _ bool) (StopComponentResult, error) {
	return StopComponentResult{}, nil
}
func (f *fakeDaemon) PauseMission(_ context.Context, _ string, _ bool) error { return nil }
func (f *fakeDaemon) ResumeMission(_ context.Context, _ string) (<-chan MissionEventData, error) {
	ch := make(chan MissionEventData)
	close(ch)
	return ch, nil
}
func (f *fakeDaemon) GetMissionHistory(_ context.Context, _ string, _, _ int) ([]MissionRunData, int, error) {
	return nil, 0, nil
}

func (f *fakeDaemon) GetMissionCheckpoints(_ context.Context, missionID string) ([]CheckpointData, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	cps, ok := f.checkpoints[missionID]
	if !ok {
		return []CheckpointData{}, nil
	}
	out := make([]CheckpointData, len(cps))
	copy(out, cps)
	return out, nil
}

func (f *fakeDaemon) GetMissionCheckpointPayload(_ context.Context, missionID, checkpointID string) (*CheckpointData, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if p, ok := f.payloads[fakePayloadKey(missionID, checkpointID)]; ok && p != nil {
		cp := *p
		return &cp, nil
	}
	return nil, fmt.Errorf("checkpoint %s not found for mission %s: not found", checkpointID, missionID)
}

func (f *fakeDaemon) RewindMission(_ context.Context, missionID, targetCheckpointID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rewindError != nil {
		return "", f.rewindError
	}
	cps := f.checkpoints[missionID]
	for _, cp := range cps {
		if cp.CheckpointID == targetCheckpointID {
			marker := "manual-" + targetCheckpointID
			f.rewindCalls = append(f.rewindCalls, rewindCall{
				MissionID:    missionID,
				TargetID:     targetCheckpointID,
				MarkerResult: marker,
			})
			return marker, nil
		}
	}
	return "", fmt.Errorf("target checkpoint %s not found for mission %s: not found",
		targetCheckpointID, missionID)
}

func (f *fakeDaemon) BuildComponent(_ context.Context, _, _ string) (BuildComponentResult, error) {
	return BuildComponentResult{}, nil
}
func (f *fakeDaemon) ShowComponent(_ context.Context, _, _ string) (ComponentInfoInternal, error) {
	return ComponentInfoInternal{}, nil
}
func (f *fakeDaemon) GetComponentLogs(_ context.Context, _, _ string, _ bool, _ int) (<-chan LogEntryData, error) {
	ch := make(chan LogEntryData)
	close(ch)
	return ch, nil
}
func (f *fakeDaemon) ListMissionDefinitions(_ context.Context, _, _ int) ([]MissionDefinitionData, int, error) {
	return nil, 0, nil
}
func (f *fakeDaemon) GetMissionDefinition(_ context.Context, _ string) (*missionpb.MissionDefinition, error) {
	return nil, nil
}
func (f *fakeDaemon) CreateMission(_ context.Context, _ CreateMissionData) (CreateMissionResultData, error) {
	return CreateMissionResultData{}, nil
}
func (f *fakeDaemon) CreateMissionDefinition(_ context.Context, _ CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error) {
	return CreateMissionDefinitionResultData{}, nil
}
func (f *fakeDaemon) RequestShutdown(_ context.Context, _ bool, _ int32) error { return nil }
func (f *fakeDaemon) RefreshToolCatalog(_ context.Context) (bool, string, error) {
	return false, "", nil
}

func fakePayloadKey(missionID, checkpointID string) string {
	return missionID + "|" + checkpointID
}

// fakeAuthorizer is a programmable authzIface that scripts Check
// responses by (user, relation, object) tuple. Unscripted tuples return false.
type fakeAuthorizer struct {
	mu      sync.RWMutex
	allowed map[string]bool // user|relation|object
	checks  []checkRecord
}

type checkRecord struct {
	User, Relation, Object string
}

func newFakeAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{allowed: make(map[string]bool)}
}

func (a *fakeAuthorizer) allow(user, relation, object string) *fakeAuthorizer {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowed[user+"|"+relation+"|"+object] = true
	return a
}

func (a *fakeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checks = append(a.checks, checkRecord{User: user, Relation: relation, Object: object})
	return a.allowed[user+"|"+relation+"|"+object], nil
}

func (a *fakeAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		ok, _ := a.Check(ctx, c.User, c.Relation, c.Object)
		out[i] = ok
	}
	return out, nil
}

func (a *fakeAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (a *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (a *fakeAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (a *fakeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

// newFakeAuditWriter returns an instance of the fakeAuditWriter
// defined in tenant_admin_create_test.go (declared once package-wide).
func newFakeAuditWriter() *fakeAuditWriter { return &fakeAuditWriter{} }

// recordedEvents returns a copy of the captured audit events. Wrapper
// around the package-level fakeAuditWriter (no mutex) so tests can
// snapshot without racing with concurrent Log calls.
func (a *fakeAuditWriter) recorded() []audit.Event {
	out := make([]audit.Event, len(a.events))
	copy(out, a.events)
	return out
}
