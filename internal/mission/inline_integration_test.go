package mission

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockInlineTargetCreator is a mock implementation of TargetCreator for integration tests.
type mockInlineTargetCreator struct {
	createdTargets []*types.Target
	createErr      error
}

func (m *mockInlineTargetCreator) Create(ctx context.Context, target *types.Target) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.createdTargets = append(m.createdTargets, target)
	return nil
}

// mockInlineWorkflowCreator is a mock implementation of WorkflowCreator for integration tests.
type mockInlineWorkflowCreator struct {
	createdDefinitions []*MissionDefinition
	createErr          error
}

func (m *mockInlineWorkflowCreator) CreateDefinition(ctx context.Context, def *MissionDefinition) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.createdDefinitions = append(m.createdDefinitions, def)
	return nil
}

// mockInlineMissionStore is a mock implementation of MissionStore for integration tests.
type mockInlineMissionStore struct {
	missions          map[types.ID]*Mission
	definitions       map[types.ID]*MissionDefinition
	savedMission      *Mission
	savedDefinition   *MissionDefinition
	saveErr           error
	createDefErr      error
	getDefinitionFunc func(id types.ID) (*MissionDefinition, error)
}

func newMockInlineMissionStore() *mockInlineMissionStore {
	return &mockInlineMissionStore{
		missions:    make(map[types.ID]*Mission),
		definitions: make(map[types.ID]*MissionDefinition),
	}
}

func (m *mockInlineMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	if mission, ok := m.missions[id]; ok {
		return mission, nil
	}
	return nil, NewNotFoundError(id.String())
}

func (m *mockInlineMissionStore) Save(ctx context.Context, mission *Mission) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.savedMission = mission
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockInlineMissionStore) List(ctx context.Context, filter MissionFilter) ([]*Mission, error) {
	result := make([]*Mission, 0, len(m.missions))
	for _, mission := range m.missions {
		result = append(result, mission)
	}
	return result, nil
}

func (m *mockInlineMissionStore) Delete(ctx context.Context, id types.ID) error {
	delete(m.missions, id)
	return nil
}

func (m *mockInlineMissionStore) Update(ctx context.Context, mission *Mission) error {
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockInlineMissionStore) CreateDefinition(ctx context.Context, def *MissionDefinition) error {
	if m.createDefErr != nil {
		return m.createDefErr
	}
	m.savedDefinition = def
	m.definitions[def.ID] = def
	return nil
}

func (m *mockInlineMissionStore) GetDefinition(ctx context.Context, id types.ID) (*MissionDefinition, error) {
	if m.getDefinitionFunc != nil {
		return m.getDefinitionFunc(id)
	}
	if def, ok := m.definitions[id]; ok {
		return def, nil
	}
	return nil, NewNotFoundError(id.String())
}

// mockInlineTargetStore is a mock implementation of TargetStoreInterface for integration tests.
type mockInlineTargetStore struct {
	targets        map[types.ID]*types.Target
	targetsByName  map[string]*types.Target
	createdTargets []*types.Target
}

func newMockInlineTargetStore() *mockInlineTargetStore {
	return &mockInlineTargetStore{
		targets:       make(map[types.ID]*types.Target),
		targetsByName: make(map[string]*types.Target),
	}
}

func (m *mockInlineTargetStore) Get(ctx context.Context, id types.ID) (*types.Target, error) {
	if target, ok := m.targets[id]; ok {
		return target, nil
	}
	return nil, NewNotFoundError(id.String())
}

func (m *mockInlineTargetStore) GetByName(ctx context.Context, name string) (*types.Target, error) {
	if target, ok := m.targetsByName[name]; ok {
		return target, nil
	}
	return nil, NewNotFoundError(name)
}

func (m *mockInlineTargetStore) Create(ctx context.Context, target *types.Target) error {
	m.createdTargets = append(m.createdTargets, target)
	m.targets[target.ID] = target
	if target.Name != "" {
		m.targetsByName[target.Name] = target
	}
	return nil
}

func (m *mockInlineTargetStore) AddTarget(target *types.Target) {
	m.targets[target.ID] = target
	if target.Name != "" {
		m.targetsByName[target.Name] = target
	}
}

// mockInlineWorkflowStore is a mock implementation of WorkflowStore for integration tests.
type mockInlineWorkflowStore struct {
	definitions map[types.ID]*MissionDefinition
}

func newMockInlineWorkflowStore() *mockInlineWorkflowStore {
	return &mockInlineWorkflowStore{
		definitions: make(map[types.ID]*MissionDefinition),
	}
}

func (m *mockInlineWorkflowStore) Get(ctx context.Context, id types.ID) (*MissionDefinition, error) {
	if def, ok := m.definitions[id]; ok {
		return def, nil
	}
	return nil, NewNotFoundError(id.String())
}

func (m *mockInlineWorkflowStore) GetByName(ctx context.Context, name string) (*MissionDefinition, error) {
	for _, def := range m.definitions {
		if def.Name == name {
			return def, nil
		}
	}
	return nil, NewNotFoundError(name)
}

func (m *mockInlineWorkflowStore) Add(def *MissionDefinition) {
	m.definitions[def.ID] = def
}

// Test creating mission with inline target
func TestCreateMissionWithInlineTarget(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add a pre-existing workflow for the mission
	workflowID := types.NewID()
	workflowStore.Add(&MissionDefinition{
		ID:          workflowID,
		Name:        "test-workflow",
		Description: "Test workflow",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with inline target
	config := &MissionConfig{
		Name:        "test-mission",
		Description: "Test mission with inline target",
		Target: MissionTargetConfig{
			Inline: &InlineTargetConfig{
				Seeds: []*TargetSeedConfig{
					{Value: "example.com", Type: "domain", Scope: "in_scope"},
				},
				Profile: "balanced",
				Depth:   2,
			},
		},
		Workflow: MissionWorkflowConfig{
			Reference: workflowID.String(),
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify mission was created
	assert.Equal(t, "test-mission", mission.Name)
	assert.Equal(t, MissionStatusPending, mission.Status)

	// Verify inline target was created
	assert.Len(t, targetStore.createdTargets, 1)
	createdTarget := targetStore.createdTargets[0]
	assert.Contains(t, string(createdTarget.ID), "inline-target-")
	assert.Contains(t, createdTarget.Config["profile"], "balanced")
}

// Test creating mission with inline workflow
func TestCreateMissionWithInlineWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add a pre-existing target for the mission
	targetID := types.NewID()
	targetStore.AddTarget(&types.Target{
		ID:        targetID,
		Name:      "test-target",
		Type:      "recon",
		Status:    types.TargetStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with inline workflow
	config := &MissionConfig{
		Name:        "test-mission",
		Description: "Test mission with inline workflow",
		Target: MissionTargetConfig{
			Reference: targetID.String(),
		},
		Workflow: MissionWorkflowConfig{
			Inline: &InlineWorkflowConfig{
				Name: "inline-test-workflow",
				Nodes: []*WorkflowNodeConfig{
					{ID: "node1", Type: "agent", Name: "recon-agent"},
					{ID: "node2", Type: "tool", Name: "nmap", DependsOn: []string{"node1"}},
				},
			},
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify mission was created
	assert.Equal(t, "test-mission", mission.Name)
	assert.Equal(t, targetID, mission.TargetID)

	// Verify inline workflow was created
	assert.NotNil(t, missionStore.savedDefinition)
	assert.Contains(t, string(missionStore.savedDefinition.ID), "inline-workflow-")
	assert.Equal(t, "inline-test-workflow", missionStore.savedDefinition.Name)
}

// Test creating mission with both inline target and inline workflow
func TestCreateMissionWithBothInlineConfigs(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with both inline target and inline workflow
	config := &MissionConfig{
		Name:        "fully-inline-mission",
		Description: "Test mission with both inline configs",
		Target: MissionTargetConfig{
			Inline: &InlineTargetConfig{
				Seeds: []*TargetSeedConfig{
					{Value: "api.example.com", Type: "host", Scope: "in_scope"},
					{Value: "192.168.1.0/24", Type: "cidr", Scope: "expand"},
				},
				Profile: "aggressive",
				Depth:   3,
			},
		},
		Workflow: MissionWorkflowConfig{
			Inline: &InlineWorkflowConfig{
				Name: "inline-recon-workflow",
				Nodes: []*WorkflowNodeConfig{
					{ID: "recon", Type: "agent", Name: "recon-agent"},
				},
			},
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify mission was created
	assert.Equal(t, "fully-inline-mission", mission.Name)

	// Verify both inline entities were created
	assert.Len(t, targetStore.createdTargets, 1)
	assert.Contains(t, string(targetStore.createdTargets[0].ID), "inline-target-")

	assert.NotNil(t, missionStore.savedDefinition)
	assert.Contains(t, string(missionStore.savedDefinition.ID), "inline-workflow-")
}

// Test error when both reference and inline target are provided
func TestCreateMissionErrorBothTargetConfigs(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add target and workflow for references
	targetID := types.NewID()
	targetStore.AddTarget(&types.Target{
		ID:        targetID,
		Name:      "test-target",
		Type:      "recon",
		Status:    types.TargetStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	workflowID := types.NewID()
	workflowStore.Add(&MissionDefinition{
		ID:          workflowID,
		Name:        "test-workflow",
		Description: "Test workflow",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with both reference and inline target (should fail)
	config := &MissionConfig{
		Name: "invalid-mission",
		Target: MissionTargetConfig{
			Reference: targetID.String(),
			Inline: &InlineTargetConfig{
				Seeds: []*TargetSeedConfig{
					{Value: "example.com", Type: "domain"},
				},
				Profile: "balanced",
				Depth:   2,
			},
		},
		Workflow: MissionWorkflowConfig{
			Reference: workflowID.String(),
		},
	}

	// Create mission should fail
	_, err := service.CreateFromConfig(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both")
}

// Test error when both reference and inline workflow are provided
func TestCreateMissionErrorBothWorkflowConfigs(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add target and workflow for references
	targetID := types.NewID()
	targetStore.AddTarget(&types.Target{
		ID:        targetID,
		Name:      "test-target",
		Type:      "recon",
		Status:    types.TargetStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	workflowID := types.NewID()
	workflowStore.Add(&MissionDefinition{
		ID:          workflowID,
		Name:        "test-workflow",
		Description: "Test workflow",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with both reference and inline workflow (should fail)
	config := &MissionConfig{
		Name: "invalid-mission",
		Target: MissionTargetConfig{
			Reference: targetID.String(),
		},
		Workflow: MissionWorkflowConfig{
			Reference: workflowID.String(),
			Inline: &InlineWorkflowConfig{
				Name: "inline-workflow",
				Nodes: []*WorkflowNodeConfig{
					{ID: "node1", Type: "agent", Name: "test-agent"},
				},
			},
		},
	}

	// Create mission should fail
	_, err := service.CreateFromConfig(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both")
}

// Test mixed configs: inline target with referenced workflow
func TestCreateMissionMixedInlineTargetReferencedWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add pre-existing workflow
	workflowID := types.NewID()
	workflowStore.Add(&MissionDefinition{
		ID:          workflowID,
		Name:        "existing-workflow",
		Description: "Pre-existing workflow",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with inline target and referenced workflow
	config := &MissionConfig{
		Name:        "mixed-mission",
		Description: "Mission with inline target and referenced workflow",
		Target: MissionTargetConfig{
			Inline: &InlineTargetConfig{
				Seeds: []*TargetSeedConfig{
					{Value: "test.example.com", Type: "domain"},
				},
				Profile: "stealth",
				Depth:   1,
			},
		},
		Workflow: MissionWorkflowConfig{
			Reference: workflowID.String(),
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify mission was created correctly
	assert.Equal(t, "mixed-mission", mission.Name)
	assert.Equal(t, workflowID, mission.WorkflowID)

	// Verify inline target was created
	assert.Len(t, targetStore.createdTargets, 1)
	assert.Contains(t, string(mission.TargetID), "inline-target-")
}

// Test mixed configs: referenced target with inline workflow
func TestCreateMissionMixedReferencedTargetInlineWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add pre-existing target
	targetID := types.NewID()
	targetStore.AddTarget(&types.Target{
		ID:        targetID,
		Name:      "existing-target",
		Type:      "recon",
		Status:    types.TargetStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with referenced target and inline workflow
	config := &MissionConfig{
		Name:        "mixed-mission-2",
		Description: "Mission with referenced target and inline workflow",
		Target: MissionTargetConfig{
			Reference: targetID.String(),
		},
		Workflow: MissionWorkflowConfig{
			Inline: &InlineWorkflowConfig{
				Name: "ad-hoc-workflow",
				Nodes: []*WorkflowNodeConfig{
					{ID: "scan", Type: "agent", Name: "scanner-agent"},
					{ID: "report", Type: "tool", Name: "reporter", DependsOn: []string{"scan"}},
				},
				Edges: []*WorkflowEdgeConfig{
					{From: "scan", To: "report"},
				},
			},
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify mission was created correctly
	assert.Equal(t, "mixed-mission-2", mission.Name)
	assert.Equal(t, targetID, mission.TargetID)

	// Verify inline workflow was created
	assert.NotNil(t, missionStore.savedDefinition)
	assert.Contains(t, string(mission.WorkflowID), "inline-workflow-")
}

// Test inline target with metadata
func TestCreateMissionInlineTargetWithMetadata(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	missionStore := newMockInlineMissionStore()
	targetStore := newMockInlineTargetStore()
	workflowStore := newMockInlineWorkflowStore()

	// Add workflow
	workflowID := types.NewID()
	workflowStore.Add(&MissionDefinition{
		ID:        workflowID,
		Name:      "test-workflow",
		Version:   "1.0.0",
		CreatedAt: time.Now(),
	})

	// Create service with inline processor
	service := NewMissionService(missionStore, workflowStore, nil)
	service.SetTargetStore(targetStore)

	// Create inline processor
	inlineProcessor := NewInlineConfigProcessor(targetStore, missionStore)
	service.SetInlineProcessor(inlineProcessor)

	// Create mission config with inline target that has metadata
	config := &MissionConfig{
		Name: "metadata-mission",
		Target: MissionTargetConfig{
			Inline: &InlineTargetConfig{
				Seeds: []*TargetSeedConfig{
					{Value: "meta.example.com", Type: "domain"},
				},
				Profile: "balanced",
				Depth:   2,
				Metadata: map[string]string{
					"project":  "security-audit",
					"priority": "high",
					"owner":    "security-team",
				},
			},
		},
		Workflow: MissionWorkflowConfig{
			Reference: workflowID.String(),
		},
	}

	// Create mission
	mission, err := service.CreateFromConfig(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, mission)

	// Verify inline target was created with metadata
	require.Len(t, targetStore.createdTargets, 1)
	createdTarget := targetStore.createdTargets[0]
	assert.Equal(t, "security-audit", createdTarget.Config["project"])
	assert.Equal(t, "high", createdTarget.Config["priority"])
}
