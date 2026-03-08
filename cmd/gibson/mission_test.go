package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/cmd/gibson/core"
	"github.com/zero-day-ai/gibson/internal/config"
	dclient "github.com/zero-day-ai/gibson/internal/daemon/client"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestMissionList(t *testing.T) {
	tests := []struct {
		name          string
		setupMissions func(*state.StateClient) error
		statusFilter  string
		wantCount     int
		wantError     bool
	}{
		{
			name: "list all missions",
			setupMissions: func(client *state.StateClient) error {
				store := mission.NewRedisMissionStore(client)
				missions := []*mission.Mission{
					{
						ID:            types.NewID(),
						Name:          "test-mission-1",
						Description:   "Test mission 1",
						Status:        mission.MissionStatusPending,
						TargetID:      types.NewID(),
						WorkflowID:    types.NewID(),
						Progress:      0.0,
						FindingsCount: 0,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					},
					{
						ID:            types.NewID(),
						Name:          "test-mission-2",
						Description:   "Test mission 2",
						Status:        mission.MissionStatusRunning,
						TargetID:      types.NewID(),
						WorkflowID:    types.NewID(),
						Progress:      0.5,
						FindingsCount: 3,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					},
				}
				for _, m := range missions {
					if err := store.Save(context.Background(), m); err != nil {
						return err
					}
				}
				return nil
			},
			statusFilter: "",
			wantCount:    2,
			wantError:    false,
		},
		{
			name: "list missions with status filter",
			setupMissions: func(client *state.StateClient) error {
				store := mission.NewRedisMissionStore(client)
				missions := []*mission.Mission{
					{
						ID:            types.NewID(),
						Name:          "pending-mission",
						Description:   "Pending mission",
						Status:        mission.MissionStatusPending,
						TargetID:      types.NewID(),
						WorkflowID:    types.NewID(),
						Progress:      0.0,
						FindingsCount: 0,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					},
					{
						ID:            types.NewID(),
						Name:          "running-mission",
						Description:   "Running mission",
						Status:        mission.MissionStatusRunning,
						TargetID:      types.NewID(),
						WorkflowID:    types.NewID(),
						Progress:      0.5,
						FindingsCount: 2,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					},
				}
				for _, m := range missions {
					if err := store.Save(context.Background(), m); err != nil {
						return err
					}
				}
				return nil
			},
			statusFilter: "running",
			wantCount:    1,
			wantError:    false,
		},
		{
			name: "empty list",
			setupMissions: func(client *state.StateClient) error {
				return nil
			},
			statusFilter: "",
			wantCount:    0,
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Setup missions
			if tt.setupMissions != nil {
				require.NoError(t, tt.setupMissions(stateClient))
			}

			// Create command
			cmd := missionListCmd
			cmd.SetContext(context.Background())

			// Set global flags directly (since test doesn't go through root command)
			globalFlags.HomeDir = homeDir

			// Set command-specific flags
			if tt.statusFilter != "" {
				cmd.Flags().Set("status", tt.statusFilter)
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{})

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify count in output
				output := buf.String()
				if tt.wantCount == 0 {
					assert.Contains(t, output, "No missions found")
				} else {
					// Basic check that output contains mission names
					assert.NotEmpty(t, output)
				}
			}
		})
	}
}

func TestMissionShow(t *testing.T) {
	tests := []struct {
		name        string
		missionName string
		setup       func(*state.StateClient) error
		wantError   bool
		checkOutput func(*testing.T, string)
	}{
		{
			name:        "show existing mission",
			missionName: "test-mission",
			setup: func(client *state.StateClient) error {
				store := mission.NewRedisMissionStore(client)
				m := &mission.Mission{
					ID:            types.NewID(),
					Name:          "test-mission",
					Description:   "Test mission description",
					Status:        mission.MissionStatusRunning,
					TargetID:      types.NewID(),
					WorkflowID:    types.NewID(),
					Progress:      0.75,
					FindingsCount: 5,
					AgentAssignments: map[string]string{
						"node1": "agent-1",
						"node2": "agent-2",
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				return store.Save(context.Background(), m)
			},
			wantError: false,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "test-mission")
				assert.Contains(t, output, "Test mission description")
				assert.Contains(t, output, "running")
				assert.Contains(t, output, "75.0%")
				assert.Contains(t, output, "5")
			},
		},
		{
			name:        "show non-existent mission",
			missionName: "non-existent",
			setup:       nil,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Setup
			if tt.setup != nil {
				require.NoError(t, tt.setup(stateClient))
			}

			// Create command
			cmd := missionShowCmd
			cmd.SetContext(context.Background())
			globalFlags.HomeDir = homeDir

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{tt.missionName})

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkOutput != nil {
					tt.checkOutput(t, buf.String())
				}
			}
		})
	}
}

func TestMissionRun(t *testing.T) {
	tests := []struct {
		name         string
		workflowYAML string
		wantError    bool
		checkMission func(*testing.T, *mission.Mission)
	}{
		{
			name: "run valid workflow",
			workflowYAML: `
name: Test Workflow
description: A test workflow
nodes:
  - id: node1
    type: agent
    name: First Node
    agent: test-agent
    task:
      action: test
`,
			// Mission run requires a valid target - this test expects an error because no target is configured
			wantError:    true,
			checkMission: nil,
		},
		{
			name: "run invalid workflow - no nodes",
			workflowYAML: `
name: Invalid Workflow
description: Missing nodes
nodes: []
`,
			wantError: true,
		},
		{
			name: "run invalid workflow - malformed YAML",
			workflowYAML: `
name: Broken
nodes
  - invalid
`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Create workflow file
			workflowFile := filepath.Join(tmpDir, "workflow.yaml")
			require.NoError(t, os.WriteFile(workflowFile, []byte(tt.workflowYAML), 0644))

			// Create command
			cmd := missionRunCmd
			cmd.SetContext(context.Background())
			globalFlags.HomeDir = homeDir
			cmd.Flags().Set("file", workflowFile)

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{})

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify mission was created
				if tt.checkMission != nil {
					store := mission.NewRedisMissionStore(stateClient)
					missions, err := store.List(context.Background(), mission.NewMissionFilter())
					require.NoError(t, err)
					require.Len(t, missions, 1)
					tt.checkMission(t, missions[0])
				}
			}
		})
	}
}

func TestMissionResume(t *testing.T) {
	tests := []struct {
		name          string
		missionName   string
		missionStatus mission.MissionStatus
		wantError     bool
		errorContains string
	}{
		{
			name:          "resume paused mission",
			missionName:   "paused-mission",
			missionStatus: mission.MissionStatusCancelled,
			wantError:     true,
			errorContains: "cannot resume",
		},
		{
			name:          "resume completed mission",
			missionName:   "completed-mission",
			missionStatus: mission.MissionStatusCompleted,
			wantError:     true,
			errorContains: "cannot resume completed",
		},
		{
			name:          "resume failed mission",
			missionName:   "failed-mission",
			missionStatus: mission.MissionStatusFailed,
			wantError:     true,
			errorContains: "cannot resume failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Create mission
			store := mission.NewRedisMissionStore(stateClient)
			m := &mission.Mission{
				ID:            types.NewID(),
				Name:          tt.missionName,
				Description:   "Test mission",
				Status:        tt.missionStatus,
				TargetID:      types.NewID(),
				WorkflowID:    types.NewID(),
				Progress:      0.5,
				FindingsCount: 0,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			require.NoError(t, store.Save(context.Background(), m))

			// Create command
			cmd := missionResumeCmd
			cmd.SetContext(context.Background())
			globalFlags.HomeDir = homeDir

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{tt.missionName})

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMissionStop(t *testing.T) {
	tests := []struct {
		name          string
		missionName   string
		missionStatus mission.MissionStatus
		wantError     bool
		errorContains string
	}{
		{
			name:          "stop running mission",
			missionName:   "running-mission",
			missionStatus: mission.MissionStatusRunning,
			wantError:     false,
		},
		{
			name:          "stop pending mission",
			missionName:   "pending-mission",
			missionStatus: mission.MissionStatusPending,
			wantError:     true,
			errorContains: "not running",
		},
		{
			name:          "stop completed mission",
			missionName:   "completed-mission",
			missionStatus: mission.MissionStatusCompleted,
			wantError:     true,
			errorContains: "not running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Create mission
			store := mission.NewRedisMissionStore(stateClient)
			now := time.Now()
			m := &mission.Mission{
				ID:            types.NewID(),
				Name:          tt.missionName,
				Description:   "Test mission",
				Status:        tt.missionStatus,
				TargetID:      types.NewID(),
				WorkflowID:    types.NewID(),
				Progress:      0.5,
				FindingsCount: 0,
				StartedAt:     &now,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			require.NoError(t, store.Save(context.Background(), m))

			// Create command
			cmd := missionStopCmd
			cmd.SetContext(context.Background())
			globalFlags.HomeDir = homeDir

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{tt.missionName})

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify status was updated
				updatedMission, err := store.GetByName(context.Background(), tt.missionName)
				require.NoError(t, err)
				assert.Equal(t, mission.MissionStatusCancelled, updatedMission.Status)
			}
		})
	}
}

func TestMissionDelete(t *testing.T) {
	tests := []struct {
		name        string
		missionName string
		force       bool
		wantError   bool
	}{
		{
			name:        "delete with force flag",
			missionName: "test-mission",
			force:       true,
			wantError:   false,
		},
		{
			name:        "delete non-existent mission",
			missionName: "non-existent",
			force:       true,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Setup test environment
			tmpDir := t.TempDir()
			homeDir := filepath.Join(tmpDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			// Skip tests requiring Redis
			t.Skip("requires Redis")

			// Initialize config
			cfg := config.DefaultConfig()
			cfg.Core.HomeDir = homeDir

			// Create StateClient
			stateCfg := &state.Config{
				URL: "redis://localhost:6379",
			}
			stateCfg.ApplyDefaults()

			stateClient, err := state.NewStateClient(stateCfg)
			require.NoError(t, err)
			defer stateClient.Close()

			// Create mission if it should exist
			if tt.missionName == "test-mission" {
				store := mission.NewRedisMissionStore(stateClient)
				m := &mission.Mission{
					ID:            types.NewID(),
					Name:          tt.missionName,
					Description:   "Test mission",
					Status:        mission.MissionStatusCompleted,
					TargetID:      types.NewID(),
					WorkflowID:    types.NewID(),
					Progress:      1.0,
					FindingsCount: 0,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				require.NoError(t, store.Save(context.Background(), m))
			}

			// Create command
			cmd := missionDeleteCmd
			cmd.SetContext(context.Background())
			globalFlags.HomeDir = homeDir
			if tt.force {
				cmd.Flags().Set("force", "true")
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.RunE(cmd, []string{tt.missionName})

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify mission was deleted
				store := mission.NewRedisMissionStore(stateClient)
				_, err := store.GetByName(context.Background(), tt.missionName)
				assert.Error(t, err)
			}
		})
	}
}

func TestIsValidMissionStatus(t *testing.T) {
	tests := []struct {
		status mission.MissionStatus
		valid  bool
	}{
		{mission.MissionStatusPending, true},
		{mission.MissionStatusRunning, true},
		{mission.MissionStatusCompleted, true},
		{mission.MissionStatusFailed, true},
		{mission.MissionStatusCancelled, true},
		{mission.MissionStatus("invalid"), false},
		{mission.MissionStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.valid, core.IsValidMissionStatus(tt.status))
		})
	}
}

func TestFormatTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		time     time.Time
		contains string
	}{
		{
			name:     "just now",
			time:     now.Add(-30 * time.Second),
			contains: "just now",
		},
		{
			name:     "minutes ago",
			time:     now.Add(-5 * time.Minute),
			contains: "minutes ago",
		},
		{
			name:     "hours ago",
			time:     now.Add(-3 * time.Hour),
			contains: "hours ago",
		},
		{
			name:     "days ago",
			time:     now.Add(-2 * 24 * time.Hour),
			contains: "days ago",
		},
		{
			name:     "absolute date",
			time:     now.Add(-10 * 24 * time.Hour),
			contains: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.time)
			assert.Contains(t, result, tt.contains)
		})
	}
}

// TestBuildInlineTargetConfig tests the inline target configuration flag parsing
func TestBuildInlineTargetConfig(t *testing.T) {
	tests := []struct {
		name           string
		seeds          string
		profile        string
		depth          int
		exclude        string
		expectNil      bool
		expectError    bool
		errorContains  string
		checkResult    func(*testing.T, *dclient.InlineTargetData)
	}{
		{
			name:      "no seeds returns nil",
			seeds:     "",
			expectNil: true,
		},
		{
			name:    "single domain seed with defaults",
			seeds:   "example.com",
			profile: "",
			depth:   0,
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Len(t, result.Seeds, 1)
				assert.Equal(t, "example.com", result.Seeds[0].Value)
				assert.Equal(t, "domain", result.Seeds[0].Type)
				assert.Equal(t, "in_scope", result.Seeds[0].Scope)
				assert.Equal(t, "balanced", result.Profile)
				assert.Equal(t, int32(2), result.Depth)
			},
		},
		{
			name:    "typed seeds",
			seeds:   "domain:example.com,host:10.0.0.1,cidr:192.168.0.0/24",
			profile: "aggressive",
			depth:   3,
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Len(t, result.Seeds, 3)
				assert.Equal(t, "example.com", result.Seeds[0].Value)
				assert.Equal(t, "domain", result.Seeds[0].Type)
				assert.Equal(t, "10.0.0.1", result.Seeds[1].Value)
				assert.Equal(t, "host", result.Seeds[1].Type)
				assert.Equal(t, "192.168.0.0/24", result.Seeds[2].Value)
				assert.Equal(t, "cidr", result.Seeds[2].Type)
				assert.Equal(t, "aggressive", result.Profile)
				assert.Equal(t, int32(3), result.Depth)
			},
		},
		{
			name:    "stealth profile",
			seeds:   "domain:test.com",
			profile: "stealth",
			depth:   1,
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Equal(t, "stealth", result.Profile)
				assert.Equal(t, int32(1), result.Depth)
			},
		},
		{
			name:    "with exclusions",
			seeds:   "domain:example.com",
			exclude: "*.internal.com,dev.*,test.*",
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Len(t, result.Excluded, 3)
				assert.Contains(t, result.Excluded, "*.internal.com")
				assert.Contains(t, result.Excluded, "dev.*")
				assert.Contains(t, result.Excluded, "test.*")
			},
		},
		{
			name:          "invalid seed type",
			seeds:         "invalid:example.com",
			expectError:   true,
			errorContains: "invalid seed type",
		},
		{
			name:          "invalid profile",
			seeds:         "domain:example.com",
			profile:       "invalid-profile",
			expectError:   true,
			errorContains: "invalid target profile",
		},
		{
			name:          "depth too low",
			seeds:         "domain:example.com",
			depth:         0,
			profile:       "balanced",
			expectError:   false, // 0 depth defaults to 2
		},
		{
			name:          "depth too high",
			seeds:         "domain:example.com",
			depth:         10,
			expectError:   true,
			errorContains: "invalid target depth",
		},
		{
			name:    "org and asn seed types",
			seeds:   "org:ExampleCorp,asn:AS12345",
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Len(t, result.Seeds, 2)
				assert.Equal(t, "ExampleCorp", result.Seeds[0].Value)
				assert.Equal(t, "org", result.Seeds[0].Type)
				assert.Equal(t, "AS12345", result.Seeds[1].Value)
				assert.Equal(t, "asn", result.Seeds[1].Type)
			},
		},
		{
			name:    "whitespace handling",
			seeds:   " domain:example.com , host:10.0.0.1 ",
			checkResult: func(t *testing.T, result *dclient.InlineTargetData) {
				assert.Len(t, result.Seeds, 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldSeeds := missionInlineTargetSeeds
			oldProfile := missionInlineTargetProfile
			oldDepth := missionInlineTargetDepth
			oldExclude := missionInlineTargetExclude
			defer func() {
				missionInlineTargetSeeds = oldSeeds
				missionInlineTargetProfile = oldProfile
				missionInlineTargetDepth = oldDepth
				missionInlineTargetExclude = oldExclude
			}()

			// Set test flags
			missionInlineTargetSeeds = tt.seeds
			missionInlineTargetProfile = tt.profile
			missionInlineTargetDepth = tt.depth
			missionInlineTargetExclude = tt.exclude

			// Call function under test
			result, err := buildInlineTargetConfig()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestBuildInlineWorkflowConfig tests the inline workflow configuration flag parsing
func TestBuildInlineWorkflowConfig(t *testing.T) {
	tests := []struct {
		name          string
		agent         string
		workflowFile  string
		workflowYAML  string // content to write to temp file
		expectNil     bool
		expectError   bool
		errorContains string
		checkResult   func(*testing.T, *dclient.InlineWorkflowData)
	}{
		{
			name:      "no flags returns nil",
			agent:     "",
			expectNil: true,
		},
		{
			name:  "single agent shorthand",
			agent: "recon-agent",
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				assert.Equal(t, "inline-recon-agent-workflow", result.Name)
				assert.Len(t, result.Nodes, 1)
				assert.Equal(t, "agent-1", result.Nodes[0].ID)
				assert.Equal(t, "agent", result.Nodes[0].Type)
				assert.Equal(t, "recon-agent", result.Nodes[0].Name)
			},
		},
		{
			name: "workflow file with nodes",
			workflowYAML: `
name: test-workflow
nodes:
  - id: node1
    type: agent
    name: scanner
  - id: node2
    type: tool
    name: nmap
    depends_on:
      - node1
edges:
  - from: node1
    to: node2
`,
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				assert.Equal(t, "test-workflow", result.Name)
				assert.Len(t, result.Nodes, 2)
				assert.Equal(t, "node1", result.Nodes[0].ID)
				assert.Equal(t, "agent", result.Nodes[0].Type)
				assert.Equal(t, "scanner", result.Nodes[0].Name)
				assert.Equal(t, "node2", result.Nodes[1].ID)
				assert.Equal(t, "tool", result.Nodes[1].Type)
				assert.Equal(t, "nmap", result.Nodes[1].Name)
				assert.Contains(t, result.Nodes[1].DependsOn, "node1")
				assert.Len(t, result.Edges, 1)
				assert.Equal(t, "node1", result.Edges[0].From)
				assert.Equal(t, "node2", result.Edges[0].To)
			},
		},
		{
			name: "workflow file with metadata",
			workflowYAML: `
name: metadata-workflow
nodes:
  - id: node1
    type: agent
    name: test-agent
metadata:
  project: security-audit
  version: "1.0"
`,
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				assert.Equal(t, "metadata-workflow", result.Name)
				assert.NotNil(t, result.Metadata)
				assert.Equal(t, "security-audit", result.Metadata["project"])
				assert.Equal(t, "1.0", result.Metadata["version"])
			},
		},
		{
			name: "workflow file with edge conditions",
			workflowYAML: `
name: conditional-workflow
nodes:
  - id: scan
    type: agent
    name: scanner
  - id: report
    type: tool
    name: reporter
edges:
  - from: scan
    to: report
    condition: "status == 'success'"
`,
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				assert.Len(t, result.Edges, 1)
				assert.Equal(t, "status == 'success'", result.Edges[0].Condition)
			},
		},
		{
			name: "workflow file with no name defaults to filename",
			workflowYAML: `
nodes:
  - id: node1
    type: agent
    name: test-agent
`,
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				// Name should be derived from filename (temp file)
				assert.NotEmpty(t, result.Name)
			},
		},
		{
			name: "workflow file with empty nodes fails",
			workflowYAML: `
name: empty-workflow
nodes: []
`,
			expectError:   true,
			errorContains: "at least one node",
		},
		{
			name:          "non-existent workflow file",
			workflowFile:  "/non/existent/file.yaml",
			expectError:   true,
			errorContains: "failed to read",
		},
		{
			name: "invalid YAML",
			workflowYAML: `
name: broken
nodes
  - invalid yaml structure
`,
			expectError:   true,
			errorContains: "failed to parse",
		},
		{
			name: "workflow with node configs",
			workflowYAML: `
name: config-workflow
nodes:
  - id: node1
    type: agent
    name: scanner
    config:
      timeout: "30s"
      verbose: "true"
`,
			checkResult: func(t *testing.T, result *dclient.InlineWorkflowData) {
				assert.Len(t, result.Nodes, 1)
				assert.NotNil(t, result.Nodes[0].Config)
				assert.Equal(t, "30s", result.Nodes[0].Config["timeout"])
				assert.Equal(t, "true", result.Nodes[0].Config["verbose"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldAgent := missionInlineWorkflowAgent
			oldFile := missionInlineWorkflowFile
			defer func() {
				missionInlineWorkflowAgent = oldAgent
				missionInlineWorkflowFile = oldFile
			}()

			// Set test flags
			missionInlineWorkflowAgent = tt.agent

			// Handle workflow file
			if tt.workflowYAML != "" {
				// Create temp file with YAML content
				tmpFile, err := os.CreateTemp("", "inline-workflow-test-*.yaml")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(tt.workflowYAML)
				require.NoError(t, err)
				require.NoError(t, tmpFile.Close())

				missionInlineWorkflowFile = tmpFile.Name()
			} else if tt.workflowFile != "" {
				missionInlineWorkflowFile = tt.workflowFile
			} else {
				missionInlineWorkflowFile = ""
			}

			// Call function under test
			result, err := buildInlineWorkflowConfig()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestDetectMissionSourceType tests source type detection
func TestDetectMissionSourceType(t *testing.T) {
	tests := []struct {
		source   string
		expected string
	}{
		// URL detection
		{"https://github.com/user/repo", "url"},
		{"http://example.com/mission", "url"},
		{"git@github.com:user/repo.git", "url"},
		{"ssh://git@github.com/user/repo", "url"},

		// File path detection
		{"./workflows/scan.yaml", "file"},
		{"/absolute/path/to/workflow.yaml", "file"},
		{"relative/path.yml", "file"},
		{"workflow.yaml", "file"},
		{"workflow.yml", "file"},
		{"../parent/workflow.yaml", "file"},

		// Mission name detection (fallback)
		{"my-mission", "name"},
		{"recon-scan", "name"},
		{"simple", "name"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			result := detectMissionSourceType(tt.source)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestInlineTargetAndWorkflowMutualExclusivity tests CLI flag validation
func TestInlineConfigFlagCombinations(t *testing.T) {
	tests := []struct {
		name           string
		targetSeeds    string
		targetFlag     string
		workflowFile   string
		workflowAgent  string
		missionFile    string
		expectedTarget bool // expect inline target config
		expectedWflow  bool // expect inline workflow config
	}{
		{
			name:           "no inline flags",
			expectedTarget: false,
			expectedWflow:  false,
		},
		{
			name:           "only inline target",
			targetSeeds:    "domain:example.com",
			expectedTarget: true,
			expectedWflow:  false,
		},
		{
			name:           "only inline workflow agent",
			workflowAgent:  "recon-agent",
			expectedTarget: false,
			expectedWflow:  true,
		},
		{
			name:           "both inline target and workflow",
			targetSeeds:    "domain:example.com",
			workflowAgent:  "recon-agent",
			expectedTarget: true,
			expectedWflow:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags
			oldSeeds := missionInlineTargetSeeds
			oldProfile := missionInlineTargetProfile
			oldDepth := missionInlineTargetDepth
			oldExclude := missionInlineTargetExclude
			oldAgent := missionInlineWorkflowAgent
			oldFile := missionInlineWorkflowFile
			defer func() {
				missionInlineTargetSeeds = oldSeeds
				missionInlineTargetProfile = oldProfile
				missionInlineTargetDepth = oldDepth
				missionInlineTargetExclude = oldExclude
				missionInlineWorkflowAgent = oldAgent
				missionInlineWorkflowFile = oldFile
			}()

			// Set test flags
			missionInlineTargetSeeds = tt.targetSeeds
			missionInlineTargetProfile = ""
			missionInlineTargetDepth = 0
			missionInlineTargetExclude = ""
			missionInlineWorkflowAgent = tt.workflowAgent
			missionInlineWorkflowFile = ""

			// Build configs
			targetConfig, err := buildInlineTargetConfig()
			require.NoError(t, err)

			workflowConfig, err := buildInlineWorkflowConfig()
			require.NoError(t, err)

			// Verify expectations
			if tt.expectedTarget {
				assert.NotNil(t, targetConfig, "expected inline target config")
			} else {
				assert.Nil(t, targetConfig, "expected no inline target config")
			}

			if tt.expectedWflow {
				assert.NotNil(t, workflowConfig, "expected inline workflow config")
			} else {
				assert.Nil(t, workflowConfig, "expected no inline workflow config")
			}
		})
	}
}
