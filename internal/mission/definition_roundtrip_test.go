// Package mission — definition_roundtrip_test.go
//
// Round-trip parity test for GetMissionDefinition (M5, gibson#134).
//
// Constructs a MissionDefinition with EVERY author-facing field populated:
//   - Top-level fields (name, version, description, source, target_ref, metadata)
//   - workspace.repositories with depends_on
//   - workspace.settings (all knobs)
//   - constraints (all fields)
//   - Every NodeType (AGENT, TOOL, PLUGIN, CONDITION, PARALLEL, JOIN)
//   - Per-node retry_policy, data_policy, reuse_policy
//   - Edges and entry/exit points
//   - MissionDependencies
//
// Calls CreateDefinition → GetDefinition and asserts structural deep-equal
// (proto.Equal). A failure here means a field is being dropped or mangled
// during JSON marshal/unmarshal in MarshalDefinitionJSON / UnmarshalDefinitionJSON.
//
// Spec: mission-author-experience M5 (gibson#134).
package mission

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// newTestConnBoundStore creates a ConnBoundMissionStore backed by miniredis.
func newTestConnBoundStore(t *testing.T) (*ConnBoundMissionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewConnBoundMissionStore(rdb), mr
}

// fullMissionDefinitionFixture constructs a MissionDefinition with every
// author-facing field populated. This is the canonical fixture for round-trip
// parity testing.
func fullMissionDefinitionFixture() *missionv1.MissionDefinition {
	agentNode := &missionv1.MissionNode{
		Id:          "node-agent",
		Type:        missionv1.NodeType_NODE_TYPE_AGENT,
		Name:        "Recon Agent",
		Description: "Runs reconnaissance",
		Config: &missionv1.MissionNode_AgentConfig{
			AgentConfig: &missionv1.AgentNodeConfig{
				AgentName:        "scanner-agent",
				MaxTokensPerCall: proto.Int32(4096),
			},
		},
		Dependencies: []string{},
		Timeout:      durationpb.New(5 * time.Minute),
		RetryPolicy: &missionv1.RetryPolicy{
			MaxRetries:      3,
			BackoffStrategy: missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL,
			InitialDelay:    durationpb.New(2 * time.Second),
			MaxDelay:        durationpb.New(30 * time.Second),
			Multiplier:      2.0,
		},
		DataPolicy: &missionv1.DataPolicy{
			StoreInput:    true,
			StoreOutput:   true,
			Retention:     durationpb.New(72 * time.Hour),
			Encryption:    true,
			AccessControl: []string{"admin", "analyst"},
		},
		Metadata: map[string]string{"phase": "recon"},
		ReusePolicy: &missionv1.ReusePolicy{
			OutputScope: "mission",
			InputScope:  "mission_run",
			Reuse:       "skip",
		},
	}

	toolNode := &missionv1.MissionNode{
		Id:          "node-tool",
		Type:        missionv1.NodeType_NODE_TYPE_TOOL,
		Name:        "Port Scanner",
		Description: "Scans open ports",
		Config: &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{
				ToolName:         "port-scanner",
				Input:            map[string]string{"target": "{{target.host}}", "ports": "1-65535"},
				MaxTokensPerCall: proto.Int32(0),
			},
		},
		Dependencies: []string{"node-agent"},
		RetryPolicy: &missionv1.RetryPolicy{
			MaxRetries:      1,
			BackoffStrategy: missionv1.BackoffStrategy_BACKOFF_STRATEGY_LINEAR,
			InitialDelay:    durationpb.New(1 * time.Second),
		},
		DataPolicy: &missionv1.DataPolicy{
			StoreOutput: true,
		},
		ReusePolicy: &missionv1.ReusePolicy{
			OutputScope: "mission_run",
			Reuse:       "rerun",
		},
	}

	pluginNode := &missionv1.MissionNode{
		Id:          "node-plugin",
		Type:        missionv1.NodeType_NODE_TYPE_PLUGIN,
		Name:        "CVE Lookup",
		Description: "Looks up CVEs for findings",
		Config: &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName:       "vuln-enricher",
				Method:           "lookup_cve",
				Params:           map[string]string{"source": "nvd", "severity": "high"},
				MaxTokensPerCall: proto.Int32(512),
			},
		},
		Dependencies: []string{"node-tool"},
		ReusePolicy: &missionv1.ReusePolicy{
			OutputScope: "global",
			InputScope:  "global",
			Reuse:       "skip",
		},
	}

	conditionNode := &missionv1.MissionNode{
		Id:          "node-condition",
		Type:        missionv1.NodeType_NODE_TYPE_CONDITION,
		Name:        "Has Critical Findings?",
		Description: "Branches on critical finding count",
		Config: &missionv1.MissionNode_ConditionConfig{
			ConditionConfig: &missionv1.ConditionNodeConfig{
				Expression:  "results.critical_count > 0",
				TrueBranch:  []string{"node-plugin"},
				FalseBranch: []string{"node-join"},
				Language:    missionv1.Language_LANGUAGE_CEL,
			},
		},
		Dependencies: []string{"node-tool"},
	}

	subAgent := &missionv1.MissionNode{
		Id:   "sub-agent-1",
		Type: missionv1.NodeType_NODE_TYPE_AGENT,
		Name: "Parallel Agent",
		Config: &missionv1.MissionNode_AgentConfig{
			AgentConfig: &missionv1.AgentNodeConfig{
				AgentName: "parallel-worker",
			},
		},
	}

	parallelNode := &missionv1.MissionNode{
		Id:          "node-parallel",
		Type:        missionv1.NodeType_NODE_TYPE_PARALLEL,
		Name:        "Parallel Enrichment",
		Description: "Runs enrichment agents in parallel",
		Config: &missionv1.MissionNode_ParallelConfig{
			ParallelConfig: &missionv1.ParallelNodeConfig{
				SubNodes:       []*missionv1.MissionNode{subAgent},
				MaxConcurrency: 4,
			},
		},
		Dependencies: []string{"node-condition"},
	}

	joinNode := &missionv1.MissionNode{
		Id:          "node-join",
		Type:        missionv1.NodeType_NODE_TYPE_JOIN,
		Name:        "Merge Results",
		Description: "Merges results from parallel branches",
		Config: &missionv1.MissionNode_JoinConfig{
			JoinConfig: &missionv1.JoinNodeConfig{
				WaitFor:  []string{"node-parallel", "node-plugin"},
				Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT,
			},
		},
		Dependencies: []string{"node-parallel", "node-plugin"},
	}

	return &missionv1.MissionDefinition{
		Name:        "full-roundtrip-mission",
		Version:     "2.1.0",
		Description: "Comprehensive fixture exercising every author-facing field",
		TargetRef:   "prod-target",
		Source:      "https://github.com/zero-day-ai/missions.git",
		// InstalledAt / CreatedAt are set by CreateDefinition — we verify they are non-nil after round-trip.
		Metadata: map[string]string{
			"owner":    "security-team",
			"env":      "prod",
			"category": "pentest",
		},
		Dependencies: &missionv1.MissionDependencies{
			Agents:  []string{"scanner-agent", "parallel-worker"},
			Tools:   []string{"port-scanner"},
			Plugins: []string{"vuln-enricher"},
		},
		Nodes: map[string]*missionv1.MissionNode{
			"node-agent":     agentNode,
			"node-tool":      toolNode,
			"node-plugin":    pluginNode,
			"node-condition": conditionNode,
			"node-parallel":  parallelNode,
			"node-join":      joinNode,
		},
		Edges: []*missionv1.MissionEdge{
			{From: "node-agent", To: "node-tool", Condition: "", Metadata: map[string]string{"weight": "1"}},
			{From: "node-tool", To: "node-condition"},
			{From: "node-condition", To: "node-plugin"},
			{From: "node-condition", To: "node-join"},
			{From: "node-plugin", To: "node-parallel"},
			{From: "node-parallel", To: "node-join"},
		},
		EntryPoints: []string{"node-agent"},
		ExitPoints:  []string{"node-join"},
		Workspace: &missionv1.WorkspaceConfig{
			Repositories: []*missionv1.RepositoryConfig{
				{
					Name:           "target-repo",
					Url:            "https://github.com/acme/app.git",
					Branch:         "main",
					CredentialName: "github-creds",
					Shallow:        true,
					DependsOn:      []string{},
				},
				{
					Name:      "tools-repo",
					Url:       "https://github.com/acme/pentest-tools.git",
					Branch:    "stable",
					DependsOn: []string{"target-repo"},
				},
			},
			Settings: &missionv1.WorkspaceSettings{
				CleanupOnComplete: true,
				UseWorktrees:      true,
				LspEnabled:        true,
				LspTimeout:        durationpb.New(30 * time.Second),
				BaseDirectory:     "/tmp/missions",
			},
		},
		Constraints: &missionv1.MissionConstraints{
			MaxDuration:       durationpb.New(4 * time.Hour),
			MaxTokens:         100000,
			MaxCost:           25.0,
			MaxFindings:       500,
			SeverityThreshold: "medium",
			RequireEvidence:   true,
			BlockedTools:      []string{"rm-tool", "shutdown-tool"},
			BlockedDomains:    []string{"prod.acme.com", "payments.acme.com"},
		},
	}
}

// TestGetMissionDefinition_RoundTrip is the canonical round-trip parity test for M5.
// It verifies that every author-facing field written via CreateDefinition is returned
// intact by GetDefinition (the persistence layer used by GetMissionDefinition RPC).
func TestGetMissionDefinition_RoundTrip(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	input := fullMissionDefinitionFixture()

	// --- Create ---
	err := store.CreateDefinition(ctx, input)
	require.NoError(t, err, "CreateDefinition should succeed for a valid fixture")

	// --- Get ---
	got, err := store.GetDefinition(ctx, input.GetName())
	require.NoError(t, err, "GetDefinition should not error for an existing definition")
	require.NotNil(t, got, "GetDefinition should return non-nil for an existing definition")

	// Timestamps are set by CreateDefinition; verify they are non-nil and recent.
	require.NotNil(t, got.GetInstalledAt(), "InstalledAt must be set by CreateDefinition")
	require.NotNil(t, got.GetCreatedAt(), "CreatedAt must be set by CreateDefinition")
	assert.WithinDuration(t, time.Now(), got.GetInstalledAt().AsTime(), 10*time.Second)

	// CreateDefinition mutates the input proto's InstalledAt/CreatedAt timestamps.
	// For proto.Equal we compare the non-timestamp fields by clearing both sides.
	wantForCmp := proto.Clone(input).(*missionv1.MissionDefinition)
	wantForCmp.InstalledAt = nil
	wantForCmp.CreatedAt = nil
	got.InstalledAt = nil
	got.CreatedAt = nil

	// --- Assert structural equality ---
	// proto.Equal performs a deep field-by-field comparison including maps, repeated
	// fields, oneofs, and optional fields. Any dropped or mangled field fails here.
	if !proto.Equal(wantForCmp, got) {
		t.Errorf("round-trip proto.Equal failed:\nwant: %v\n got: %v", wantForCmp, got)
	}
}

// TestGetMissionDefinition_NotFound verifies GetDefinition returns nil, nil
// (not an error) for an unknown name. The handler layer converts nil to codes.NotFound.
func TestGetMissionDefinition_NotFound(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	got, err := store.GetDefinition(ctx, "does-not-exist")
	require.NoError(t, err, "GetDefinition should not error on miss")
	assert.Nil(t, got, "GetDefinition should return nil for unknown name")
}

// TestGetMissionDefinition_WorkspaceFields verifies workspace + constraints fields
// specifically, since they are optional proto fields that may be nil-dropped.
func TestGetMissionDefinition_WorkspaceFields(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	input := fullMissionDefinitionFixture()
	require.NoError(t, store.CreateDefinition(ctx, input))

	got, err := store.GetDefinition(ctx, input.GetName())
	require.NoError(t, err)
	require.NotNil(t, got)

	// Workspace assertions
	require.NotNil(t, got.GetWorkspace(), "workspace must round-trip")
	repos := got.GetWorkspace().GetRepositories()
	require.Len(t, repos, 2, "both repositories must round-trip")

	// Verify DependsOn (repeated field inside nested message)
	var toolsRepo *missionv1.RepositoryConfig
	for _, r := range repos {
		if r.GetName() == "tools-repo" {
			toolsRepo = r
		}
	}
	require.NotNil(t, toolsRepo, "tools-repo must be present")
	assert.Equal(t, []string{"target-repo"}, toolsRepo.GetDependsOn())

	ws := got.GetWorkspace().GetSettings()
	require.NotNil(t, ws, "workspace.settings must round-trip")
	assert.True(t, ws.GetUseWorktrees())
	assert.True(t, ws.GetLspEnabled())
	assert.Equal(t, "/tmp/missions", ws.GetBaseDirectory())

	// Constraints assertions (optional field)
	c := got.GetConstraints()
	require.NotNil(t, c, "constraints must round-trip")
	assert.Equal(t, int64(100000), c.GetMaxTokens())
	assert.Equal(t, 25.0, c.GetMaxCost())
	assert.Equal(t, int32(500), c.GetMaxFindings())
	assert.Equal(t, "medium", c.GetSeverityThreshold())
	assert.True(t, c.GetRequireEvidence())
	assert.Equal(t, []string{"rm-tool", "shutdown-tool"}, c.GetBlockedTools())
	assert.Equal(t, []string{"prod.acme.com", "payments.acme.com"}, c.GetBlockedDomains())
	require.NotNil(t, c.GetMaxDuration())
	assert.Equal(t, durationpb.New(4*time.Hour).AsDuration(), c.GetMaxDuration().AsDuration())
}

// TestGetMissionDefinition_NodePolicies verifies per-node policies round-trip correctly.
func TestGetMissionDefinition_NodePolicies(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	input := fullMissionDefinitionFixture()
	require.NoError(t, store.CreateDefinition(ctx, input))

	got, err := store.GetDefinition(ctx, input.GetName())
	require.NoError(t, err)
	require.NotNil(t, got)

	agentNode := got.GetNodes()["node-agent"]
	require.NotNil(t, agentNode, "node-agent must be present")

	// RetryPolicy
	rp := agentNode.GetRetryPolicy()
	require.NotNil(t, rp, "retry_policy must round-trip on agent node")
	assert.Equal(t, int32(3), rp.GetMaxRetries())
	assert.Equal(t, missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL, rp.GetBackoffStrategy())
	assert.Equal(t, 2.0, rp.GetMultiplier())

	// DataPolicy
	dp := agentNode.GetDataPolicy()
	require.NotNil(t, dp, "data_policy must round-trip on agent node")
	assert.True(t, dp.GetStoreInput())
	assert.True(t, dp.GetEncryption())
	assert.Equal(t, []string{"admin", "analyst"}, dp.GetAccessControl())

	// ReusePolicy
	ruse := agentNode.GetReusePolicy()
	require.NotNil(t, ruse, "reuse_policy must round-trip on agent node")
	assert.Equal(t, "mission", ruse.GetOutputScope())
	assert.Equal(t, "mission_run", ruse.GetInputScope())
	assert.Equal(t, "skip", ruse.GetReuse())

	// AgentNodeConfig.max_tokens_per_call (optional int32)
	ac := agentNode.GetAgentConfig()
	require.NotNil(t, ac, "agent_config must be present")
	require.NotNil(t, ac.MaxTokensPerCall, "max_tokens_per_call optional field must round-trip")
	assert.Equal(t, int32(4096), ac.GetMaxTokensPerCall())
}

// TestGetMissionDefinition_AllNodeTypes verifies that every NodeType in the fixture
// round-trips with its config populated.
func TestGetMissionDefinition_AllNodeTypes(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	input := fullMissionDefinitionFixture()
	require.NoError(t, store.CreateDefinition(ctx, input))

	got, err := store.GetDefinition(ctx, input.GetName())
	require.NoError(t, err)
	require.NotNil(t, got)

	nodes := got.GetNodes()

	// AGENT
	agentNode := nodes["node-agent"]
	require.NotNil(t, agentNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_AGENT, agentNode.GetType())
	assert.NotNil(t, agentNode.GetAgentConfig())

	// TOOL
	toolNode := nodes["node-tool"]
	require.NotNil(t, toolNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_TOOL, toolNode.GetType())
	tc := toolNode.GetToolConfig()
	require.NotNil(t, tc)
	assert.Equal(t, "port-scanner", tc.GetToolName())
	assert.Equal(t, "{{target.host}}", tc.GetInput()["target"])

	// PLUGIN
	pluginNode := nodes["node-plugin"]
	require.NotNil(t, pluginNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_PLUGIN, pluginNode.GetType())
	pc := pluginNode.GetPluginConfig()
	require.NotNil(t, pc)
	assert.Equal(t, "vuln-enricher", pc.GetPluginName())
	assert.Equal(t, "lookup_cve", pc.GetMethod())

	// CONDITION
	condNode := nodes["node-condition"]
	require.NotNil(t, condNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_CONDITION, condNode.GetType())
	cc := condNode.GetConditionConfig()
	require.NotNil(t, cc)
	assert.Equal(t, "results.critical_count > 0", cc.GetExpression())
	assert.Equal(t, missionv1.Language_LANGUAGE_CEL, cc.GetLanguage())
	assert.Equal(t, []string{"node-plugin"}, cc.GetTrueBranch())
	assert.Equal(t, []string{"node-join"}, cc.GetFalseBranch())

	// PARALLEL (including sub-node)
	parallelNode := nodes["node-parallel"]
	require.NotNil(t, parallelNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_PARALLEL, parallelNode.GetType())
	pcp := parallelNode.GetParallelConfig()
	require.NotNil(t, pcp)
	assert.Equal(t, int32(4), pcp.GetMaxConcurrency())
	require.Len(t, pcp.GetSubNodes(), 1)
	assert.Equal(t, "parallel-worker", pcp.GetSubNodes()[0].GetAgentConfig().GetAgentName())

	// JOIN
	joinNode := nodes["node-join"]
	require.NotNil(t, joinNode)
	assert.Equal(t, missionv1.NodeType_NODE_TYPE_JOIN, joinNode.GetType())
	jc := joinNode.GetJoinConfig()
	require.NotNil(t, jc)
	assert.ElementsMatch(t, []string{"node-parallel", "node-plugin"}, jc.GetWaitFor())
	assert.Equal(t, missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT, jc.GetStrategy())
}

// TestGetMissionDefinition_TimestampsSetByCreate verifies that InstalledAt and CreatedAt
// are always set to a non-zero time by CreateDefinition, even when absent in the input.
func TestGetMissionDefinition_TimestampsSetByCreate(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	// Use a minimal definition with no timestamps.
	def := &missionv1.MissionDefinition{
		Name:    "minimal-def",
		Version: "1.0.0",
	}

	before := timestamppb.Now()
	require.NoError(t, store.CreateDefinition(ctx, def))
	after := timestamppb.Now()

	got, err := store.GetDefinition(ctx, "minimal-def")
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NotNil(t, got.GetInstalledAt())
	require.NotNil(t, got.GetCreatedAt())

	installedAt := got.GetInstalledAt().AsTime()
	assert.False(t, installedAt.Before(before.AsTime()), "InstalledAt should not be before the create call")
	assert.False(t, installedAt.After(after.AsTime()), "InstalledAt should not be after the create call")
}
