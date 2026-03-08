package main

import (
	"github.com/zero-day-ai/gibson/internal/state"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Legacy test variables for backward compatibility with old tests
// These were replaced by addConnection in the new schema-based implementation
// TODO: Update tests to use addConnection instead
var (
	addName  string
	addModel string
)

// setupTestDB creates a test StateClient for testing
func setupTestDB(t *testing.T) (*state.StateClient, string, func()) {
	t.Helper()

	// Skip tests that require Redis
	t.Skip("requires Redis")

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "gibson-test-*")
	require.NoError(t, err)

	// Set GIBSON_HOME to temp directory
	oldHome := os.Getenv("GIBSON_HOME")
	os.Setenv("GIBSON_HOME", tempDir)

	// Create state config
	stateCfg := &state.Config{
		URL: "redis://localhost:6379",
	}
	stateCfg.ApplyDefaults()

	// Create StateClient
	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		t.Fatalf("failed to create state client: %v", err)
	}

	// Cleanup function
	cleanup := func() {
		stateClient.Close()
		os.RemoveAll(tempDir)
		os.Setenv("GIBSON_HOME", oldHome)
	}

	return stateClient, tempDir, cleanup
}

// TestTargetAdd tests the target add command
func TestTargetAdd(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		wantErr     bool
		errContains string
		validate    func(*testing.T, *state.StateClient)
	}{
		{
			name: "valid URL with name",
			args: []string{"https://api.openai.com/v1/chat/completions"},
			flags: map[string]string{
				"name": "test-target",
				"type": "llm_api",
			},
			wantErr: false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "test-target")
				require.NoError(t, err)
				assert.Equal(t, "test-target", target.Name)
				assert.Equal(t, "https://api.openai.com/v1/chat/completions", target.URL)
				assert.Equal(t, types.TargetTypeLLMAPI, target.Type)
				assert.Equal(t, types.ProviderOpenAI, target.Provider)
			},
		},
		{
			name: "valid URL with provider override",
			args: []string{"https://example.com/api/v1/chat"},
			flags: map[string]string{
				"name":     "custom-target",
				"provider": "custom",
				"type":     "llm_chat",
			},
			wantErr: false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "custom-target")
				require.NoError(t, err)
				assert.Equal(t, types.ProviderCustom, target.Provider)
				assert.Equal(t, types.TargetTypeLLMChat, target.Type)
			},
		},
		{
			name: "anthropic URL auto-detection",
			args: []string{"https://api.anthropic.com/v1/messages"},
			flags: map[string]string{
				"name": "claude-target",
			},
			wantErr: false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "claude-target")
				require.NoError(t, err)
				assert.Equal(t, types.ProviderAnthropic, target.Provider)
			},
		},
		{
			name: "invalid URL - missing scheme",
			args: []string{"api.openai.com/v1/chat"},
			flags: map[string]string{
				"name": "bad-target",
			},
			wantErr:     true,
			errContains: "scheme",
		},
		{
			name: "invalid target type",
			args: []string{"https://api.openai.com/v1/chat"},
			flags: map[string]string{
				"name": "bad-type-target",
				"type": "invalid_type",
			},
			wantErr:     true,
			errContains: "invalid target type",
		},
		{
			name: "invalid provider",
			args: []string{"https://api.openai.com/v1/chat"},
			flags: map[string]string{
				"name":     "bad-provider-target",
				"provider": "invalid_provider",
			},
			wantErr:     true,
			errContains: "invalid provider",
		},
		{
			name: "duplicate target name",
			args: []string{"https://api.openai.com/v1/chat"},
			flags: map[string]string{
				"name": "duplicate-target",
			},
			wantErr: false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				// Create a second command to try adding duplicate
				cmd2 := &cobra.Command{
					Use:  "add",
					Args: cobra.ExactArgs(1),
					RunE: runTargetAdd,
				}

				cmd2.Flags().StringVar(&addName, "name", "", "Human-readable name for the target (required)")
				cmd2.Flags().StringVar(&addType, "type", "llm_api", "Target type")
				cmd2.Flags().StringVar(&addProvider, "provider", "", "Provider")
				cmd2.Flags().StringVar(&addCredential, "credential", "", "Credential name")
				cmd2.Flags().StringVar(&addModel, "model", "", "Model identifier")
				cmd2.Flags().IntVar(&addTimeout, "timeout", 30, "Request timeout in seconds")

				cmd2.SetArgs([]string{"https://different-url.com"})
				cmd2.Flags().Set("name", "duplicate-target")

				buf := new(bytes.Buffer)
				cmd2.SetOut(buf)
				cmd2.SetErr(buf)

				err := cmd2.ExecuteContext(context.Background())
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "already exists")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:  "add",
				Args: cobra.ExactArgs(1),
				RunE: runTargetAdd,
			}

			// Re-register flags
			cmd.Flags().StringVar(&addName, "name", "", "Human-readable name for the target (required)")
			cmd.Flags().StringVar(&addType, "type", "llm_api", "Target type")
			cmd.Flags().StringVar(&addProvider, "provider", "", "Provider")
			cmd.Flags().StringVar(&addCredential, "credential", "", "Credential name")
			cmd.Flags().StringVar(&addModel, "model", "", "Model identifier")
			cmd.Flags().IntVar(&addTimeout, "timeout", 30, "Request timeout in seconds")
			cmd.MarkFlagRequired("name")

			cmd.SetArgs(tt.args)

			// Set flags
			for key, value := range tt.flags {
				cmd.Flags().Set(key, value)
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(context.Background())

			// Check error expectation
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			// Run validation if provided
			if tt.validate != nil && !tt.wantErr {
				tt.validate(t, stateClient)
			}
		})
	}
}

// TestTargetList tests the target list command
func TestTargetList(t *testing.T) {
	tests := []struct {
		name         string
		setupTargets []types.Target
		statusFilter string
		provFilter   string
		wantCount    int
		wantNames    []string
	}{
		{
			name: "list all targets",
			setupTargets: []types.Target{
				*types.NewTarget("target1", "https://api.openai.com/v1", types.TargetTypeLLMAPI),
				*types.NewTarget("target2", "https://api.anthropic.com/v1", types.TargetTypeLLMAPI),
			},
			wantCount: 2,
			wantNames: []string{"target1", "target2"},
		},
		{
			name: "filter by status",
			setupTargets: []types.Target{
				func() types.Target {
					t := types.NewTarget("active-target", "https://api.openai.com/v1", types.TargetTypeLLMAPI)
					t.Status = types.TargetStatusActive
					return *t
				}(),
				func() types.Target {
					t := types.NewTarget("inactive-target", "https://api.anthropic.com/v1", types.TargetTypeLLMAPI)
					t.Status = types.TargetStatusInactive
					return *t
				}(),
			},
			statusFilter: "active",
			wantCount:    1,
			wantNames:    []string{"active-target"},
		},
		{
			name: "filter by provider",
			setupTargets: []types.Target{
				func() types.Target {
					t := types.NewTarget("openai-target", "https://api.openai.com/v1", types.TargetTypeLLMAPI)
					t.Provider = types.ProviderOpenAI
					return *t
				}(),
				func() types.Target {
					t := types.NewTarget("anthropic-target", "https://api.anthropic.com/v1", types.TargetTypeLLMAPI)
					t.Provider = types.ProviderAnthropic
					return *t
				}(),
			},
			provFilter: "openai",
			wantCount:  1,
			wantNames:  []string{"openai-target"},
		},
		{
			name:         "empty list",
			setupTargets: []types.Target{},
			wantCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup targets
			dao := database.NewRedisTargetDAO(stateClient)
			ctx := context.Background()
			for _, target := range tt.setupTargets {
				err := dao.Create(ctx, &target)
				require.NoError(t, err)
			}

			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:  "list",
				RunE: runTargetList,
			}

			// Re-register flags
			cmd.Flags().StringVar(&listStatusFilter, "status", "", "Filter by status")
			cmd.Flags().StringVar(&listProviderFilter, "provider", "", "Filter by provider")

			cmd.SetArgs([]string{})

			if tt.statusFilter != "" {
				cmd.Flags().Set("status", tt.statusFilter)
			}
			if tt.provFilter != "" {
				cmd.Flags().Set("provider", tt.provFilter)
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(ctx)
			require.NoError(t, err)

			// Verify output
			output := buf.String()
			if tt.wantCount == 0 {
				assert.Contains(t, output, "No targets found")
			} else {
				for _, name := range tt.wantNames {
					assert.Contains(t, output, name)
				}
			}
		})
	}
}

// TestTargetShow tests the target show command
func TestTargetShow(t *testing.T) {
	tests := []struct {
		name        string
		setupTarget *types.Target
		targetName  string
		wantErr     bool
		wantOutput  []string
	}{
		{
			name: "show existing target",
			setupTarget: func() *types.Target {
				t := types.NewTarget("show-test", "https://api.openai.com/v1", types.TargetTypeLLMAPI)
				t.Provider = types.ProviderOpenAI
				t.Model = "gpt-4"
				t.Description = "Test target"
				return t
			}(),
			targetName: "show-test",
			wantErr:    false,
			wantOutput: []string{
				"show-test",
				"https://api.openai.com/v1",
				"gpt-4",
				"openai",
				"Test target",
			},
		},
		{
			name:       "show non-existent target",
			targetName: "does-not-exist",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup target if provided
			if tt.setupTarget != nil {
				dao := database.NewRedisTargetDAO(stateClient)
				err := dao.Create(context.Background(), tt.setupTarget)
				require.NoError(t, err)
			}

			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:  "show",
				Args: cobra.ExactArgs(1),
				RunE: runTargetShow,
			}

			cmd.SetArgs([]string{tt.targetName})

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(context.Background())

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				output := buf.String()
				for _, want := range tt.wantOutput {
					assert.Contains(t, output, want)
				}
			}
		})
	}
}

// TestTargetDelete tests the target delete command
func TestTargetDelete(t *testing.T) {
	tests := []struct {
		name        string
		setupTarget *types.Target
		targetName  string
		useForce    bool
		wantErr     bool
	}{
		{
			name: "delete with force flag",
			setupTarget: func() *types.Target {
				return types.NewTarget("delete-test", "https://api.openai.com/v1", types.TargetTypeLLMAPI)
			}(),
			targetName: "delete-test",
			useForce:   true,
			wantErr:    false,
		},
		{
			name:       "delete non-existent target",
			targetName: "does-not-exist",
			useForce:   true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup target if provided
			var targetID types.ID
			if tt.setupTarget != nil {
				dao := database.NewRedisTargetDAO(stateClient)
				err := dao.Create(context.Background(), tt.setupTarget)
				require.NoError(t, err)
				targetID = tt.setupTarget.ID
			}

			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:  "delete",
				Args: cobra.ExactArgs(1),
				RunE: runTargetDelete,
			}

			// Re-register flags
			cmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")

			cmd.SetArgs([]string{tt.targetName})

			if tt.useForce {
				cmd.Flags().Set("force", "true")
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(context.Background())

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify target was deleted
				dao := database.NewRedisTargetDAO(stateClient)
				exists, err := dao.Exists(context.Background(), targetID.String())
				require.NoError(t, err)
				assert.False(t, exists, "target should be deleted")
			}
		})
	}
}

// TestDetectProvider tests the provider auto-detection logic
func TestDetectProvider(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "OpenAI API",
			url:      "https://api.openai.com/v1/chat/completions",
			expected: "openai",
		},
		{
			name:     "Anthropic API",
			url:      "https://api.anthropic.com/v1/messages",
			expected: "anthropic",
		},
		{
			name:     "Google API",
			url:      "https://generativelanguage.googleapis.com/v1/models",
			expected: "google",
		},
		{
			name:     "Azure OpenAI",
			url:      "https://myresource.openai.azure.com/openai/deployments",
			expected: "azure",
		},
		{
			name:     "Ollama localhost",
			url:      "http://localhost:11434/api/generate",
			expected: "ollama",
		},
		{
			name:     "Custom endpoint",
			url:      "https://my-custom-llm.example.com/api",
			expected: "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			result := detectProvider(u)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDetectModel tests the model auto-detection logic
func TestDetectModel(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		provider string
		expected string
	}{
		{
			name:     "GPT-4 in path",
			url:      "https://api.openai.com/v1/engines/gpt-4/completions",
			provider: "openai",
			expected: "gpt-4",
		},
		{
			name:     "Claude in path",
			url:      "https://api.anthropic.com/v1/models/claude-3",
			provider: "anthropic",
			expected: "claude-3-opus",
		},
		{
			name:     "Default for OpenAI",
			url:      "https://api.openai.com/v1/chat/completions",
			provider: "openai",
			expected: "gpt-4",
		},
		{
			name:     "Default for Anthropic",
			url:      "https://api.anthropic.com/v1/messages",
			provider: "anthropic",
			expected: "claude-3-opus",
		},
		{
			name:     "Unknown custom",
			url:      "https://custom.example.com/api",
			provider: "custom",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			result := detectModel(u, tt.provider)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetGibsonHome tests the Gibson home directory resolution
func TestGetGibsonHome(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		wantPrefix string
	}{
		{
			name:       "use environment variable",
			envValue:   "/custom/gibson/home",
			wantPrefix: "/custom/gibson/home",
		},
		{
			name:       "use default when env not set",
			envValue:   "",
			wantPrefix: "/.gibson",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore environment
			oldEnv := os.Getenv("GIBSON_HOME")
			defer os.Setenv("GIBSON_HOME", oldEnv)

			// Set test environment
			if tt.envValue != "" {
				os.Setenv("GIBSON_HOME", tt.envValue)
			} else {
				os.Unsetenv("GIBSON_HOME")
			}

			// Get home directory
			home, err := getGibsonHome()
			require.NoError(t, err)

			if tt.envValue != "" {
				assert.Equal(t, tt.envValue, home)
			} else {
				assert.Contains(t, home, tt.wantPrefix)
			}
		})
	}
}

// TestTargetAddWithSchemaBasedTypes tests the schema-based target add command
// Note: These tests require tasks 11-12 to be complete (--type and --connection flags)
// These tests will fail until the --connection flag is added to the target add command
func TestTargetAddWithSchemaBasedTypes(t *testing.T) {
	// Skip this test if the --connection flag hasn't been implemented yet
	t.Skip("Skipping until tasks 11-12 are complete: --type and --connection flags need to be added to target.go")

	tests := []struct {
		name        string
		targetType  string
		connection  string
		targetName  string
		flags       map[string]string
		wantErr     bool
		errContains string
		validate    func(*testing.T, *state.StateClient)
	}{
		{
			name:       "http_api target with required fields",
			targetType: "http_api",
			connection: `{"url":"https://api.openai.com/v1/chat/completions","method":"POST"}`,
			targetName: "test-http-api",
			wantErr:    false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "test-http-api")
				require.NoError(t, err)
				assert.Equal(t, "http_api", string(target.Type))
				assert.NotNil(t, target.Connection)
				assert.Equal(t, "https://api.openai.com/v1/chat/completions", target.Connection["url"])
				assert.Equal(t, "POST", target.Connection["method"])
			},
		},
		{
			name:       "kubernetes target with cluster and namespace",
			targetType: "kubernetes",
			connection: `{"cluster":"prod-cluster","namespace":"ml-pipeline"}`,
			targetName: "test-k8s",
			wantErr:    false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "test-k8s")
				require.NoError(t, err)
				assert.Equal(t, "kubernetes", string(target.Type))
				assert.Equal(t, "prod-cluster", target.Connection["cluster"])
				assert.Equal(t, "ml-pipeline", target.Connection["namespace"])
			},
		},
		{
			name:       "smart_contract target with chain and address",
			targetType: "smart_contract",
			connection: `{"chain":"ethereum","address":"0x1234567890abcdef1234567890abcdef12345678"}`,
			targetName: "test-contract",
			wantErr:    false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "test-contract")
				require.NoError(t, err)
				assert.Equal(t, "smart_contract", string(target.Type))
				assert.Equal(t, "ethereum", target.Connection["chain"])
				assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", target.Connection["address"])
			},
		},
		{
			name:        "http_api target missing required url field",
			targetType:  "http_api",
			connection:  `{"method":"POST"}`,
			targetName:  "test-invalid",
			wantErr:     true,
			errContains: "url",
		},
		{
			name:        "kubernetes target missing required cluster field",
			targetType:  "kubernetes",
			connection:  `{"namespace":"default"}`,
			targetName:  "test-invalid-k8s",
			wantErr:     true,
			errContains: "cluster",
		},
		{
			name:        "invalid JSON in connection parameter",
			targetType:  "http_api",
			connection:  `{"url":"https://example.com"`,
			targetName:  "test-bad-json",
			wantErr:     true,
			errContains: "JSON",
		},
		{
			name:       "llm_api target with headers and timeout",
			targetType: "llm_api",
			connection: `{"url":"https://api.anthropic.com/v1/messages","headers":{"x-api-version":"2024-01-01"},"timeout":60}`,
			targetName: "test-llm-api",
			wantErr:    false,
			validate: func(t *testing.T, stateClient *state.StateClient) {
				dao := database.NewRedisTargetDAO(stateClient)
				target, err := dao.GetByName(context.Background(), "test-llm-api")
				require.NoError(t, err)
				assert.Equal(t, "llm_api", string(target.Type))
				headers := target.Connection["headers"].(map[string]any)
				assert.Equal(t, "2024-01-01", headers["x-api-version"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Create a fresh command for each test
			cmd := &cobra.Command{
				Use:  "add",
				Args: cobra.MinimumNArgs(1),
				RunE: runTargetAdd,
			}

			// Set up flags (these should exist after tasks 11-12 are complete)
			var addConnection string // Placeholder - should be added to target.go in tasks 11-12
			cmd.Flags().StringVar(&addName, "name", "", "Human-readable name for the target")
			cmd.Flags().StringVar(&addType, "type", "", "Target type")
			cmd.Flags().StringVar(&addConnection, "connection", "", "Connection parameters as JSON")
			cmd.Flags().StringVar(&addProvider, "provider", "", "Provider")
			cmd.Flags().StringVar(&addModel, "model", "", "Model identifier")
			cmd.Flags().IntVar(&addTimeout, "timeout", 30, "Request timeout in seconds")

			cmd.SetArgs([]string{tt.targetName})
			cmd.Flags().Set("name", tt.targetName)
			cmd.Flags().Set("type", tt.targetType)
			cmd.Flags().Set("connection", tt.connection)

			// Set additional flags if provided
			for key, value := range tt.flags {
				cmd.Flags().Set(key, value)
			}

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(context.Background())

			// Check error expectation
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			// Run validation if provided
			if tt.validate != nil && !tt.wantErr {
				tt.validate(t, stateClient)
			}
		})
	}
}

// TestTargetListWithSchemaBasedTypes tests the list command output format with schema-based targets
// Note: These tests require task 12 to be complete (target list updates for Type column)
func TestTargetListWithSchemaBasedTypes(t *testing.T) {
	t.Skip("Skipping until task 12 is complete: target list needs to show Type column")

	tests := []struct {
		name         string
		setupTargets []types.Target
		wantOutput   []string
	}{
		{
			name: "list targets with different schema types",
			setupTargets: []types.Target{
				func() types.Target {
					t := types.NewTarget("http-target", "", types.TargetType("http_api"))
					t.Connection = map[string]any{
						"url":    "https://api.example.com",
						"method": "POST",
					}
					return *t
				}(),
				func() types.Target {
					t := types.NewTarget("k8s-target", "", types.TargetType("kubernetes"))
					t.Connection = map[string]any{
						"cluster":   "prod",
						"namespace": "default",
					}
					return *t
				}(),
				func() types.Target {
					t := types.NewTarget("contract-target", "", types.TargetType("smart_contract"))
					t.Connection = map[string]any{
						"chain":   "ethereum",
						"address": "0xabcd",
					}
					return *t
				}(),
			},
			wantOutput: []string{
				"http-target",
				"http_api",
				"k8s-target",
				"kubernetes",
				"contract-target",
				"smart_contract",
				"TYPE", // Column header
			},
		},
		{
			name: "list shows connection summary for http_api",
			setupTargets: []types.Target{
				func() types.Target {
					t := types.NewTarget("api-target", "", types.TargetType("http_api"))
					t.Connection = map[string]any{
						"url": "https://api.openai.com",
					}
					return *t
				}(),
			},
			wantOutput: []string{
				"api-target",
				"https://api.openai.com",
			},
		},
		{
			name: "list shows connection summary for kubernetes",
			setupTargets: []types.Target{
				func() types.Target {
					t := types.NewTarget("cluster-target", "", types.TargetType("kubernetes"))
					t.Connection = map[string]any{
						"cluster": "staging-cluster",
					}
					return *t
				}(),
			},
			wantOutput: []string{
				"cluster-target",
				"staging-cluster",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup targets
			dao := database.NewRedisTargetDAO(stateClient)
			ctx := context.Background()
			for _, target := range tt.setupTargets {
				err := dao.Create(ctx, &target)
				require.NoError(t, err)
			}

			// Create command
			cmd := &cobra.Command{
				Use:  "list",
				RunE: runTargetList,
			}

			cmd.Flags().StringVar(&listStatusFilter, "status", "", "Filter by status")
			cmd.Flags().StringVar(&listProviderFilter, "provider", "", "Filter by provider")
			cmd.SetArgs([]string{})

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err := cmd.ExecuteContext(ctx)
			require.NoError(t, err)

			// Verify output contains expected strings
			output := buf.String()
			for _, want := range tt.wantOutput {
				assert.Contains(t, output, want, "output should contain %q", want)
			}
		})
	}
}

// TestTargetShowWithSensitiveFieldMasking tests that sensitive fields are masked in show output
// Note: These tests require task 12 to be complete (target show updates for Connection field masking)
func TestTargetShowWithSensitiveFieldMasking(t *testing.T) {
	t.Skip("Skipping until task 12 is complete: target show needs to mask sensitive Connection fields")

	tests := []struct {
		name               string
		setupTarget        *types.Target
		wantContain        []string
		wantNotContain     []string
		sensitiveFieldName string
	}{
		{
			name: "api_key in connection is masked",
			setupTarget: func() *types.Target {
				t := types.NewTarget("secure-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":     "https://api.example.com",
					"api_key": "sk-1234567890abcdefghijklmnop",
				}
				return t
			}(),
			wantContain:        []string{"secure-target", "https://api.example.com", "api_key"},
			wantNotContain:     []string{"sk-1234567890abcdefghijklmnop"},
			sensitiveFieldName: "api_key",
		},
		{
			name: "token in connection is masked",
			setupTarget: func() *types.Target {
				t := types.NewTarget("auth-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":   "https://api.example.com",
					"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				}
				return t
			}(),
			wantContain:        []string{"auth-target", "token"},
			wantNotContain:     []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
			sensitiveFieldName: "token",
		},
		{
			name: "password in connection is masked",
			setupTarget: func() *types.Target {
				t := types.NewTarget("db-target", "", types.TargetType("kubernetes"))
				t.Connection = map[string]any{
					"cluster":  "prod",
					"password": "supersecretpassword123",
				}
				return t
			}(),
			wantContain:        []string{"db-target", "password"},
			wantNotContain:     []string{"supersecretpassword123"},
			sensitiveFieldName: "password",
		},
		{
			name: "secret in connection is masked",
			setupTarget: func() *types.Target {
				t := types.NewTarget("secret-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":    "https://api.example.com",
					"secret": "very-secret-value-12345",
				}
				return t
			}(),
			wantContain:        []string{"secret-target", "secret"},
			wantNotContain:     []string{"very-secret-value-12345"},
			sensitiveFieldName: "secret",
		},
		{
			name: "non-sensitive fields are shown",
			setupTarget: func() *types.Target {
				t := types.NewTarget("normal-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":     "https://api.example.com",
					"method":  "POST",
					"timeout": 30,
				}
				return t
			}(),
			wantContain:    []string{"normal-target", "https://api.example.com", "POST", "30"},
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup target
			dao := database.NewRedisTargetDAO(stateClient)
			err := dao.Create(context.Background(), tt.setupTarget)
			require.NoError(t, err)

			// Create command
			cmd := &cobra.Command{
				Use:  "show",
				Args: cobra.ExactArgs(1),
				RunE: runTargetShow,
			}

			cmd.SetArgs([]string{tt.setupTarget.Name})

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.ExecuteContext(context.Background())
			require.NoError(t, err)

			output := buf.String()

			// Verify expected content is present
			for _, want := range tt.wantContain {
				assert.Contains(t, output, want, "output should contain %q", want)
			}

			// Verify sensitive content is NOT present
			for _, notWant := range tt.wantNotContain {
				assert.NotContains(t, output, notWant, "output should NOT contain sensitive value %q", notWant)
			}

			// If there's a sensitive field, verify it shows masked value
			if tt.sensitiveFieldName != "" {
				assert.Contains(t, output, "***", "sensitive field should be masked with ***")
			}
		})
	}
}

// TestTargetShowJSONOutput tests JSON output format for target show
// Note: These tests require task 12 to be complete (target show JSON output with Connection field)
func TestTargetShowJSONOutput(t *testing.T) {
	t.Skip("Skipping until task 12 is complete: target show JSON output needs Connection field support")

	tests := []struct {
		name        string
		setupTarget *types.Target
		useJSON     bool
		validate    func(*testing.T, string)
	}{
		{
			name: "json output includes all fields",
			setupTarget: func() *types.Target {
				t := types.NewTarget("json-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":    "https://api.example.com",
					"method": "POST",
				}
				t.Description = "Test target for JSON"
				t.Tags = []string{"test", "api"}
				return t
			}(),
			useJSON: true,
			validate: func(t *testing.T, output string) {
				var result map[string]any
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err, "output should be valid JSON")

				assert.Equal(t, "json-target", result["name"])
				assert.Equal(t, "http_api", result["type"])
				assert.NotNil(t, result["connection"])

				connection := result["connection"].(map[string]any)
				assert.Equal(t, "https://api.example.com", connection["url"])
				assert.Equal(t, "POST", connection["method"])
			},
		},
		{
			name: "json output masks sensitive fields",
			setupTarget: func() *types.Target {
				t := types.NewTarget("secure-json-target", "", types.TargetType("http_api"))
				t.Connection = map[string]any{
					"url":     "https://api.example.com",
					"api_key": "sk-secret123",
				}
				return t
			}(),
			useJSON: true,
			validate: func(t *testing.T, output string) {
				var result map[string]any
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)

				connection := result["connection"].(map[string]any)
				// Sensitive field should be masked
				assert.NotEqual(t, "sk-secret123", connection["api_key"])
				assert.Contains(t, connection["api_key"], "***")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateClient, _, cleanup := setupTestDB(t)
			defer cleanup()

			// Setup target
			dao := database.NewRedisTargetDAO(stateClient)
			err := dao.Create(context.Background(), tt.setupTarget)
			require.NoError(t, err)

			// Create command
			cmd := &cobra.Command{
				Use:  "show",
				Args: cobra.ExactArgs(1),
				RunE: runTargetShow,
			}

			if tt.useJSON {
				cmd.Flags().StringVar(&showOutputFormat, "output", "json", "Output format")
				cmd.Flags().Set("output", "json")
			}

			cmd.SetArgs([]string{tt.setupTarget.Name})

			// Capture output
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Execute command
			err = cmd.ExecuteContext(context.Background())
			require.NoError(t, err)

			// Validate output
			if tt.validate != nil {
				tt.validate(t, buf.String())
			}
		})
	}
}
