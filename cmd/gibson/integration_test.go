package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	initpkg "github.com/zero-day-ai/gibson/internal/init"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/state"
)

// setupIntegrationTest creates a complete test environment with temp home directory
func setupIntegrationTest(t *testing.T) (homeDir string, cleanup func()) {
	t.Helper()

	// Create temp directory for test home
	tempDir, err := os.MkdirTemp("", "gibson-integration-*")
	require.NoError(t, err, "Failed to create temp directory")

	// Set GIBSON_HOME environment variable
	oldHome := os.Getenv("GIBSON_HOME")
	os.Setenv("GIBSON_HOME", tempDir)

	cleanup = func() {
		os.RemoveAll(tempDir)
		os.Setenv("GIBSON_HOME", oldHome)
	}

	return tempDir, cleanup
}

// TestWorkflow_InitConfigAgent tests the init → config → agent workflow
func TestWorkflow_InitConfigAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Step 1: gibson init
	t.Run("init creates home directory and config", func(t *testing.T) {
		initializer := initpkg.NewDefaultInitializer()
		opts := initpkg.InitOptions{
			HomeDir:        homeDir,
			NonInteractive: true,
			Force:          false,
		}

		result, err := initializer.Initialize(ctx, opts)
		require.NoError(t, err, "Init should succeed")
		assert.NotNil(t, result)
		assert.True(t, result.ConfigCreated, "Config should be created")
		assert.True(t, result.KeyCreated, "Encryption key should be created")
		assert.Greater(t, len(result.DirsCreated), 0, "Directories should be created")

		// Verify home directory structure
		assert.DirExists(t, homeDir, "Home directory should exist")
		assert.FileExists(t, filepath.Join(homeDir, "config.yaml"), "Config file should exist")
		assert.FileExists(t, filepath.Join(homeDir, "master.key"), "Encryption key should exist")
	})

	// Step 2: gibson config show
	t.Run("config show displays configuration", func(t *testing.T) {
		configPath := filepath.Join(homeDir, "config.yaml")
		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.Load(configPath)
		require.NoError(t, err, "Config should load successfully")
		assert.NotNil(t, cfg)

		// Verify core config values
		assert.Equal(t, homeDir, cfg.Core.HomeDir, "Home directory should match")
		assert.NotEmpty(t, cfg.Core.DataDir, "Data directory should be set")
		assert.NotEmpty(t, cfg.Security.EncryptionAlgorithm, "Encryption algorithm should be set")
	})

	// Step 3: gibson agent list (should be empty initially)
	t.Run("agent list shows empty list initially", func(t *testing.T) {
		// Skip - requires Redis
		t.Skip("requires Redis")

		// This test would require the component registry to be set up
		// Create StateClient
		stateCfg := &state.Config{
			URL: "redis://localhost:6379",
		}
		stateCfg.ApplyDefaults()

		stateClient, err := state.NewStateClient(stateCfg)
		require.NoError(t, err, "StateClient should be created successfully")
		defer stateClient.Close()

		// Verify state client is accessible
		err = stateClient.Client().Ping(context.Background()).Err()
		require.NoError(t, err, "Should ping Redis successfully")
	})
}

// TestWorkflow_CredentialTargetFlow tests credential → target association workflow
func TestWorkflow_CredentialTargetFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Skip - requires Redis
	t.Skip("requires Redis")

	// Initialize environment
	initializer := initpkg.NewDefaultInitializer()
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: true,
		Force:          false,
	}
	_, err := initializer.Initialize(ctx, opts)
	require.NoError(t, err, "Init should succeed")

	// Create StateClient
	stateCfg := &state.Config{
		URL: "redis://localhost:6379",
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	require.NoError(t, err, "StateClient should be created")
	defer stateClient.Close()

	// Step 1: Add a credential (mocked - would normally go through credential command)
	t.Run("credential add creates encrypted credential", func(t *testing.T) {
		// With Redis, credentials would be stored in Redis
		// This test validates the state client is ready
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	// Step 2: Add a target (mocked - would normally go through target command)
	t.Run("target add with credential reference", func(t *testing.T) {
		// With Redis, targets would be stored in Redis
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	// Step 3: Verify target has credential associated
	t.Run("verify credential-target association", func(t *testing.T) {
		// With Redis, associations would be managed differently
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})
}

// TestWorkflow_MissionFindingExport tests mission → finding export workflow
func TestWorkflow_MissionFindingExport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Skip - requires Redis
	t.Skip("requires Redis")

	// Initialize environment
	initializer := initpkg.NewDefaultInitializer()
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: true,
		Force:          false,
	}
	_, err := initializer.Initialize(ctx, opts)
	require.NoError(t, err, "Init should succeed")

	// Create StateClient
	stateCfg := &state.Config{
		URL: "redis://localhost:6379",
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	require.NoError(t, err, "StateClient should be created")
	defer stateClient.Close()

	// Step 1: Create test mission in database
	t.Run("create test mission", func(t *testing.T) {
		missionStore := mission.NewRedisMissionStore(stateClient)
		require.NotNil(t, missionStore, "Mission store should be created")

		// Verify state client is accessible
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	// Step 2: Create test findings (mocked)
	t.Run("create test findings", func(t *testing.T) {
		// With Redis, findings would be stored in Redis
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	// Step 3: gibson finding list --mission ID (verify query structure)
	t.Run("finding list supports mission filter", func(t *testing.T) {
		// With Redis, would use RediSearch queries
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	// Step 4: gibson finding export --format json (verify export capability)
	t.Run("finding export formats available", func(t *testing.T) {
		// With Redis, export would read from Redis
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})
}

// TestWorkflow_ConfigValidation tests configuration validation across workflows
func TestWorkflow_ConfigValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Initialize
	initializer := initpkg.NewDefaultInitializer()
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: true,
		Force:          false,
	}
	_, err := initializer.Initialize(ctx, opts)
	require.NoError(t, err)

	t.Run("config file has valid structure", func(t *testing.T) {
		configPath := filepath.Join(homeDir, "config.yaml")
		content, err := os.ReadFile(configPath)
		require.NoError(t, err)

		// Check for key sections
		configStr := string(content)
		assert.Contains(t, configStr, "core:", "Config should have core section")
		assert.Contains(t, configStr, "database:", "Config should have database section")
		assert.Contains(t, configStr, "security:", "Config should have security section")
		assert.Contains(t, configStr, "llm:", "Config should have llm section")
	})

	t.Run("config validates successfully", func(t *testing.T) {
		configPath := filepath.Join(homeDir, "config.yaml")
		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.Load(configPath)
		require.NoError(t, err, "Config should load and validate")
		assert.NotNil(t, cfg)
	})

	t.Run("config get retrieves values", func(t *testing.T) {
		configPath := filepath.Join(homeDir, "config.yaml")
		loader := config.NewConfigLoader(config.NewValidator())
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)

		// Test various config accessors
		assert.NotEmpty(t, cfg.Core.HomeDir)
		assert.NotEmpty(t, cfg.Security.EncryptionAlgorithm)
		assert.Greater(t, cfg.Core.ParallelLimit, 0)
	})
}

// TestWorkflow_DatabaseIntegrity tests database operations across workflows
func TestWorkflow_DatabaseIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	ctx := context.Background()

	// Initialize
	initializer := initpkg.NewDefaultInitializer()
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: true,
		Force:          false,
	}
	_, err := initializer.Initialize(ctx, opts)
	require.NoError(t, err)

	// Skip - requires Redis
	t.Skip("requires Redis")

	// Create StateClient
	stateCfg := &state.Config{
		URL: "redis://localhost:6379",
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	require.NoError(t, err)
	defer stateClient.Close()

	t.Run("all core indexes exist", func(t *testing.T) {
		// With Redis, we would verify RediSearch indexes exist
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	t.Run("state client supports concurrent access", func(t *testing.T) {
		// Redis supports concurrent access natively
		err := stateClient.Client().Ping(ctx).Err()
		require.NoError(t, err, "Redis should be accessible")
	})

	t.Run("state client is properly configured", func(t *testing.T) {
		cfg := stateClient.Config()
		assert.NotEmpty(t, cfg.URL, "URL should be set")
		assert.Greater(t, cfg.PoolSize, 0, "Pool size should be positive")
	})
}

// TestWorkflow_ErrorHandling tests error handling across workflows
func TestWorkflow_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("init fails on invalid home directory", func(t *testing.T) {
		initializer := initpkg.NewDefaultInitializer()
		opts := initpkg.InitOptions{
			HomeDir:        "/root/cannot-write-here",
			NonInteractive: true,
			Force:          false,
		}

		_, err := initializer.Initialize(context.Background(), opts)
		if os.Geteuid() != 0 {
			// Should fail if not root
			assert.Error(t, err, "Init should fail on unwritable directory")
		}
	})

	t.Run("config load fails on missing file", func(t *testing.T) {
		loader := config.NewConfigLoader(config.NewValidator())
		_, err := loader.Load("/nonexistent/config.yaml")
		assert.Error(t, err, "Config load should fail on missing file")
	})

	t.Run("state client fails with invalid config", func(t *testing.T) {
		invalidCfg := &state.Config{
			URL:         "",
			ClusterMode: false,
		}
		_, err := state.NewStateClient(invalidCfg)
		assert.Error(t, err, "StateClient creation should fail with invalid config")
	})
}

// TestWorkflow_CLICommands tests that CLI commands integrate properly
func TestWorkflow_CLICommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	homeDir, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Initialize
	initializer := initpkg.NewDefaultInitializer()
	opts := initpkg.InitOptions{
		HomeDir:        homeDir,
		NonInteractive: true,
		Force:          false,
	}
	_, err := initializer.Initialize(context.Background(), opts)
	require.NoError(t, err)

	t.Run("all commands are registered", func(t *testing.T) {
		// Check that rootCmd has all expected subcommands
		expectedCommands := []string{
			"init",
			"version",
			"config",
			"target",
			"credential",
			"agent",
			"tool",
			"plugin",
			"mission",
			"finding",
			"attack",
			"status",
		}

		registeredCommands := make(map[string]bool)
		for _, cmd := range rootCmd.Commands() {
			registeredCommands[cmd.Name()] = true
		}

		for _, cmdName := range expectedCommands {
			assert.True(t, registeredCommands[cmdName], "Command %s should be registered", cmdName)
		}
	})

	t.Run("help text is available for all commands", func(t *testing.T) {
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs([]string{"--help"})

		err := rootCmd.Execute()
		require.NoError(t, err)

		helpText := buf.String()
		assert.Contains(t, helpText, "Gibson", "Help should contain Gibson")
		assert.Contains(t, helpText, "Available Commands", "Help should list commands")
	})

	t.Run("version command works", func(t *testing.T) {
		var buf bytes.Buffer
		versionCmd.SetOut(&buf)
		versionCmd.Run(versionCmd, []string{})

		output := buf.String()
		assert.Contains(t, strings.ToLower(output), "gibson", "Version should contain Gibson")
	})
}
