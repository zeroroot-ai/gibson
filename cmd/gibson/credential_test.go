package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// testMutex ensures credential tests run sequentially to avoid etcd port conflicts
var testMutex sync.Mutex

// portCounter is used to allocate unique ports for tests
var portCounter int = 30000

// getTestPorts returns two sequential available TCP ports for etcd (client and peer)
// Uses a counter starting at 30000 and increments by 10 each time to avoid conflicts
// NOTE: Caller must hold testMutex
func getTestPorts(t *testing.T) (int, int) {
	clientPort := portCounter
	peerPort := portCounter + 1
	portCounter += 10 // Leave gaps to avoid race conditions

	return clientPort, peerPort
}

// setupCredentialTest creates a test environment with database and config
func setupCredentialTest(t *testing.T) (string, *state.StateClient, func()) {
	// Skip tests that require Redis
	t.Skip("requires Redis")

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "gibson-credential-test-*")
	require.NoError(t, err)

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

	// Get free port for etcd to avoid conflicts between tests
	clientPort, _ := getTestPorts(t)

	// Write minimal config YAML
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`core:
  home_dir: %s
  data_dir: %s/data
  cache_dir: %s/cache
  parallel_limit: 10
  timeout: 5m
state:
  url: redis://localhost:6379
  database: 0
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
logging:
  level: info
  format: json
registry:
  type: embedded
  data_dir: %s/etcd-data
  listen_address: 127.0.0.1:%d
  namespace: gibson-test
  ttl: 30s
`, tmpDir, tmpDir, tmpDir, tmpDir, clientPort)

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Create master key file
	masterKey := []byte("test-master-key-for-encrypt-32!!") // Must be exactly 32 bytes
	keyManager := crypto.NewFileKeyManager()
	keyPath := filepath.Join(tmpDir, "master.key")
	err = keyManager.SaveKey(masterKey, keyPath)
	require.NoError(t, err)

	// Set GIBSON_HOME for tests
	oldHome := os.Getenv("GIBSON_HOME")
	os.Setenv("GIBSON_HOME", tmpDir)

	cleanup := func() {
		// Shutdown global registry if it was started
		if globalRegistryManager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			globalRegistryManager.Stop(ctx)
			cancel()
			globalRegistryManager = nil
			// Wait for ports to be fully released
			time.Sleep(200 * time.Millisecond)
		}

		stateClient.Close()
		os.RemoveAll(tmpDir)
		if oldHome != "" {
			os.Setenv("GIBSON_HOME", oldHome)
		} else {
			os.Unsetenv("GIBSON_HOME")
		}
	}

	return tmpDir, stateClient, cleanup
}

// TestCredentialList tests the credential list command
func TestCredentialList(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	tmpDir, stateClient, cleanup := setupCredentialTest(t)
	defer cleanup()

	// Create test credentials
	dao := database.NewRedisCredentialDAO(stateClient)
	ctx := context.Background()

	masterKey := []byte("test-master-key-for-encrypt-32!!")
	encryptor := crypto.NewAESGCMEncryptor()

	// Create credential 1
	encryptedValue1, iv1, salt1, err := encryptor.Encrypt([]byte("secret-api-key-1"), masterKey)
	require.NoError(t, err)

	cred1 := types.NewCredential("openai-key", types.CredentialTypeAPIKey)
	cred1.Provider = "openai"
	cred1.Description = "OpenAI API Key"
	cred1.EncryptedValue = encryptedValue1
	cred1.EncryptionIV = iv1
	cred1.KeyDerivationSalt = salt1

	err = dao.Create(ctx, cred1)
	require.NoError(t, err)

	// Create credential 2
	encryptedValue2, iv2, salt2, err := encryptor.Encrypt([]byte("secret-api-key-2"), masterKey)
	require.NoError(t, err)

	cred2 := types.NewCredential("anthropic-key", types.CredentialTypeAPIKey)
	cred2.Provider = "anthropic"
	cred2.EncryptedValue = encryptedValue2
	cred2.EncryptionIV = iv2
	cred2.KeyDerivationSalt = salt2

	err = dao.Create(ctx, cred2)
	require.NoError(t, err)

	tests := []struct {
		name         string
		args         []string
		wantErr      bool
		checkOutput  func(t *testing.T, output string)
		checkSecrets bool
	}{
		{
			name:    "list all credentials (text format)",
			args:    []string{"credential", "list", "--config", filepath.Join(tmpDir, "config.yaml")},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "openai-key")
				assert.Contains(t, output, "anthropic-key")
				assert.Contains(t, output, "openai")
				assert.Contains(t, output, "anthropic")
			},
			checkSecrets: true,
		},
		{
			name:    "list all credentials (JSON format)",
			args:    []string{"credential", "list", "--config", filepath.Join(tmpDir, "config.yaml"), "--output", "json"},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				var result []map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)
				assert.Len(t, result, 2)

				// Database may return in any order, so check both credentials exist
				foundOpenAI := false
				foundAnthropic := false
				for _, cred := range result {
					if cred["name"] == "openai-key" {
						assert.Equal(t, "openai", cred["provider"])
						assert.Equal(t, "api_key", cred["type"])
						foundOpenAI = true
					}
					if cred["name"] == "anthropic-key" {
						assert.Equal(t, "anthropic", cred["provider"])
						foundAnthropic = true
					}
				}
				assert.True(t, foundOpenAI, "openai-key credential not found")
				assert.True(t, foundAnthropic, "anthropic-key credential not found")
			},
			checkSecrets: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command
			cmd := rootCmd
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)
			cmd.SetArgs(tt.args)

			// Execute command
			err := cmd.Execute()

			// Handle error the same way main.go does
			if err != nil {
				internal.HandleError(cmd, err)
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()

			// Check output
			if tt.checkOutput != nil {
				tt.checkOutput(t, output)
			}

			// CRITICAL SECURITY CHECK: Verify secrets are never in output
			if tt.checkSecrets {
				assert.NotContains(t, output, "secret-api-key-1", "Plaintext secret leaked in output!")
				assert.NotContains(t, output, "secret-api-key-2", "Plaintext secret leaked in output!")
			}

			// Reset command and flags for next test
			cmd.SetArgs(nil)
			// Reset the output flag to default (text)
			if f := cmd.Flag("output"); f != nil {
				f.Value.Set("text")
			}
		})
	}
}

// TestCredentialAdd tests the credential add command
func TestCredentialAdd(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	tmpDir, _, cleanup := setupCredentialTest(t)
	defer cleanup()

	tests := []struct {
		name         string
		args         []string
		envVars      map[string]string
		wantErr      bool
		checkOutput  func(t *testing.T, output string)
		checkSecrets bool
	}{
		{
			name: "add credential from environment variable",
			args: []string{
				"credential", "add",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--name", "test-api-key",
				"--type", "api_key",
				"--provider", "test-provider",
				"--from-env", "TEST_API_KEY",
			},
			envVars: map[string]string{
				"TEST_API_KEY": "my-secret-key-12345",
			},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "Credential created: test-api-key")
			},
			checkSecrets: true,
		},
		{
			name: "add credential with invalid type",
			args: []string{
				"credential", "add",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--name", "test-invalid",
				"--type", "invalid_type",
				"--from-env", "TEST_API_KEY",
			},
			envVars: map[string]string{
				"TEST_API_KEY": "my-secret-key-12345",
			},
			wantErr: true,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "invalid credential type")
			},
			checkSecrets: false,
		},
		{
			name: "add credential with missing environment variable",
			args: []string{
				"credential", "add",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--name", "test-missing",
				"--type", "api_key",
				"--from-env", "MISSING_VAR",
			},
			envVars: map[string]string{},
			wantErr: true,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "not set or empty")
			},
			checkSecrets: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Create command
			cmd := rootCmd
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)
			cmd.SetArgs(tt.args)

			// Execute command
			err := cmd.Execute()

			// Shutdown registry if it was started
			if globalRegistryManager != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				globalRegistryManager.Stop(ctx)
				cancel()
				globalRegistryManager = nil
			}

			// Handle error the same way main.go does
			if err != nil {
				internal.HandleError(cmd, err)
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()

			// Check output
			if tt.checkOutput != nil {
				tt.checkOutput(t, output)
			}

			// CRITICAL SECURITY CHECK: Verify secrets are never in output
			if tt.checkSecrets {
				for _, value := range tt.envVars {
					assert.NotContains(t, output, value, "Plaintext secret leaked in output!")
				}
			}

			// Reset command and flags for next test
			cmd.SetArgs(nil)
			// Reset the output flag to default (text)
			if f := cmd.Flag("output"); f != nil {
				f.Value.Set("text")
			}
		})
	}
}

// TestCredentialShow tests the credential show command
func TestCredentialShow(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	tmpDir, stateClient, cleanup := setupCredentialTest(t)
	defer cleanup()

	// Create test credential
	dao := database.NewRedisCredentialDAO(stateClient)
	ctx := context.Background()

	masterKey := []byte("test-master-key-for-encrypt-32!!")
	encryptor := crypto.NewAESGCMEncryptor()

	secretValue := "super-secret-api-key-xyz"
	encryptedValue, iv, salt, err := encryptor.Encrypt([]byte(secretValue), masterKey)
	require.NoError(t, err)

	cred := types.NewCredential("show-test-key", types.CredentialTypeAPIKey)
	cred.Provider = "test-provider"
	cred.Description = "Test credential for show command"
	cred.EncryptedValue = encryptedValue
	cred.EncryptionIV = iv
	cred.KeyDerivationSalt = salt
	cred.Tags = []string{"test", "demo"}

	err = dao.Create(ctx, cred)
	require.NoError(t, err)

	tests := []struct {
		name         string
		args         []string
		wantErr      bool
		checkOutput  func(t *testing.T, output string)
		checkSecrets bool
	}{
		{
			name: "show credential (text format)",
			args: []string{
				"credential", "show", "show-test-key",
				"--config", filepath.Join(tmpDir, "config.yaml"),
			},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "Credential: show-test-key")
				assert.Contains(t, output, "Type: api_key")
				assert.Contains(t, output, "Provider: test-provider")
				assert.Contains(t, output, "Description: Test credential for show command")
				assert.Contains(t, output, "Tags: test, demo")
			},
			checkSecrets: true,
		},
		{
			name: "show credential (JSON format)",
			args: []string{
				"credential", "show", "show-test-key",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--output", "json",
			},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				var result map[string]interface{}
				err := json.Unmarshal([]byte(output), &result)
				require.NoError(t, err)

				assert.Equal(t, "show-test-key", result["name"])
				assert.Equal(t, "api_key", result["type"])
				assert.Equal(t, "test-provider", result["provider"])
				assert.Equal(t, "Test credential for show command", result["description"])

				// Verify encrypted fields are NOT in output
				assert.NotContains(t, result, "encrypted_value")
				assert.NotContains(t, result, "encryption_iv")
				assert.NotContains(t, result, "key_derivation_salt")
			},
			checkSecrets: true,
		},
		{
			name: "show nonexistent credential",
			args: []string{
				"credential", "show", "nonexistent",
				"--config", filepath.Join(tmpDir, "config.yaml"),
			},
			wantErr: true,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "not found")
			},
			checkSecrets: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command
			cmd := rootCmd
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)
			cmd.SetArgs(tt.args)

			// Execute command
			err := cmd.Execute()

			// Shutdown registry if it was started
			if globalRegistryManager != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				globalRegistryManager.Stop(ctx)
				cancel()
				globalRegistryManager = nil
			}

			// Handle error the same way main.go does
			if err != nil {
				internal.HandleError(cmd, err)
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()

			// Check output
			if tt.checkOutput != nil {
				tt.checkOutput(t, output)
			}

			// CRITICAL SECURITY CHECK: Verify secrets are never in output
			if tt.checkSecrets {
				assert.NotContains(t, output, secretValue, "Plaintext secret leaked in output!")
				// Also verify encrypted data is not in output
				assert.NotContains(t, strings.ToLower(output), "encrypted_value")
				assert.NotContains(t, strings.ToLower(output), "encryption_iv")
				assert.NotContains(t, strings.ToLower(output), "key_derivation_salt")
			}

			// Reset command and flags for next test
			cmd.SetArgs(nil)
			// Reset the output flag to default (text)
			if f := cmd.Flag("output"); f != nil {
				f.Value.Set("text")
			}
		})
	}
}

// TestCredentialDelete tests the credential delete command
func TestCredentialDelete(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	tmpDir, stateClient, cleanup := setupCredentialTest(t)
	defer cleanup()

	// Create test credential
	dao := database.NewRedisCredentialDAO(stateClient)
	ctx := context.Background()

	masterKey := []byte("test-master-key-for-encrypt-32!!")
	encryptor := crypto.NewAESGCMEncryptor()

	encryptedValue, iv, salt, err := encryptor.Encrypt([]byte("secret-key"), masterKey)
	require.NoError(t, err)

	cred := types.NewCredential("delete-test-key", types.CredentialTypeAPIKey)
	cred.EncryptedValue = encryptedValue
	cred.EncryptionIV = iv
	cred.KeyDerivationSalt = salt

	err = dao.Create(ctx, cred)
	require.NoError(t, err)

	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		checkOutput func(t *testing.T, output string)
	}{
		{
			name: "delete credential with --force",
			args: []string{
				"credential", "delete", "delete-test-key",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--force",
			},
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "Credential deleted: delete-test-key")

				// Verify credential is deleted
				_, err := dao.GetByName(ctx, "delete-test-key")
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), "not found")
				}
			},
		},
		{
			name: "delete nonexistent credential",
			args: []string{
				"credential", "delete", "nonexistent",
				"--config", filepath.Join(tmpDir, "config.yaml"),
				"--force",
			},
			wantErr: true,
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command
			cmd := rootCmd
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)
			cmd.SetArgs(tt.args)

			// Execute command
			err := cmd.Execute()

			// Shutdown registry if it was started
			if globalRegistryManager != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				globalRegistryManager.Stop(ctx)
				cancel()
				globalRegistryManager = nil
			}

			// Handle error the same way main.go does
			if err != nil {
				internal.HandleError(cmd, err)
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()

			// Check output
			if tt.checkOutput != nil {
				tt.checkOutput(t, output)
			}

			// Reset command and flags for next test
			cmd.SetArgs(nil)
			// Reset the output flag to default (text)
			if f := cmd.Flag("output"); f != nil {
				f.Value.Set("text")
			}
		})
	}
}

// TestCredentialEncryption tests that credentials are properly encrypted
func TestCredentialEncryption(t *testing.T) {
	tmpDir, stateClient, cleanup := setupCredentialTest(t)
	defer cleanup()

	secretValue := "my-super-secret-value-12345"

	// Add credential via command
	os.Setenv("TEST_SECRET", secretValue)
	defer os.Unsetenv("TEST_SECRET")

	cmd := rootCmd
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{
		"credential", "add",
		"--config", filepath.Join(tmpDir, "config.yaml"),
		"--name", "encryption-test",
		"--type", "api_key",
		"--from-env", "TEST_SECRET",
	})

	err := cmd.Execute()
	require.NoError(t, err)

	// Retrieve credential from database
	dao := database.NewRedisCredentialDAO(stateClient)
	ctx := context.Background()
	cred, err := dao.GetByName(ctx, "encryption-test")
	require.NoError(t, err)

	// Verify encrypted value is NOT the plaintext
	assert.NotEqual(t, []byte(secretValue), cred.EncryptedValue, "Credential is not encrypted!")

	// Verify we can decrypt it
	masterKey := []byte("test-master-key-for-encrypt-32!!")
	encryptor := crypto.NewAESGCMEncryptor()
	decrypted, err := encryptor.Decrypt(cred.EncryptedValue, cred.EncryptionIV, cred.KeyDerivationSalt, masterKey)
	require.NoError(t, err)

	// Verify decrypted value matches original
	assert.Equal(t, secretValue, string(decrypted))
}

// TestSecurityNoSecretsInOutput is a comprehensive security test
// This verifies that credentials are NEVER exposed in ANY command output
func TestSecurityNoSecretsInOutput(t *testing.T) {
	tmpDir, stateClient, cleanup := setupCredentialTest(t)
	defer cleanup()

	// Create multiple credentials with known secret values
	secrets := []string{
		"secret-value-1-abc123",
		"secret-value-2-def456",
		"secret-value-3-ghi789",
	}

	dao := database.NewRedisCredentialDAO(stateClient)
	ctx := context.Background()
	masterKey := []byte("test-master-key-for-encrypt-32!!")
	encryptor := crypto.NewAESGCMEncryptor()

	for i, secret := range secrets {
		encryptedValue, iv, salt, err := encryptor.Encrypt([]byte(secret), masterKey)
		require.NoError(t, err)

		cred := types.NewCredential(
			[]string{"secret-1", "secret-2", "secret-3"}[i],
			types.CredentialTypeAPIKey,
		)
		cred.EncryptedValue = encryptedValue
		cred.EncryptionIV = iv
		cred.KeyDerivationSalt = salt

		err = dao.Create(ctx, cred)
		require.NoError(t, err)
	}

	// Test all commands that might display credential data
	commands := [][]string{
		{"credential", "list", "--config", filepath.Join(tmpDir, "config.yaml")},
		{"credential", "list", "--config", filepath.Join(tmpDir, "config.yaml"), "--output", "json"},
		{"credential", "show", "secret-1", "--config", filepath.Join(tmpDir, "config.yaml")},
		{"credential", "show", "secret-1", "--config", filepath.Join(tmpDir, "config.yaml"), "--output", "json"},
		{"credential", "show", "secret-2", "--config", filepath.Join(tmpDir, "config.yaml")},
		{"credential", "show", "secret-3", "--config", filepath.Join(tmpDir, "config.yaml")},
	}

	for _, cmdArgs := range commands {
		t.Run(strings.Join(cmdArgs, " "), func(t *testing.T) {
			cmd := rootCmd
			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)
			cmd.SetArgs(cmdArgs)

			err := cmd.Execute()
			require.NoError(t, err)

			output := outBuf.String()

			// CRITICAL: Verify NONE of the secret values appear in output
			for _, secret := range secrets {
				assert.NotContains(t, output, secret,
					"SECURITY VIOLATION: Secret value '%s' found in output of command: %v",
					secret, cmdArgs)
			}

			// Reset command
			cmd.SetArgs(nil)
		})
	}
}
