package git

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseRepoURL tests parsing of various repository URL formats
func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedInfo  *RepoInfo
		expectedError string
	}{
		{
			name: "HTTPS URL with .git extension",
			url:  "https://github.com/org/gibson-agent-scanner.git",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-agent-scanner",
			},
		},
		{
			name: "HTTPS URL without .git extension",
			url:  "https://github.com/org/gibson-tool-nmap",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-tool-nmap",
			},
		},
		{
			name: "SSH URL with .git extension",
			url:  "git@github.com:org/gibson-plugin-vuln-db.git",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-plugin-vuln-db",
			},
		},
		{
			name: "SSH URL without .git extension",
			url:  "git@github.com:org/gibson-agent-scanner",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-agent-scanner",
			},
		},
		{
			name: "Multi-hyphen component name",
			url:  "https://github.com/zero-day/gibson-tool-web-scanner.git",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "zero-day",
				Repo:  "gibson-tool-web-scanner",
			},
		},
		{
			name: "HTTP URL (not HTTPS)",
			url:  "http://github.com/org/gibson-agent-test.git",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-agent-test",
			},
		},
		{
			name: "Different git host",
			url:  "https://gitlab.com/myorg/gibson-plugin-custom.git",
			expectedInfo: &RepoInfo{
				Host:  "gitlab.com",
				Owner: "myorg",
				Repo:  "gibson-plugin-custom",
			},
		},
		{
			name: "Any repository name allowed",
			url:  "git@github.com:user/any-repo-name.git",
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "user",
				Repo:  "any-repo-name",
			},
		},
		{
			name:          "Empty URL",
			url:           "",
			expectedError: "repository URL cannot be empty",
		},
		{
			name:          "Invalid URL format",
			url:           "not-a-valid-url",
			expectedError: "unable to parse repository URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitOps := NewDefaultGitOperations()
			info, err := gitOps.ParseRepoURL(tt.url)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, info)
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, tt.expectedInfo.Host, info.Host)
				assert.Equal(t, tt.expectedInfo.Owner, info.Owner)
				assert.Equal(t, tt.expectedInfo.Repo, info.Repo)
			}
		})
	}
}

// TestRepoInfo_String tests the String method of RepoInfo
func TestRepoInfo_String(t *testing.T) {
	info := &RepoInfo{
		Host:  "github.com",
		Owner: "org",
		Repo:  "gibson-agent-scanner",
	}

	expected := "github.com/org/gibson-agent-scanner"
	assert.Equal(t, expected, info.String())
}

// TestRepoInfo_ToURL tests the ToURL method of RepoInfo
func TestRepoInfo_ToURL(t *testing.T) {
	info := &RepoInfo{
		Host:  "github.com",
		Owner: "org",
		Repo:  "gibson-agent-scanner",
	}

	expected := "https://github.com/org/gibson-agent-scanner.git"
	assert.Equal(t, expected, info.ToURL())
}

// TestRepoInfo_ToSSHURL tests the ToSSHURL method of RepoInfo
func TestRepoInfo_ToSSHURL(t *testing.T) {
	info := &RepoInfo{
		Host:  "github.com",
		Owner: "org",
		Repo:  "gibson-tool-nmap",
	}

	expected := "git@github.com:org/gibson-tool-nmap.git"
	assert.Equal(t, expected, info.ToSSHURL())
}

// TestClone tests the Clone method (integration test - requires git)
func TestClone(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	tests := []struct {
		name        string
		url         string
		opts        CloneOptions
		expectError bool
		skipReason  string
	}{
		{
			name:        "Invalid URL",
			url:         "https://invalid-git-url-that-does-not-exist-12345.com/repo.git",
			opts:        CloneOptions{Depth: 1},
			expectError: true,
		},
		{
			name:        "Empty URL",
			url:         "",
			opts:        CloneOptions{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			gitOps := NewDefaultGitOperations()
			tmpDir := t.TempDir()
			dest := filepath.Join(tmpDir, "repo")

			err := gitOps.Clone(tt.url, dest, tt.opts)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify .git directory exists
				gitDir := filepath.Join(dest, ".git")
				_, err := os.Stat(gitDir)
				assert.NoError(t, err, "expected .git directory to exist")
			}
		})
	}
}

// TestPull tests the Pull method
func TestPull(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	tests := []struct {
		name        string
		setupDir    func(t *testing.T) string
		expectError bool
	}{
		{
			name: "Non-existent directory",
			setupDir: func(t *testing.T) string {
				return "/non/existent/path"
			},
			expectError: true,
		},
		{
			name: "Directory without git repo",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitOps := NewDefaultGitOperations()
			dir := tt.setupDir(t)

			err := gitOps.Pull(dir)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetVersion tests the GetVersion method
func TestGetVersion(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	tests := []struct {
		name        string
		setupDir    func(t *testing.T) string
		expectError bool
		validateFn  func(t *testing.T, version string)
	}{
		{
			name: "Non-existent directory",
			setupDir: func(t *testing.T) string {
				return "/non/existent/path"
			},
			expectError: true,
		},
		{
			name: "Directory without git repo",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError: true,
		},
		{
			name: "Valid git repository",
			setupDir: func(t *testing.T) string {
				tmpDir := t.TempDir()
				// Initialize a git repo
				cmd := exec.Command("git", "init")
				cmd.Dir = tmpDir
				require.NoError(t, cmd.Run())

				// Configure git user (required for commit)
				cmd = exec.Command("git", "config", "user.email", "test@example.com")
				cmd.Dir = tmpDir
				require.NoError(t, cmd.Run())

				cmd = exec.Command("git", "config", "user.name", "Test User")
				cmd.Dir = tmpDir
				require.NoError(t, cmd.Run())

				// Create a file and commit
				testFile := filepath.Join(tmpDir, "test.txt")
				require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

				cmd = exec.Command("git", "add", "test.txt")
				cmd.Dir = tmpDir
				require.NoError(t, cmd.Run())

				cmd = exec.Command("git", "commit", "-m", "Initial commit")
				cmd.Dir = tmpDir
				require.NoError(t, cmd.Run())

				return tmpDir
			},
			expectError: false,
			validateFn: func(t *testing.T, version string) {
				// Verify it's a valid git hash (40 hex characters)
				assert.Len(t, version, 40)
				assert.True(t, isHexString(version), "expected version to be a hex string")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitOps := NewDefaultGitOperations()
			dir := tt.setupDir(t)

			version, err := gitOps.GetVersion(dir)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, version)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, version)
				if tt.validateFn != nil {
					tt.validateFn(t, version)
				}
			}
		})
	}
}

// TestMockGitOperations_Clone tests the mock Clone implementation
func TestMockGitOperations_Clone(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		dest        string
		opts        CloneOptions
		setupMock   func(*MockGitOperations)
		expectError bool
	}{
		{
			name: "Successful clone",
			url:  "https://github.com/org/gibson-agent-test.git",
			dest: "/tmp/test",
			opts: CloneOptions{Depth: 1},
			setupMock: func(m *MockGitOperations) {
				m.CloneError = nil
			},
			expectError: false,
		},
		{
			name: "Clone with error",
			url:  "https://github.com/org/gibson-tool-test.git",
			dest: "/tmp/test2",
			opts: CloneOptions{Branch: "main"},
			setupMock: func(m *MockGitOperations) {
				m.SetCloneError(errors.New("clone failed"))
			},
			expectError: true,
		},
		{
			name: "Clone with tag",
			url:  "https://github.com/org/gibson-plugin-test.git",
			dest: "/tmp/test3",
			opts: CloneOptions{Tag: "v1.0.0"},
			setupMock: func(m *MockGitOperations) {
				m.CloneError = nil
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockGitOperations()
			tt.setupMock(mock)

			err := mock.Clone(tt.url, tt.dest, tt.opts)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify operation was recorded
			assert.True(t, mock.VerifyOperation("clone"))
			assert.True(t, mock.VerifyOperationWithURL("clone", tt.url))

			ops := mock.GetOperationsByType("clone")
			require.Len(t, ops, 1)
			assert.Equal(t, tt.url, ops[0].URL)
			assert.Equal(t, tt.dest, ops[0].Dest)
			assert.Equal(t, tt.opts.Depth, ops[0].Options.Depth)
			assert.Equal(t, tt.opts.Branch, ops[0].Options.Branch)
			assert.Equal(t, tt.opts.Tag, ops[0].Options.Tag)
		})
	}
}

// TestMockGitOperations_Pull tests the mock Pull implementation
func TestMockGitOperations_Pull(t *testing.T) {
	tests := []struct {
		name        string
		dir         string
		setupMock   func(*MockGitOperations)
		expectError bool
	}{
		{
			name: "Successful pull",
			dir:  "/tmp/repo",
			setupMock: func(m *MockGitOperations) {
				m.PullError = nil
			},
			expectError: false,
		},
		{
			name: "Pull with error",
			dir:  "/tmp/repo2",
			setupMock: func(m *MockGitOperations) {
				m.SetPullError(errors.New("pull failed"))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockGitOperations()
			tt.setupMock(mock)

			err := mock.Pull(tt.dir)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify operation was recorded
			assert.True(t, mock.VerifyOperation("pull"))
			assert.True(t, mock.VerifyOperationWithDir("pull", tt.dir))

			ops := mock.GetOperationsByType("pull")
			require.Len(t, ops, 1)
			assert.Equal(t, tt.dir, ops[0].Dir)
		})
	}
}

// TestMockGitOperations_GetVersion tests the mock GetVersion implementation
func TestMockGitOperations_GetVersion(t *testing.T) {
	tests := []struct {
		name            string
		dir             string
		setupMock       func(*MockGitOperations)
		expectedVersion string
		expectError     bool
	}{
		{
			name: "Successful get version",
			dir:  "/tmp/repo",
			setupMock: func(m *MockGitOperations) {
				m.SetGetVersionResponse("abc123def456")
			},
			expectedVersion: "abc123def456",
			expectError:     false,
		},
		{
			name: "Get version with error",
			dir:  "/tmp/repo2",
			setupMock: func(m *MockGitOperations) {
				m.SetGetVersionError(errors.New("failed to get version"))
			},
			expectedVersion: "",
			expectError:     true,
		},
		{
			name: "Custom version hash",
			dir:  "/tmp/repo3",
			setupMock: func(m *MockGitOperations) {
				m.SetGetVersionResponse("1234567890abcdef1234567890abcdef12345678")
			},
			expectedVersion: "1234567890abcdef1234567890abcdef12345678",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockGitOperations()
			tt.setupMock(mock)

			version, err := mock.GetVersion(tt.dir)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVersion, version)
			}

			// Verify operation was recorded
			assert.True(t, mock.VerifyOperation("get_version"))
			assert.True(t, mock.VerifyOperationWithDir("get_version", tt.dir))
		})
	}
}

// TestMockGitOperations_ParseRepoURL tests the mock ParseRepoURL implementation
func TestMockGitOperations_ParseRepoURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		setupMock     func(*MockGitOperations)
		expectedInfo  *RepoInfo
		expectError   bool
		useRealParser bool
	}{
		{
			name: "Custom response",
			url:  "https://github.com/org/gibson-agent-test.git",
			setupMock: func(m *MockGitOperations) {
				m.SetParseRepoURLResponse(&RepoInfo{
					Host:  "custom.com",
					Owner: "customorg",
					Repo:  "customrepo",
				})
			},
			expectedInfo: &RepoInfo{
				Host:  "custom.com",
				Owner: "customorg",
				Repo:  "customrepo",
			},
			expectError: false,
		},
		{
			name: "Parse error",
			url:  "invalid-url",
			setupMock: func(m *MockGitOperations) {
				m.SetParseRepoURLError(errors.New("invalid URL"))
			},
			expectError: true,
		},
		{
			name: "Use real parser",
			url:  "https://github.com/org/gibson-tool-nmap.git",
			setupMock: func(m *MockGitOperations) {
				// Don't set custom response - should use real parser
			},
			expectedInfo: &RepoInfo{
				Host:  "github.com",
				Owner: "org",
				Repo:  "gibson-tool-nmap",
			},
			expectError:   false,
			useRealParser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockGitOperations()
			tt.setupMock(mock)

			info, err := mock.ParseRepoURL(tt.url)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, tt.expectedInfo.Host, info.Host)
				assert.Equal(t, tt.expectedInfo.Owner, info.Owner)
				assert.Equal(t, tt.expectedInfo.Repo, info.Repo)
			}

			// Verify operation was recorded
			assert.True(t, mock.VerifyOperation("parse_url"))
			assert.True(t, mock.VerifyOperationWithURL("parse_url", tt.url))
		})
	}
}

// TestMockGitOperations_Reset tests the Reset method
func TestMockGitOperations_Reset(t *testing.T) {
	mock := NewMockGitOperations()

	// Perform some operations
	_ = mock.Clone("url1", "dest1", CloneOptions{})
	_ = mock.Pull("dir1")
	_, _ = mock.GetVersion("dir2")

	// Set some errors
	mock.SetCloneError(errors.New("error"))
	mock.SetPullError(errors.New("error"))

	// Verify operations were recorded
	assert.Equal(t, 3, mock.GetOperationCount())

	// Reset
	mock.Reset()

	// Verify everything is cleared
	assert.Equal(t, 0, mock.GetOperationCount())
	assert.Nil(t, mock.CloneError)
	assert.Nil(t, mock.PullError)
	assert.Nil(t, mock.GetVersionError)
	assert.Equal(t, "abc123def456", mock.GetVersionResponse)
}

// TestMockGitOperations_OperationCounting tests operation counting methods
func TestMockGitOperations_OperationCounting(t *testing.T) {
	mock := NewMockGitOperations()

	// Perform various operations
	_ = mock.Clone("url1", "dest1", CloneOptions{})
	_ = mock.Clone("url2", "dest2", CloneOptions{})
	_ = mock.Pull("dir1")
	_, _ = mock.GetVersion("dir1")
	_, _ = mock.ParseRepoURL("url1")

	// Test operation counting
	assert.Equal(t, 5, mock.GetOperationCount())

	// Test filtering by type
	clones := mock.GetOperationsByType("clone")
	assert.Len(t, clones, 2)

	pulls := mock.GetOperationsByType("pull")
	assert.Len(t, pulls, 1)

	versions := mock.GetOperationsByType("get_version")
	assert.Len(t, versions, 1)

	// Test verification
	assert.True(t, mock.VerifyOperation("clone"))
	assert.True(t, mock.VerifyOperation("pull"))
	assert.True(t, mock.VerifyOperation("get_version"))
	assert.False(t, mock.VerifyOperation("nonexistent"))
}

// TestMockGitOperations_ConcurrentAccess tests thread-safety
func TestMockGitOperations_ConcurrentAccess(t *testing.T) {
	mock := NewMockGitOperations()

	// Run operations concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_ = mock.Clone("url", "dest", CloneOptions{})
			_ = mock.Pull("dir")
			_, _ = mock.GetVersion("dir")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 30 operations (3 per goroutine * 10 goroutines)
	assert.Equal(t, 30, mock.GetOperationCount())
}

// TestMockGitOperations_String tests the String method
func TestMockGitOperations_String(t *testing.T) {
	mock := NewMockGitOperations()
	str := mock.String()
	assert.Contains(t, str, "MockGitOperations")
	assert.Contains(t, str, "operations=0")

	// Add some operations
	_ = mock.Clone("url", "dest", CloneOptions{})
	mock.SetCloneError(errors.New("error"))

	str = mock.String()
	assert.Contains(t, str, "operations=1")
	assert.Contains(t, str, "cloneErr=true")
}

// TestCloneOptions tests CloneOptions structure
func TestCloneOptions(t *testing.T) {
	tests := []struct {
		name string
		opts CloneOptions
	}{
		{
			name: "Empty options",
			opts: CloneOptions{},
		},
		{
			name: "With depth",
			opts: CloneOptions{Depth: 1},
		},
		{
			name: "With branch",
			opts: CloneOptions{Branch: "main"},
		},
		{
			name: "With tag",
			opts: CloneOptions{Tag: "v1.0.0"},
		},
		{
			name: "All options",
			opts: CloneOptions{
				Depth:  1,
				Branch: "develop",
				Tag:    "v2.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the struct can be created and accessed
			assert.GreaterOrEqual(t, tt.opts.Depth, 0)
		})
	}
}

// Helper function to check if a string is hexadecimal
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// TestGitOperationsInterface verifies that both implementations satisfy the interface
func TestGitOperationsInterface(t *testing.T) {
	var _ GitOperations = (*DefaultGitOperations)(nil)
	var _ GitOperations = (*MockGitOperations)(nil)
}

// TestDefaultGitOperations_Constructor tests the constructor
func TestDefaultGitOperations_Constructor(t *testing.T) {
	gitOps := NewDefaultGitOperations()
	assert.NotNil(t, gitOps)

	// Verify it's the correct type
	_, ok := gitOps.(*DefaultGitOperations)
	assert.True(t, ok)
}

// TestMockGitOperations_Constructor tests the mock constructor
func TestMockGitOperations_Constructor(t *testing.T) {
	mock := NewMockGitOperations()
	assert.NotNil(t, mock)
	assert.Empty(t, mock.Operations)
	assert.Equal(t, "abc123def456", mock.GetVersionResponse)
	assert.Nil(t, mock.CloneError)
	assert.Nil(t, mock.PullError)
	assert.Nil(t, mock.GetVersionError)
}

// TestOperationRecord tests the OperationRecord structure
func TestOperationRecord(t *testing.T) {
	opts := CloneOptions{Depth: 1, Branch: "main"}
	record := OperationRecord{
		Operation: "clone",
		URL:       "https://github.com/org/repo.git",
		Dir:       "/tmp/dir",
		Dest:      "/tmp/dest",
		Options:   &opts,
	}

	assert.Equal(t, "clone", record.Operation)
	assert.Equal(t, "https://github.com/org/repo.git", record.URL)
	assert.Equal(t, "/tmp/dir", record.Dir)
	assert.Equal(t, "/tmp/dest", record.Dest)
	assert.NotNil(t, record.Options)
	assert.Equal(t, 1, record.Options.Depth)
	assert.Equal(t, "main", record.Options.Branch)
}

// TestRepoInfo_AllMethods tests all RepoInfo methods together
func TestRepoInfo_AllMethods(t *testing.T) {
	info := &RepoInfo{
		Host:  "github.com",
		Owner: "zero-day",
		Repo:  "gibson-tool-web-scanner",
	}

	// Test String
	str := info.String()
	assert.Contains(t, str, "github.com")
	assert.Contains(t, str, "zero-day")
	assert.Contains(t, str, "gibson-tool-web-scanner")

	// Test ToURL
	url := info.ToURL()
	assert.Equal(t, "https://github.com/zero-day/gibson-tool-web-scanner.git", url)

	// Test ToSSHURL
	sshURL := info.ToSSHURL()
	assert.Equal(t, "git@github.com:zero-day/gibson-tool-web-scanner.git", sshURL)
}
