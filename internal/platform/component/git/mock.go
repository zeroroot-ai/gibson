package git

import (
	"fmt"
	"sync"
)

// OperationRecord records details of a git operation
type OperationRecord struct {
	// Operation is the name of the operation (clone, pull, get_version, parse_url)
	Operation string

	// URL is the repository URL (for clone and parse_url operations)
	URL string

	// Dir is the directory path (for pull and get_version operations)
	Dir string

	// Dest is the destination path (for clone operations)
	Dest string

	// Options are the clone options (for clone operations)
	Options *CloneOptions
}

// MockGitOperations is a mock implementation of GitOperations for testing
type MockGitOperations struct {
	mu sync.Mutex

	// Operations records all operations performed
	Operations []OperationRecord

	// CloneError controls the error returned by Clone
	CloneError error

	// PullError controls the error returned by Pull
	PullError error

	// GetVersionError controls the error returned by GetVersion
	GetVersionError error

	// GetVersionResponse controls the version string returned by GetVersion
	GetVersionResponse string

	// ParseRepoURLError controls the error returned by ParseRepoURL
	ParseRepoURLError error

	// ParseRepoURLResponse controls the RepoInfo returned by ParseRepoURL
	ParseRepoURLResponse *RepoInfo
}

// NewMockGitOperations creates a new MockGitOperations instance
func NewMockGitOperations() *MockGitOperations {
	return &MockGitOperations{
		Operations:         make([]OperationRecord, 0),
		GetVersionResponse: "abc123def456", // Default mock commit hash
	}
}

// Clone records the clone operation and returns the configured error (if any)
func (m *MockGitOperations) Clone(url, dest string, opts CloneOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create a copy of options to avoid mutation issues
	optsCopy := opts

	m.Operations = append(m.Operations, OperationRecord{
		Operation: "clone",
		URL:       url,
		Dest:      dest,
		Options:   &optsCopy,
	})

	return m.CloneError
}

// Pull records the pull operation and returns the configured error (if any)
func (m *MockGitOperations) Pull(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Operations = append(m.Operations, OperationRecord{
		Operation: "pull",
		Dir:       dir,
	})

	return m.PullError
}

// GetVersion records the get_version operation and returns the configured response/error
func (m *MockGitOperations) GetVersion(dir string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Operations = append(m.Operations, OperationRecord{
		Operation: "get_version",
		Dir:       dir,
	})

	return m.GetVersionResponse, m.GetVersionError
}

// ParseRepoURL records the parse_url operation and returns the configured response/error
func (m *MockGitOperations) ParseRepoURL(url string) (*RepoInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Operations = append(m.Operations, OperationRecord{
		Operation: "parse_url",
		URL:       url,
	})

	// If a custom response is set, return it
	if m.ParseRepoURLResponse != nil {
		return m.ParseRepoURLResponse, m.ParseRepoURLError
	}

	// Otherwise, use the real implementation for convenience in tests
	// This allows tests to verify parsing logic without setting up responses
	if m.ParseRepoURLError != nil {
		return nil, m.ParseRepoURLError
	}

	defaultImpl := NewDefaultGitOperations()
	return defaultImpl.ParseRepoURL(url)
}

// Reset clears all recorded operations and errors
func (m *MockGitOperations) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Operations = make([]OperationRecord, 0)
	m.CloneError = nil
	m.PullError = nil
	m.GetVersionError = nil
	m.GetVersionResponse = "abc123def456"
	m.ParseRepoURLError = nil
	m.ParseRepoURLResponse = nil
}

// GetOperations returns a copy of all recorded operations
func (m *MockGitOperations) GetOperations() []OperationRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	ops := make([]OperationRecord, len(m.Operations))
	copy(ops, m.Operations)
	return ops
}

// GetOperationCount returns the number of operations performed
func (m *MockGitOperations) GetOperationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.Operations)
}

// GetOperationsByType returns all operations of a specific type
func (m *MockGitOperations) GetOperationsByType(opType string) []OperationRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	var filtered []OperationRecord
	for _, op := range m.Operations {
		if op.Operation == opType {
			filtered = append(filtered, op)
		}
	}
	return filtered
}

// VerifyOperation checks if a specific operation was performed
func (m *MockGitOperations) VerifyOperation(opType string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, op := range m.Operations {
		if op.Operation == opType {
			return true
		}
	}
	return false
}

// VerifyOperationWithURL checks if an operation with a specific URL was performed
func (m *MockGitOperations) VerifyOperationWithURL(opType, url string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, op := range m.Operations {
		if op.Operation == opType && op.URL == url {
			return true
		}
	}
	return false
}

// VerifyOperationWithDir checks if an operation with a specific directory was performed
func (m *MockGitOperations) VerifyOperationWithDir(opType, dir string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, op := range m.Operations {
		if op.Operation == opType && op.Dir == dir {
			return true
		}
	}
	return false
}

// SetCloneError configures the error to return from Clone
func (m *MockGitOperations) SetCloneError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CloneError = err
}

// SetPullError configures the error to return from Pull
func (m *MockGitOperations) SetPullError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PullError = err
}

// SetGetVersionError configures the error to return from GetVersion
func (m *MockGitOperations) SetGetVersionError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetVersionError = err
}

// SetGetVersionResponse configures the version string to return from GetVersion
func (m *MockGitOperations) SetGetVersionResponse(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetVersionResponse = version
}

// SetParseRepoURLError configures the error to return from ParseRepoURL
func (m *MockGitOperations) SetParseRepoURLError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ParseRepoURLError = err
}

// SetParseRepoURLResponse configures the RepoInfo to return from ParseRepoURL
func (m *MockGitOperations) SetParseRepoURLResponse(info *RepoInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ParseRepoURLResponse = info
}

// String returns a string representation of the mock's state
func (m *MockGitOperations) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return fmt.Sprintf("MockGitOperations{operations=%d, cloneErr=%v, pullErr=%v, versionErr=%v}",
		len(m.Operations), m.CloneError != nil, m.PullError != nil, m.GetVersionError != nil)
}
