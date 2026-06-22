package build

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockBuildExecutor is a mock implementation of BuildExecutor for testing.
type MockBuildExecutor struct {
	mu sync.Mutex

	// BuildFunc allows customizing the Build behavior
	BuildFunc func(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error)

	// CleanFunc allows customizing the Clean behavior
	CleanFunc func(ctx context.Context, workDir string) (*CleanResult, error)

	// TestFunc allows customizing the Test behavior
	TestFunc func(ctx context.Context, workDir string) (*TestResult, error)

	// BuildCalls records all calls to Build
	BuildCalls []BuildCall

	// CleanCalls records all calls to Clean
	CleanCalls []CleanCall

	// TestCalls records all calls to Test
	TestCalls []TestCall

	// BuildResults is a queue of results to return from Build calls
	BuildResults []*BuildResult

	// BuildErrors is a queue of errors to return from Build calls
	BuildErrors []error

	// CleanResults is a queue of results to return from Clean calls
	CleanResults []*CleanResult

	// CleanErrors is a queue of errors to return from Clean calls
	CleanErrors []error

	// TestResults is a queue of results to return from Test calls
	TestResults []*TestResult

	// TestErrors is a queue of errors to return from Test calls
	TestErrors []error

	// BuildDelay simulates build execution time
	BuildDelay time.Duration

	// CleanDelay simulates clean execution time
	CleanDelay time.Duration

	// TestDelay simulates test execution time
	TestDelay time.Duration
}

// BuildCall records a single call to Build.
type BuildCall struct {
	Config           BuildConfig
	ComponentName    string
	ComponentVersion string
	GibsonVersion    string
	Timestamp        time.Time
}

// CleanCall records a single call to Clean.
type CleanCall struct {
	WorkDir   string
	Timestamp time.Time
}

// TestCall records a single call to Test.
type TestCall struct {
	WorkDir   string
	Timestamp time.Time
}

// NewMockBuildExecutor creates a new MockBuildExecutor.
func NewMockBuildExecutor() *MockBuildExecutor {
	return &MockBuildExecutor{
		BuildCalls:   make([]BuildCall, 0),
		CleanCalls:   make([]CleanCall, 0),
		TestCalls:    make([]TestCall, 0),
		BuildResults: make([]*BuildResult, 0),
		BuildErrors:  make([]error, 0),
		CleanResults: make([]*CleanResult, 0),
		CleanErrors:  make([]error, 0),
		TestResults:  make([]*TestResult, 0),
		TestErrors:   make([]error, 0),
	}
}

// Build executes the build command and returns the configured result.
func (m *MockBuildExecutor) Build(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record the call
	m.BuildCalls = append(m.BuildCalls, BuildCall{
		Config:           config,
		ComponentName:    componentName,
		ComponentVersion: componentVersion,
		GibsonVersion:    gibsonVersion,
		Timestamp:        time.Now(),
	})

	// If custom function is provided, use it
	if m.BuildFunc != nil {
		return m.BuildFunc(ctx, config, componentName, componentVersion, gibsonVersion)
	}

	// Simulate build delay
	if m.BuildDelay > 0 {
		select {
		case <-time.After(m.BuildDelay):
		case <-ctx.Done():
			return &BuildResult{
				Success:  false,
				Duration: m.BuildDelay,
				Error:    ctx.Err(),
			}, ctx.Err()
		}
	}

	// Return queued error if available
	if len(m.BuildErrors) > 0 {
		err := m.BuildErrors[0]
		m.BuildErrors = m.BuildErrors[1:]
		return &BuildResult{
			Success:  false,
			Duration: m.BuildDelay,
			Error:    err,
		}, err
	}

	// Return queued result if available
	if len(m.BuildResults) > 0 {
		result := m.BuildResults[0]
		m.BuildResults = m.BuildResults[1:]
		return result, nil
	}

	// Default success result
	return &BuildResult{
		Success:    true,
		OutputPath: config.OutputPath,
		Duration:   m.BuildDelay,
		Stdout:     "mock build stdout",
		Stderr:     "",
	}, nil
}

// Clean executes the clean command and returns the configured result.
func (m *MockBuildExecutor) Clean(ctx context.Context, workDir string) (*CleanResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record the call
	m.CleanCalls = append(m.CleanCalls, CleanCall{
		WorkDir:   workDir,
		Timestamp: time.Now(),
	})

	// If custom function is provided, use it
	if m.CleanFunc != nil {
		return m.CleanFunc(ctx, workDir)
	}

	// Simulate clean delay
	if m.CleanDelay > 0 {
		select {
		case <-time.After(m.CleanDelay):
		case <-ctx.Done():
			return &CleanResult{
				Success:  false,
				Duration: m.CleanDelay,
				Error:    ctx.Err(),
			}, ctx.Err()
		}
	}

	// Return queued error if available
	if len(m.CleanErrors) > 0 {
		err := m.CleanErrors[0]
		m.CleanErrors = m.CleanErrors[1:]
		return &CleanResult{
			Success:  false,
			Duration: m.CleanDelay,
			Error:    err,
		}, err
	}

	// Return queued result if available
	if len(m.CleanResults) > 0 {
		result := m.CleanResults[0]
		m.CleanResults = m.CleanResults[1:]
		return result, nil
	}

	// Default success result
	return &CleanResult{
		Success:  true,
		Duration: m.CleanDelay,
		Output:   "mock clean output",
	}, nil
}

// Test executes the test command and returns the configured result.
func (m *MockBuildExecutor) Test(ctx context.Context, workDir string) (*TestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record the call
	m.TestCalls = append(m.TestCalls, TestCall{
		WorkDir:   workDir,
		Timestamp: time.Now(),
	})

	// If custom function is provided, use it
	if m.TestFunc != nil {
		return m.TestFunc(ctx, workDir)
	}

	// Simulate test delay
	if m.TestDelay > 0 {
		select {
		case <-time.After(m.TestDelay):
		case <-ctx.Done():
			return &TestResult{
				Success:  false,
				Duration: m.TestDelay,
				Error:    ctx.Err(),
			}, ctx.Err()
		}
	}

	// Return queued error if available
	if len(m.TestErrors) > 0 {
		err := m.TestErrors[0]
		m.TestErrors = m.TestErrors[1:]
		return &TestResult{
			Success:  false,
			Duration: m.TestDelay,
			Error:    err,
		}, err
	}

	// Return queued result if available
	if len(m.TestResults) > 0 {
		result := m.TestResults[0]
		m.TestResults = m.TestResults[1:]
		return result, nil
	}

	// Default success result
	return &TestResult{
		Success:  true,
		Passed:   10,
		Failed:   0,
		Duration: m.TestDelay,
		Output:   "mock test output\nall tests passed",
	}, nil
}

// Reset clears all recorded calls and queued results.
func (m *MockBuildExecutor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.BuildCalls = make([]BuildCall, 0)
	m.CleanCalls = make([]CleanCall, 0)
	m.TestCalls = make([]TestCall, 0)
	m.BuildResults = make([]*BuildResult, 0)
	m.BuildErrors = make([]error, 0)
	m.CleanResults = make([]*CleanResult, 0)
	m.CleanErrors = make([]error, 0)
	m.TestResults = make([]*TestResult, 0)
	m.TestErrors = make([]error, 0)
	m.BuildFunc = nil
	m.CleanFunc = nil
	m.TestFunc = nil
}

// GetBuildCallCount returns the number of times Build was called.
func (m *MockBuildExecutor) GetBuildCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.BuildCalls)
}

// GetCleanCallCount returns the number of times Clean was called.
func (m *MockBuildExecutor) GetCleanCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.CleanCalls)
}

// GetTestCallCount returns the number of times Test was called.
func (m *MockBuildExecutor) GetTestCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.TestCalls)
}

// SetBuildResult queues a result to be returned by the next Build call.
func (m *MockBuildExecutor) SetBuildResult(result *BuildResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BuildResults = append(m.BuildResults, result)
}

// SetBuildError queues an error to be returned by the next Build call.
func (m *MockBuildExecutor) SetBuildError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BuildErrors = append(m.BuildErrors, err)
}

// SetCleanResult queues a result to be returned by the next Clean call.
func (m *MockBuildExecutor) SetCleanResult(result *CleanResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CleanResults = append(m.CleanResults, result)
}

// SetCleanError queues an error to be returned by the next Clean call.
func (m *MockBuildExecutor) SetCleanError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CleanErrors = append(m.CleanErrors, err)
}

// SetTestResult queues a result to be returned by the next Test call.
func (m *MockBuildExecutor) SetTestResult(result *TestResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TestResults = append(m.TestResults, result)
}

// SetTestError queues an error to be returned by the next Test call.
func (m *MockBuildExecutor) SetTestError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TestErrors = append(m.TestErrors, err)
}

// VerifyBuildCalled verifies that Build was called with the expected parameters.
func (m *MockBuildExecutor) VerifyBuildCalled(componentName, componentVersion, gibsonVersion string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.BuildCalls) == 0 {
		return fmt.Errorf("Build was not called")
	}

	lastCall := m.BuildCalls[len(m.BuildCalls)-1]
	if lastCall.ComponentName != componentName {
		return fmt.Errorf("expected component name %s, got %s", componentName, lastCall.ComponentName)
	}
	if lastCall.ComponentVersion != componentVersion {
		return fmt.Errorf("expected component version %s, got %s", componentVersion, lastCall.ComponentVersion)
	}
	if lastCall.GibsonVersion != gibsonVersion {
		return fmt.Errorf("expected gibson version %s, got %s", gibsonVersion, lastCall.GibsonVersion)
	}

	return nil
}

// VerifyCleanCalled verifies that Clean was called with the expected work directory.
func (m *MockBuildExecutor) VerifyCleanCalled(workDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.CleanCalls) == 0 {
		return fmt.Errorf("Clean was not called")
	}

	lastCall := m.CleanCalls[len(m.CleanCalls)-1]
	if lastCall.WorkDir != workDir {
		return fmt.Errorf("expected work directory %s, got %s", workDir, lastCall.WorkDir)
	}

	return nil
}

// VerifyTestCalled verifies that Test was called with the expected work directory.
func (m *MockBuildExecutor) VerifyTestCalled(workDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.TestCalls) == 0 {
		return fmt.Errorf("Test was not called")
	}

	lastCall := m.TestCalls[len(m.TestCalls)-1]
	if lastCall.WorkDir != workDir {
		return fmt.Errorf("expected work directory %s, got %s", workDir, lastCall.WorkDir)
	}

	return nil
}
