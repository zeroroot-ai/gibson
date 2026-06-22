package build

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewMockBuildExecutor tests creating a new MockBuildExecutor.
func TestNewMockBuildExecutor(t *testing.T) {
	mock := NewMockBuildExecutor()
	assert.NotNil(t, mock)
	assert.Implements(t, (*BuildExecutor)(nil), mock)
	assert.Empty(t, mock.BuildCalls)
	assert.Empty(t, mock.CleanCalls)
	assert.Empty(t, mock.TestCalls)
}

// TestMockBuildExecutor_Build_DefaultBehavior tests default Build behavior.
func TestMockBuildExecutor_Build_DefaultBehavior(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	config := BuildConfig{
		WorkDir:    "/tmp/test",
		Command:    "make",
		Args:       []string{"build"},
		OutputPath: "bin/output",
	}

	result, err := mock.Build(ctx, config, "test-component", "1.0.0", "0.1.0")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, "bin/output", result.OutputPath)
	assert.Contains(t, result.Stdout, "mock build stdout")
	assert.Equal(t, 1, mock.GetBuildCallCount())
}

// TestMockBuildExecutor_Build_RecordsCalls tests that Build records calls.
func TestMockBuildExecutor_Build_RecordsCalls(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	config := BuildConfig{
		WorkDir: "/tmp/test",
		Command: "make",
	}

	// Make multiple calls
	_, _ = mock.Build(ctx, config, "component1", "1.0.0", "0.1.0")
	_, _ = mock.Build(ctx, config, "component2", "2.0.0", "0.2.0")
	_, _ = mock.Build(ctx, config, "component3", "3.0.0", "0.3.0")

	assert.Equal(t, 3, mock.GetBuildCallCount())
	assert.Len(t, mock.BuildCalls, 3)

	assert.Equal(t, "component1", mock.BuildCalls[0].ComponentName)
	assert.Equal(t, "component2", mock.BuildCalls[1].ComponentName)
	assert.Equal(t, "component3", mock.BuildCalls[2].ComponentName)
}

// TestMockBuildExecutor_Build_CustomFunction tests custom Build function.
func TestMockBuildExecutor_Build_CustomFunction(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	customResult := &BuildResult{
		Success:    true,
		OutputPath: "/custom/path",
		Duration:   200 * time.Millisecond,
		Stdout:     "custom stdout",
	}

	mock.BuildFunc = func(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error) {
		return customResult, nil
	}

	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}
	result, err := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")

	assert.NoError(t, err)
	assert.Equal(t, customResult, result)
	assert.Equal(t, "/custom/path", result.OutputPath)
	assert.Equal(t, "custom stdout", result.Stdout)
}

// TestMockBuildExecutor_Build_QueuedResults tests queued results.
func TestMockBuildExecutor_Build_QueuedResults(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Queue multiple results
	result1 := &BuildResult{Success: true, OutputPath: "/path1"}
	result2 := &BuildResult{Success: true, OutputPath: "/path2"}
	result3 := &BuildResult{Success: false, Error: fmt.Errorf("build failed")}

	mock.SetBuildResult(result1)
	mock.SetBuildResult(result2)
	mock.SetBuildResult(result3)

	// First call returns first result
	r1, err1 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, err1)
	assert.Equal(t, result1, r1)

	// Second call returns second result
	r2, err2 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, err2)
	assert.Equal(t, result2, r2)

	// Third call returns third result
	r3, err3 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, err3)
	assert.Equal(t, result3, r3)

	// Fourth call returns default result
	r4, err4 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, err4)
	assert.True(t, r4.Success)
}

// TestMockBuildExecutor_Build_QueuedErrors tests queued errors.
func TestMockBuildExecutor_Build_QueuedErrors(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Queue multiple errors
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")

	mock.SetBuildError(err1)
	mock.SetBuildError(err2)

	// First call returns first error
	r1, e1 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.Error(t, e1)
	assert.Equal(t, err1, e1)
	assert.False(t, r1.Success)

	// Second call returns second error
	r2, e2 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.Error(t, e2)
	assert.Equal(t, err2, e2)
	assert.False(t, r2.Success)

	// Third call returns default success
	r3, e3 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, e3)
	assert.True(t, r3.Success)
}

// TestMockBuildExecutor_Build_Delay tests build delay simulation.
func TestMockBuildExecutor_Build_Delay(t *testing.T) {
	mock := NewMockBuildExecutor()
	mock.BuildDelay = 100 * time.Millisecond

	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	start := time.Now()
	result, err := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.GreaterOrEqual(t, elapsed, mock.BuildDelay)
}

// TestMockBuildExecutor_Build_ContextCancellation tests context cancellation.
func TestMockBuildExecutor_Build_ContextCancellation(t *testing.T) {
	mock := NewMockBuildExecutor()
	mock.BuildDelay = 1 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	result, err := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")

	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.False(t, result.Success)
}

// TestMockBuildExecutor_Clean_DefaultBehavior tests default Clean behavior.
func TestMockBuildExecutor_Clean_DefaultBehavior(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	result, err := mock.Clean(ctx, "/tmp/test")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Output, "mock clean output")
	assert.Equal(t, 1, mock.GetCleanCallCount())
}

// TestMockBuildExecutor_Clean_RecordsCalls tests that Clean records calls.
func TestMockBuildExecutor_Clean_RecordsCalls(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	_, _ = mock.Clean(ctx, "/tmp/dir1")
	_, _ = mock.Clean(ctx, "/tmp/dir2")
	_, _ = mock.Clean(ctx, "/tmp/dir3")

	assert.Equal(t, 3, mock.GetCleanCallCount())
	assert.Len(t, mock.CleanCalls, 3)

	assert.Equal(t, "/tmp/dir1", mock.CleanCalls[0].WorkDir)
	assert.Equal(t, "/tmp/dir2", mock.CleanCalls[1].WorkDir)
	assert.Equal(t, "/tmp/dir3", mock.CleanCalls[2].WorkDir)
}

// TestMockBuildExecutor_Clean_CustomFunction tests custom Clean function.
func TestMockBuildExecutor_Clean_CustomFunction(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	customResult := &CleanResult{
		Success:  true,
		Duration: 50 * time.Millisecond,
		Output:   "custom clean output",
	}

	mock.CleanFunc = func(ctx context.Context, workDir string) (*CleanResult, error) {
		return customResult, nil
	}

	result, err := mock.Clean(ctx, "/tmp/test")

	assert.NoError(t, err)
	assert.Equal(t, customResult, result)
	assert.Equal(t, "custom clean output", result.Output)
}

// TestMockBuildExecutor_Test_DefaultBehavior tests default Test behavior.
func TestMockBuildExecutor_Test_DefaultBehavior(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	result, err := mock.Test(ctx, "/tmp/test")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 10, result.Passed)
	assert.Equal(t, 0, result.Failed)
	assert.Contains(t, result.Output, "mock test output")
	assert.Equal(t, 1, mock.GetTestCallCount())
}

// TestMockBuildExecutor_Test_RecordsCalls tests that Test records calls.
func TestMockBuildExecutor_Test_RecordsCalls(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	_, _ = mock.Test(ctx, "/tmp/dir1")
	_, _ = mock.Test(ctx, "/tmp/dir2")

	assert.Equal(t, 2, mock.GetTestCallCount())
	assert.Len(t, mock.TestCalls, 2)

	assert.Equal(t, "/tmp/dir1", mock.TestCalls[0].WorkDir)
	assert.Equal(t, "/tmp/dir2", mock.TestCalls[1].WorkDir)
}

// TestMockBuildExecutor_Test_CustomFunction tests custom Test function.
func TestMockBuildExecutor_Test_CustomFunction(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	customResult := &TestResult{
		Success:  true,
		Passed:   5,
		Failed:   2,
		Duration: 100 * time.Millisecond,
		Output:   "custom test output",
	}

	mock.TestFunc = func(ctx context.Context, workDir string) (*TestResult, error) {
		return customResult, nil
	}

	result, err := mock.Test(ctx, "/tmp/test")

	assert.NoError(t, err)
	assert.Equal(t, customResult, result)
	assert.Equal(t, 5, result.Passed)
	assert.Equal(t, 2, result.Failed)
}

// TestMockBuildExecutor_Reset tests Reset method.
func TestMockBuildExecutor_Reset(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Make some calls and set some state
	_, _ = mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	_, _ = mock.Clean(ctx, "/tmp/test")
	_, _ = mock.Test(ctx, "/tmp/test")
	mock.SetBuildError(fmt.Errorf("error"))
	mock.BuildFunc = func(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error) {
		return nil, nil
	}

	// Verify state exists
	assert.Equal(t, 1, mock.GetBuildCallCount())
	assert.Equal(t, 1, mock.GetCleanCallCount())
	assert.Equal(t, 1, mock.GetTestCallCount())
	assert.Len(t, mock.BuildErrors, 1)
	assert.NotNil(t, mock.BuildFunc)

	// Reset
	mock.Reset()

	// Verify state is cleared
	assert.Equal(t, 0, mock.GetBuildCallCount())
	assert.Equal(t, 0, mock.GetCleanCallCount())
	assert.Equal(t, 0, mock.GetTestCallCount())
	assert.Empty(t, mock.BuildErrors)
	assert.Empty(t, mock.BuildResults)
	assert.Empty(t, mock.CleanErrors)
	assert.Empty(t, mock.CleanResults)
	assert.Empty(t, mock.TestErrors)
	assert.Empty(t, mock.TestResults)
	assert.Nil(t, mock.BuildFunc)
	assert.Nil(t, mock.CleanFunc)
	assert.Nil(t, mock.TestFunc)
}

// TestMockBuildExecutor_VerifyBuildCalled tests VerifyBuildCalled method.
func TestMockBuildExecutor_VerifyBuildCalled(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// No calls yet
	err := mock.VerifyBuildCalled("test", "1.0.0", "0.1.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Build was not called")

	// Make a call
	_, _ = mock.Build(ctx, config, "test", "1.0.0", "0.1.0")

	// Verify with correct parameters
	err = mock.VerifyBuildCalled("test", "1.0.0", "0.1.0")
	assert.NoError(t, err)

	// Verify with wrong component name
	err = mock.VerifyBuildCalled("wrong", "1.0.0", "0.1.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected component name")

	// Verify with wrong component version
	err = mock.VerifyBuildCalled("test", "2.0.0", "0.1.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected component version")

	// Verify with wrong gibson version
	err = mock.VerifyBuildCalled("test", "1.0.0", "0.2.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected gibson version")
}

// TestMockBuildExecutor_VerifyCleanCalled tests VerifyCleanCalled method.
func TestMockBuildExecutor_VerifyCleanCalled(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	// No calls yet
	err := mock.VerifyCleanCalled("/tmp/test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Clean was not called")

	// Make a call
	_, _ = mock.Clean(ctx, "/tmp/test")

	// Verify with correct work directory
	err = mock.VerifyCleanCalled("/tmp/test")
	assert.NoError(t, err)

	// Verify with wrong work directory
	err = mock.VerifyCleanCalled("/tmp/wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected work directory")
}

// TestMockBuildExecutor_VerifyTestCalled tests VerifyTestCalled method.
func TestMockBuildExecutor_VerifyTestCalled(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	// No calls yet
	err := mock.VerifyTestCalled("/tmp/test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Test was not called")

	// Make a call
	_, _ = mock.Test(ctx, "/tmp/test")

	// Verify with correct work directory
	err = mock.VerifyTestCalled("/tmp/test")
	assert.NoError(t, err)

	// Verify with wrong work directory
	err = mock.VerifyTestCalled("/tmp/wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected work directory")
}

// TestMockBuildExecutor_Concurrency tests concurrent access to mock.
func TestMockBuildExecutor_Concurrency(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Run concurrent operations
	const goroutines = 10
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, _ = mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
			_, _ = mock.Clean(ctx, "/tmp/test")
			_, _ = mock.Test(ctx, "/tmp/test")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	// Verify all calls were recorded
	assert.Equal(t, goroutines, mock.GetBuildCallCount())
	assert.Equal(t, goroutines, mock.GetCleanCallCount())
	assert.Equal(t, goroutines, mock.GetTestCallCount())
}

// TestMockBuildExecutor_QueuedResultsPriority tests that queued errors take priority over results.
func TestMockBuildExecutor_QueuedResultsPriority(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Queue both result and error
	mock.SetBuildResult(&BuildResult{Success: true, OutputPath: "/path"})
	mock.SetBuildError(fmt.Errorf("build failed"))

	// Error should be returned first (queued second, but errors have priority in implementation)
	result, err := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.Error(t, err)
	assert.False(t, result.Success)

	// Then result should be returned
	result2, err2 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.NoError(t, err2)
	assert.True(t, result2.Success)
}

// TestMockBuildExecutor_SetterMethods tests all setter methods.
func TestMockBuildExecutor_SetterMethods(t *testing.T) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	// Test SetBuildResult
	buildResult := &BuildResult{Success: true, OutputPath: "/custom"}
	mock.SetBuildResult(buildResult)
	r1, _ := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.Equal(t, buildResult, r1)

	// Test SetBuildError
	buildErr := fmt.Errorf("custom build error")
	mock.SetBuildError(buildErr)
	_, e1 := mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	assert.Equal(t, buildErr, e1)

	// Test SetCleanResult
	cleanResult := &CleanResult{Success: true, Output: "custom clean"}
	mock.SetCleanResult(cleanResult)
	r2, _ := mock.Clean(ctx, "/tmp/test")
	assert.Equal(t, cleanResult, r2)

	// Test SetCleanError
	cleanErr := fmt.Errorf("custom clean error")
	mock.SetCleanError(cleanErr)
	_, e2 := mock.Clean(ctx, "/tmp/test")
	assert.Equal(t, cleanErr, e2)

	// Test SetTestResult
	testResult := &TestResult{Success: true, Passed: 5, Failed: 1}
	mock.SetTestResult(testResult)
	r3, _ := mock.Test(ctx, "/tmp/test")
	assert.Equal(t, testResult, r3)

	// Test SetTestError
	testErr := fmt.Errorf("custom test error")
	mock.SetTestError(testErr)
	_, e3 := mock.Test(ctx, "/tmp/test")
	assert.Equal(t, testErr, e3)
}

// TestBuildCall_Fields tests BuildCall structure.
func TestBuildCall_Fields(t *testing.T) {
	now := time.Now()
	call := BuildCall{
		Config:           BuildConfig{WorkDir: "/tmp/test", Command: "make"},
		ComponentName:    "test-component",
		ComponentVersion: "1.0.0",
		GibsonVersion:    "0.1.0",
		Timestamp:        now,
	}

	assert.Equal(t, "/tmp/test", call.Config.WorkDir)
	assert.Equal(t, "test-component", call.ComponentName)
	assert.Equal(t, "1.0.0", call.ComponentVersion)
	assert.Equal(t, "0.1.0", call.GibsonVersion)
	assert.Equal(t, now, call.Timestamp)
}

// TestCleanCall_Fields tests CleanCall structure.
func TestCleanCall_Fields(t *testing.T) {
	now := time.Now()
	call := CleanCall{
		WorkDir:   "/tmp/test",
		Timestamp: now,
	}

	assert.Equal(t, "/tmp/test", call.WorkDir)
	assert.Equal(t, now, call.Timestamp)
}

// TestTestCall_Fields tests TestCall structure.
func TestTestCall_Fields(t *testing.T) {
	now := time.Now()
	call := TestCall{
		WorkDir:   "/tmp/test",
		Timestamp: now,
	}

	assert.Equal(t, "/tmp/test", call.WorkDir)
	assert.Equal(t, now, call.Timestamp)
}

// BenchmarkMockBuildExecutor_Build benchmarks mock Build method.
func BenchmarkMockBuildExecutor_Build(b *testing.B) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()
	config := BuildConfig{WorkDir: "/tmp/test", Command: "make"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mock.Build(ctx, config, "test", "1.0.0", "0.1.0")
	}
}

// BenchmarkMockBuildExecutor_Clean benchmarks mock Clean method.
func BenchmarkMockBuildExecutor_Clean(b *testing.B) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mock.Clean(ctx, "/tmp/test")
	}
}

// BenchmarkMockBuildExecutor_Test benchmarks mock Test method.
func BenchmarkMockBuildExecutor_Test(b *testing.B) {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mock.Test(ctx, "/tmp/test")
	}
}

// ExampleMockBuildExecutor demonstrates using MockBuildExecutor.
func ExampleMockBuildExecutor() {
	mock := NewMockBuildExecutor()
	ctx := context.Background()

	// Configure mock to return custom result
	mock.SetBuildResult(&BuildResult{
		Success:    true,
		OutputPath: "/tmp/output",
		Duration:   100 * time.Millisecond,
		Stdout:     "Build successful",
	})

	config := BuildConfig{
		WorkDir: "/tmp/test",
		Command: "make",
		Args:    []string{"build"},
	}

	result, err := mock.Build(ctx, config, "my-component", "1.0.0", "0.1.0")
	if err != nil {
		fmt.Printf("build failed: %v\n", err)
		return
	}

	fmt.Printf("Build success: %v\n", result.Success)
	fmt.Printf("Output path: %s\n", result.OutputPath)

	// Verify the call
	err = mock.VerifyBuildCalled("my-component", "1.0.0", "0.1.0")
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}

	// Output:
	// Build success: true
	// Output path: /tmp/output
}
