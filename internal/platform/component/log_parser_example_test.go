package component_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

func ExampleParseRecentErrors() {
	// Create a temporary log file with mixed JSON and key=value formats
	tmpDir, _ := os.MkdirTemp("", "example")
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "app.log")
	logContent := `{"level":"INFO","msg":"application started","time":"2025-01-01T12:00:00Z"}
{"level":"ERROR","msg":"database connection failed","time":"2025-01-01T12:01:00Z"}
time=2025-01-01T12:02:00Z level=DEBUG msg="processing request"
time=2025-01-01T12:03:00Z level=ERROR msg="timeout waiting for response"
{"level":"FATAL","msg":"critical system failure","time":"2025-01-01T12:04:00Z"}
`
	_ = os.WriteFile(logFile, []byte(logContent), 0644)

	// Parse the most recent 3 errors
	errors, err := component.ParseRecentErrors(logFile, 3)
	if err != nil {
		fmt.Printf("error parsing logs: %v\n", err)
		return
	}

	// Display the errors (newest first)
	for i, logErr := range errors {
		fmt.Printf("Error %d: [%s] %s\n", i+1, logErr.Level, logErr.Message)
	}

	// Output:
	// Error 1: [FATAL] critical system failure
	// Error 2: [ERROR] timeout waiting for response
	// Error 3: [ERROR] database connection failed
}

func ExampleParseRecentErrors_missingFile() {
	// Parsing a non-existent file returns empty slice, no error
	errors, err := component.ParseRecentErrors("/nonexistent/file.log", 5)

	fmt.Printf("Errors found: %d\n", len(errors))
	fmt.Printf("Error returned: %v\n", err)

	// Output:
	// Errors found: 0
	// Error returned: <nil>
}

func ExampleParseRecentErrors_noErrors() {
	tmpDir, _ := os.MkdirTemp("", "example")
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "clean.log")
	logContent := `{"level":"INFO","msg":"all good","time":"2025-01-01T12:00:00Z"}
{"level":"DEBUG","msg":"processing","time":"2025-01-01T12:01:00Z"}
{"level":"WARN","msg":"slow query","time":"2025-01-01T12:02:00Z"}
`
	_ = os.WriteFile(logFile, []byte(logContent), 0644)

	errors, _ := component.ParseRecentErrors(logFile, 10)

	fmt.Printf("Errors found: %d\n", len(errors))

	// Output:
	// Errors found: 0
}
