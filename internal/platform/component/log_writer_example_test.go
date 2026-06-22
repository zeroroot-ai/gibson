package component_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// ExampleDefaultLogWriter demonstrates how to create a log writer and capture
// component output to log files with timestamps and stream markers.
func ExampleDefaultLogWriter() {
	// Create a temporary directory for logs
	tmpDir, err := os.MkdirTemp("", "gibson-logs-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create the log writer
	logWriter, err := component.NewDefaultLogWriter(tmpDir, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create writers for stdout and stderr
	stdoutWriter, err := logWriter.CreateWriter("example-component", "stdout")
	if err != nil {
		log.Fatal(err)
	}

	stderrWriter, err := logWriter.CreateWriter("example-component", "stderr")
	if err != nil {
		log.Fatal(err)
	}

	// Write some output
	fmt.Fprintln(stdoutWriter, "Component started successfully")
	fmt.Fprintln(stderrWriter, "Warning: high memory usage detected")
	fmt.Fprintln(stdoutWriter, "Processing request...")

	// Close all writers for the component
	if err := logWriter.Close("example-component"); err != nil {
		log.Fatal(err)
	}

	// Verify the log file was created
	logPath := filepath.Join(tmpDir, "example-component.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		log.Fatal("log file was not created")
	}

	fmt.Println("Log file created successfully")
	// Output: Log file created successfully
}
