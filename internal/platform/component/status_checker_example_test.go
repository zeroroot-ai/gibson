package component_test

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// ExampleStatusChecker demonstrates how to use the StatusChecker
// to get comprehensive status information about a component.
func ExampleStatusChecker() {
	// Create a status checker with the logs directory
	checker := component.NewStatusChecker("/home/user/.gibson/logs")

	// Create a component to check (typically loaded from database)
	startedAt := time.Now().Add(-5 * time.Minute)
	comp := &component.Component{
		ID:        1,
		Kind:      component.ComponentKindAgent,
		Name:      "davinci",
		Version:   "1.0.0",
		Port:      50051,
		PID:       12345,
		Status:    component.ComponentStatusRunning,
		StartedAt: &startedAt,
	}

	// Check the component's status
	ctx := context.Background()
	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		fmt.Printf("Error checking status: %v\n", err)
		return
	}

	// Display status information
	fmt.Printf("Component: %s\n", result.Component.Name)
	fmt.Printf("Process State: %s\n", result.ProcessState)
	fmt.Printf("Uptime: %s\n", result.Uptime.Round(time.Second))

	if result.HealthCheck != nil {
		fmt.Printf("Health: %s (%s protocol)\n", result.HealthCheck.Status, result.HealthCheck.Protocol)
		fmt.Printf("Response Time: %s\n", result.HealthCheck.ResponseTime)
		if result.HealthCheck.Error != "" {
			fmt.Printf("Error: %s\n", result.HealthCheck.Error)
		}
	}

	if result.HasRecentErrors() {
		fmt.Printf("Recent Errors: %d\n", len(result.RecentErrors))
		for i, logErr := range result.RecentErrors {
			fmt.Printf("  %d. [%s] %s\n", i+1, logErr.Level, logErr.Message)
		}
	}
}

// ExampleStatusChecker_stoppedComponent demonstrates checking status
// of a stopped component.
func ExampleStatusChecker_stoppedComponent() {
	checker := component.NewStatusChecker("/home/user/.gibson/logs")

	// Component that has stopped
	comp := &component.Component{
		ID:      1,
		Kind:    component.ComponentKindTool,
		Name:    "nmap",
		Version: "1.0.0",
		Port:    50052,
		PID:     99999, // Non-existent PID
		Status:  component.ComponentStatusStopped,
	}

	ctx := context.Background()
	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Component: %s\n", result.Component.Name)
	fmt.Printf("Process State: %s\n", result.ProcessState)
	fmt.Printf("Running: %t\n", result.IsRunning())
	fmt.Printf("Healthy: %t\n", result.IsHealthy())

	// Health check is nil for stopped components
	if result.HealthCheck == nil {
		fmt.Println("Health check: skipped (component not running)")
	}
}
