package component_test

import (
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// ExampleCheckProcessState demonstrates how to check the state of a process by its PID.
func ExampleCheckProcessState() {
	// Check the state of the current process
	currentPID := os.Getpid()
	state := component.CheckProcessState(currentPID)

	fmt.Printf("Current process state: %s\n", state)

	// Check a non-existent process (very high PID unlikely to exist)
	nonExistentPID := 99999
	state = component.CheckProcessState(nonExistentPID)

	fmt.Printf("Non-existent process state: %s\n", state)

	// Output:
	// Current process state: running
	// Non-existent process state: dead
}

// ExampleCheckProcessState_monitoring demonstrates using CheckProcessState
// in a monitoring scenario.
func ExampleCheckProcessState_monitoring() {
	// Example: Monitor a component process
	var componentPID int = 12345 // Example PID

	state := component.CheckProcessState(componentPID)

	switch state {
	case component.ProcessStateRunning:
		fmt.Println("Component is running normally")
	case component.ProcessStateDead:
		fmt.Println("Component has stopped - may need restart")
	case component.ProcessStateZombie:
		fmt.Println("Component is a zombie - parent should reap it")
	default:
		fmt.Printf("Unknown state: %s\n", state)
	}
}
