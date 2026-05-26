package state_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zeroroot-ai/gibson/internal/state"
)

// ExampleStateClient_IncrementAndGetRunNumber demonstrates how to get unique run numbers.
func ExampleStateClient_IncrementAndGetRunNumber() {
	// Create a StateClient
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	missionID := "mission-abc123"

	// Get the next run number
	runNumber, err := client.IncrementAndGetRunNumber(ctx, missionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Starting run #%d\n", runNumber)
	// Output (will vary): Starting run #1
}

// ExampleStateClient_CascadeDeleteMission demonstrates how to atomically delete a mission.
func ExampleStateClient_CascadeDeleteMission() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	missionID := "mission-to-delete"

	// Atomically delete mission and all related data
	err = client.CascadeDeleteMission(ctx, missionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Mission and all related data deleted successfully")
	// Output: Mission and all related data deleted successfully
}

// ExampleStateClient_FindOrCreateMission demonstrates atomic mission lookup/creation.
func ExampleStateClient_FindOrCreateMission() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Ensure indexes are created
	if err := client.EnsureIndexes(ctx); err != nil {
		log.Fatal(err)
	}

	missionName := "vulnerability-scan"
	missionJSON := `{"id":"mission-123","name":"vulnerability-scan","status":"pending"}`
	newID := "mission-123"

	// Try to find or create mission
	result, err := client.FindOrCreateMission(ctx, missionName, missionJSON, newID)
	if err != nil {
		log.Fatal(err)
	}

	if result.Created {
		fmt.Println("Created new mission")
	} else {
		fmt.Println("Found existing mission")
	}
	// Output: Created new mission
}

// ExampleStateClient_RunScript demonstrates custom script execution.
func ExampleStateClient_RunScript() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	missionID := "mission-xyz"
	counterKey := fmt.Sprintf("gibson:mission:run_counter:%s", missionID)

	// Use the pre-defined script
	result, err := client.RunScript(ctx,
		state.IncrementAndGetRunNumberScript,
		[]string{counterKey},
	)
	if err != nil {
		log.Fatal(err)
	}

	runNumber := result.(int64)
	fmt.Printf("Run number: %d\n", runNumber)
	// Output (will vary): Run number: 1
}

// ExampleStateClient_Pipeline demonstrates batch operations.
func ExampleStateClient_Pipeline() {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Create a pipeline for batch operations
	pipe := client.Pipeline(ctx)

	// Queue multiple commands
	pipe.Set(ctx, "key1", "value1", 0)
	pipe.Set(ctx, "key2", "value2", 0)
	pipe.Incr(ctx, "counter")

	// Execute all commands together
	_, err = pipe.Exec(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Batch operations completed")
	// Output: Batch operations completed
}
