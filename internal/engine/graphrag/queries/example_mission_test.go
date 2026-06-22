package queries_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/queries"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Example demonstrating how to use MissionQueries to orchestrate mission execution.
// This shows the typical orchestration loop pattern.
func ExampleMissionQueries_orchestrationLoop() {
	ctx := context.Background()

	// Create Neo4j client
	config := graph.GraphClientConfig{
		URI:      "bolt://localhost:7687",
		Username: "neo4j",
		Password: "password",
		Database: "neo4j",
	}

	client, err := graph.NewNeo4jClient(config)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close(ctx)

	// Create mission queries
	mq := queries.NewMissionQueries(client)

	// Mission ID (would come from mission creation)
	missionID := types.NewID()

	// Orchestration loop
	for {
		// Get ready nodes (all dependencies completed)
		readyNodes, err := mq.GetReadyNodes(ctx, missionID)
		if err != nil {
			log.Fatal(err)
		}

		// No ready nodes means we're done or blocked
		if len(readyNodes) == 0 {
			break
		}

		// Execute each ready node
		for _, node := range readyNodes {
			fmt.Printf("Executing node: %s (%s)\n", node.Name, node.Type)

			// Execute the node (actual execution logic here)
			// ...

			// Check execution result
			success := true // placeholder

			if success {
				// Node completed successfully
				fmt.Printf("Node %s completed\n", node.Name)
			} else {
				// Node failed
				fmt.Printf("Node %s failed\n", node.Name)
			}
		}

		// Get mission status
		status, err := mq.GetMissionStats(ctx, missionID)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Mission progress: %d/%d completed, %d failed\n",
			status.CompletedNodes, status.TotalNodes, status.FailedNodes)

		// Check if mission is complete
		if status.CompletedNodes+status.FailedNodes == status.TotalNodes {
			break
		}
	}

	fmt.Println("Mission execution complete")
}

// Example demonstrating how to query mission dependencies.
func ExampleMissionQueries_dependencies() {
	ctx := context.Background()

	// Setup (client creation omitted for brevity)
	var client graph.GraphClient
	mq := queries.NewMissionQueries(client)

	nodeID := types.NewID()

	// Get all dependencies for a node
	deps, err := mq.GetNodeDependencies(ctx, nodeID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Node has %d dependencies:\n", len(deps))
	for _, dep := range deps {
		fmt.Printf("  - %s (status: %s)\n", dep.Name, dep.Status)
	}

	// Check if all dependencies are completed
	allCompleted := true
	for _, dep := range deps {
		if dep.Status != schema.MissionNodeStatusCompleted {
			allCompleted = false
			break
		}
	}

	if allCompleted {
		fmt.Println("All dependencies completed - node is ready to execute")
	} else {
		fmt.Println("Waiting for dependencies to complete")
	}
}

// Example demonstrating how to track mission execution history.
func ExampleMissionQueries_executionHistory() {
	ctx := context.Background()

	// Setup (client creation omitted for brevity)
	var client graph.GraphClient
	mq := queries.NewMissionQueries(client)

	nodeID := types.NewID()

	// Get all executions for a node (including retries)
	executions, err := mq.GetNodeExecutions(ctx, nodeID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Node has %d execution attempts:\n", len(executions))
	for _, exec := range executions {
		fmt.Printf("  Attempt %d: %s (started: %s)\n",
			exec.Attempt, exec.Status, exec.StartedAt)

		if exec.Error != "" {
			fmt.Printf("    Error: %s\n", exec.Error)
		}
	}
}

// Example demonstrating how to query orchestrator decisions.
func ExampleMissionQueries_decisions() {
	ctx := context.Background()

	// Setup (client creation omitted for brevity)
	var client graph.GraphClient
	mq := queries.NewMissionQueries(client)

	missionID := types.NewID()

	// Get all orchestrator decisions
	decisions, err := mq.GetMissionDecisions(ctx, missionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Orchestrator made %d decisions:\n", len(decisions))
	for _, decision := range decisions {
		fmt.Printf("  Iteration %d: %s (confidence: %.2f)\n",
			decision.Iteration, decision.Action, decision.Confidence)
		fmt.Printf("    Reasoning: %s\n", decision.Reasoning)

		if decision.TargetNodeID != "" {
			fmt.Printf("    Target: %s\n", decision.TargetNodeID)
		}
	}
}

// Example demonstrating how to get comprehensive mission statistics.
func ExampleMissionQueries_statistics() {
	ctx := context.Background()

	// Setup (client creation omitted for brevity)
	var client graph.GraphClient
	mq := queries.NewMissionQueries(client)

	missionID := types.NewID()

	// Get comprehensive mission statistics
	stats, err := mq.GetMissionStats(ctx, missionID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Mission Statistics:\n")
	fmt.Printf("  Nodes: %d total, %d completed, %d failed, %d pending\n",
		stats.TotalNodes, stats.CompletedNodes, stats.FailedNodes, stats.PendingNodes)
	fmt.Printf("  Decisions: %d\n", stats.TotalDecisions)
	fmt.Printf("  Executions: %d\n", stats.TotalExecutions)

	if !stats.StartTime.IsZero() {
		fmt.Printf("  Started: %s\n", stats.StartTime)
	}
	if !stats.EndTime.IsZero() {
		fmt.Printf("  Completed: %s\n", stats.EndTime)
		duration := stats.EndTime.Sub(stats.StartTime)
		fmt.Printf("  Duration: %s\n", duration)
	}

	// Calculate completion percentage
	if stats.TotalNodes > 0 {
		completionPct := float64(stats.CompletedNodes) / float64(stats.TotalNodes) * 100
		fmt.Printf("  Progress: %.1f%%\n", completionPct)
	}
}
