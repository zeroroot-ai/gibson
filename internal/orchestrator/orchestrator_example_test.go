package orchestrator_test

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
)

// ExampleOrchestrator demonstrates basic orchestrator usage.
func ExampleOrchestrator() {
	// Create orchestrator components (observer, thinker, actor would be initialized here)
	// For this example, we're showing the configuration pattern
	var observer *orchestrator.Observer // Would be initialized with graph queries
	var thinker *orchestrator.Thinker   // Would be initialized with LLM client
	var actor *orchestrator.Actor       // Would be initialized with harness

	// Create orchestrator with configuration
	orch := orchestrator.NewOrchestrator(
		observer,
		thinker,
		actor,
		orchestrator.WithMaxIterations(100),
		orchestrator.WithBudget(100000),   // 100k token budget
		orchestrator.WithMaxConcurrent(5), // Max 5 parallel executions
		orchestrator.WithTimeout(30*time.Minute), // 30 minute timeout
		orchestrator.WithLogger(orchestrator.WrapSlogLogger(slog.Default())),
	)

	// Run orchestration for a mission
	ctx := context.Background()
	missionID := "mission-123"

	result, err := orch.Run(ctx, missionID)
	if err != nil {
		fmt.Printf("Orchestration error: %v\n", err)
		return
	}

	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Iterations: %d\n", result.TotalIterations)
	fmt.Printf("Tokens Used: %d\n", result.TotalTokensUsed)
	fmt.Printf("Duration: %s\n", result.Duration)
}

// ExampleNewOrchestrator_withOptions demonstrates orchestrator with options.
func ExampleNewOrchestrator_withOptions() {
	var observer *orchestrator.Observer
	var thinker *orchestrator.Thinker
	var actor *orchestrator.Actor

	// Create orchestrator without event bus for this example
	// In production, you would pass an actual EventBus implementation
	orch := orchestrator.NewOrchestrator(
		observer,
		thinker,
		actor,
		orchestrator.WithMaxIterations(50),
	)

	fmt.Printf("Orchestrator configured with %d max iterations\n", 50)
	_ = orch
}

// ExampleOrchestratorResult demonstrates result handling.
func ExampleOrchestratorResult() {
	// Simulate an orchestrator result
	result := &orchestrator.OrchestratorResult{
		MissionID:       "mission-abc123",
		Status:          "completed",
		TotalIterations: 25,
		TotalDecisions:  20,
		TotalTokensUsed: 45000,
		Duration:        5 * time.Minute,
		CompletedNodes:  18,
		FailedNodes:     2,
		StopReason:      "all mission nodes completed successfully",
	}

	// Display results
	fmt.Printf("Mission: %s\n", result.MissionID)
	fmt.Printf("%s\n", result.String())
}
