package queries_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Example demonstrating execution tracking mission
func Example_executionTracking() {
	// Setup Neo4j client
	config := graph.GraphClientConfig{
		URI:               "bolt://localhost:7687",
		Username:          "neo4j",
		Password:          "password",
		ConnectionTimeout: 30,
	}

	client, err := graph.NewNeo4jClient(config)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close(ctx)

	// Create execution queries
	execQueries := queries.NewExecutionQueries(client)

	// Scenario: Track a vulnerability scan execution
	missionID := types.NewID()

	// 1. Create orchestrator decision
	decision := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
		WithTargetNode("vuln-scan-node").
		WithReasoning("Initial vulnerability scan required based on target analysis").
		WithConfidence(0.95).
		WithLangfuseSpanID("span-123")

	if err := execQueries.CreateDecision(ctx, decision); err != nil {
		log.Fatal(err)
	}

	// 2. Create agent execution
	execution := schema.NewAgentExecution("vuln-scan-node", missionID).
		WithConfig(map[string]any{
			"target": "192.168.1.1",
			"ports":  "1-1000",
		}).
		WithLangfuseSpanID("execution-span-456")

	if err := execQueries.CreateAgentExecution(ctx, execution); err != nil {
		log.Fatal(err)
	}

	// 3. Track tool execution
	tool := schema.NewToolExecution(execution.ID, "nmap").
		WithInput(map[string]any{
			"target": "192.168.1.1",
			"flags":  "-sV -sC",
		}).
		WithLangfuseSpanID("tool-span-789")

	if err := execQueries.CreateToolExecution(ctx, tool); err != nil {
		log.Fatal(err)
	}

	// Simulate tool completion
	tool.MarkCompleted().
		WithOutput(map[string]any{
			"open_ports": []int{22, 80, 443},
			"services":   []string{"ssh", "http", "https"},
		})

	// 4. Mark execution completed with results
	execution.MarkCompleted().
		WithResult(map[string]any{
			"vulnerabilities_found": 3,
			"severity":              "high",
		})

	if err := execQueries.UpdateExecution(ctx, execution); err != nil {
		log.Fatal(err)
	}

	// 5. Link execution to findings
	findingIDs := []string{"finding-001", "finding-002", "finding-003"}
	if err := execQueries.LinkExecutionToFindings(ctx, execution.ID.String(), findingIDs); err != nil {
		log.Fatal(err)
	}

	// 6. Retrieve audit trail
	decisions, err := execQueries.GetMissionDecisions(ctx, missionID.String())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Mission has %d decisions\n", len(decisions))

	// 7. Check execution history (for retry tracking)
	executions, err := execQueries.GetNodeExecutions(ctx, "vuln-scan-node")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Node has %d execution attempts\n", len(executions))

	// 8. Get tools used in execution
	tools, err := execQueries.GetExecutionTools(ctx, execution.ID.String())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Execution used %d tools\n", len(tools))
}

// Example demonstrating retry tracking
func Example_retryTracking() {
	client := graph.NewMockGraphClient()
	client.Connect(context.Background())

	execQueries := queries.NewExecutionQueries(client)
	ctx := context.Background()

	missionID := types.NewID()
	nodeID := "flaky-node"

	// First attempt - fails
	attempt1 := schema.NewAgentExecution(nodeID, missionID).
		WithAttempt(1)

	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": attempt1.ID.String()}},
	})

	if err := execQueries.CreateAgentExecution(ctx, attempt1); err != nil {
		log.Fatal(err)
	}

	// Simulate failure
	attempt1.MarkFailed("Connection timeout")

	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": attempt1.ID.String()}},
	})

	if err := execQueries.UpdateExecution(ctx, attempt1); err != nil {
		log.Fatal(err)
	}

	// Second attempt - succeeds
	attempt2 := schema.NewAgentExecution(nodeID, missionID).
		WithAttempt(2)

	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": attempt2.ID.String()}},
	})

	if err := execQueries.CreateAgentExecution(ctx, attempt2); err != nil {
		log.Fatal(err)
	}

	attempt2.MarkCompleted()

	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": attempt2.ID.String()}},
	})

	if err := execQueries.UpdateExecution(ctx, attempt2); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Retry tracking completed successfully")
	// Output: Retry tracking completed successfully
}

// Example demonstrating orchestrator decision audit trail
func Example_decisionAuditTrail() {
	client := graph.NewMockGraphClient()
	client.Connect(context.Background())

	execQueries := queries.NewExecutionQueries(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Create a series of orchestrator decisions
	decisions := []*schema.Decision{
		schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
			WithTargetNode("scan-node").
			WithReasoning("Initial reconnaissance required").
			WithConfidence(0.95),

		schema.NewDecision(missionID, 2, schema.DecisionActionModifyParams).
			WithTargetNode("scan-node").
			WithReasoning("Adjust scan intensity based on results").
			WithConfidence(0.85).
			WithModifications(map[string]any{"intensity": "aggressive"}),

		schema.NewDecision(missionID, 3, schema.DecisionActionExecuteAgent).
			WithTargetNode("exploit-node").
			WithReasoning("Vulnerabilities found, proceed with exploitation").
			WithConfidence(0.90),

		schema.NewDecision(missionID, 4, schema.DecisionActionComplete).
			WithReasoning("Mission objectives achieved").
			WithConfidence(0.98),
	}

	// Store each decision
	for _, decision := range decisions {
		client.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": decision.ID.String()}},
		})

		if err := execQueries.CreateDecision(ctx, decision); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("Created %d orchestrator decisions\n", len(decisions))
	fmt.Println("Decisions provide complete audit trail of orchestrator reasoning")
	// Output:
	// Created 4 orchestrator decisions
	// Decisions provide complete audit trail of orchestrator reasoning
}
