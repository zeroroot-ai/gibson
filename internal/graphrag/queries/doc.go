// Package queries provides high-level query interfaces for Gibson graph operations.
//
// # Overview
//
// The queries package abstracts Neo4j Cypher queries into type-safe Go methods,
// providing a clean interface for interacting with the Gibson graph database.
// Each query struct focuses on a specific domain (execution, mission, mission).
//
// # ExecutionQueries
//
// ExecutionQueries handles runtime execution tracking for the Gibson orchestrator.
// It tracks three main types of execution nodes:
//
//   - AgentExecution: Tracks individual agent executions with status, timing, and results
//   - Decision: Captures orchestrator decisions with reasoning and confidence scores
//   - ToolExecution: Records tool invocations within agent executions
//
// # Graph Relationships
//
// The execution tracking creates the following relationships:
//
//	AgentExecution -[:EXECUTES]-> MissionNode
//	AgentExecution -[:PRODUCED]-> Finding
//	AgentExecution -[:USED_TOOL]-> ToolExecution
//	Mission -[:HAS_DECISION]-> Decision
//
// # Usage Example
//
//	// Create execution queries
//	client := graph.NewNeo4jClient(config)
//	queries := queries.NewExecutionQueries(client)
//
//	// Track agent execution
//	exec := schema.NewAgentExecution("scan-node", missionID)
//	if err := queries.CreateAgentExecution(ctx, exec); err != nil {
//	    return err
//	}
//
//	// Update execution status
//	exec.MarkCompleted()
//	exec.WithResult(map[string]any{"vulnerabilities": 5})
//	if err := queries.UpdateExecution(ctx, exec); err != nil {
//	    return err
//	}
//
//	// Link execution to findings
//	findingIDs := []string{"finding-1", "finding-2"}
//	if err := queries.LinkExecutionToFindings(ctx, exec.ID.String(), findingIDs); err != nil {
//	    return err
//	}
//
//	// Create orchestrator decision
//	decision := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
//	    WithTargetNode("scan-node").
//	    WithReasoning("Initial vulnerability scan required").
//	    WithConfidence(0.95)
//	if err := queries.CreateDecision(ctx, decision); err != nil {
//	    return err
//	}
//
//	// Retrieve mission audit trail
//	decisions, err := queries.GetMissionDecisions(ctx, missionID.String())
//	if err != nil {
//	    return err
//	}
//
//	// Check retry attempts
//	executions, err := queries.GetNodeExecutions(ctx, "scan-node")
//	if err != nil {
//	    return err
//	}
//
// # Error Handling
//
// All methods return typed errors using the types.Error system with specific error codes:
//
//   - ErrCodeGraphInvalidQuery: Invalid input parameters or validation failures
//   - ErrCodeGraphNodeNotFound: Referenced nodes don't exist
//   - ErrCodeGraphNodeCreateFailed: Node creation failed
//   - ErrCodeGraphQueryFailed: Query execution failed
//
// # Concurrency
//
// All query methods are thread-safe and can be called concurrently.
// The underlying graph.GraphClient handles connection pooling and transaction management.
//
// # Performance Considerations
//
//   - Batch operations: LinkExecutionToFindings uses UNWIND for efficient batch linking
//   - Atomic operations: CreateAgentExecution creates node and relationship atomically
//   - Indexed queries: All queries use indexed fields (id, mission_node_id) for fast lookups
//   - Read vs Write: Query method automatically selects appropriate transaction type
package queries
