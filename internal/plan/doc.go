// Package plan provides execution plan generation, risk assessment, and execution
// capabilities for the Gibson AI agent framework. It enables safe, controlled, and
// auditable execution of multi-step operations with approval missions and guardrail
// integration.
//
// # Overview
//
// The plan package is a core component of Gibson that translates high-level agent tasks
// into structured execution plans with explicit steps, dependencies, and risk assessments.
// It provides:
//
//   - ExecutionPlan generation from agent tasks
//   - Risk assessment for individual steps and entire plans
//   - Approval missions for high-risk operations
//   - Step execution with guardrail integration
//   - Comprehensive error handling and result tracking
//
// # Architecture
//
// The package implements a complete plan lifecycle with state transitions:
//
//	draft -> pending_approval -> approved -> executing -> completed/failed
//
// Key components work together to manage this lifecycle:
//
//   - PlanGenerator: Creates execution plans from high-level tasks
//   - RiskAssessor: Evaluates steps and plans for risk levels
//   - ApprovalService: Manages approval missions for high-risk steps
//   - PlanExecutor: Orchestrates plan execution with guardrails
//
// Plans integrate deeply with the Gibson harness to execute tools, plugins, and
// delegate to other agents. The guardrail system provides safety checks at both
// input and output boundaries for each step.
//
// # Plan Lifecycle
//
// Every execution plan progresses through well-defined states:
//
//  1. Draft: Initial plan generation and construction
//  2. Pending Approval: Risk assessment complete, awaiting approval decision
//  3. Approved: Authorization granted, ready for execution
//  4. Executing: Active step-by-step execution in progress
//  5. Completed: All steps executed successfully
//  6. Failed: Execution failed due to step error or approval denial
//  7. Cancelled: Execution cancelled by user or system
//
// State transitions are strictly enforced via the PlanStatus.CanTransitionTo method.
// Terminal states (completed, failed, cancelled) cannot transition to other states.
//
// # Key Types
//
// ExecutionPlan is the central type representing a complete execution plan with steps,
// risk summary, and metadata. Each plan contains:
//
//   - Unique identifiers for plan and parent mission
//   - Ordered list of ExecutionStep instances
//   - PlanRiskSummary with aggregated risk assessment
//   - Status tracking and timestamps
//
// ExecutionStep represents an individual operation within a plan. Steps support
// multiple types:
//
//   - StepTypeTool: Execute a tool from the harness
//   - StepTypePlugin: Invoke a plugin method
//   - StepTypeAgent: Delegate to another agent
//   - StepTypeCondition: Conditional branching based on runtime evaluation
//   - StepTypeParallel: Execute multiple steps concurrently
//
// Each step includes risk level, approval requirements, dependencies, and execution state.
//
// RiskLevel classifies the danger level of operations:
//
//   - RiskLevelLow: Safe operations with minimal impact
//   - RiskLevelMedium: Operations requiring caution
//   - RiskLevelHigh: Dangerous operations requiring approval
//   - RiskLevelCritical: Extremely dangerous operations requiring approval
//
// Steps with high or critical risk automatically require approval before execution.
//
// PlanStatus tracks the lifecycle state of an execution plan with strict transition
// rules enforced by the state machine.
//
// # Risk Assessment
//
// The RiskAssessor component evaluates execution steps and plans using configurable
// risk rules. Default rules detect common dangerous patterns:
//
//   - Destructive operations (delete, remove, destroy)
//   - Data exfiltration (download, export, extract)
//   - Privilege escalation (sudo, root, admin)
//   - Network modifications (firewall, iptables, route)
//   - Credential access (password, key, secret)
//   - Agent delegation (complexity risk)
//   - Parallel execution (race condition risk)
//
// Custom rules can be added via WithRule to implement domain-specific risk logic.
// Risk assessments produce a RiskLevel and explanatory rationale for each step.
//
// # Approval Missions
//
// The ApprovalService interface manages human-in-the-loop approval for high-risk
// operations. When a step requires approval:
//
//  1. Executor creates an ApprovalRequest with full context
//  2. Request is submitted to the approval service
//  3. Execution blocks waiting for decision
//  4. Human approver reviews risk assessment and plan context
//  5. ApprovalDecision is submitted (approved or rejected)
//  6. Execution proceeds or fails based on decision
//
// Approval requests include timeout handling to prevent indefinite blocking.
//
// # Error Handling
//
// The package provides comprehensive error types for different failure scenarios:
//
//   - PlanError: Plan-level errors with error codes
//   - StepError: Step-level execution failures
//
// Error codes distinguish between different failure modes:
//
//   - ErrPlanNotApproved: Plan not in approved state
//   - ErrStepExecutionFailed: Step execution error
//   - ErrApprovalTimeout: Approval request timed out
//   - ErrApprovalDenied: Approval explicitly rejected
//   - ErrGuardrailBlocked: Guardrail check failed
//
// All errors implement standard Go error interfaces and support error unwrapping.
//
// # Usage Examples
//
// Creating a Plan Generator:
//
//	// Create an LLM-based plan generator
//	generator := plan.NewLLMPlanGenerator(
//		llmClient,
//		plan.WithLLMLogger(logger),
//		plan.WithLLMTracer(tracer),
//	)
//
//	// Generate a plan from a task
//	input := plan.GenerateInput{
//		Task: agent.NewTask(
//			"port-scan",
//			"Scan the target network for open ports",
//			map[string]any{"target": "192.168.1.0/24"},
//		),
//		AvailableTools: harnessTools,
//		AvailablePlugins: harnessPlugins,
//		AvailableAgents: harnessAgents,
//	}
//
//	plan, err := generator.Generate(ctx, input, harness)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Risk Assessment:
//
//	// Create a risk assessor with default rules
//	assessor := plan.NewRiskAssessor(plan.WithDefaultRules())
//
//	// Assess individual step
//	step := &plan.ExecutionStep{
//		Name: "Delete temporary files",
//		Description: "Remove all files in /tmp",
//		Type: plan.StepTypeTool,
//	}
//
//	assessment := assessor.AssessStep(step, plan.RiskContext{})
//	if assessment.RequiresApproval {
//		fmt.Printf("Step requires approval: %s\n", assessment.Rationale)
//	}
//
//	// Assess entire plan
//	summary := assessor.AssessPlan(execPlan, plan.RiskContext{})
//	fmt.Printf("Plan risk: %s, requires approval: %t\n",
//		summary.OverallLevel, summary.ApprovalRequired)
//
// Approval Mission:
//
//	// Create a mock approval service for testing
//	approvalService := plan.NewMockApprovalService()
//
//	// Pre-approve all requests
//	approvalService.SetDefaultDecision(plan.ApprovalDecision{
//		Approved: true,
//		ApproverID: "admin@example.com",
//		DecidedAt: time.Now(),
//	})
//
//	// Or handle approvals dynamically
//	go func() {
//		pending, _ := approvalService.GetPendingApprovals(ctx, plan.ApprovalFilter{})
//		for _, req := range pending {
//			decision := plan.ApprovalDecision{
//				Approved: req.RiskAssessment.Level != plan.RiskLevelCritical,
//				ApproverID: "security-team@example.com",
//				Reason: "Reviewed and assessed",
//				DecidedAt: time.Now(),
//			}
//			approvalService.SubmitDecision(ctx, req.ID, decision)
//		}
//	}()
//
// Executing an Approved Plan:
//
//	// Create a plan executor with guardrails and approval service
//	executor := plan.NewPlanExecutor(
//		plan.WithGuardrails(guardrailPipeline),
//		plan.WithApprovalService(approvalService),
//		plan.WithExecutorLogger(logger),
//		plan.WithStepTimeout(5 * time.Minute),
//	)
//
//	// Execute the approved plan
//	result, err := executor.Execute(ctx, approvedPlan, harness)
//	if err != nil {
//		var planErr *plan.PlanError
//		if errors.As(err, &planErr) {
//			switch planErr.Code {
//			case plan.ErrApprovalDenied:
//				log.Printf("Approval denied: %s", planErr.Message)
//			case plan.ErrStepExecutionFailed:
//				log.Printf("Step failed: %s", planErr.Message)
//			default:
//				log.Printf("Plan error: %s", planErr.Message)
//			}
//		}
//		return
//	}
//
//	// Process results
//	fmt.Printf("Plan completed in %s\n", result.TotalDuration)
//	fmt.Printf("Found %d findings\n", len(result.Findings))
//	for _, stepResult := range result.StepResults {
//		fmt.Printf("Step %s: %s (%s)\n",
//			stepResult.StepID, stepResult.Status, stepResult.Duration)
//	}
//
// Creating Steps with Dependencies:
//
//	// Create a tool step
//	scanStep := plan.ExecutionStep{
//		ID: types.NewID(),
//		Sequence: 1,
//		Type: plan.StepTypeTool,
//		Name: "Port Scan",
//		ToolName: "nmap",
//		ToolInput: map[string]any{
//			"target": "192.168.1.1",
//			"ports": "1-1000",
//		},
//		RiskLevel: plan.RiskLevelLow,
//		Status: plan.StepStatusPending,
//	}
//
//	// Create an agent step that depends on the scan
//	analysisStep := plan.ExecutionStep{
//		ID: types.NewID(),
//		Sequence: 2,
//		Type: plan.StepTypeAgent,
//		Name: "Analyze Results",
//		AgentName: "vulnerability-analyzer",
//		AgentTask: &agent.Task{
//			Name: "analyze-scan",
//			Description: "Review scan results",
//		},
//		DependsOn: []types.ID{scanStep.ID}, // Depends on scan step
//		RiskLevel: plan.RiskLevelMedium,
//		Status: plan.StepStatusPending,
//	}
//
// Parallel Execution:
//
//	// Create a parallel step with multiple concurrent operations
//	parallelStep := plan.ExecutionStep{
//		ID: types.NewID(),
//		Sequence: 1,
//		Type: plan.StepTypeParallel,
//		Name: "Multi-target Scan",
//		Description: "Scan multiple targets simultaneously",
//		ParallelSteps: []plan.ExecutionStep{
//			{
//				ID: types.NewID(),
//				Type: plan.StepTypeTool,
//				Name: "Scan Target A",
//				ToolName: "nmap",
//				ToolInput: map[string]any{"target": "192.168.1.1"},
//				RiskLevel: plan.RiskLevelLow,
//			},
//			{
//				ID: types.NewID(),
//				Type: plan.StepTypeTool,
//				Name: "Scan Target B",
//				ToolName: "nmap",
//				ToolInput: map[string]any{"target": "192.168.1.2"},
//				RiskLevel: plan.RiskLevelLow,
//			},
//		},
//		RiskLevel: plan.RiskLevelMedium,
//	}
//
// Conditional Execution:
//
//	// Create a conditional step for branching logic
//	conditionalStep := plan.ExecutionStep{
//		ID: types.NewID(),
//		Sequence: 3,
//		Type: plan.StepTypeCondition,
//		Name: "Check Severity",
//		Description: "Branch based on vulnerability severity",
//		Condition: &plan.StepCondition{
//			Expression: "vulnerabilities.severity == 'critical'",
//			TrueSteps: []types.ID{escalationStepID},
//			FalseSteps: []types.ID{reportStepID},
//		},
//		RiskLevel: plan.RiskLevelLow,
//	}
//
// Custom Risk Rules:
//
//	// Define a custom risk rule
//	databaseRule := plan.RiskRule{
//		Name: "database_modification",
//		Description: "Detects database modification operations",
//		Evaluate: func(step *plan.ExecutionStep, ctx plan.RiskContext) (plan.RiskLevel, string) {
//			if step.ToolName == "database" || step.PluginName == "db" {
//				return plan.RiskLevelHigh, "modifies database state"
//			}
//			return plan.RiskLevelLow, ""
//		},
//	}
//
//	// Create assessor with custom rule
//	assessor := plan.NewRiskAssessor(
//		plan.WithDefaultRules(),
//		plan.WithRule(databaseRule),
//	)
//
// # Integration with Harness
//
// The plan package integrates seamlessly with the Gibson harness for execution:
//
//   - Tool steps execute via harness.ExecuteTool()
//   - Plugin steps execute via harness.ExecutePlugin()
//   - Agent steps delegate via harness.DelegateToAgent()
//
// Input and output guardrails wrap each step execution to ensure safety:
//
//	Input -> Guardrails -> Step Execution -> Guardrails -> Output
//
// This architecture ensures that all operations are subject to safety checks
// regardless of their type or complexity.
//
// # Observability
//
// The package provides comprehensive observability through:
//
//   - Structured logging via slog
//   - OpenTelemetry tracing with span creation
//   - Detailed timing and duration tracking
//   - Finding aggregation across all steps
//   - Metadata capture at plan and step levels
//
// Traces include attributes for plan IDs, mission IDs, step sequences, risk levels,
// and execution status to enable detailed debugging and monitoring.
//
// # Thread Safety
//
// The package types are not inherently thread-safe. Plan execution is designed to
// be sequential with explicit ordering through the Sequence field and DependsOn
// dependencies. However, parallel steps execute concurrently with proper
// synchronization handled by the executor.
//
// When implementing custom ApprovalService or PlanGenerator instances, ensure
// proper synchronization for concurrent access.
package plan
