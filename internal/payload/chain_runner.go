package payload

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ChainRunner orchestrates the execution of multi-stage attack chains
type ChainRunner interface {
	// Execute runs an attack chain against a target
	Execute(ctx context.Context, req *ChainExecutionRequest) (*ChainResult, error)

	// Pause pauses an ongoing chain execution
	Pause(ctx context.Context, chainExecutionID types.ID) error

	// Resume resumes a paused chain execution
	Resume(ctx context.Context, chainExecutionID types.ID) error

	// GetProgress returns the current progress of a chain execution
	GetProgress(ctx context.Context, chainExecutionID types.ID) (*ChainProgress, error)
}

// ChainRunnerConfig holds configuration for the chain runner
type ChainRunnerConfig struct {
	EnableCheckpoints    bool          // Whether to checkpoint progress for resume
	CheckpointInterval   time.Duration // How often to checkpoint
	MaxParallelStages    int           // Maximum number of stages to run in parallel (0 = unlimited)
	DefaultStageTimeout  time.Duration // Default timeout for individual stages
	EnableContextPassing bool          // Whether to pass context between stages
}

// DefaultChainRunnerConfig returns the default chain runner configuration
func DefaultChainRunnerConfig() ChainRunnerConfig {
	return ChainRunnerConfig{
		EnableCheckpoints:    true,
		CheckpointInterval:   30 * time.Second,
		MaxParallelStages:    4,
		DefaultStageTimeout:  2 * time.Minute,
		EnableContextPassing: true,
	}
}

// chainRunner implements ChainRunner
type chainRunner struct {
	config         ChainRunnerConfig
	executor       PayloadExecutor
	registry       PayloadRegistry
	executionStore ExecutionStore
	store          PayloadStore // For retrieving chain definitions

	// Track active executions for pause/resume
	activeMu     sync.RWMutex
	activeChains map[types.ID]*activeChain
}

// activeChain tracks an ongoing chain execution
type activeChain struct {
	req      *ChainExecutionRequest
	chain    *AttackChain
	progress *ChainProgress
	ctx      context.Context
	cancel   context.CancelFunc
	pauseCh  chan struct{}
	resumeCh chan struct{}
	paused   bool
	mu       sync.RWMutex
}

// NewChainRunner creates a new chain runner
func NewChainRunner(
	executor PayloadExecutor,
	registry PayloadRegistry,
	executionStore ExecutionStore,
	store PayloadStore,
	config ChainRunnerConfig,
) ChainRunner {
	return &chainRunner{
		config:         config,
		executor:       executor,
		registry:       registry,
		executionStore: executionStore,
		store:          store,
		activeChains:   make(map[types.ID]*activeChain),
	}
}

// NewChainRunnerWithDefaults creates a new chain runner with default configuration
func NewChainRunnerWithDefaults(
	executor PayloadExecutor,
	registry PayloadRegistry,
	executionStore ExecutionStore,
	store PayloadStore,
) ChainRunner {
	return NewChainRunner(executor, registry, executionStore, store, DefaultChainRunnerConfig())
}

// Execute runs an attack chain
func (cr *chainRunner) Execute(ctx context.Context, req *ChainExecutionRequest) (*ChainResult, error) {
	// Validate request
	if req == nil {
		return nil, fmt.Errorf("chain execution request cannot be nil")
	}
	if req.ChainID == "" {
		return nil, fmt.Errorf("chain ID is required")
	}
	if req.TargetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}

	// Get the attack chain (for now, we'd need a chain store - stub this)
	chain, err := cr.getChain(ctx, req.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	// Check if chain is enabled
	if !chain.Enabled {
		return nil, fmt.Errorf("chain %s is disabled", chain.ID)
	}

	// Create chain execution ID and progress tracker
	chainExecutionID := types.NewID()
	progress := NewChainProgress(chainExecutionID, req.ChainID, chain.StageCount())

	// Create cancellable context
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Apply timeout if specified
	if req.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(execCtx, req.Timeout)
		defer cancel()
	}

	// Create active chain for tracking
	active := &activeChain{
		req:      req,
		chain:    chain,
		progress: progress,
		ctx:      execCtx,
		cancel:   cancel,
		pauseCh:  make(chan struct{}),
		resumeCh: make(chan struct{}),
		paused:   false,
	}

	// Register active chain for pause/resume support
	cr.activeMu.Lock()
	cr.activeChains[chainExecutionID] = active
	cr.activeMu.Unlock()

	// Cleanup after execution
	defer func() {
		cr.activeMu.Lock()
		delete(cr.activeChains, chainExecutionID)
		cr.activeMu.Unlock()
	}()

	// Start execution
	progress.Start()
	startTime := time.Now()

	// Execute the chain
	result := NewChainResult(chainExecutionID, req.ChainID)
	result.StartedAt = startTime

	// Build execution plan (DAG) from stages
	plan, err := cr.buildExecutionPlan(chain)
	if err != nil {
		progress.Fail(err)
		result.Status = ChainStatusFailed
		result.ErrorMessage = fmt.Sprintf("Failed to build execution plan: %v", err)
		result.CompletedAt = time.Now()
		return result, err
	}

	// Execute stages according to the plan
	if err := cr.executeStages(execCtx, active, plan, result); err != nil {
		// Check if it was cancelled or timed out
		if execCtx.Err() == context.Canceled {
			progress.Status = ChainStatusCancelled
			result.Status = ChainStatusCancelled
			result.ErrorMessage = "Chain execution was cancelled"
		} else if execCtx.Err() == context.DeadlineExceeded {
			progress.Status = ChainStatusFailed
			result.Status = ChainStatusFailed
			result.ErrorMessage = "Chain execution timed out"
		} else {
			progress.Fail(err)
			result.Status = ChainStatusFailed
			result.ErrorMessage = err.Error()
		}
		result.CompletedAt = time.Now()
		return result, err
	}

	// Mark as completed
	progress.Complete()
	result.Status = ChainStatusCompleted
	result.Success = result.FailedStages == 0
	result.CompletedAt = time.Now()
	result.TotalDuration = time.Since(startTime)

	// Copy final context
	result.FinalContext = progress.ChainContext

	return result, nil
}

// Pause pauses an ongoing chain execution
func (cr *chainRunner) Pause(ctx context.Context, chainExecutionID types.ID) error {
	cr.activeMu.RLock()
	active, exists := cr.activeChains[chainExecutionID]
	cr.activeMu.RUnlock()

	if !exists {
		return fmt.Errorf("chain execution %s not found or already completed", chainExecutionID)
	}

	active.mu.Lock()
	defer active.mu.Unlock()

	if active.paused {
		return fmt.Errorf("chain execution %s is already paused", chainExecutionID)
	}

	active.paused = true
	active.progress.Pause()

	// Signal pause - this will be checked between stages
	select {
	case active.pauseCh <- struct{}{}:
	default:
	}

	return nil
}

// Resume resumes a paused chain execution
func (cr *chainRunner) Resume(ctx context.Context, chainExecutionID types.ID) error {
	cr.activeMu.RLock()
	active, exists := cr.activeChains[chainExecutionID]
	cr.activeMu.RUnlock()

	if !exists {
		return fmt.Errorf("chain execution %s not found or already completed", chainExecutionID)
	}

	active.mu.Lock()
	defer active.mu.Unlock()

	if !active.paused {
		return fmt.Errorf("chain execution %s is not paused", chainExecutionID)
	}

	active.paused = false
	active.progress.Resume()

	// Signal resume
	select {
	case active.resumeCh <- struct{}{}:
	default:
	}

	return nil
}

// GetProgress returns the current progress of a chain execution
func (cr *chainRunner) GetProgress(ctx context.Context, chainExecutionID types.ID) (*ChainProgress, error) {
	cr.activeMu.RLock()
	active, exists := cr.activeChains[chainExecutionID]
	cr.activeMu.RUnlock()

	if !exists {
		// Check if it's a completed execution (would need to query storage)
		return nil, fmt.Errorf("chain execution %s not found", chainExecutionID)
	}

	// Return a copy of the progress
	active.mu.RLock()
	defer active.mu.RUnlock()

	// Deep copy to avoid race conditions
	progressCopy := *active.progress
	return &progressCopy, nil
}

// executionPlan represents the execution plan for a chain
type executionPlan struct {
	stages     []*ChainStage
	stageIndex map[string]int  // Stage ID to index mapping
	levels     [][]*ChainStage // Stages grouped by dependency level (for parallel execution)
}

// buildExecutionPlan creates an execution plan from the chain stages
func (cr *chainRunner) buildExecutionPlan(chain *AttackChain) (*executionPlan, error) {
	plan := &executionPlan{
		stages:     make([]*ChainStage, 0, len(chain.Stages)),
		stageIndex: make(map[string]int),
		levels:     [][]*ChainStage{},
	}

	// Simple topological sort based on dependencies
	// For now, we'll use a simple algorithm that handles basic dependencies
	visited := make(map[string]bool)
	inProgress := make(map[string]bool)

	// Helper function for DFS-based topological sort
	var visit func(stageID string) error
	visit = func(stageID string) error {
		if visited[stageID] {
			return nil
		}
		if inProgress[stageID] {
			return fmt.Errorf("circular dependency detected involving stage %s", stageID)
		}

		stage := chain.Stages[stageID]
		if stage == nil {
			return fmt.Errorf("stage %s not found in chain", stageID)
		}

		inProgress[stageID] = true

		// Visit dependencies first
		for _, depID := range stage.Dependencies {
			if err := visit(depID); err != nil {
				return err
			}
		}

		inProgress[stageID] = false
		visited[stageID] = true

		// Add to plan
		plan.stageIndex[stageID] = len(plan.stages)
		plan.stages = append(plan.stages, stage)

		return nil
	}

	// Start with entry stages
	for _, entryID := range chain.EntryStages {
		if err := visit(entryID); err != nil {
			return nil, err
		}
	}

	// Visit any remaining stages not reached from entry points
	for stageID := range chain.Stages {
		if !visited[stageID] {
			if err := visit(stageID); err != nil {
				return nil, err
			}
		}
	}

	// Build dependency levels for parallel execution
	plan.levels = cr.buildDependencyLevels(plan.stages)

	return plan, nil
}

// buildDependencyLevels groups stages into levels based on dependencies
func (cr *chainRunner) buildDependencyLevels(stages []*ChainStage) [][]*ChainStage {
	levels := [][]*ChainStage{}
	stageLevel := make(map[string]int)

	// Calculate level for each stage (max dependency level + 1)
	for _, stage := range stages {
		maxDepLevel := -1
		for _, depID := range stage.Dependencies {
			if level, exists := stageLevel[depID]; exists {
				if level > maxDepLevel {
					maxDepLevel = level
				}
			}
		}
		level := maxDepLevel + 1
		stageLevel[stage.ID] = level

		// Ensure we have enough levels
		for len(levels) <= level {
			levels = append(levels, []*ChainStage{})
		}
		levels[level] = append(levels[level], stage)
	}

	return levels
}

// executeStages executes stages according to the execution plan
func (cr *chainRunner) executeStages(
	ctx context.Context,
	active *activeChain,
	plan *executionPlan,
	result *ChainResult,
) error {
	// Track which stages have completed successfully
	completedStages := make(map[string]bool)
	failedStages := make(map[string]bool)

	// Execute stages level by level (enables parallel execution within levels)
	for levelIdx, levelStages := range plan.levels {
		// Check for pause before starting a new level
		if err := cr.checkPause(active); err != nil {
			return err
		}

		// Check context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Determine if we should execute stages in parallel
		parallel := active.req.ParallelStages && len(levelStages) > 1

		if parallel {
			// Execute stages in parallel
			if err := cr.executeParallelStages(ctx, active, levelStages, levelIdx, completedStages, failedStages, result); err != nil {
				if active.req.StopOnFailure {
					return err
				}
				// Continue to next level if not stopping on failure
			}
		} else {
			// Execute stages sequentially
			for stageIdx, stage := range levelStages {
				if err := cr.executeSingleStage(ctx, active, stage, stageIdx, completedStages, failedStages, result); err != nil {
					if active.req.StopOnFailure {
						return err
					}
					// Continue to next stage if not stopping on failure
				}
			}
		}
	}

	return nil
}

// executeParallelStages executes multiple stages in parallel
func (cr *chainRunner) executeParallelStages(
	ctx context.Context,
	active *activeChain,
	stages []*ChainStage,
	levelIdx int,
	completedStages map[string]bool,
	failedStages map[string]bool,
	result *ChainResult,
) error {
	// Create a wait group and error channel
	var wg sync.WaitGroup
	errCh := make(chan error, len(stages))

	// Semaphore for limiting parallel execution
	maxParallel := cr.config.MaxParallelStages
	if maxParallel <= 0 {
		maxParallel = len(stages)
	}
	semaphore := make(chan struct{}, maxParallel)

	// Execute each stage in a goroutine
	for idx, stage := range stages {
		wg.Add(1)
		go func(s *ChainStage, index int) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := cr.executeSingleStage(ctx, active, s, index, completedStages, failedStages, result); err != nil {
				errCh <- err
			}
		}(stage, idx)
	}

	// Wait for all stages to complete
	wg.Wait()
	close(errCh)

	// Check for errors
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// executeSingleStage executes a single stage in the chain
func (cr *chainRunner) executeSingleStage(
	ctx context.Context,
	active *activeChain,
	stage *ChainStage,
	stageIdx int,
	completedStages map[string]bool,
	failedStages map[string]bool,
	result *ChainResult,
) error {
	// Check if stage condition is met
	if stage.Condition != nil {
		shouldExecute, err := cr.evaluateCondition(stage.Condition, active.progress)
		if err != nil {
			return fmt.Errorf("failed to evaluate stage condition: %w", err)
		}
		if !shouldExecute {
			// Skip this stage
			return nil
		}
	}

	// Update progress
	active.progress.SetCurrentStage(stageIdx, types.ID(stage.ID))

	// Merge parameters: chain-level params + stage-level params
	stageParams := make(map[string]interface{})
	for k, v := range active.req.Parameters {
		stageParams[k] = v
	}
	for k, v := range stage.Parameters {
		stageParams[k] = v
	}

	// Inject chain context if enabled
	if cr.config.EnableContextPassing {
		for k, v := range active.progress.ChainContext {
			stageParams[k] = v
		}
	}

	// Create execution request
	execReq := NewExecutionRequest(stage.PayloadID, active.req.TargetID, active.req.AgentID)
	execReq.Parameters = stageParams
	execReq.MissionID = active.req.MissionID
	execReq.Tags = active.req.Tags

	// Apply stage timeout
	stageCtx := ctx
	if stage.Timeout > 0 {
		var cancel context.CancelFunc
		stageCtx, cancel = context.WithTimeout(ctx, stage.Timeout)
		defer cancel()
	} else if cr.config.DefaultStageTimeout > 0 {
		var cancel context.CancelFunc
		stageCtx, cancel = context.WithTimeout(ctx, cr.config.DefaultStageTimeout)
		defer cancel()
	}

	// Execute the payload
	startTime := time.Now()
	execResult, err := cr.executor.Execute(stageCtx, execReq)
	duration := time.Since(startTime)

	// Create stage result
	stageResult := NewStageResult(types.ID(stage.ID), stage.Name, stageIdx, stage.PayloadID, execResult.ExecutionID)
	stageResult.StartedAt = startTime
	stageResult.CompletedAt = time.Now()
	stageResult.Duration = duration

	// Handle execution result
	if err != nil {
		stageResult.Status = ExecutionStatusFailed
		stageResult.Success = false
		stageResult.ErrorMessage = err.Error()
		failedStages[stage.ID] = true

		// Add to progress and result
		active.progress.AddStageResult(*stageResult)
		result.AddStageResult(*stageResult)

		// Handle failure according to stage configuration
		switch stage.OnFailure {
		case FailureActionStop:
			return fmt.Errorf("stage %s failed: %w", stage.Name, err)
		case FailureActionContinue:
			return nil // Continue to next stage
		case FailureActionSkip:
			// Skip dependent stages (would need more sophisticated tracking)
			return nil
		default:
			return fmt.Errorf("stage %s failed: %w", stage.Name, err)
		}
	}

	// Execution succeeded
	stageResult.Status = execResult.Status
	stageResult.Success = execResult.Success
	stageResult.ConfidenceScore = execResult.ConfidenceScore
	stageResult.Response = execResult.Response
	stageResult.InstantiatedText = execResult.InstantiatedText
	stageResult.IndicatorsMatched = execResult.IndicatorsMatched
	stageResult.TokensUsed = execResult.TokensUsed
	stageResult.Cost = execResult.Cost
	stageResult.FindingCreated = execResult.FindingCreated

	// Update context with stage output
	if cr.config.EnableContextPassing && stageResult.Success {
		// Store stage result in context for use by later stages
		stageResult.OutputContext["success"] = true
		stageResult.OutputContext["confidence_score"] = stageResult.ConfidenceScore
		stageResult.OutputContext["response_length"] = len(stageResult.Response)

		// Merge into chain context
		for k, v := range stageResult.OutputContext {
			active.progress.ChainContext[fmt.Sprintf("stages.%s.%s", stage.ID, k)] = v
		}
	}

	completedStages[stage.ID] = true

	// Add to progress and result
	active.progress.AddStageResult(*stageResult)
	result.AddStageResult(*stageResult)

	// Handle conditional branching if specified
	if stage.Action != nil {
		if err := cr.handleStageAction(ctx, active, stage, stageResult, result); err != nil {
			return err
		}
	}

	return nil
}

// evaluateCondition evaluates a stage condition
func (cr *chainRunner) evaluateCondition(condition *StageCondition, progress *ChainProgress) (bool, error) {
	switch condition.Type {
	case ConditionTypeSuccessRate:
		// Check if previous stages meet success rate threshold
		if progress.TotalExecutions == 0 {
			return true, nil // No previous stages, proceed
		}
		successRate := float64(progress.SuccessfulAttacks) / float64(progress.TotalExecutions)
		return successRate >= condition.Threshold, nil

	case ConditionTypeFindingSeverity:
		// Check if any findings meet severity threshold
		// This would require access to findings
		// For now, return true
		return true, nil

	case ConditionTypeExpression:
		// Evaluate expression against chain context
		// This would require an expression evaluator
		// For now, return true
		return true, nil

	case ConditionTypeCustom:
		// Custom condition function
		// Would need a plugin system
		return true, nil

	default:
		return false, fmt.Errorf("unknown condition type: %s", condition.Type)
	}
}

// handleStageAction handles conditional branching based on stage results
func (cr *chainRunner) handleStageAction(
	ctx context.Context,
	active *activeChain,
	stage *ChainStage,
	stageResult *StageResult,
	result *ChainResult,
) error {
	// This is a simplified implementation
	// A full implementation would need to dynamically modify the execution plan
	// based on the branching logic

	action := stage.Action

	// Check OnSuccess/OnFailure branches
	var nextStages []string
	if stageResult.Success && len(action.OnSuccess) > 0 {
		nextStages = action.OnSuccess
	} else if !stageResult.Success && len(action.OnFailure) > 0 {
		nextStages = action.OnFailure
	}

	// Check conditional branches
	for _, branch := range action.OnCondition {
		shouldBranch, err := cr.evaluateCondition(&branch.Condition, active.progress)
		if err != nil {
			return fmt.Errorf("failed to evaluate branch condition: %w", err)
		}
		if shouldBranch {
			nextStages = branch.NextStages
			break
		}
	}

	// Store next stages in context for potential future execution
	// In a full implementation, this would modify the execution plan
	if len(nextStages) > 0 {
		active.progress.ChainContext[fmt.Sprintf("stages.%s.next_stages", stage.ID)] = nextStages
	}

	return nil
}

// checkPause checks if execution should pause and waits for resume
func (cr *chainRunner) checkPause(active *activeChain) error {
	active.mu.RLock()
	paused := active.paused
	active.mu.RUnlock()

	if !paused {
		return nil
	}

	// Wait for resume signal or context cancellation
	select {
	case <-active.resumeCh:
		return nil
	case <-active.ctx.Done():
		return active.ctx.Err()
	}
}

// getChain retrieves a chain from the store and converts it to AttackChain
func (cr *chainRunner) getChain(ctx context.Context, chainID types.ID) (*AttackChain, error) {
	if cr.store == nil {
		return nil, fmt.Errorf("chain store not configured - cannot retrieve chain %s", chainID)
	}

	// Get the PayloadChain from the store
	payloadChain, err := cr.store.GetChain(ctx, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain %s: %w", chainID, err)
	}

	// Convert PayloadChain to AttackChain
	chain := &AttackChain{
		ID:          payloadChain.ID,
		Name:        payloadChain.Name,
		Description: payloadChain.Description,
		Stages:      make(map[string]*ChainStage),
		EntryStages: []string{},
		Metadata: ChainMetadata{
			Author:     payloadChain.Metadata.Author,
			References: payloadChain.Metadata.References,
		},
		CreatedAt: payloadChain.CreatedAt,
		UpdatedAt: payloadChain.UpdatedAt,
	}

	// Convert steps to stages
	stageOrder := make([]string, 0, len(payloadChain.Steps))
	for _, step := range payloadChain.Steps {
		// Convert OnFailure string to FailureAction
		var failureAction FailureAction
		switch step.OnFailure {
		case "stop":
			failureAction = FailureActionStop
		case "continue":
			failureAction = FailureActionContinue
		case "skip":
			failureAction = FailureActionSkip
		default:
			failureAction = FailureActionStop // default to stop
		}

		stage := &ChainStage{
			ID:           step.ID,
			PayloadID:    step.PayloadID,
			Parameters:   step.Params,
			Dependencies: step.Requires,
			OnFailure:    failureAction,
		}
		chain.Stages[step.ID] = stage
		stageOrder = append(stageOrder, step.ID)

		// Identify entry stages (those with no dependencies)
		if len(step.Requires) == 0 {
			chain.EntryStages = append(chain.EntryStages, step.ID)
		}
	}

	// If no entry stages identified, use the first step
	if len(chain.EntryStages) == 0 && len(stageOrder) > 0 {
		chain.EntryStages = []string{stageOrder[0]}
	}

	return chain, nil
}
