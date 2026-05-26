package orchestrator

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/eval"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// WithEvalOptions adds evaluation capabilities to the orchestrator.
// When eval options are provided, the orchestrator will wrap the harness factory
// with an EvalHarnessFactory that enables trajectory recording, real-time feedback,
// and result aggregation across all agents in the mission.
//
// The eval system provides:
//   - Automatic trajectory recording for all agent executions
//   - Real-time feedback and scoring during mission execution
//   - Aggregated evaluation results accessible via GetEvalResults()
//   - Optional export to Langfuse and OpenTelemetry
//
// Example usage:
//
//	evalOpts := eval.NewEvalOptions()
//	evalOpts.Enabled = true
//	evalOpts.FeedbackEnabled = true
//	evalOpts.GroundTruthPath = "/path/to/ground_truth.json"
//
//	config := orchestrator.Config{
//	    GraphRAGClient: graphClient,
//	    HarnessFactory: baseFactory,
//	    EvalOptions: evalOpts,
//	    // ... other config
//	}
//	orch, err := orchestrator.NewMissionAdapter(config)
//
// NOTE: This should be called before NewMissionAdapter. The config
// will automatically wrap the harness factory if eval options are provided.
func WithEvalOptions(opts *eval.EvalOptions, config *Config) error {
	if opts == nil || !opts.Enabled {
		return nil
	}

	// Validate options before wrapping
	if err := opts.Validate(); err != nil {
		return types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"invalid evaluation options",
			err,
		)
	}

	// Wrap the harness factory with eval capabilities
	evalFactory, err := eval.NewEvalHarnessFactory(config.HarnessFactory, opts)
	if err != nil {
		return types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"failed to create eval harness factory",
			err,
		)
	}

	// Replace the harness factory in config with the wrapped version
	config.HarnessFactory = evalFactory

	return nil
}

// EvalOrchestrator wraps MissionAdapter with evaluation capabilities.
// It extends the base orchestrator to provide access to evaluation results and
// finalization methods.
type EvalOrchestrator struct {
	*MissionAdapter
	evalOptions   *eval.EvalOptions
	evalCollector *eval.EvalResultCollector
}

// NewEvalOrchestrator creates a new orchestrator with evaluation enabled.
// This is a convenience function that wraps the configuration and factory setup.
//
// Parameters:
//   - config: Base orchestrator configuration
//   - evalOptions: Evaluation options (if nil or disabled, returns regular orchestrator)
//
// Returns:
//   - *EvalOrchestrator: Orchestrator with eval capabilities
//   - error: Non-nil if creation fails
func NewEvalOrchestrator(config Config, evalOptions *eval.EvalOptions) (*EvalOrchestrator, error) {
	if evalOptions == nil || !evalOptions.Enabled {
		// Eval not enabled, create regular orchestrator
		baseOrch, err := NewMissionAdapter(config)
		if err != nil {
			return nil, err
		}
		return &EvalOrchestrator{
			MissionAdapter: baseOrch,
			evalOptions:    nil,
			evalCollector:  nil,
		}, nil
	}

	// Validate eval options
	if err := evalOptions.Validate(); err != nil {
		return nil, types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"invalid evaluation options",
			err,
		)
	}

	// Wrap the harness factory with eval capabilities
	evalFactory, err := eval.NewEvalHarnessFactory(config.HarnessFactory, evalOptions)
	if err != nil {
		return nil, types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"failed to create eval harness factory",
			err,
		)
	}

	// Replace harness factory with wrapped version
	config.HarnessFactory = evalFactory

	// Create base orchestrator with wrapped factory
	baseOrch, err := NewMissionAdapter(config)
	if err != nil {
		return nil, err
	}

	// Create eval orchestrator wrapper
	return &EvalOrchestrator{
		MissionAdapter: baseOrch,
		evalOptions:    evalOptions,
		evalCollector:  evalFactory.Results(),
	}, nil
}

// GetEvalResults returns the evaluation result collector if eval is enabled.
// This provides access to trajectories, feedback, and scores collected during
// mission execution.
//
// Returns:
//   - *eval.EvalResultCollector: Collector with aggregated results, or nil if eval disabled
//
// The collector can be used to:
//   - Call Finalize(ctx) to compute the final evaluation summary
//   - Call GetSummary() to get current evaluation state (safe during execution)
//   - Access individual agent trajectories and feedback
//   - Export results to JSONL, Langfuse, or OpenTelemetry
func (e *EvalOrchestrator) GetEvalResults() *eval.EvalResultCollector {
	return e.evalCollector
}

// FinalizeEvalResults computes and returns the final evaluation summary.
// This should be called after mission execution completes to get the complete
// evaluation metrics.
//
// Parameters:
//   - ctx: Context for the finalization operation
//
// Returns:
//   - *eval.EvalSummary: Complete evaluation summary with all metrics
//   - error: Non-nil if finalization fails or eval is not enabled
//
// The summary includes:
//   - Overall score and per-scorer scores
//   - Total steps executed and tokens used
//   - Alert counts (warnings and critical)
//   - Complete feedback history
//
// If evaluation is not enabled, this returns an error.
func (e *EvalOrchestrator) FinalizeEvalResults(ctx context.Context) (*eval.EvalSummary, error) {
	if e.evalCollector == nil {
		return nil, types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			"evaluation is not enabled for this orchestrator",
		)
	}

	return e.evalCollector.Finalize(ctx)
}

// wrapFactoryWithEval wraps a harness factory with evaluation capabilities.
// This is a utility function used internally by the adapter when eval options are provided.
//
// Parameters:
//   - factory: The base harness factory to wrap (must not be nil)
//   - opts: Evaluation options controlling behavior (must not be nil)
//
// Returns:
//   - harness.HarnessFactoryInterface: Wrapped factory (or original if eval disabled)
//   - *eval.EvalResultCollector: Collector for aggregating eval results (or nil if eval disabled)
//   - error: Non-nil if wrapping fails
//
// If evaluation is disabled (opts.Enabled == false), this function returns the
// original factory unchanged with a nil collector and no error.
func wrapFactoryWithEval(
	factory harness.HarnessFactoryInterface,
	opts *eval.EvalOptions,
) (harness.HarnessFactoryInterface, *eval.EvalResultCollector, error) {
	// If evaluation is disabled, return the original factory
	if opts == nil || !opts.Enabled {
		return factory, nil, nil
	}

	// Validate options before wrapping
	if err := opts.Validate(); err != nil {
		return nil, nil, types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"invalid evaluation options",
			err,
		)
	}

	// Create the eval harness factory
	evalFactory, err := eval.NewEvalHarnessFactory(factory, opts)
	if err != nil {
		return nil, nil, types.WrapError(
			types.CONFIG_VALIDATION_FAILED,
			"failed to create eval harness factory",
			err,
		)
	}

	// Return the wrapped factory and its collector
	return evalFactory, evalFactory.Results(), nil
}
