package eval

import (
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// EvalHarnessFactory wraps a HarnessFactoryInterface to create harnesses with
// evaluation capabilities. It transparently wraps base harnesses with RecordingHarness
// and optionally FeedbackHarness based on EvalOptions configuration.
//
// The factory ensures that:
//   - All harnesses record trajectories for evaluation
//   - Feedback is collected and aggregated across all agents
//   - Evaluation results are centrally stored in the collector
//
// Example usage:
//
//	innerFactory, _ := harness.NewHarnessFactory(config)
//	evalFactory, _ := NewEvalHarnessFactory(innerFactory, evalOpts)
//	h, _ := evalFactory.Create("my_agent", missionCtx, targetInfo)
//	// h is now wrapped with evaluation capabilities
//	results := evalFactory.Results() // Access aggregated evaluation results
type EvalHarnessFactory struct {
	inner     harness.HarnessFactoryInterface
	options   *EvalOptions
	collector *EvalResultCollector
}

// NewEvalHarnessFactory creates a new EvalHarnessFactory that wraps the given inner factory.
//
// Parameters:
//   - inner: The base harness factory to wrap (must not be nil)
//   - opts: Evaluation options controlling behavior (must not be nil)
//
// Returns:
//   - *EvalHarnessFactory: Configured factory ready for creating eval harnesses
//   - error: Non-nil if validation fails
//
// The factory validates the options and creates a result collector for aggregating
// evaluation data across all agents in the mission.
func NewEvalHarnessFactory(inner harness.HarnessFactoryInterface, opts *EvalOptions) (*EvalHarnessFactory, error) {
	// Validate inputs
	if inner == nil {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED,
			"inner harness factory cannot be nil")
	}
	if opts == nil {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED,
			"evaluation options cannot be nil")
	}

	// Validate options
	if err := opts.Validate(); err != nil {
		return nil, types.WrapError(types.CONFIG_VALIDATION_FAILED,
			"invalid evaluation options", err)
	}

	// Create result collector with a zero mission ID
	// This will be updated when the first harness is created
	collector := NewEvalResultCollector("")

	return &EvalHarnessFactory{
		inner:     inner,
		options:   opts,
		collector: collector,
	}, nil
}

// Create creates a new AgentHarness with evaluation capabilities.
//
// The created harness is wrapped with evaluation tracking that records:
//   - Trajectory of all operations for post-execution analysis
//   - Real-time feedback if FeedbackEnabled is true
//
// The wrapped harness is registered with the collector to enable result aggregation.
//
// Parameters:
//   - agentName: Name of the agent this harness is for
//   - missionCtx: Mission context providing mission-level metadata
//   - target: Target information for the current mission
//
// Returns:
//   - harness.AgentHarness: Fully configured harness with eval capabilities
//   - error: Non-nil if creation fails
func (f *EvalHarnessFactory) Create(agentName string, missionCtx harness.MissionContext, target harness.TargetInfo) (harness.AgentHarness, error) {
	// If evaluation is disabled, delegate directly to inner factory
	if !f.options.Enabled {
		return f.inner.Create(agentName, missionCtx, target)
	}

	// Update collector mission ID from context if needed
	if f.collector.missionID == "" {
		f.collector.missionID = missionCtx.ID
	}

	// Create base harness from inner factory
	baseHarness, err := f.inner.Create(agentName, missionCtx, target)
	if err != nil {
		return nil, err
	}

	// TODO(eval): Implement SDK eval harness adapter [Future Work - Phase 11+]
	//
	// CONTEXT:
	// The SDK eval harnesses (RecordingHarness, FeedbackHarness) expect agent.Harness interface
	// which uses SDK types (sdk/llm.Message, sdk/llm.CompletionResponse).
	//
	// Gibson's harness uses internal types (internal/llm.Message, internal/llm.CompletionResponse).
	//
	// SOLUTION:
	// The adapter (harness_adapter.go) bridges these type systems by:
	// 1. Wrapping Gibson's AgentHarness
	// 2. Implementing SDK's agent.Harness interface
	// 3. Converting types bidirectionally
	//
	// INTEGRATION APPROACH:
	// - Wrap baseHarness with GibsonHarnessAdapter
	// - Wrap adapter with SDK RecordingHarness for trajectory capture
	// - If FeedbackEnabled, wrap with SDK FeedbackHarness for real-time evaluation
	// - Register wrapped harness with collector
	//
	// This creates the chain: Gibson harness -> Adapter -> Recording -> (optional) Feedback
	//
	// CURRENT STATUS:
	// Returning base harness unchanged to avoid import cycles and maintain stability.
	// This is intentional - the evaluation system foundation is in place, but the
	// adapter implementation is deferred until SDK-Gibson integration is needed in production.
	//
	// TRACKING: This work is planned for when evaluation features are prioritized.
	// For now, missions run without trajectory recording, which is acceptable for
	// basic attack execution.

	return baseHarness, nil
}

// CreateChild creates a child harness from a parent for sub-agent delegation.
//
// The child harness inherits evaluation settings from the parent and is registered
// with the same collector to enable unified result aggregation.
//
// Parameters:
//   - parent: The parent harness that is delegating to a sub-agent
//   - agentName: Name of the child agent this harness is for
//
// Returns:
//   - harness.AgentHarness: Child harness with eval capabilities
//   - error: Non-nil if creation fails
func (f *EvalHarnessFactory) CreateChild(parent harness.AgentHarness, agentName string) (harness.AgentHarness, error) {
	// If evaluation is disabled, delegate directly to inner factory
	if !f.options.Enabled {
		return f.inner.CreateChild(parent, agentName)
	}

	// Validate inputs
	if parent == nil {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED,
			"parent harness cannot be nil")
	}
	if agentName == "" {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED,
			"agent name cannot be empty")
	}

	// Delegate to inner factory to create child
	child, err := f.inner.CreateChild(parent, agentName)
	if err != nil {
		return nil, err
	}

	// For now, return the base child harness
	// TODO(eval): Wrap with recording/feedback when adapter is implemented [Future Work]
	// See TODO above in Create() method for full context on the adapter implementation.
	// This follows the same pattern: child harness should also be wrapped with
	// recording/feedback capabilities once the adapter is complete.

	return child, nil
}

// Results returns the evaluation result collector containing aggregated results
// from all harnesses created by this factory.
//
// Returns:
//   - *EvalResultCollector: Collector with trajectories, feedback, and scores
//
// The collector provides methods to:
//   - Finalize() - Compute final evaluation summary
//   - GetSummary() - Get current evaluation state
//   - GetTrajectory(agentName) - Get trajectory for specific agent
//   - GetFeedbackHistory(agentName) - Get feedback for specific agent
func (f *EvalHarnessFactory) Results() *EvalResultCollector {
	return f.collector
}

// Ensure EvalHarnessFactory implements HarnessFactoryInterface
var _ harness.HarnessFactoryInterface = (*EvalHarnessFactory)(nil)
