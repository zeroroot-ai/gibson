package checkpoint

import (
	"encoding/json"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ExecutionState represents the complete serializable state of mission execution.
// This is the canonical format for state persistence and recovery, designed to be
// easily serializable to JSON or msgpack for storage.
//
// ExecutionState differs from Checkpoint in that:
//   - Checkpoint is the storage/transport format (includes metadata, checksums, etc.)
//   - ExecutionState is the logical execution state (pure business logic)
//
// When resuming a mission, the checkpoint is loaded and converted to ExecutionState
// which is then used to reconstruct the runtime execution context.
type ExecutionState struct {
	// MissionID identifies which mission this state belongs to.
	MissionID types.ID `json:"mission_id" msgpack:"mission_id"`

	// ThreadID identifies which execution thread this state is for.
	ThreadID string `json:"thread_id" msgpack:"thread_id"`

	// CurrentNodeID is the node currently being executed or next to execute.
	CurrentNodeID string `json:"current_node_id" msgpack:"current_node_id"`

	// NodeStates maps node IDs to their current execution state.
	// This tracks which nodes have been started, completed, or failed.
	NodeStates map[string]*NodeState `json:"node_states" msgpack:"node_states"`

	// CompletedResults maps node IDs to their final outputs.
	// Only includes nodes that have completed successfully.
	CompletedResults map[string]*NodeOutput `json:"completed_results" msgpack:"completed_results"`

	// PendingQueue is the ordered list of nodes waiting to be executed.
	// Order is determined by DAG dependencies and scheduling strategy.
	PendingQueue []string `json:"pending_queue" msgpack:"pending_queue"`

	// InProgress captures state of a node that was mid-execution when paused.
	// Nil if no node was in progress.
	InProgress *InProgressNodeState `json:"in_progress,omitempty" msgpack:"in_progress,omitempty"`

	// WorkingMemory is the ephemeral agent memory scoped to the current task.
	// Reset between major task boundaries. Typically contains current context.
	WorkingMemory map[string]any `json:"working_memory,omitempty" msgpack:"working_memory,omitempty"`

	// MissionMemory is the persistent mission-wide memory shared across all nodes.
	// Accumulates state throughout mission execution. Contains mission context.
	MissionMemory map[string]any `json:"mission_memory,omitempty" msgpack:"mission_memory,omitempty"`

	// ConversationHistory contains the LLM conversation messages.
	// Used to reconstruct conversation context when resuming.
	ConversationHistory []llm.Message `json:"conversation_history,omitempty" msgpack:"conversation_history,omitempty"`

	// DAGState captures the current position in the mission DAG.
	// Enables resuming from the exact point of interruption.
	DAGState *DAGTraversalState `json:"dag_state,omitempty" msgpack:"dag_state,omitempty"`

	// Findings contains IDs of all findings discovered so far.
	// Full finding data is stored separately in the findings store.
	Findings []types.ID `json:"findings,omitempty" msgpack:"findings,omitempty"`

	// ApprovalState captures approval mission state if waiting for approval.
	// Nil if not awaiting approval.
	ApprovalState *ApprovalState `json:"approval_state,omitempty" msgpack:"approval_state,omitempty"`

	// Metadata provides arbitrary key-value storage for state-specific information.
	Metadata map[string]any `json:"metadata,omitempty" msgpack:"metadata,omitempty"`
}

// NewExecutionState creates a new execution state for a mission and thread.
func NewExecutionState(missionID types.ID, threadID string) *ExecutionState {
	return &ExecutionState{
		MissionID:           missionID,
		ThreadID:            threadID,
		NodeStates:          make(map[string]*NodeState),
		CompletedResults:    make(map[string]*NodeOutput),
		PendingQueue:        []string{},
		WorkingMemory:       make(map[string]any),
		MissionMemory:       make(map[string]any),
		ConversationHistory: []llm.Message{},
		Findings:            []types.ID{},
		Metadata:            make(map[string]any),
	}
}

// ToCheckpoint converts ExecutionState to a Checkpoint for persistence.
// This serializes the memory and conversation history into byte slices.
func (s *ExecutionState) ToCheckpoint(checkpointID string, version int) (*Checkpoint, error) {
	// Serialize working memory
	workingMemBytes, err := SerializeMemory(s.WorkingMemory)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize working memory: %w", err)
	}

	// Serialize mission memory
	missionMemBytes, err := SerializeMemory(s.MissionMemory)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize mission memory: %w", err)
	}

	// Serialize conversation history
	convBytes, err := SerializeConversation(s.ConversationHistory)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize conversation: %w", err)
	}

	checkpoint := NewCheckpoint(s.MissionID, s.ThreadID)
	checkpoint.ID = checkpointID
	checkpoint.Version = version
	checkpoint.CurrentNodeID = s.CurrentNodeID
	checkpoint.NodeStates = s.NodeStates
	checkpoint.CompletedNodes = s.CompletedResults
	checkpoint.PendingNodes = s.PendingQueue
	checkpoint.InProgressNode = s.InProgress
	checkpoint.WorkingMemory = workingMemBytes
	checkpoint.MissionMemory = missionMemBytes
	checkpoint.ConversationHistory = convBytes
	checkpoint.DAGState = s.DAGState
	checkpoint.Findings = s.Findings

	// Copy approval state
	if s.ApprovalState != nil {
		checkpoint.ApprovalState = s.ApprovalState
	}

	return checkpoint, nil
}

// FromCheckpoint converts a Checkpoint back into ExecutionState for execution.
// This deserializes the memory and conversation history from byte slices.
func FromCheckpoint(checkpoint *Checkpoint) (*ExecutionState, error) {
	// Deserialize working memory
	workingMem, err := DeserializeMemory(checkpoint.WorkingMemory)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize working memory: %w", err)
	}

	// Deserialize mission memory
	missionMem, err := DeserializeMemory(checkpoint.MissionMemory)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize mission memory: %w", err)
	}

	// Deserialize conversation history
	conversation, err := DeserializeConversation(checkpoint.ConversationHistory)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize conversation: %w", err)
	}

	state := &ExecutionState{
		MissionID:           checkpoint.MissionID,
		ThreadID:            checkpoint.ThreadID,
		CurrentNodeID:       checkpoint.CurrentNodeID,
		NodeStates:          checkpoint.NodeStates,
		CompletedResults:    checkpoint.CompletedNodes,
		PendingQueue:        checkpoint.PendingNodes,
		InProgress:          checkpoint.InProgressNode,
		WorkingMemory:       workingMem,
		MissionMemory:       missionMem,
		ConversationHistory: conversation,
		DAGState:            checkpoint.DAGState,
		Findings:            checkpoint.Findings,
		ApprovalState:       checkpoint.ApprovalState,
		Metadata:            make(map[string]any),
	}

	return state, nil
}

// IsComplete returns true if all nodes have reached a terminal state.
func (s *ExecutionState) IsComplete() bool {
	for _, state := range s.NodeStates {
		if !state.Status.IsTerminal() {
			return false
		}
	}
	return true
}

// HasPendingNodes returns true if there are nodes waiting to be executed.
func (s *ExecutionState) HasPendingNodes() bool {
	return len(s.PendingQueue) > 0
}

// IsAwaitingApproval returns true if execution is paused for approval.
func (s *ExecutionState) IsAwaitingApproval() bool {
	return s.ApprovalState != nil && !s.ApprovalState.IsResolved()
}

// SerializeMemory serializes a memory map to JSON bytes.
// Returns nil bytes for nil/empty memory (not an error).
func SerializeMemory(memory map[string]any) ([]byte, error) {
	if memory == nil || len(memory) == 0 {
		return nil, nil
	}

	data, err := json.Marshal(memory)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal memory: %w", err)
	}

	return data, nil
}

// DeserializeMemory deserializes JSON bytes to a memory map.
// Returns an empty map for nil/empty bytes (not an error).
func DeserializeMemory(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return make(map[string]any), nil
	}

	var memory map[string]any
	if err := json.Unmarshal(data, &memory); err != nil {
		return nil, fmt.Errorf("failed to unmarshal memory: %w", err)
	}

	return memory, nil
}

// SerializeConversation serializes conversation history to msgpack bytes.
// Returns nil bytes for nil/empty conversation (not an error).
func SerializeConversation(messages []llm.Message) ([]byte, error) {
	if messages == nil || len(messages) == 0 {
		return nil, nil
	}

	data, err := msgpack.Marshal(messages)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal conversation: %w", err)
	}

	return data, nil
}

// DeserializeConversation deserializes msgpack bytes to conversation history.
// Returns an empty slice for nil/empty bytes (not an error).
func DeserializeConversation(data []byte) ([]llm.Message, error) {
	if len(data) == 0 {
		return []llm.Message{}, nil
	}

	var messages []llm.Message
	if err := msgpack.Unmarshal(data, &messages); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conversation: %w", err)
	}

	return messages, nil
}

// Clone creates a deep copy of the execution state.
func (s *ExecutionState) Clone() *ExecutionState {
	clone := &ExecutionState{
		MissionID:           s.MissionID,
		ThreadID:            s.ThreadID,
		CurrentNodeID:       s.CurrentNodeID,
		NodeStates:          make(map[string]*NodeState),
		CompletedResults:    make(map[string]*NodeOutput),
		PendingQueue:        make([]string, len(s.PendingQueue)),
		WorkingMemory:       make(map[string]any),
		MissionMemory:       make(map[string]any),
		ConversationHistory: make([]llm.Message, len(s.ConversationHistory)),
		Findings:            make([]types.ID, len(s.Findings)),
		Metadata:            make(map[string]any),
	}

	// Deep copy maps
	for k, v := range s.NodeStates {
		stateCopy := *v
		clone.NodeStates[k] = &stateCopy
	}
	for k, v := range s.CompletedResults {
		outputCopy := *v
		clone.CompletedResults[k] = &outputCopy
	}
	for k, v := range s.WorkingMemory {
		clone.WorkingMemory[k] = v
	}
	for k, v := range s.MissionMemory {
		clone.MissionMemory[k] = v
	}
	for k, v := range s.Metadata {
		clone.Metadata[k] = v
	}

	// Copy slices
	copy(clone.PendingQueue, s.PendingQueue)
	copy(clone.ConversationHistory, s.ConversationHistory)
	copy(clone.Findings, s.Findings)

	// Copy DAG state
	if s.DAGState != nil {
		clone.DAGState = &DAGTraversalState{
			PendingNodes:   make([]string, len(s.DAGState.PendingNodes)),
			CurrentBranch:  s.DAGState.CurrentBranch,
			ParallelState:  make(map[string][]string),
			VisitedNodes:   make([]string, len(s.DAGState.VisitedNodes)),
			ExecutionOrder: make([]string, len(s.DAGState.ExecutionOrder)),
		}
		copy(clone.DAGState.PendingNodes, s.DAGState.PendingNodes)
		copy(clone.DAGState.VisitedNodes, s.DAGState.VisitedNodes)
		copy(clone.DAGState.ExecutionOrder, s.DAGState.ExecutionOrder)
		for k, v := range s.DAGState.ParallelState {
			clone.DAGState.ParallelState[k] = make([]string, len(v))
			copy(clone.DAGState.ParallelState[k], v)
		}
	}

	// Copy in-progress node
	if s.InProgress != nil {
		clone.InProgress = &InProgressNodeState{
			NodeID:        s.InProgress.NodeID,
			StartedAt:     s.InProgress.StartedAt,
			RetryCount:    s.InProgress.RetryCount,
			PartialOutput: make(map[string]any),
			Elapsed:       s.InProgress.Elapsed,
		}
		for k, v := range s.InProgress.PartialOutput {
			clone.InProgress.PartialOutput[k] = v
		}
	}

	// Copy approval state
	if s.ApprovalState != nil {
		clone.ApprovalState = s.ApprovalState.Clone()
	}

	return clone
}

// AddNodeState adds or updates a node's execution state.
func (s *ExecutionState) AddNodeState(nodeID string, state *NodeState) {
	if s.NodeStates == nil {
		s.NodeStates = make(map[string]*NodeState)
	}
	s.NodeStates[nodeID] = state
}

// AddCompletedResult adds a completed node's output.
func (s *ExecutionState) AddCompletedResult(nodeID string, output *NodeOutput) {
	if s.CompletedResults == nil {
		s.CompletedResults = make(map[string]*NodeOutput)
	}
	s.CompletedResults[nodeID] = output
}

// AddFinding adds a finding ID to the state.
func (s *ExecutionState) AddFinding(findingID types.ID) {
	if s.Findings == nil {
		s.Findings = []types.ID{}
	}
	s.Findings = append(s.Findings, findingID)
}

// SetWorkingMemory sets a value in working memory.
func (s *ExecutionState) SetWorkingMemory(key string, value any) {
	if s.WorkingMemory == nil {
		s.WorkingMemory = make(map[string]any)
	}
	s.WorkingMemory[key] = value
}

// GetWorkingMemory gets a value from working memory.
func (s *ExecutionState) GetWorkingMemory(key string) (any, bool) {
	if s.WorkingMemory == nil {
		return nil, false
	}
	val, ok := s.WorkingMemory[key]
	return val, ok
}

// SetMissionMemory sets a value in mission memory.
func (s *ExecutionState) SetMissionMemory(key string, value any) {
	if s.MissionMemory == nil {
		s.MissionMemory = make(map[string]any)
	}
	s.MissionMemory[key] = value
}

// GetMissionMemory gets a value from mission memory.
func (s *ExecutionState) GetMissionMemory(key string) (any, bool) {
	if s.MissionMemory == nil {
		return nil, false
	}
	val, ok := s.MissionMemory[key]
	return val, ok
}

// AddConversationMessage adds a message to the conversation history.
func (s *ExecutionState) AddConversationMessage(msg llm.Message) {
	if s.ConversationHistory == nil {
		s.ConversationHistory = []llm.Message{}
	}
	s.ConversationHistory = append(s.ConversationHistory, msg)
}
