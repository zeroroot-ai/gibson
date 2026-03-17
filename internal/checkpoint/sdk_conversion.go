package checkpoint

import (
	"github.com/zero-day-ai/gibson/internal/types"
	sdkcheckpoint "github.com/zero-day-ai/sdk/checkpoint"
)

// ToSDKCheckpoint converts an internal checkpoint to SDK type.
// This is used by the harness implementation to expose internal
// checkpoints to agents via the SDK interface.
//
// Internal details like node states, memory snapshots, and DAG state
// are hidden from the SDK, exposing only high-level checkpoint metadata.
func (c *Checkpoint) ToSDK() *sdkcheckpoint.Checkpoint {
	if c == nil {
		return nil
	}

	// Convert metadata
	metadata := make(map[string]string)
	if c.Metadata != nil {
		for k, v := range c.Metadata {
			metadata[k] = v
		}
	}

	return &sdkcheckpoint.Checkpoint{
		ID:        c.ID,
		ThreadID:  c.ThreadID,
		Label:     c.Label,
		CreatedAt: c.CreatedAt,
		Metadata:  metadata,
	}
}

// FromSDKCheckpoint converts an SDK checkpoint to internal type.
// This is used when SDK checkpoint data needs to be passed to
// internal checkpoint operations.
//
// Note: Only metadata fields are converted. Internal fields like
// node states and memory are not populated as they are managed
// by the orchestrator, not the agent.
func FromSDKCheckpoint(sdk *sdkcheckpoint.Checkpoint) *Checkpoint {
	if sdk == nil {
		return nil
	}

	// Convert metadata
	metadata := make(map[string]string)
	if sdk.Metadata != nil {
		for k, v := range sdk.Metadata {
			metadata[k] = v
		}
	}

	return &Checkpoint{
		ID:        sdk.ID,
		ThreadID:  sdk.ThreadID,
		Label:     sdk.Label,
		CreatedAt: sdk.CreatedAt,
		Metadata:  metadata,
		// Internal fields (Version, MissionID, NodeStates, etc.) are not
		// populated here as they are managed by the orchestrator.
	}
}

// ToSDKThread converts an internal thread to SDK type.
// This is used by the harness implementation to expose thread
// information to agents via the SDK interface.
func (t *Thread) ToSDK() *sdkcheckpoint.Thread {
	if t == nil {
		return nil
	}

	return &sdkcheckpoint.Thread{
		ID:           t.ID,
		MissionID:    t.MissionID.String(),
		ParentThread: t.ParentThread,
		Label:        t.Label,
		Status:       string(t.Status),
		CreatedAt:    t.CreatedAt,
	}
}

// FromSDKThread converts an SDK thread to internal type.
// This is used when SDK thread data needs to be passed to
// internal thread operations.
func FromSDKThread(sdk *sdkcheckpoint.Thread) *Thread {
	if sdk == nil {
		return nil
	}

	// Parse mission ID
	var missionID types.ID
	if sdk.MissionID != "" {
		// Convert string to ID type
		missionID = types.ID(sdk.MissionID)
	}

	return &Thread{
		ID:           sdk.ID,
		MissionID:    missionID,
		ParentThread: sdk.ParentThread,
		Label:        sdk.Label,
		Status:       ThreadStatus(sdk.Status),
		CreatedAt:    sdk.CreatedAt,
	}
}
