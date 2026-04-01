// Package client provides proto-to-domain type conversions for daemon gRPC responses.
//
// This file contains conversion functions that transform protocol buffer types (from the
// generated api package) into domain types used by the client and CLI commands. These
// conversions ensure a clean separation between the gRPC layer and the application layer.
package client

import (
	"time"

	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
)

// convertProtoStatus converts a gRPC StatusResponse to a domain DaemonStatus.
//
// This function maps all fields from the protocol buffer response to the daemon status
// structure used throughout the application. It handles timestamp conversion from Unix
// seconds to Go time.Time.
//
// Parameters:
//   - resp: The gRPC status response
//
// Returns:
//   - *daemon.DaemonStatus: The converted daemon status
func convertProtoStatus(resp *api.StatusResponse) *daemon.DaemonStatus {
	if resp == nil {
		return nil
	}

	return &daemon.DaemonStatus{
		Running:      resp.Running,
		PID:          int(resp.Pid),
		StartTime:    time.Unix(resp.StartTime, 0),
		Uptime:       resp.Uptime,
		GRPCAddress:  resp.GrpcAddress,
		RegistryType: resp.RegistryType,
		RegistryAddr: resp.RegistryAddr,
		CallbackAddr: resp.CallbackAddr,
		AgentCount:   int(resp.AgentCount),
	}
}

// convertProtoAgents converts a slice of gRPC AgentInfo messages to domain AgentInfo structs.
//
// This function transforms the protocol buffer agent information into the simpler domain
// types used by CLI commands for display. It handles nil slices gracefully by returning
// an empty slice rather than nil.
//
// Parameters:
//   - agents: Slice of gRPC agent info messages
//
// Returns:
//   - []AgentInfo: Converted agent information slice (never nil)
func convertProtoAgents(agents []*api.AgentInfo) []AgentInfo {
	if agents == nil {
		return []AgentInfo{}
	}

	result := make([]AgentInfo, 0, len(agents))
	for _, a := range agents {
		if a == nil {
			continue
		}

		result = append(result, AgentInfo{
			Name:        a.Name,
			Version:     a.Version,
			Description: "", // Description not in proto AgentInfo
			Address:     a.Endpoint,
			Status:      a.Health,
		})
	}

	return result
}

// convertProtoTools converts a slice of gRPC ToolInfo messages to domain ToolInfo structs.
//
// This function transforms the protocol buffer tool information into the simpler domain
// types used by CLI commands for display. It handles nil slices gracefully by returning
// an empty slice rather than nil.
//
// Parameters:
//   - tools: Slice of gRPC tool info messages
//
// Returns:
//   - []ToolInfo: Converted tool information slice (never nil)
func convertProtoTools(tools []*api.ToolInfo) []ToolInfo {
	if tools == nil {
		return []ToolInfo{}
	}

	result := make([]ToolInfo, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}

		var caps *Capabilities
		if t.Capabilities != nil {
			caps = &Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}

		result = append(result, ToolInfo{
			Name:         t.Name,
			Version:      t.Version,
			Description:  t.Description,
			Address:      t.Endpoint,
			Status:       t.Health,
			Capabilities: caps,
		})
	}

	return result
}

// convertProtoPlugins converts a slice of gRPC PluginInfo messages to domain PluginInfo structs.
//
// This function transforms the protocol buffer plugin information into the simpler domain
// types used by CLI commands for display. It handles nil slices gracefully by returning
// an empty slice rather than nil.
//
// Parameters:
//   - plugins: Slice of gRPC plugin info messages
//
// Returns:
//   - []PluginInfo: Converted plugin information slice (never nil)
func convertProtoPlugins(plugins []*api.PluginInfo) []PluginInfo {
	if plugins == nil {
		return []PluginInfo{}
	}

	result := make([]PluginInfo, 0, len(plugins))
	for _, p := range plugins {
		if p == nil {
			continue
		}

		result = append(result, PluginInfo{
			Name:        p.Name,
			Version:     p.Version,
			Description: p.Description,
			Address:     p.Endpoint,
			Status:      p.Health,
		})
	}

	return result
}

// convertProtoMissionEvent converts a gRPC MissionEvent to a domain MissionEvent.
//
// This function transforms mission events from the streaming RPC into the domain type
// used by CLI commands and the TUI. It handles timestamp conversion and JSON decoding
// of event data fields.
//
// Parameters:
//   - event: The gRPC mission event
//
// Returns:
//   - MissionEvent: The converted mission event
func convertProtoMissionEvent(event *api.RunMissionResponse) MissionEvent {
	if event == nil {
		return MissionEvent{}
	}

	// Convert TypedMap data to map[string]interface{}
	var data map[string]interface{}
	if event.Data != nil {
		data = api.TypedMapToMap(event.Data)
	}

	return MissionEvent{
		Type:      event.EventType,
		Timestamp: time.Unix(event.Timestamp, 0),
		Message:   event.Message,
		Data:      data,
	}
}

// convertProtoAttackEvent converts a gRPC AttackEvent to a domain AttackEvent.
//
// This function transforms attack events from the streaming RPC into the domain type
// used by CLI commands for displaying attack progress. It handles timestamp conversion
// and JSON decoding of event data fields.
//
// Parameters:
//   - event: The gRPC attack event
//
// Returns:
//   - AttackEvent: The converted attack event
func convertProtoAttackEvent(event *api.RunAttackResponse) AttackEvent {
	if event == nil {
		return AttackEvent{}
	}

	// Convert TypedMap data to map[string]interface{}
	var data map[string]interface{}
	if event.Data != nil {
		data = api.TypedMapToMap(event.Data)
	}

	// Convert OperationResult if present
	var result *OperationResult
	if event.Result != nil {
		result = &OperationResult{
			Status:        event.Result.Status,
			DurationMs:    event.Result.DurationMs,
			StartedAt:     event.Result.StartedAt,
			CompletedAt:   event.Result.CompletedAt,
			TurnsUsed:     event.Result.TurnsUsed,
			TokensUsed:    event.Result.TokensUsed,
			NodesExecuted: event.Result.NodesExecuted,
			NodesFailed:   event.Result.NodesFailed,
			FindingsCount: event.Result.FindingsCount,
			CriticalCount: event.Result.CriticalCount,
			HighCount:     event.Result.HighCount,
			MediumCount:   event.Result.MediumCount,
			LowCount:      event.Result.LowCount,
			ErrorMessage:  event.Result.ErrorMessage,
			ErrorCode:     event.Result.ErrorCode,
		}
	}

	return AttackEvent{
		Type:      event.EventType,
		Timestamp: time.Unix(event.Timestamp, 0),
		Message:   event.Message,
		Severity:  "", // Severity not in proto AttackEvent
		Data:      data,
		Result:    result,
	}
}

// convertProtoEvent converts a gRPC Event to a domain Event.
//
// This function transforms generic daemon events from the Subscribe stream into the
// domain type used by the TUI for real-time updates. It handles the oneof event field
// by extracting the specific event type when present.
//
// Parameters:
//   - event: The gRPC event
//
// Returns:
//   - Event: The converted event
func convertProtoEvent(event *api.SubscribeResponse) Event {
	if event == nil {
		return Event{}
	}

	// Convert TypedMap data to map[string]interface{}
	var data map[string]interface{}
	if event.Data != nil {
		data = api.TypedMapToMap(event.Data)
	}

	return Event{
		Type:      event.EventType,
		Source:    event.Source,
		Timestamp: time.Unix(event.Timestamp, 0),
		Data:      data,
	}
}
