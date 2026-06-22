package agent

import (
	"encoding/json"
	"fmt"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// TaskToProto converts a Gibson internal Task to a proto Task message.
func TaskToProto(task Task) *typespb.Task {
	protoTask := &typespb.Task{
		Id:      task.ID.String(),
		Goal:    task.Goal,
		Context: mapToTypedValueMap(task.Context),
		Metadata: mapToTypedValueMap(map[string]any{
			"name":        task.Name,
			"description": task.Description,
			"timeout_ms":  task.Timeout.Milliseconds(),
		}),
	}

	// Add optional fields to metadata if present
	if task.MissionID != nil {
		if protoTask.Metadata == nil {
			protoTask.Metadata = make(map[string]*commonpb.TypedValue)
		}
		protoTask.Metadata["mission_id"] = stringToTypedValue(task.MissionID.String())
	}
	if task.ParentTaskID != nil {
		if protoTask.Metadata == nil {
			protoTask.Metadata = make(map[string]*commonpb.TypedValue)
		}
		protoTask.Metadata["parent_task_id"] = stringToTypedValue(task.ParentTaskID.String())
	}
	if task.TargetID != nil {
		if protoTask.Metadata == nil {
			protoTask.Metadata = make(map[string]*commonpb.TypedValue)
		}
		protoTask.Metadata["target_id"] = stringToTypedValue(task.TargetID.String())
	}

	return protoTask
}

// ResultToProto converts a Gibson internal Result to a proto Result message.
func ResultToProto(r Result) *typespb.Result {
	protoResult := &typespb.Result{
		Status: resultStatusToProto(r.Status),
		Output: anyToTypedValue(r.Output),
	}

	// Convert error if present
	if r.Error != nil {
		details := make(map[string]string)
		for k, v := range r.Error.Details {
			details[k] = fmt.Sprintf("%v", v)
		}
		protoResult.Error = &typespb.ResultError{
			Message: r.Error.Message,
			Code:    commonpb.ErrorCode(commonpb.ErrorCode_value[r.Error.Code]),
			Details: details,
		}
	}

	// Convert findings to finding IDs
	if len(r.Findings) > 0 {
		protoResult.FindingIds = make([]string, len(r.Findings))
		for i, f := range r.Findings {
			protoResult.FindingIds[i] = string(f.ID)
		}
	}

	return protoResult
}

// resultStatusToProto converts an internal ResultStatus to a proto ResultStatus.
func resultStatusToProto(status ResultStatus) typespb.ResultStatus {
	switch status {
	case ResultStatusPending:
		return typespb.ResultStatus_RESULT_STATUS_UNSPECIFIED
	case ResultStatusCompleted:
		return typespb.ResultStatus_RESULT_STATUS_SUCCESS
	case ResultStatusFailed:
		return typespb.ResultStatus_RESULT_STATUS_FAILED
	case ResultStatusCancelled:
		return typespb.ResultStatus_RESULT_STATUS_CANCELLED
	default:
		return typespb.ResultStatus_RESULT_STATUS_UNSPECIFIED
	}
}

// ProtoToResult converts a proto Result to a Gibson internal Result.
func ProtoToResult(pr *typespb.Result) Result {
	if pr == nil {
		return Result{}
	}

	result := Result{
		Status:   protoStatusToResultStatus(pr.Status),
		Output:   typedValueToMap(pr.Output),
		Findings: []Finding{}, // FindingIDs are used instead of full findings in proto
	}

	// Convert error if present
	if pr.Error != nil {
		// Convert Details map[string]string to map[string]any
		details := make(map[string]any)
		for k, v := range pr.Error.Details {
			details[k] = v
		}

		result.Error = &ResultError{
			Message: pr.Error.Message,
			Code:    pr.Error.Code.String(),
			Details: details,
		}
	}

	return result
}

// protoStatusToResultStatus converts a proto ResultStatus to an internal ResultStatus.
func protoStatusToResultStatus(status typespb.ResultStatus) ResultStatus {
	switch status {
	case typespb.ResultStatus_RESULT_STATUS_UNSPECIFIED:
		return ResultStatusPending
	case typespb.ResultStatus_RESULT_STATUS_SUCCESS:
		return ResultStatusCompleted
	case typespb.ResultStatus_RESULT_STATUS_FAILED:
		return ResultStatusFailed
	case typespb.ResultStatus_RESULT_STATUS_PARTIAL:
		return ResultStatusCompleted // Partial is still completed
	case typespb.ResultStatus_RESULT_STATUS_CANCELLED:
		return ResultStatusCancelled
	case typespb.ResultStatus_RESULT_STATUS_TIMEOUT:
		return ResultStatusFailed // Timeout is a type of failure
	default:
		return ResultStatusFailed
	}
}

// mapToTypedValueMap converts a map[string]any to map[string]*TypedValue.
func mapToTypedValueMap(m map[string]any) map[string]*commonpb.TypedValue {
	if m == nil {
		return nil
	}

	result := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		result[k] = anyToTypedValue(v)
	}
	return result
}

// typedValueMapToMap converts map[string]*TypedValue to map[string]any.
func typedValueMapToMap(m map[string]*commonpb.TypedValue) map[string]any {
	if m == nil {
		return nil
	}

	result := make(map[string]any)
	for k, v := range m {
		result[k] = typedValueToAny(v)
	}
	return result
}

// typedValueToMap converts a TypedValue to map[string]any if it's a map, otherwise returns empty map.
// It also handles the case where the TypedValue is a JSON string that represents a map/struct.
// This is needed because the SDK serializes proto messages (like DiscoveryResult) to JSON strings.
func typedValueToMap(tv *commonpb.TypedValue) map[string]any {
	if tv == nil {
		return make(map[string]any)
	}

	if mapVal, ok := tv.Kind.(*commonpb.TypedValue_MapValue); ok && mapVal.MapValue != nil {
		return typedValueMapToMap(mapVal.MapValue.Entries)
	}

	// If it's a string, try to parse it as JSON - this handles the case where
	// the SDK serialized a proto message (like DiscoveryResult) to JSON
	if strVal, ok := tv.Kind.(*commonpb.TypedValue_StringValue); ok && strVal.StringValue != "" {
		// Check if it looks like JSON (starts with { or [)
		str := strVal.StringValue
		if len(str) > 0 && (str[0] == '{' || str[0] == '[') {
			var result map[string]any
			if err := json.Unmarshal([]byte(str), &result); err == nil {
				return result
			}
		}
	}

	// If not a map and not a JSON string, return empty map
	return make(map[string]any)
}

// anyToTypedValue converts any Go value to a proto TypedValue.
func anyToTypedValue(v any) *commonpb.TypedValue {
	if v == nil {
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_NullValue{
				NullValue: commonpb.NullValue_NULL_VALUE_UNSPECIFIED,
			},
		}
	}

	switch val := v.(type) {
	case string:
		return stringToTypedValue(val)
	case int:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: val},
		}
	case float32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: float64(val)},
		}
	case float64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: val},
		}
	case bool:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BoolValue{BoolValue: val},
		}
	case []byte:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BytesValue{BytesValue: val},
		}
	case []any:
		items := make([]*commonpb.TypedValue, len(val))
		for i, item := range val {
			items[i] = anyToTypedValue(item)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_ArrayValue{
				ArrayValue: &commonpb.TypedArray{Items: items},
			},
		}
	case map[string]any:
		entries := make(map[string]*commonpb.TypedValue)
		for k, v := range val {
			entries[k] = anyToTypedValue(v)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_MapValue{
				MapValue: &commonpb.TypedMap{Entries: entries},
			},
		}
	default:
		// For unknown types, convert to string representation
		return stringToTypedValue(fmt.Sprintf("%v", v))
	}
}

// stringToTypedValue creates a TypedValue with a string value.
func stringToTypedValue(s string) *commonpb.TypedValue {
	return &commonpb.TypedValue{
		Kind: &commonpb.TypedValue_StringValue{StringValue: s},
	}
}

// typedValueToAny converts a proto TypedValue to a Go any value.
func typedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch kind := tv.Kind.(type) {
	case *commonpb.TypedValue_NullValue:
		return nil
	case *commonpb.TypedValue_StringValue:
		return kind.StringValue
	case *commonpb.TypedValue_IntValue:
		return kind.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return kind.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return kind.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return kind.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if kind.ArrayValue == nil {
			return []any{}
		}
		result := make([]any, len(kind.ArrayValue.Items))
		for i, item := range kind.ArrayValue.Items {
			result[i] = typedValueToAny(item)
		}
		return result
	case *commonpb.TypedValue_MapValue:
		if kind.MapValue == nil {
			return map[string]any{}
		}
		result := make(map[string]any)
		for k, v := range kind.MapValue.Entries {
			result[k] = typedValueToAny(v)
		}
		return result
	default:
		return nil
	}
}
