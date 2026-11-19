// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agent

import (
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
