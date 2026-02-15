package api

import (
	"encoding/json"
	"fmt"

	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
)

// StringToTypedMap converts a JSON string to TypedMap (for backward compatibility with events).
// This is used when converting internal event Data (string) to proto TypedMap.
func StringToTypedMap(jsonStr string) *commonpb.TypedMap {
	if jsonStr == "" {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil
	}
	return mapToTypedMap(data)
}

// MapToTypedMap converts map[string]any to *TypedMap.
func MapToTypedMap(m map[string]any) *commonpb.TypedMap {
	if m == nil {
		return nil
	}
	entries := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		entries[k] = AnyToTypedValue(v)
	}
	return &commonpb.TypedMap{Entries: entries}
}

// mapToTypedMap is the internal unexported version for backward compatibility.
func mapToTypedMap(m map[string]any) *commonpb.TypedMap {
	return MapToTypedMap(m)
}

// AnyToTypedValue converts any Go value to TypedValue.
func AnyToTypedValue(v any) *commonpb.TypedValue {
	if v == nil {
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_NullValue{}}
	}
	switch val := v.(type) {
	case string:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: val}}
	case float64:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: val}}
	case bool:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_BoolValue{BoolValue: val}}
	case int:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)}}
	case int64:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_IntValue{IntValue: val}}
	case []any:
		items := make([]*commonpb.TypedValue, len(val))
		for i, item := range val {
			items[i] = AnyToTypedValue(item)
		}
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_ArrayValue{ArrayValue: &commonpb.TypedArray{Items: items}}}
	case map[string]any:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_MapValue{MapValue: MapToTypedMap(val)}}
	default:
		// Fallback: convert to string
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: fmt.Sprintf("%v", v)}}
	}
}

// anyToTypedValue is the internal unexported version for backward compatibility.
func anyToTypedValue(v any) *commonpb.TypedValue {
	return AnyToTypedValue(v)
}

// TypedMapToMap converts TypedMap back to map[string]any.
func TypedMapToMap(tm *commonpb.TypedMap) map[string]any {
	if tm == nil {
		return nil
	}
	result := make(map[string]any)
	for k, v := range tm.Entries {
		result[k] = TypedValueToAny(v)
	}
	return result
}

// TypedValueToAny converts TypedValue to any.
func TypedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}
	switch v := tv.Kind.(type) {
	case *commonpb.TypedValue_NullValue:
		return nil
	case *commonpb.TypedValue_StringValue:
		return v.StringValue
	case *commonpb.TypedValue_IntValue:
		return v.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return v.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return v.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if v.ArrayValue == nil {
			return nil
		}
		result := make([]any, len(v.ArrayValue.Items))
		for i, item := range v.ArrayValue.Items {
			result[i] = TypedValueToAny(item)
		}
		return result
	case *commonpb.TypedValue_MapValue:
		return TypedMapToMap(v.MapValue)
	default:
		return nil
	}
}
