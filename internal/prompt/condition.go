package prompt

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Condition represents a conditional expression that can be evaluated against context data.
// Conditions support various operators for comparing values, checking existence, and more.
type Condition struct {
	Field    string `json:"field" yaml:"field"`       // Path to value (dot-notation)
	Operator string `json:"operator" yaml:"operator"` // eq, ne, gt, lt, gte, lte, contains, exists, not_exists
	Value    any    `json:"value" yaml:"value"`       // Value to compare against (not used for exists/not_exists)
}

// Operator constants for condition evaluation
const (
	OpEqual     = "eq"
	OpNotEqual  = "ne"
	OpGreater   = "gt"
	OpLess      = "lt"
	OpGreaterEq = "gte"
	OpLessEq    = "lte"
	OpContains  = "contains"
	OpExists    = "exists"
	OpNotExists = "not_exists"
)

// Evaluate checks if the condition is satisfied given the context.
// Returns true if the condition passes, false otherwise.
// Returns an error for invalid operators or type mismatches.
func (c *Condition) Evaluate(ctx map[string]any) (bool, error) {
	// Resolve the field value from context
	fieldValue, found := ResolvePath(ctx, c.Field)

	// Handle existence operators
	switch c.Operator {
	case OpExists:
		return found, nil
	case OpNotExists:
		return !found, nil
	}

	// For all other operators, the field must exist
	if !found {
		return false, nil
	}

	// Evaluate based on operator
	switch c.Operator {
	case OpEqual:
		return c.evaluateEqual(fieldValue)
	case OpNotEqual:
		result, err := c.evaluateEqual(fieldValue)
		return !result, err
	case OpGreater:
		return c.evaluateNumeric(fieldValue, func(field, val float64) bool {
			return field > val
		})
	case OpLess:
		return c.evaluateNumeric(fieldValue, func(field, val float64) bool {
			return field < val
		})
	case OpGreaterEq:
		return c.evaluateNumeric(fieldValue, func(field, val float64) bool {
			return field >= val
		})
	case OpLessEq:
		return c.evaluateNumeric(fieldValue, func(field, val float64) bool {
			return field <= val
		})
	case OpContains:
		return c.evaluateContains(fieldValue)
	default:
		return false, types.NewError(
			PROMPT_CONDITION_INVALID,
			fmt.Sprintf("invalid operator '%s'", c.Operator),
		)
	}
}

// evaluateEqual checks if two values are equal.
// Supports string, int, float64, and bool comparisons.
func (c *Condition) evaluateEqual(fieldValue any) (bool, error) {
	// Handle nil cases
	if fieldValue == nil && c.Value == nil {
		return true, nil
	}
	if fieldValue == nil || c.Value == nil {
		return false, nil
	}

	// Use reflect.DeepEqual for complex types
	if reflect.DeepEqual(fieldValue, c.Value) {
		return true, nil
	}

	// Try numeric comparison if types differ but both are numeric
	fieldNum, fieldIsNum := toFloat64(fieldValue)
	valueNum, valueIsNum := toFloat64(c.Value)
	if fieldIsNum && valueIsNum {
		return fieldNum == valueNum, nil
	}

	// Try string comparison
	fieldStr, fieldIsStr := fieldValue.(string)
	valueStr, valueIsStr := c.Value.(string)
	if fieldIsStr && valueIsStr {
		return fieldStr == valueStr, nil
	}

	return false, nil
}

// evaluateNumeric performs numeric comparisons using the provided comparison function.
func (c *Condition) evaluateNumeric(fieldValue any, compare func(float64, float64) bool) (bool, error) {
	fieldNum, fieldOk := toFloat64(fieldValue)
	valueNum, valueOk := toFloat64(c.Value)

	if !fieldOk || !valueOk {
		return false, types.NewError(
			PROMPT_CONDITION_INVALID,
			fmt.Sprintf("numeric comparison requires numeric values, got field=%T, value=%T", fieldValue, c.Value),
		)
	}

	return compare(fieldNum, valueNum), nil
}

// evaluateContains checks if the field value contains the condition value.
// Supports:
//   - String contains substring
//   - Slice contains element
func (c *Condition) evaluateContains(fieldValue any) (bool, error) {
	// String contains substring
	if fieldStr, ok := fieldValue.(string); ok {
		if valueStr, ok := c.Value.(string); ok {
			return strings.Contains(fieldStr, valueStr), nil
		}
		return false, types.NewError(
			PROMPT_CONDITION_INVALID,
			"contains operator with string field requires string value",
		)
	}

	// Slice contains element
	fieldVal := reflect.ValueOf(fieldValue)
	if fieldVal.Kind() == reflect.Slice || fieldVal.Kind() == reflect.Array {
		for i := 0; i < fieldVal.Len(); i++ {
			elem := fieldVal.Index(i).Interface()
			if reflect.DeepEqual(elem, c.Value) {
				return true, nil
			}
		}
		return false, nil
	}

	return false, types.NewError(
		PROMPT_CONDITION_INVALID,
		fmt.Sprintf("contains operator requires string or slice field, got %T", fieldValue),
	)
}

// toFloat64 attempts to convert a value to float64.
// Supports int, int8, int16, int32, int64, float32, float64.
func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int8:
		return float64(val), true
	case int16:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint8:
		return float64(val), true
	case uint16:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	default:
		return 0, false
	}
}
