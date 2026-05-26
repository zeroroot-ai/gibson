package prompt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestCondition_Evaluate_Equal(t *testing.T) {
	tests := []struct {
		name        string
		condition   Condition
		ctx         map[string]any
		expected    bool
		expectError bool
	}{
		{
			name: "string equal - match",
			condition: Condition{
				Field:    "status",
				Operator: OpEqual,
				Value:    "active",
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "string equal - no match",
			condition: Condition{
				Field:    "status",
				Operator: OpEqual,
				Value:    "inactive",
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected:    false,
			expectError: false,
		},
		{
			name: "integer equal - match",
			condition: Condition{
				Field:    "count",
				Operator: OpEqual,
				Value:    42,
			},
			ctx: map[string]any{
				"count": 42,
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "integer equal - no match",
			condition: Condition{
				Field:    "count",
				Operator: OpEqual,
				Value:    42,
			},
			ctx: map[string]any{
				"count": 43,
			},
			expected:    false,
			expectError: false,
		},
		{
			name: "float equal - match",
			condition: Condition{
				Field:    "price",
				Operator: OpEqual,
				Value:    19.99,
			},
			ctx: map[string]any{
				"price": 19.99,
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "boolean equal - match",
			condition: Condition{
				Field:    "enabled",
				Operator: OpEqual,
				Value:    true,
			},
			ctx: map[string]any{
				"enabled": true,
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "boolean equal - no match",
			condition: Condition{
				Field:    "enabled",
				Operator: OpEqual,
				Value:    true,
			},
			ctx: map[string]any{
				"enabled": false,
			},
			expected:    false,
			expectError: false,
		},
		{
			name: "nested path equal",
			condition: Condition{
				Field:    "mission.target.url",
				Operator: OpEqual,
				Value:    "https://example.com",
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "nil values equal",
			condition: Condition{
				Field:    "nullable",
				Operator: OpEqual,
				Value:    nil,
			},
			ctx: map[string]any{
				"nullable": nil,
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "numeric type coercion - int to float",
			condition: Condition{
				Field:    "value",
				Operator: OpEqual,
				Value:    42.0,
			},
			ctx: map[string]any{
				"value": 42,
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "field not found",
			condition: Condition{
				Field:    "missing",
				Operator: OpEqual,
				Value:    "anything",
			},
			ctx:         map[string]any{},
			expected:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCondition_Evaluate_NotEqual(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
		ctx       map[string]any
		expected  bool
	}{
		{
			name: "string not equal - different",
			condition: Condition{
				Field:    "status",
				Operator: OpNotEqual,
				Value:    "inactive",
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "string not equal - same",
			condition: Condition{
				Field:    "status",
				Operator: OpNotEqual,
				Value:    "active",
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected: false,
		},
		{
			name: "integer not equal",
			condition: Condition{
				Field:    "count",
				Operator: OpNotEqual,
				Value:    42,
			},
			ctx: map[string]any{
				"count": 43,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCondition_Evaluate_NumericComparisons(t *testing.T) {
	tests := []struct {
		name        string
		condition   Condition
		ctx         map[string]any
		expected    bool
		expectError bool
	}{
		// Greater than
		{
			name: "gt - true",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 20,
			},
			expected: true,
		},
		{
			name: "gt - false (equal)",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 10,
			},
			expected: false,
		},
		{
			name: "gt - false (less)",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 5,
			},
			expected: false,
		},
		// Less than
		{
			name: "lt - true",
			condition: Condition{
				Field:    "value",
				Operator: OpLess,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 5,
			},
			expected: true,
		},
		{
			name: "lt - false (equal)",
			condition: Condition{
				Field:    "value",
				Operator: OpLess,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 10,
			},
			expected: false,
		},
		// Greater than or equal
		{
			name: "gte - true (greater)",
			condition: Condition{
				Field:    "value",
				Operator: OpGreaterEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 20,
			},
			expected: true,
		},
		{
			name: "gte - true (equal)",
			condition: Condition{
				Field:    "value",
				Operator: OpGreaterEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 10,
			},
			expected: true,
		},
		{
			name: "gte - false",
			condition: Condition{
				Field:    "value",
				Operator: OpGreaterEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 5,
			},
			expected: false,
		},
		// Less than or equal
		{
			name: "lte - true (less)",
			condition: Condition{
				Field:    "value",
				Operator: OpLessEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 5,
			},
			expected: true,
		},
		{
			name: "lte - true (equal)",
			condition: Condition{
				Field:    "value",
				Operator: OpLessEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 10,
			},
			expected: true,
		},
		{
			name: "lte - false",
			condition: Condition{
				Field:    "value",
				Operator: OpLessEq,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 20,
			},
			expected: false,
		},
		// Float comparisons
		{
			name: "gt with floats",
			condition: Condition{
				Field:    "price",
				Operator: OpGreater,
				Value:    19.99,
			},
			ctx: map[string]any{
				"price": 29.99,
			},
			expected: true,
		},
		// Mixed int and float
		{
			name: "gt int field, float value",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10.5,
			},
			ctx: map[string]any{
				"value": 20,
			},
			expected: true,
		},
		{
			name: "gt float field, int value",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10,
			},
			ctx: map[string]any{
				"value": 20.5,
			},
			expected: true,
		},
		// Error cases
		{
			name: "gt with string field",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    10,
			},
			ctx: map[string]any{
				"value": "not a number",
			},
			expectError: true,
		},
		{
			name: "gt with string value",
			condition: Condition{
				Field:    "value",
				Operator: OpGreater,
				Value:    "not a number",
			},
			ctx: map[string]any{
				"value": 10,
			},
			expectError: true,
		},
		// Nested paths
		{
			name: "gt with nested path",
			condition: Condition{
				Field:    "config.timeout",
				Operator: OpGreater,
				Value:    30,
			},
			ctx: map[string]any{
				"config": map[string]any{
					"timeout": 60,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)

			if tt.expectError {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, PROMPT_CONDITION_INVALID, gibsonErr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCondition_Evaluate_Contains(t *testing.T) {
	tests := []struct {
		name        string
		condition   Condition
		ctx         map[string]any
		expected    bool
		expectError bool
	}{
		{
			name: "string contains - match",
			condition: Condition{
				Field:    "message",
				Operator: OpContains,
				Value:    "world",
			},
			ctx: map[string]any{
				"message": "hello world",
			},
			expected: true,
		},
		{
			name: "string contains - no match",
			condition: Condition{
				Field:    "message",
				Operator: OpContains,
				Value:    "foo",
			},
			ctx: map[string]any{
				"message": "hello world",
			},
			expected: false,
		},
		{
			name: "string contains - exact match",
			condition: Condition{
				Field:    "message",
				Operator: OpContains,
				Value:    "hello world",
			},
			ctx: map[string]any{
				"message": "hello world",
			},
			expected: true,
		},
		{
			name: "string contains - empty substring",
			condition: Condition{
				Field:    "message",
				Operator: OpContains,
				Value:    "",
			},
			ctx: map[string]any{
				"message": "hello world",
			},
			expected: true,
		},
		{
			name: "slice contains - string element match",
			condition: Condition{
				Field:    "tags",
				Operator: OpContains,
				Value:    "important",
			},
			ctx: map[string]any{
				"tags": []string{"urgent", "important", "review"},
			},
			expected: true,
		},
		{
			name: "slice contains - string element no match",
			condition: Condition{
				Field:    "tags",
				Operator: OpContains,
				Value:    "missing",
			},
			ctx: map[string]any{
				"tags": []string{"urgent", "important", "review"},
			},
			expected: false,
		},
		{
			name: "slice contains - int element match",
			condition: Condition{
				Field:    "numbers",
				Operator: OpContains,
				Value:    42,
			},
			ctx: map[string]any{
				"numbers": []int{1, 42, 100},
			},
			expected: true,
		},
		{
			name: "slice contains - int element no match",
			condition: Condition{
				Field:    "numbers",
				Operator: OpContains,
				Value:    99,
			},
			ctx: map[string]any{
				"numbers": []int{1, 42, 100},
			},
			expected: false,
		},
		{
			name: "slice contains - any interface slice",
			condition: Condition{
				Field:    "items",
				Operator: OpContains,
				Value:    "test",
			},
			ctx: map[string]any{
				"items": []any{"foo", "test", 123},
			},
			expected: true,
		},
		{
			name: "array contains - match",
			condition: Condition{
				Field:    "values",
				Operator: OpContains,
				Value:    2,
			},
			ctx: map[string]any{
				"values": [3]int{1, 2, 3},
			},
			expected: true,
		},
		{
			name: "nested path contains",
			condition: Condition{
				Field:    "data.tags",
				Operator: OpContains,
				Value:    "production",
			},
			ctx: map[string]any{
				"data": map[string]any{
					"tags": []string{"development", "production"},
				},
			},
			expected: true,
		},
		// Error cases
		{
			name: "string field with non-string value",
			condition: Condition{
				Field:    "message",
				Operator: OpContains,
				Value:    42,
			},
			ctx: map[string]any{
				"message": "hello world",
			},
			expectError: true,
		},
		{
			name: "invalid field type",
			condition: Condition{
				Field:    "value",
				Operator: OpContains,
				Value:    "test",
			},
			ctx: map[string]any{
				"value": 42,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)

			if tt.expectError {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, PROMPT_CONDITION_INVALID, gibsonErr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCondition_Evaluate_Exists(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
		ctx       map[string]any
		expected  bool
	}{
		{
			name: "field exists",
			condition: Condition{
				Field:    "status",
				Operator: OpExists,
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "field does not exist",
			condition: Condition{
				Field:    "missing",
				Operator: OpExists,
			},
			ctx:      map[string]any{},
			expected: false,
		},
		{
			name: "nested field exists",
			condition: Condition{
				Field:    "mission.target.url",
				Operator: OpExists,
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			expected: true,
		},
		{
			name: "nested field partial path exists",
			condition: Condition{
				Field:    "mission.target.missing",
				Operator: OpExists,
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			expected: false,
		},
		{
			name: "field exists with nil value",
			condition: Condition{
				Field:    "nullable",
				Operator: OpExists,
			},
			ctx: map[string]any{
				"nullable": nil,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCondition_Evaluate_NotExists(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
		ctx       map[string]any
		expected  bool
	}{
		{
			name: "field does not exist",
			condition: Condition{
				Field:    "missing",
				Operator: OpNotExists,
			},
			ctx:      map[string]any{},
			expected: true,
		},
		{
			name: "field exists",
			condition: Condition{
				Field:    "status",
				Operator: OpNotExists,
			},
			ctx: map[string]any{
				"status": "active",
			},
			expected: false,
		},
		{
			name: "nested field does not exist",
			condition: Condition{
				Field:    "mission.target.missing",
				Operator: OpNotExists,
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.condition.Evaluate(tt.ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCondition_Evaluate_InvalidOperator(t *testing.T) {
	condition := Condition{
		Field:    "value",
		Operator: "invalid_op",
		Value:    "anything",
	}

	ctx := map[string]any{
		"value": "test",
	}

	result, err := condition.Evaluate(ctx)
	require.Error(t, err)
	assert.False(t, result)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, PROMPT_CONDITION_INVALID, gibsonErr.Code)
	assert.Contains(t, gibsonErr.Message, "invalid operator")
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected float64
		ok       bool
	}{
		{"float64", float64(42.5), 42.5, true},
		{"float32", float32(42.5), 42.5, true},
		{"int", int(42), 42.0, true},
		{"int8", int8(42), 42.0, true},
		{"int16", int16(42), 42.0, true},
		{"int32", int32(42), 42.0, true},
		{"int64", int64(42), 42.0, true},
		{"uint", uint(42), 42.0, true},
		{"uint8", uint8(42), 42.0, true},
		{"uint16", uint16(42), 42.0, true},
		{"uint32", uint32(42), 42.0, true},
		{"uint64", uint64(42), 42.0, true},
		{"string", "not a number", 0, false},
		{"bool", true, 0, false},
		{"nil", nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := toFloat64(tt.value)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
