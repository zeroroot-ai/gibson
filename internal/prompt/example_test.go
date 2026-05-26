package prompt

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestExample_Validate(t *testing.T) {
	tests := []struct {
		name    string
		example Example
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name: "valid example with description",
			example: Example{
				Description: "Simple greeting",
				Input:       "Hello",
				Output:      "Hi there!",
			},
			wantErr: false,
		},
		{
			name: "valid example without description",
			example: Example{
				Input:  "What is 2+2?",
				Output: "4",
			},
			wantErr: false,
		},
		{
			name: "missing input",
			example: Example{
				Description: "Test case",
				Output:      "Expected output",
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name: "missing output",
			example: Example{
				Description: "Test case",
				Input:       "Test input",
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name: "empty input (whitespace only)",
			example: Example{
				Input:  "   ",
				Output: "Output",
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name: "empty output (whitespace only)",
			example: Example{
				Input:  "Input",
				Output: "   ",
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name:    "both fields empty",
			example: Example{},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.example.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}

				var gibsonErr *types.GibsonError
				if !isGibsonError(err, &gibsonErr) {
					t.Errorf("expected GibsonError, got %T", err)
					return
				}

				if gibsonErr.Code != tt.errCode {
					t.Errorf("error code = %v, want %v", gibsonErr.Code, tt.errCode)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestExample_String(t *testing.T) {
	tests := []struct {
		name     string
		example  Example
		contains []string
	}{
		{
			name: "with description",
			example: Example{
				Description: "Greeting",
				Input:       "Hi",
				Output:      "Hello",
			},
			contains: []string{"Example", "Greeting", "Hi", "Hello"},
		},
		{
			name: "without description",
			example: Example{
				Input:  "Question",
				Output: "Answer",
			},
			contains: []string{"Example", "Question", "Answer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.example.String()

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("String() = %v, missing substring %v", result, substr)
				}
			}
		})
	}
}

func TestExamples_Validate(t *testing.T) {
	tests := []struct {
		name     string
		examples Examples
		wantErr  bool
		errCode  types.ErrorCode
	}{
		{
			name: "all valid examples",
			examples: Examples{
				{Input: "Q1", Output: "A1"},
				{Input: "Q2", Output: "A2"},
				{Input: "Q3", Output: "A3"},
			},
			wantErr: false,
		},
		{
			name:     "empty examples",
			examples: Examples{},
			wantErr:  false,
		},
		{
			name: "first example invalid",
			examples: Examples{
				{Input: "", Output: "A1"},
				{Input: "Q2", Output: "A2"},
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name: "middle example invalid",
			examples: Examples{
				{Input: "Q1", Output: "A1"},
				{Input: "Q2", Output: ""},
				{Input: "Q3", Output: "A3"},
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
		{
			name: "last example invalid",
			examples: Examples{
				{Input: "Q1", Output: "A1"},
				{Input: "Q2", Output: "A2"},
				{Input: "", Output: ""},
			},
			wantErr: true,
			errCode: ErrCodeInvalidExample,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.examples.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}

				var gibsonErr *types.GibsonError
				if !isGibsonError(err, &gibsonErr) {
					t.Errorf("expected GibsonError, got %T", err)
					return
				}

				if gibsonErr.Code != tt.errCode {
					t.Errorf("error code = %v, want %v", gibsonErr.Code, tt.errCode)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestExamples_String(t *testing.T) {
	tests := []struct {
		name     string
		examples Examples
		contains []string
	}{
		{
			name: "multiple examples",
			examples: Examples{
				{Input: "Q1", Output: "A1"},
				{Input: "Q2", Output: "A2"},
			},
			contains: []string{"Examples", "[0]", "[1]", "Q1", "A1", "Q2", "A2"},
		},
		{
			name:     "empty examples",
			examples: Examples{},
			contains: []string{"Examples", "[]"},
		},
		{
			name: "single example",
			examples: Examples{
				{Input: "Single", Output: "Result"},
			},
			contains: []string{"Examples", "[0]", "Single", "Result"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.examples.String()

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("String() = %v, missing substring %v", result, substr)
				}
			}
		})
	}
}

// Helper function to check if an error is a GibsonError
func isGibsonError(err error, target **types.GibsonError) bool {
	if err == nil {
		return false
	}

	gibsonErr, ok := err.(*types.GibsonError)
	if !ok {
		return false
	}

	*target = gibsonErr
	return true
}
