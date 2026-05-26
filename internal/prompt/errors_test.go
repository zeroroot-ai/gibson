package prompt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestPromptManagementErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name:     "prompt not found",
			errFunc:  func() error { return NewPromptNotFoundError("test-prompt") },
			wantCode: ErrCodePromptNotFound,
			wantMsg:  []string{"prompt not found", "test-prompt"},
		},
		{
			name:     "prompt already exists",
			errFunc:  func() error { return NewPromptAlreadyExistsError("existing-prompt") },
			wantCode: ErrCodePromptAlreadyExists,
			wantMsg:  []string{"prompt already exists", "existing-prompt"},
		},
		{
			name:     "invalid prompt",
			errFunc:  func() error { return NewInvalidPromptError("missing required field") },
			wantCode: ErrCodeInvalidPrompt,
			wantMsg:  []string{"invalid prompt", "missing required field"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestTemplateErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name: "template render error",
			errFunc: func() error {
				return NewTemplateRenderError("greeting-template", errors.New("syntax error"))
			},
			wantCode: ErrCodeTemplateRender,
			wantMsg:  []string{"failed to render template", "greeting-template"},
		},
		{
			name:     "missing variable",
			errFunc:  func() error { return NewMissingVariableError("user-prompt", "username") },
			wantCode: ErrCodeMissingVariable,
			wantMsg:  []string{"requires variable", "user-prompt", "username"},
		},
		{
			name: "invalid template",
			errFunc: func() error {
				return NewInvalidTemplateError("bad-template", errors.New("unclosed bracket"))
			},
			wantCode: ErrCodeInvalidTemplate,
			wantMsg:  []string{"invalid template syntax", "bad-template"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestConditionErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name: "condition eval error",
			errFunc: func() error {
				return NewConditionEvalError("user.age > 18", errors.New("undefined variable"))
			},
			wantCode: ErrCodeConditionEval,
			wantMsg:  []string{"failed to evaluate condition", "user.age > 18"},
		},
		{
			name:     "invalid operator",
			errFunc:  func() error { return NewInvalidOperatorError("~=") },
			wantCode: ErrCodeInvalidOperator,
			wantMsg:  []string{"invalid condition operator", "~="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestYAMLErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name: "YAML parse error",
			errFunc: func() error {
				return NewYAMLParseError("/path/to/prompt.yaml", errors.New("invalid YAML"))
			},
			wantCode: ErrCodeYAMLParse,
			wantMsg:  []string{"failed to parse YAML", "/path/to/prompt.yaml"},
		},
		{
			name: "YAML validation error",
			errFunc: func() error {
				return NewYAMLValidationError("/path/to/prompt.yaml", "missing id field")
			},
			wantCode: ErrCodeYAMLValidation,
			wantMsg:  []string{"YAML validation failed", "/path/to/prompt.yaml", "missing id field"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestAssemblyAndRelayErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name: "relay failed error",
			errFunc: func() error {
				return NewRelayFailedError("json-relay", errors.New("invalid JSON"))
			},
			wantCode: ErrCodeRelayFailed,
			wantMsg:  []string{"relay transformation failed", "json-relay"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestExampleValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		errFunc  func() error
		wantCode types.ErrorCode
		wantMsg  []string
	}{
		{
			name:     "invalid example error",
			errFunc:  func() error { return NewInvalidExampleError(0, "missing input field") },
			wantCode: ErrCodeInvalidExample,
			wantMsg:  []string{"invalid example", "index 0", "missing input field"},
		},
		{
			name:     "invalid example at different index",
			errFunc:  func() error { return NewInvalidExampleError(5, "output is empty") },
			wantCode: ErrCodeInvalidExample,
			wantMsg:  []string{"invalid example", "index 5", "output is empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assertGibsonError(t, err, tt.wantCode, tt.wantMsg)
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	tests := []struct {
		name       string
		errFunc    func() error
		causeMsg   string
		shouldWrap bool
	}{
		{
			name: "template render wraps cause",
			errFunc: func() error {
				return NewTemplateRenderError("test", errors.New("template error"))
			},
			causeMsg:   "template error",
			shouldWrap: true,
		},
		{
			name: "invalid template wraps cause",
			errFunc: func() error {
				return NewInvalidTemplateError("test", errors.New("syntax error"))
			},
			causeMsg:   "syntax error",
			shouldWrap: true,
		},
		{
			name: "condition eval wraps cause",
			errFunc: func() error {
				return NewConditionEvalError("test", errors.New("eval error"))
			},
			causeMsg:   "eval error",
			shouldWrap: true,
		},
		{
			name: "YAML parse wraps cause",
			errFunc: func() error {
				return NewYAMLParseError("test.yaml", errors.New("parse error"))
			},
			causeMsg:   "parse error",
			shouldWrap: true,
		},
		{
			name: "relay failed wraps cause",
			errFunc: func() error {
				return NewRelayFailedError("test", errors.New("relay error"))
			},
			causeMsg:   "relay error",
			shouldWrap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()

			var gibsonErr *types.GibsonError
			if !errors.As(err, &gibsonErr) {
				t.Fatalf("expected GibsonError, got %T", err)
			}

			if tt.shouldWrap {
				if gibsonErr.Cause == nil {
					t.Error("expected error to wrap a cause, but Cause is nil")
					return
				}

				// Verify the cause message is preserved
				if !strings.Contains(gibsonErr.Cause.Error(), tt.causeMsg) {
					t.Errorf("expected cause to contain %q, got %q", tt.causeMsg, gibsonErr.Cause.Error())
				}

				// Verify Unwrap() works
				unwrapped := errors.Unwrap(err)
				if unwrapped == nil {
					t.Error("Unwrap() returned nil")
				}
			}
		})
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify all error codes are unique
	codes := map[types.ErrorCode]bool{
		ErrCodePromptNotFound:      true,
		ErrCodePromptAlreadyExists: true,
		ErrCodeInvalidPrompt:       true,
		ErrCodeTemplateRender:      true,
		ErrCodeMissingVariable:     true,
		ErrCodeInvalidTemplate:     true,
		ErrCodeConditionEval:       true,
		ErrCodeInvalidOperator:     true,
		ErrCodeYAMLParse:           true,
		ErrCodeYAMLValidation:      true,
		ErrCodeRelayFailed:         true,
		ErrCodeInvalidExample:      true,
	}

	expectedCount := 12
	if len(codes) != expectedCount {
		t.Errorf("expected %d unique error codes, got %d", expectedCount, len(codes))
	}

	// Verify all error codes have expected prefix or naming convention
	for code := range codes {
		codeStr := string(code)
		if codeStr == "" {
			t.Error("error code cannot be empty")
		}

		// Most codes should be uppercase with underscores
		if !strings.Contains(codeStr, "_") && codeStr != strings.ToUpper(codeStr) {
			t.Errorf("error code %q should follow UPPER_CASE convention", codeStr)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	// Verify error messages are properly formatted
	tests := []struct {
		name    string
		errFunc func() error
	}{
		{
			name:    "prompt not found",
			errFunc: func() error { return NewPromptNotFoundError("test") },
		},
		{
			name:    "missing variable",
			errFunc: func() error { return NewMissingVariableError("prompt", "var") },
		},
		{
			name:    "invalid operator",
			errFunc: func() error { return NewInvalidOperatorError("==") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			msg := err.Error()

			// All error messages should start with [ERROR_CODE]
			if !strings.HasPrefix(msg, "[") {
				t.Errorf("error message should start with '[ERROR_CODE]', got: %s", msg)
			}

			// Error messages should not be empty
			if msg == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

// Helper function to assert GibsonError properties
func assertGibsonError(t *testing.T, err error, wantCode types.ErrorCode, wantMsgSubstrings []string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}

	// Check error code
	if gibsonErr.Code != wantCode {
		t.Errorf("error code = %v, want %v", gibsonErr.Code, wantCode)
	}

	// Check message contains expected substrings
	errMsg := err.Error()
	for _, substr := range wantMsgSubstrings {
		if !strings.Contains(errMsg, substr) {
			t.Errorf("error message %q should contain %q", errMsg, substr)
		}
	}

	// Verify Error() method includes the code
	if !strings.Contains(errMsg, fmt.Sprintf("[%s]", wantCode)) {
		t.Errorf("error message should include code [%s], got: %s", wantCode, errMsg)
	}
}
