package prompt

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Prompt error codes follow the Gibson error pattern
const (
	// Prompt management errors
	ErrCodePromptNotFound      types.ErrorCode = "PROMPT_NOT_FOUND"
	ErrCodePromptAlreadyExists types.ErrorCode = "PROMPT_ALREADY_EXISTS"
	ErrCodeInvalidPrompt       types.ErrorCode = "INVALID_PROMPT"

	// Template errors
	ErrCodeTemplateRender  types.ErrorCode = "TEMPLATE_RENDER_FAILED"
	ErrCodeMissingVariable types.ErrorCode = "MISSING_REQUIRED_VARIABLE"
	ErrCodeInvalidTemplate types.ErrorCode = "INVALID_TEMPLATE_SYNTAX"

	// Condition errors
	ErrCodeConditionEval   types.ErrorCode = "CONDITION_EVAL_FAILED"
	ErrCodeInvalidOperator types.ErrorCode = "INVALID_CONDITION_OPERATOR"

	// YAML errors
	ErrCodeYAMLParse      types.ErrorCode = "YAML_PARSE_FAILED"
	ErrCodeYAMLValidation types.ErrorCode = "YAML_VALIDATION_FAILED"

	// Assembly and relay errors
	ErrCodeRelayFailed types.ErrorCode = "RELAY_TRANSFORM_FAILED"

	// Example validation errors
	ErrCodeInvalidExample types.ErrorCode = "INVALID_EXAMPLE"
)

// Prompt management error helpers

// NewPromptNotFoundError creates an error for when a prompt is not found
func NewPromptNotFoundError(id string) error {
	return types.NewError(ErrCodePromptNotFound, fmt.Sprintf("prompt not found: %s", id))
}

// NewPromptAlreadyExistsError creates an error for when a prompt already exists
func NewPromptAlreadyExistsError(id string) error {
	return types.NewError(ErrCodePromptAlreadyExists, fmt.Sprintf("prompt already exists: %s", id))
}

// NewInvalidPromptError creates an error for invalid prompt definitions
func NewInvalidPromptError(reason string) error {
	return types.NewError(ErrCodeInvalidPrompt, fmt.Sprintf("invalid prompt: %s", reason))
}

// Template error helpers

// NewTemplateRenderError creates an error for template rendering failures
func NewTemplateRenderError(templateID string, cause error) error {
	return types.WrapError(
		ErrCodeTemplateRender,
		fmt.Sprintf("failed to render template '%s'", templateID),
		cause,
	)
}

// NewMissingVariableError creates an error for missing required template variables
func NewMissingVariableError(promptID, varName string) error {
	return types.NewError(
		ErrCodeMissingVariable,
		fmt.Sprintf("prompt '%s' requires variable '%s'", promptID, varName),
	)
}

// NewInvalidTemplateError creates an error for invalid template syntax
func NewInvalidTemplateError(templateID string, cause error) error {
	return types.WrapError(
		ErrCodeInvalidTemplate,
		fmt.Sprintf("invalid template syntax in '%s'", templateID),
		cause,
	)
}

// Condition error helpers

// NewConditionEvalError creates an error for condition evaluation failures
func NewConditionEvalError(condition string, cause error) error {
	return types.WrapError(
		ErrCodeConditionEval,
		fmt.Sprintf("failed to evaluate condition: %s", condition),
		cause,
	)
}

// NewInvalidOperatorError creates an error for invalid condition operators
func NewInvalidOperatorError(operator string) error {
	return types.NewError(
		ErrCodeInvalidOperator,
		fmt.Sprintf("invalid condition operator: %s", operator),
	)
}

// YAML error helpers

// NewYAMLParseError creates an error for YAML parsing failures
func NewYAMLParseError(filePath string, cause error) error {
	return types.WrapError(
		ErrCodeYAMLParse,
		fmt.Sprintf("failed to parse YAML file: %s", filePath),
		cause,
	)
}

// NewYAMLValidationError creates an error for YAML validation failures
func NewYAMLValidationError(filePath, reason string) error {
	return types.NewError(
		ErrCodeYAMLValidation,
		fmt.Sprintf("YAML validation failed for %s: %s", filePath, reason),
	)
}

// Assembly and relay error helpers

// NewRelayFailedError creates an error for relay transformation failures
func NewRelayFailedError(relayName string, cause error) error {
	return types.WrapError(
		ErrCodeRelayFailed,
		fmt.Sprintf("relay transformation failed: %s", relayName),
		cause,
	)
}

// Example validation error helpers

// NewInvalidExampleError creates an error for invalid few-shot examples
func NewInvalidExampleError(index int, reason string) error {
	return types.NewError(
		ErrCodeInvalidExample,
		fmt.Sprintf("invalid example at index %d: %s", index, reason),
	)
}
