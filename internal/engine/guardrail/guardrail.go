package guardrail

import "context"

// GuardrailType defines the category of guardrail
type GuardrailType string

const (
	GuardrailTypeScope   GuardrailType = "scope"
	GuardrailTypeContent GuardrailType = "content"
	GuardrailTypeRate    GuardrailType = "rate"
	GuardrailTypeTool    GuardrailType = "tool"
	GuardrailTypePII     GuardrailType = "pii"
)

// Guardrail defines the interface for safety checks
type Guardrail interface {
	Name() string
	Type() GuardrailType
	CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error)
	CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error)
}
