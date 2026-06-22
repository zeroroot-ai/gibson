package guardrail

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GuardrailPipeline executes a sequence of guardrails on input and output
type GuardrailPipeline struct {
	guardrails []Guardrail
	tracer     trace.Tracer
	logger     *slog.Logger
}

// NewGuardrailPipeline creates a new pipeline with the given guardrails
func NewGuardrailPipeline(guardrails ...Guardrail) *GuardrailPipeline {
	return &GuardrailPipeline{
		guardrails: guardrails,
		logger:     slog.Default(),
	}
}

// WithTracer sets the OpenTelemetry tracer for the pipeline
func (p *GuardrailPipeline) WithTracer(tracer trace.Tracer) *GuardrailPipeline {
	p.tracer = tracer
	return p
}

// WithLogger sets the logger for the pipeline
func (p *GuardrailPipeline) WithLogger(logger *slog.Logger) *GuardrailPipeline {
	p.logger = logger
	return p
}

// ProcessInput runs all guardrails on input sequentially
// - On block: immediately return GuardrailBlockedError
// - On redact: update input.Content with ModifiedContent for next guardrail
// - On warn: log warning and continue
// - On allow: continue to next guardrail
func (p *GuardrailPipeline) ProcessInput(ctx context.Context, input GuardrailInput) (GuardrailInput, error) {
	// Empty pipeline - pass through
	if len(p.guardrails) == 0 {
		return input, nil
	}

	// Process each guardrail in sequence
	currentInput := input
	for _, guardrail := range p.guardrails {
		// Create span if tracer is available
		var span trace.Span
		if p.tracer != nil {
			ctx, span = p.tracer.Start(ctx, "guardrail.check_input",
				trace.WithAttributes(
					attribute.String("guardrail.name", guardrail.Name()),
					attribute.String("guardrail.type", string(guardrail.Type())),
				),
			)
		}

		// Check the input
		result, err := guardrail.CheckInput(ctx, currentInput)
		if span != nil {
			span.SetAttributes(
				attribute.String("guardrail.action", string(result.Action)),
				attribute.String("guardrail.reason", result.Reason),
			)
			span.End()
		}

		if err != nil {
			return currentInput, err
		}

		// Handle the result based on action
		switch result.Action {
		case GuardrailActionBlock:
			// Short-circuit on block
			return currentInput, NewGuardrailBlockedError(
				guardrail.Name(),
				guardrail.Type(),
				result.Reason,
			)

		case GuardrailActionRedact:
			// Update content for next guardrail
			if result.ModifiedContent != "" {
				currentInput.Content = result.ModifiedContent
			}
			p.logger.InfoContext(ctx, "guardrail redacted content",
				"guardrail", guardrail.Name(),
				"reason", result.Reason,
			)

		case GuardrailActionWarn:
			// Log warning and continue
			p.logger.WarnContext(ctx, "guardrail warning",
				"guardrail", guardrail.Name(),
				"reason", result.Reason,
			)

		case GuardrailActionAllow:
			// Continue to next guardrail
			continue
		}
	}

	return currentInput, nil
}

// ProcessOutput runs all guardrails on output sequentially
// - On block: immediately return GuardrailBlockedError
// - On redact: update output.Content with ModifiedContent for next guardrail
// - On warn: log warning and continue
// - On allow: continue to next guardrail
func (p *GuardrailPipeline) ProcessOutput(ctx context.Context, output GuardrailOutput) (GuardrailOutput, error) {
	// Empty pipeline - pass through
	if len(p.guardrails) == 0 {
		return output, nil
	}

	// Process each guardrail in sequence
	currentOutput := output
	for _, guardrail := range p.guardrails {
		// Create span if tracer is available
		var span trace.Span
		if p.tracer != nil {
			ctx, span = p.tracer.Start(ctx, "guardrail.check_output",
				trace.WithAttributes(
					attribute.String("guardrail.name", guardrail.Name()),
					attribute.String("guardrail.type", string(guardrail.Type())),
				),
			)
		}

		// Check the output
		result, err := guardrail.CheckOutput(ctx, currentOutput)
		if span != nil {
			span.SetAttributes(
				attribute.String("guardrail.action", string(result.Action)),
				attribute.String("guardrail.reason", result.Reason),
			)
			span.End()
		}

		if err != nil {
			return currentOutput, err
		}

		// Handle the result based on action
		switch result.Action {
		case GuardrailActionBlock:
			// Short-circuit on block
			return currentOutput, NewGuardrailBlockedError(
				guardrail.Name(),
				guardrail.Type(),
				result.Reason,
			)

		case GuardrailActionRedact:
			// Update content for next guardrail
			if result.ModifiedContent != "" {
				currentOutput.Content = result.ModifiedContent
			}
			p.logger.InfoContext(ctx, "guardrail redacted content",
				"guardrail", guardrail.Name(),
				"reason", result.Reason,
			)

		case GuardrailActionWarn:
			// Log warning and continue
			p.logger.WarnContext(ctx, "guardrail warning",
				"guardrail", guardrail.Name(),
				"reason", result.Reason,
			)

		case GuardrailActionAllow:
			// Continue to next guardrail
			continue
		}
	}

	return currentOutput, nil
}

// Add returns a new pipeline with additional guardrails
func (p *GuardrailPipeline) Add(guardrails ...Guardrail) *GuardrailPipeline {
	newGuardrails := make([]Guardrail, len(p.guardrails)+len(guardrails))
	copy(newGuardrails, p.guardrails)
	copy(newGuardrails[len(p.guardrails):], guardrails)

	return &GuardrailPipeline{
		guardrails: newGuardrails,
		tracer:     p.tracer,
		logger:     p.logger,
	}
}

// Guardrails returns the list of guardrails in the pipeline
func (p *GuardrailPipeline) Guardrails() []Guardrail {
	// Return a copy to prevent external modification
	result := make([]Guardrail, len(p.guardrails))
	copy(result, p.guardrails)
	return result
}
