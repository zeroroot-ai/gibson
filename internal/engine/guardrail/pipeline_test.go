package guardrail

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

// Mock guardrails for testing

// mockAlwaysAllow always returns allow action
type mockAlwaysAllow struct {
	name      string
	callCount int
}

func newMockAlwaysAllow(name string) *mockAlwaysAllow {
	return &mockAlwaysAllow{name: name}
}

func (m *mockAlwaysAllow) Name() string {
	return m.name
}

func (m *mockAlwaysAllow) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockAlwaysAllow) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	m.callCount++
	return NewAllowResult(), nil
}

func (m *mockAlwaysAllow) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	m.callCount++
	return NewAllowResult(), nil
}

// mockAlwaysBlock always returns block action
type mockAlwaysBlock struct {
	name      string
	callCount int
}

func newMockAlwaysBlock(name string) *mockAlwaysBlock {
	return &mockAlwaysBlock{name: name}
}

func (m *mockAlwaysBlock) Name() string {
	return m.name
}

func (m *mockAlwaysBlock) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockAlwaysBlock) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	m.callCount++
	return NewBlockResult("blocked by " + m.name), nil
}

func (m *mockAlwaysBlock) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	m.callCount++
	return NewBlockResult("blocked by " + m.name), nil
}

// mockAlwaysRedact always returns redact action
type mockAlwaysRedact struct {
	name      string
	suffix    string
	callCount int
}

func newMockAlwaysRedact(name, suffix string) *mockAlwaysRedact {
	return &mockAlwaysRedact{name: name, suffix: suffix}
}

func (m *mockAlwaysRedact) Name() string {
	return m.name
}

func (m *mockAlwaysRedact) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockAlwaysRedact) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	m.callCount++
	return NewRedactResult("redacted by "+m.name, input.Content+m.suffix), nil
}

func (m *mockAlwaysRedact) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	m.callCount++
	return NewRedactResult("redacted by "+m.name, output.Content+m.suffix), nil
}

// mockAlwaysWarn always returns warn action
type mockAlwaysWarn struct {
	name      string
	callCount int
}

func newMockAlwaysWarn(name string) *mockAlwaysWarn {
	return &mockAlwaysWarn{name: name}
}

func (m *mockAlwaysWarn) Name() string {
	return m.name
}

func (m *mockAlwaysWarn) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockAlwaysWarn) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	m.callCount++
	return NewWarnResult("warning from " + m.name), nil
}

func (m *mockAlwaysWarn) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	m.callCount++
	return NewWarnResult("warning from " + m.name), nil
}

// mockConditional blocks on specific content
type mockConditional struct {
	name        string
	blockString string
	callCount   int
}

func newMockConditional(name, blockString string) *mockConditional {
	return &mockConditional{name: name, blockString: blockString}
}

func (m *mockConditional) Name() string {
	return m.name
}

func (m *mockConditional) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockConditional) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	m.callCount++
	if strings.Contains(input.Content, m.blockString) {
		return NewBlockResult("content contains forbidden string: " + m.blockString), nil
	}
	return NewAllowResult(), nil
}

func (m *mockConditional) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	m.callCount++
	if strings.Contains(output.Content, m.blockString) {
		return NewBlockResult("content contains forbidden string: " + m.blockString), nil
	}
	return NewAllowResult(), nil
}

// mockErrorGuardrail returns an error
type mockErrorGuardrail struct {
	name string
	err  error
}

func newMockErrorGuardrail(name string, err error) *mockErrorGuardrail {
	return &mockErrorGuardrail{name: name, err: err}
}

func (m *mockErrorGuardrail) Name() string {
	return m.name
}

func (m *mockErrorGuardrail) Type() GuardrailType {
	return GuardrailTypeContent
}

func (m *mockErrorGuardrail) CheckInput(ctx context.Context, input GuardrailInput) (GuardrailResult, error) {
	return GuardrailResult{}, m.err
}

func (m *mockErrorGuardrail) CheckOutput(ctx context.Context, output GuardrailOutput) (GuardrailResult, error) {
	return GuardrailResult{}, m.err
}

// Tests

func TestNewGuardrailPipeline(t *testing.T) {
	t.Run("empty pipeline", func(t *testing.T) {
		pipeline := NewGuardrailPipeline()
		assert.NotNil(t, pipeline)
		assert.Empty(t, pipeline.Guardrails())
		assert.NotNil(t, pipeline.logger)
	})

	t.Run("pipeline with guardrails", func(t *testing.T) {
		g1 := newMockAlwaysAllow("g1")
		g2 := newMockAlwaysAllow("g2")
		pipeline := NewGuardrailPipeline(g1, g2)
		assert.Len(t, pipeline.Guardrails(), 2)
	})
}

func TestGuardrailPipeline_WithTracer(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	pipeline := NewGuardrailPipeline().WithTracer(tracer)
	assert.NotNil(t, pipeline.tracer)
}

func TestGuardrailPipeline_WithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	pipeline := NewGuardrailPipeline().WithLogger(logger)
	assert.NotNil(t, pipeline.logger)
}

func TestGuardrailPipeline_ProcessInput_EmptyPipeline(t *testing.T) {
	pipeline := NewGuardrailPipeline()
	input := GuardrailInput{Content: "test content"}

	result, err := pipeline.ProcessInput(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, input.Content, result.Content)
}

func TestGuardrailPipeline_ProcessOutput_EmptyPipeline(t *testing.T) {
	pipeline := NewGuardrailPipeline()
	output := GuardrailOutput{Content: "test content"}

	result, err := pipeline.ProcessOutput(context.Background(), output)
	require.NoError(t, err)
	assert.Equal(t, output.Content, result.Content)
}

func TestGuardrailPipeline_ProcessInput_SingleGuardrail(t *testing.T) {
	tests := []struct {
		name        string
		guardrail   Guardrail
		wantErr     bool
		errType     error
		checkResult func(t *testing.T, input GuardrailInput)
	}{
		{
			name:      "allow",
			guardrail: newMockAlwaysAllow("allow"),
			wantErr:   false,
			checkResult: func(t *testing.T, input GuardrailInput) {
				assert.Equal(t, "test", input.Content)
			},
		},
		{
			name:      "block",
			guardrail: newMockAlwaysBlock("block"),
			wantErr:   true,
			errType:   &GuardrailBlockedError{},
			checkResult: func(t *testing.T, input GuardrailInput) {
				assert.Equal(t, "test", input.Content)
			},
		},
		{
			name:      "redact",
			guardrail: newMockAlwaysRedact("redact", "[REDACTED]"),
			wantErr:   false,
			checkResult: func(t *testing.T, input GuardrailInput) {
				assert.Equal(t, "test[REDACTED]", input.Content)
			},
		},
		{
			name:      "warn",
			guardrail: newMockAlwaysWarn("warn"),
			wantErr:   false,
			checkResult: func(t *testing.T, input GuardrailInput) {
				assert.Equal(t, "test", input.Content)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := NewGuardrailPipeline(tt.guardrail)
			input := GuardrailInput{Content: "test"}

			result, err := pipeline.ProcessInput(context.Background(), input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorAs(t, err, &tt.errType)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestGuardrailPipeline_ProcessOutput_SingleGuardrail(t *testing.T) {
	tests := []struct {
		name        string
		guardrail   Guardrail
		wantErr     bool
		errType     error
		checkResult func(t *testing.T, output GuardrailOutput)
	}{
		{
			name:      "allow",
			guardrail: newMockAlwaysAllow("allow"),
			wantErr:   false,
			checkResult: func(t *testing.T, output GuardrailOutput) {
				assert.Equal(t, "test", output.Content)
			},
		},
		{
			name:      "block",
			guardrail: newMockAlwaysBlock("block"),
			wantErr:   true,
			errType:   &GuardrailBlockedError{},
			checkResult: func(t *testing.T, output GuardrailOutput) {
				assert.Equal(t, "test", output.Content)
			},
		},
		{
			name:      "redact",
			guardrail: newMockAlwaysRedact("redact", "[REDACTED]"),
			wantErr:   false,
			checkResult: func(t *testing.T, output GuardrailOutput) {
				assert.Equal(t, "test[REDACTED]", output.Content)
			},
		},
		{
			name:      "warn",
			guardrail: newMockAlwaysWarn("warn"),
			wantErr:   false,
			checkResult: func(t *testing.T, output GuardrailOutput) {
				assert.Equal(t, "test", output.Content)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := NewGuardrailPipeline(tt.guardrail)
			output := GuardrailOutput{Content: "test"}

			result, err := pipeline.ProcessOutput(context.Background(), output)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorAs(t, err, &tt.errType)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestGuardrailPipeline_ProcessInput_MultipleGuardrails(t *testing.T) {
	t.Run("all allow", func(t *testing.T) {
		g1 := newMockAlwaysAllow("g1")
		g2 := newMockAlwaysAllow("g2")
		g3 := newMockAlwaysAllow("g3")

		pipeline := NewGuardrailPipeline(g1, g2, g3)
		input := GuardrailInput{Content: "test"}

		result, err := pipeline.ProcessInput(context.Background(), input)
		require.NoError(t, err)
		assert.Equal(t, "test", result.Content)
		assert.Equal(t, 1, g1.callCount)
		assert.Equal(t, 1, g2.callCount)
		assert.Equal(t, 1, g3.callCount)
	})

	t.Run("mixed allow and warn", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		g1 := newMockAlwaysAllow("g1")
		g2 := newMockAlwaysWarn("g2")
		g3 := newMockAlwaysAllow("g3")

		pipeline := NewGuardrailPipeline(g1, g2, g3).WithLogger(logger)
		input := GuardrailInput{Content: "test"}

		result, err := pipeline.ProcessInput(context.Background(), input)
		require.NoError(t, err)
		assert.Equal(t, "test", result.Content)

		// Check that warning was logged
		logs := buf.String()
		assert.Contains(t, logs, "guardrail warning")
		assert.Contains(t, logs, "g2")
	})
}

func TestGuardrailPipeline_ProcessInput_ShortCircuitOnBlock(t *testing.T) {
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockAlwaysBlock("g2")
	g3 := newMockAlwaysAllow("g3") // Should not be called

	pipeline := NewGuardrailPipeline(g1, g2, g3)
	input := GuardrailInput{Content: "test"}

	result, err := pipeline.ProcessInput(context.Background(), input)
	require.Error(t, err)

	var blockedErr *GuardrailBlockedError
	require.ErrorAs(t, err, &blockedErr)
	assert.Equal(t, "g2", blockedErr.GuardrailName)
	assert.Contains(t, blockedErr.Reason, "blocked by g2")

	// Verify g1 and g2 were called, but not g3
	assert.Equal(t, 1, g1.callCount)
	assert.Equal(t, 1, g2.callCount)
	assert.Equal(t, 0, g3.callCount, "g3 should not be called after g2 blocks")

	// Content should remain unchanged
	assert.Equal(t, "test", result.Content)
}

func TestGuardrailPipeline_ProcessOutput_ShortCircuitOnBlock(t *testing.T) {
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockAlwaysBlock("g2")
	g3 := newMockAlwaysAllow("g3") // Should not be called

	pipeline := NewGuardrailPipeline(g1, g2, g3)
	output := GuardrailOutput{Content: "test"}

	_, err := pipeline.ProcessOutput(context.Background(), output)
	require.Error(t, err)

	var blockedErr *GuardrailBlockedError
	require.ErrorAs(t, err, &blockedErr)
	assert.Equal(t, "g2", blockedErr.GuardrailName)

	// Verify g3 was not called
	assert.Equal(t, 0, g3.callCount, "g3 should not be called after g2 blocks")
}

func TestGuardrailPipeline_ProcessInput_RedactionAccumulation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	g1 := newMockAlwaysRedact("g1", "[R1]")
	g2 := newMockAlwaysRedact("g2", "[R2]")
	g3 := newMockAlwaysRedact("g3", "[R3]")

	pipeline := NewGuardrailPipeline(g1, g2, g3).WithLogger(logger)
	input := GuardrailInput{Content: "test"}

	result, err := pipeline.ProcessInput(context.Background(), input)
	require.NoError(t, err)

	// Content should be accumulated through all redactions
	assert.Equal(t, "test[R1][R2][R3]", result.Content)

	// Verify all guardrails were called
	assert.Equal(t, 1, g1.callCount)
	assert.Equal(t, 1, g2.callCount)
	assert.Equal(t, 1, g3.callCount)

	// Check that redactions were logged
	logs := buf.String()
	assert.Contains(t, logs, "guardrail redacted content")
	assert.Contains(t, logs, "g1")
	assert.Contains(t, logs, "g2")
	assert.Contains(t, logs, "g3")
}

func TestGuardrailPipeline_ProcessOutput_RedactionAccumulation(t *testing.T) {
	g1 := newMockAlwaysRedact("g1", "[R1]")
	g2 := newMockAlwaysRedact("g2", "[R2]")
	g3 := newMockAlwaysRedact("g3", "[R3]")

	pipeline := NewGuardrailPipeline(g1, g2, g3)
	output := GuardrailOutput{Content: "test"}

	result, err := pipeline.ProcessOutput(context.Background(), output)
	require.NoError(t, err)

	// Content should be accumulated through all redactions
	assert.Equal(t, "test[R1][R2][R3]", result.Content)
}

func TestGuardrailPipeline_ProcessInput_ConditionalBlocking(t *testing.T) {
	g1 := newMockConditional("g1", "forbidden")
	g2 := newMockAlwaysAllow("g2")

	pipeline := NewGuardrailPipeline(g1, g2)

	t.Run("allowed content", func(t *testing.T) {
		input := GuardrailInput{Content: "safe content"}
		result, err := pipeline.ProcessInput(context.Background(), input)
		require.NoError(t, err)
		assert.Equal(t, "safe content", result.Content)
	})

	t.Run("blocked content", func(t *testing.T) {
		input := GuardrailInput{Content: "this contains forbidden word"}
		result, err := pipeline.ProcessInput(context.Background(), input)
		require.Error(t, err)

		var blockedErr *GuardrailBlockedError
		require.ErrorAs(t, err, &blockedErr)
		assert.Contains(t, blockedErr.Reason, "forbidden")
		assert.Equal(t, "this contains forbidden word", result.Content)
	})
}

func TestGuardrailPipeline_ProcessInput_ContextCancellation(t *testing.T) {
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	g := newMockAlwaysAllow("g1")
	pipeline := NewGuardrailPipeline(g)
	input := GuardrailInput{Content: "test"}

	// The guardrail should still execute since we don't check context in mocks
	// In real implementations, guardrails should respect context cancellation
	_, err := pipeline.ProcessInput(ctx, input)

	// Current implementation doesn't fail on cancelled context in mock
	// This test demonstrates the pattern for context-aware implementations
	require.NoError(t, err)
}

func TestGuardrailPipeline_ProcessInput_ErrorPropagation(t *testing.T) {
	expectedErr := errors.New("guardrail internal error")
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockErrorGuardrail("g2", expectedErr)
	g3 := newMockAlwaysAllow("g3") // Should not be called

	pipeline := NewGuardrailPipeline(g1, g2, g3)
	input := GuardrailInput{Content: "test"}

	_, err := pipeline.ProcessInput(context.Background(), input)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestGuardrailPipeline_ProcessOutput_ErrorPropagation(t *testing.T) {
	expectedErr := errors.New("guardrail internal error")
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockErrorGuardrail("g2", expectedErr)

	pipeline := NewGuardrailPipeline(g1, g2)
	output := GuardrailOutput{Content: "test"}

	_, err := pipeline.ProcessOutput(context.Background(), output)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestGuardrailPipeline_Add(t *testing.T) {
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockAlwaysAllow("g2")
	g3 := newMockAlwaysAllow("g3")
	g4 := newMockAlwaysAllow("g4")

	pipeline1 := NewGuardrailPipeline(g1, g2)
	pipeline2 := pipeline1.Add(g3, g4)

	// Original pipeline should be unchanged
	assert.Len(t, pipeline1.Guardrails(), 2)
	// New pipeline should have all guardrails
	assert.Len(t, pipeline2.Guardrails(), 4)

	// Verify order is preserved
	guardrails := pipeline2.Guardrails()
	assert.Equal(t, "g1", guardrails[0].Name())
	assert.Equal(t, "g2", guardrails[1].Name())
	assert.Equal(t, "g3", guardrails[2].Name())
	assert.Equal(t, "g4", guardrails[3].Name())

	// Tracer and logger should be copied
	tracer := noop.NewTracerProvider().Tracer("test")
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	pipeline3 := NewGuardrailPipeline(g1).WithTracer(tracer).WithLogger(logger)
	pipeline4 := pipeline3.Add(g2)

	assert.NotNil(t, pipeline4.tracer)
	assert.NotNil(t, pipeline4.logger)
}

func TestGuardrailPipeline_Guardrails_ReturnsCopy(t *testing.T) {
	g1 := newMockAlwaysAllow("g1")
	g2 := newMockAlwaysAllow("g2")

	pipeline := NewGuardrailPipeline(g1, g2)
	guardrails := pipeline.Guardrails()

	// Modify the returned slice
	guardrails[0] = newMockAlwaysAllow("modified")

	// Original pipeline should be unchanged
	originalGuardrails := pipeline.Guardrails()
	assert.Equal(t, "g1", originalGuardrails[0].Name())
}

func TestGuardrailPipeline_WithTracer_Integration(t *testing.T) {
	// Use noop tracer for testing
	tracer := noop.NewTracerProvider().Tracer("test")

	g1 := newMockAlwaysAllow("g1")
	g2 := newMockAlwaysRedact("g2", "[REDACTED]")

	pipeline := NewGuardrailPipeline(g1, g2).WithTracer(tracer)
	input := GuardrailInput{Content: "test"}

	result, err := pipeline.ProcessInput(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "test[REDACTED]", result.Content)
}

func TestGuardrailPipeline_ComplexScenario(t *testing.T) {
	t.Run("safe content passes through with redactions", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		g1 := newMockAlwaysAllow("initial-allow")
		g2 := newMockAlwaysRedact("pii-redact", "[PII-REDACTED]")
		g3 := newMockAlwaysWarn("suspicious-warn")
		g4 := newMockConditional("forbidden-block", "forbidden")
		g5 := newMockAlwaysRedact("final-redact", "[FINAL]")

		pipeline := NewGuardrailPipeline(g1, g2, g3, g4, g5).WithLogger(logger)

		input := GuardrailInput{Content: "safe content"}
		result, err := pipeline.ProcessInput(context.Background(), input)
		require.NoError(t, err)
		assert.Equal(t, "safe content[PII-REDACTED][FINAL]", result.Content)

		logs := buf.String()
		assert.Contains(t, logs, "guardrail redacted content")
		assert.Contains(t, logs, "guardrail warning")
	})

	t.Run("forbidden content is blocked", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		g1 := newMockAlwaysAllow("initial-allow")
		g2 := newMockAlwaysRedact("pii-redact", "[PII-REDACTED]")
		g3 := newMockAlwaysWarn("suspicious-warn")
		g4 := newMockConditional("forbidden-block", "forbidden")
		g5 := newMockAlwaysRedact("final-redact", "[FINAL]")

		pipeline := NewGuardrailPipeline(g1, g2, g3, g4, g5).WithLogger(logger)

		input := GuardrailInput{Content: "this is forbidden"}
		result, err := pipeline.ProcessInput(context.Background(), input)
		require.Error(t, err)

		var blockedErr *GuardrailBlockedError
		require.ErrorAs(t, err, &blockedErr)
		assert.Equal(t, "forbidden-block", blockedErr.GuardrailName)

		// Content should have been redacted by g2 before blocking
		assert.Equal(t, "this is forbidden[PII-REDACTED]", result.Content)

		// g5 should not have been called
		assert.Equal(t, 0, g5.callCount)
	})
}
