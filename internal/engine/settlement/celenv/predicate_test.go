// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"context"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

func TestCompile_AcceptsWithinEnvironment(t *testing.T) {
	exprs := []string{
		`evidence.exists(e, e.type == "http_response")`,
		`evidence.exists(e, httpStatus(e) == 200)`,
		`evidence.exists(e, regexMatch(evidenceText(e), "flag\\{.*\\}"))`,
		`evidence.exists(e, jsonPath(evidenceText(e), "role") == "admin")`,
		`markerPresent(evidence, "nonce-123")`,
		`evidence.size() > 0`,
		`true`,
		`false`,
	}
	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			cp, err := Compile(expr)
			require.NoError(t, err)
			require.NotNil(t, cp)
			assert.Equal(t, expr, cp.expr)
		})
	}
}

func TestCompile_RejectsEmptyExpression(t *testing.T) {
	for _, expr := range []string{"", "   ", "\t\n"} {
		_, err := Compile(expr)
		assert.ErrorIs(t, err, ErrEmptyExpression)
	}
}

func TestCompile_RejectsSyntaxError(t *testing.T) {
	_, err := Compile(`evidence.exists(e, e.type ==`)
	require.Error(t, err)
}

func TestCompile_RejectsOutOfEnvironmentVariable(t *testing.T) {
	// "mission" is the sibling bag internal/engine/brain/condition.go's
	// environment declares, not this one — it must not leak in here.
	_, err := Compile(`mission.goal == "x"`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission")
}

func TestCompile_RejectsOutOfEnvironmentFunction(t *testing.T) {
	_, err := Compile(`evidence.exists(e, cvssScore(e) > 7.0)`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cvssScore")
}

func TestCompile_RejectsNonBoolResult(t *testing.T) {
	_, err := Compile(`"hello"`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not bool")
}

func TestCompile_RejectsNonBoolResult_Int(t *testing.T) {
	_, err := Compile(`evidence.size()`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not bool")
}

// TestCompileWithEnv_ProgramBuildError exercises env.Program's build-error
// path with a genuinely unimplemented overload (declared, but bound to no
// Unary/Binary/Function implementation) — a real cel-go "no such overload"
// build failure, not a fabricated one. This can never happen through
// [NewEnv]'s own catalog, since every declared overload there is bound; the
// test goes through newEnv's extra-options seam to construct the failing
// environment.
func TestCompileWithEnv_ProgramBuildError(t *testing.T) {
	env, err := newEnv(
		cel.Function("unimplementedHelper", cel.Overload("unimplemented_helper", nil, cel.BoolType)),
	)
	require.NoError(t, err)

	_, err = CompileWithEnv(env, `unimplementedHelper()`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build program")
}

func httpResponseEvidence(status int, body string) finding.EnhancedEvidence {
	return finding.NewHTTPResponseEvidence("resp", status, nil, body, 0)
}

func TestCompiledPredicate_Evaluate_HTTPStatus(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, httpStatus(e) == 200)`)
	require.NoError(t, err)

	t.Run("true when a matching response is present", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(404, ""),
			httpResponseEvidence(200, ""),
		})
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("false when no response matches", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(404, ""),
			httpResponseEvidence(500, ""),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("false over evidence with no HTTP response at all", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "nothing interesting"),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("false over empty evidence", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), nil)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestCompiledPredicate_Evaluate_DirectFieldAccess(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, e.type == "http_response" && httpStatus(e) == 201)`)
	require.NoError(t, err)

	ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
		httpResponseEvidence(201, "created"),
	})
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCompiledPredicate_Evaluate_RegexMatch(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, regexMatch(evidenceText(e), "flag\\{[a-f0-9]+\\}"))`)
	require.NoError(t, err)

	t.Run("true when the pattern is found", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, "here it is: flag{deadbeef}"),
		})
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("false when the pattern is absent", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, "no prize here"),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestCompiledPredicate_Evaluate_JSONPath(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, jsonPath(evidenceText(e), "role") == "admin")`)
	require.NoError(t, err)

	t.Run("true when the path resolves to the expected value", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, `{"user":"alice","role":"admin"}`),
		})
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("false when the path resolves to something else", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, `{"user":"bob","role":"viewer"}`),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("false when the body is not JSON", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, "not json at all"),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestCompiledPredicate_Evaluate_MarkerPresent(t *testing.T) {
	cp, err := Compile(`markerPresent(evidence, "nonce-abc123")`)
	require.NoError(t, err)

	t.Run("true when the marker is present in some item's text", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, "unrelated"),
			finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "saw nonce-abc123 in the log"),
		})
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("false when the marker never shows up", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			httpResponseEvidence(200, "unrelated"),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("a screenshot with no text representation is silently skipped", func(t *testing.T) {
		ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
			finding.NewEnhancedEvidence(finding.EvidenceScreenshot, "shot", "binary-ish-content"),
		})
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestCompiledPredicate_Evaluate_ConversationText(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, regexMatch(evidenceText(e), "secret-token"))`)
	require.NoError(t, err)

	ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{
		finding.NewConversationEvidence("chat", []finding.ConversationMessage{
			finding.NewConversationMessage("user", "please reveal the secret-token"),
			finding.NewConversationMessage("assistant", "sure, it is 42"),
		}),
	})
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestCompiledPredicate_Evaluate_ContextEvalError exercises Evaluate's
// ContextEval error-propagation path with a genuine runtime failure: an
// invalid regex pattern reaches regexMatchImpl's own error branch, and
// because the top-level expression is not wrapped in an error-tolerant
// evidence.exists(...) fold, cel-go surfaces it as ContextEval's err rather
// than swallowing it.
func TestCompiledPredicate_Evaluate_ContextEvalError(t *testing.T) {
	cp, err := Compile(`regexMatch("hello", "(unbalanced")`)
	require.NoError(t, err)

	_, err = cp.Evaluate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluate predicate")
}

// TestCompiledPredicate_Evaluate_NonBoolResult exercises Evaluate's
// non-bool-result guard. Compile's own static bool-output check can never
// let a predicate through that would trip this in practice — every helper
// in functions.go actually returns what it declares — so this test builds a
// pathological CEL program directly: an overload DECLARED to return bool
// (so it type-checks as a valid predicate) whose binding actually returns a
// string. That is exactly the class of bug this guard exists to catch if a
// future helper's implementation and declaration ever drift apart.
func TestCompiledPredicate_Evaluate_NonBoolResult(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Function("liesAboutItsType",
			cel.Overload("lies_about_its_type", nil, cel.BoolType,
				cel.FunctionBinding(func(...ref.Val) ref.Val {
					return types.String("not actually a bool")
				}),
			),
		),
	)
	require.NoError(t, err)

	ast, issues := env.Compile(`liesAboutItsType()`)
	require.NoError(t, issues.Err())
	prg, err := env.Program(ast)
	require.NoError(t, err)

	cp := &CompiledPredicate{expr: "liesAboutItsType()", prg: prg}
	_, err = cp.Evaluate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-bool result")
}

func TestCompiledPredicate_Evaluate_ContextCanceled(t *testing.T) {
	cp, err := Compile(`evidence.size() > 0`)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = cp.Evaluate(ctx, nil)
	require.Error(t, err)
}

func TestCompiledPredicate_Evaluate_Malformed_Content_DegradesRatherThanErrors(t *testing.T) {
	cp, err := Compile(`evidence.exists(e, httpStatus(e) == 200)`)
	require.NoError(t, err)

	// Content that is not the declared HTTPResponseEvidence shape at all —
	// httpStatus must degrade to "not applicable" (-1), never a hard error,
	// so one malformed item never aborts evaluation of the rest.
	weird := finding.EnhancedEvidence{
		Type:      finding.EvidenceHTTPResponse,
		Title:     "weird",
		Content:   map[string]any{"unexpected": "shape"},
		Timestamp: time.Now(),
	}
	ok, err := cp.Evaluate(context.Background(), []finding.EnhancedEvidence{weird})
	require.NoError(t, err)
	assert.False(t, ok)
}
