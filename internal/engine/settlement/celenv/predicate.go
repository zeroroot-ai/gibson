// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// EvaluationCostLimit caps a single predicate evaluation's CEL cost
// (defense-in-depth on top of ADR-0031 decision 4's inherent safety: CEL is
// non-Turing-complete and terminating on its own). It mirrors
// internal/engine/brain/condition.go's celCostLimit, the repo's other cel-go
// consumer.
const EvaluationCostLimit uint64 = 50_000

// ErrEmptyExpression is returned by Compile and CompileWithEnv for an empty
// or whitespace-only predicate expression.
var ErrEmptyExpression = errors.New("celenv: predicate expression must not be empty")

// CompiledPredicate is a settlement predicate expression already compiled
// and type-checked against the gibson-owned CEL environment ([NewEnv]).
// Build one with [Compile] or [CompileWithEnv]; it is safe for concurrent
// [CompiledPredicate.Evaluate] calls.
type CompiledPredicate struct {
	expr string
	prg  cel.Program
}

// Compile parses, type-checks, and builds an executable program from expr
// against a freshly built gibson-owned CEL environment ([NewEnv]). See
// [CompileWithEnv] for the fail-closed behavior this delegates to, and
// prefer it directly when compiling more than one expression — Compile pays
// NewEnv's declaration cost on every call.
func Compile(expr string) (*CompiledPredicate, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}
	return CompileWithEnv(env, expr)
}

// CompileWithEnv is [Compile] against an already-built environment. It
// fails closed (ADR-0031 decision 2) on:
//   - an empty or whitespace-only expression ([ErrEmptyExpression]);
//   - a syntax error;
//   - a reference to any variable or function env does not declare —
//     cel-go's checker reports this as an "undeclared reference" issue,
//     which CompileWithEnv surfaces as an error rather than a partial or
//     best-effort program;
//   - an expression whose checked result type is not bool — a settlement
//     predicate is a yes/no claim, never a value for something else to
//     interpret further.
//
// env is expected to come from [NewEnv] (or wrap one via cel.Env.Extend);
// CompileWithEnv does not itself re-declare [EvidenceVariable] or the helper
// catalog.
func CompileWithEnv(env *cel.Env, expr string) (*CompiledPredicate, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, ErrEmptyExpression
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("celenv: compile predicate %q: %w", expr, issues.Err())
	}

	if outType := ast.OutputType(); !outType.IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("celenv: predicate %q evaluates to %s, not bool", expr, outType)
	}

	prg, err := env.Program(ast, cel.CostLimit(EvaluationCostLimit))
	if err != nil {
		return nil, fmt.Errorf("celenv: build program for predicate %q: %w", expr, err)
	}

	return &CompiledPredicate{expr: expr, prg: prg}, nil
}

// Evaluate runs the compiled predicate over evidence and returns its
// boolean verdict.
//
// Unlike internal/engine/brain/condition.go's evalCondition (which fails
// closed to false on any error, to keep a mission's control flow
// deterministic even under a malformed condition node), Evaluate surfaces a
// runtime error rather than swallowing it: this is a load/evaluate library
// call, not a step in a replay loop, so the caller (gibson#389's SubmitProof
// handler) decides how to log and report a genuine evaluation failure — a
// cost-limit trip, or a canceled context — rather than settling a bet TRUE
// or FALSE on a silently-produced false.
func (c *CompiledPredicate) Evaluate(ctx context.Context, evidence []finding.EnhancedEvidence) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("celenv: evaluate predicate %q: %w", c.expr, err)
	}

	out, _, err := c.prg.ContextEval(ctx, map[string]any{
		EvidenceVariable: evidenceToCEL(evidence),
	})
	if err != nil {
		return false, fmt.Errorf("celenv: evaluate predicate %q: %w", c.expr, err)
	}

	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("celenv: predicate %q produced a non-bool result %s", c.expr, out.Type().TypeName())
	}
	return bool(b), nil
}
