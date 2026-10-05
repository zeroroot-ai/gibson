// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package auditcel is the second CEL environment of the daemon (ADR-0133,
// gibson#765). A compliance mapping rule is a control id and one CEL
// predicate over one audit event. This package compiles and evaluates those
// predicates.
//
// It is a separate package from celenv, the environment of a settlement
// proof, on purpose. Each environment declares one variable: celenv
// declares "evidence", and this package declares "event". Neither package
// imports the other, so a proof predicate cannot read an audit event, and a
// mapping rule cannot read the evidence of a proof.
package auditcel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
)

// EventVariable is the one CEL variable that a mapping rule sees.
const EventVariable = "event"

// EvaluationCostLimit caps the CEL cost of one rule evaluation. It has the
// same value as the limit of the proof environment.
const EvaluationCostLimit uint64 = 50_000

// ErrEmptyExpression is returned for an empty or whitespace-only rule.
var ErrEmptyExpression = errors.New("auditcel: rule expression must not be empty")

// Event is one audit record as a mapping rule sees it. The field names in
// CEL come from the cel tags: event.action, event.resource_type,
// event.resource_id, event.effect, event.actor_id, event.actor_type and
// event.time. A rule that names any other field fails at compile time.
//
// Each field is a permanent part of the rule language: a shipped pack can
// depend on it. Add a field only with a reason, and never remove one.
type Event struct {
	// Action is the action of the record, for example "grant_created".
	Action string `cel:"action"`
	// ResourceType and ResourceID name the resource that the action
	// touched (the target_type and target_id columns of audit_log).
	ResourceType string `cel:"resource_type"`
	ResourceID   string `cel:"resource_id"`
	// Effect is the decision of the record: "allow", "deny", or "" for an
	// event that is not an authorization decision.
	Effect string `cel:"effect"`
	// ActorID and ActorType name who acted. ActorType is "user", "agent"
	// or "system".
	ActorID   string `cel:"actor_id"`
	ActorType string `cel:"actor_type"`
	// Time is when the record was written.
	Time time.Time `cel:"time"`
}

// eventTypeName is the CEL type name of Event, as the native type provider
// derives it from the Go package path and type name.
var eventTypeName = func() string {
	t := reflect.TypeFor[Event]()
	return t.PkgPath()[strings.LastIndex(t.PkgPath(), "/")+1:] + "." + t.Name()
}()

// NewEnv builds the audit event environment. It declares the one variable
// EventVariable, of the native type Event, and nothing else: no helper
// function and no optional extension library.
func NewEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[Event](), ext.ParseStructTags(true)),
		cel.Variable(EventVariable, cel.ObjectType(eventTypeName)),
	)
	if err != nil {
		return nil, fmt.Errorf("auditcel: build environment: %w", err)
	}
	return env, nil
}

// CompiledRule is a mapping rule that compiled and type-checked against the
// audit event environment. It is safe for concurrent Match calls.
type CompiledRule struct {
	expr string
	prg  cel.Program
}

// Compile compiles expr against a new audit event environment. Prefer
// CompileWithEnv when more than one rule is compiled.
func Compile(expr string) (*CompiledRule, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}
	return CompileWithEnv(env, expr)
}

// CompileWithEnv compiles expr against env, which comes from NewEnv. It
// refuses an empty expression, a syntax error, a reference to a variable,
// a field or a function that env does not declare, and an expression whose
// result type is not bool.
func CompileWithEnv(env *cel.Env, expr string) (*CompiledRule, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, ErrEmptyExpression
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("auditcel: compile rule %q: %w", expr, issues.Err())
	}
	if out := ast.OutputType(); !out.IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("auditcel: rule %q evaluates to %s, not bool", expr, out)
	}
	prg, err := env.Program(ast, cel.CostLimit(EvaluationCostLimit))
	if err != nil {
		return nil, fmt.Errorf("auditcel: build program for rule %q: %w", expr, err)
	}
	return &CompiledRule{expr: expr, prg: prg}, nil
}

// Match reports whether the event is evidence for the rule. A runtime error
// is returned, never folded into false, so that the caller can tell "no
// match" from "the rule failed".
func (r *CompiledRule) Match(ctx context.Context, event Event) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("auditcel: evaluate rule %q: %w", r.expr, err)
	}
	out, _, err := r.prg.ContextEval(ctx, map[string]any{EventVariable: event})
	if err != nil {
		return false, fmt.Errorf("auditcel: evaluate rule %q: %w", r.expr, err)
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("auditcel: rule %q produced a non-bool result %s", r.expr, out.Type().TypeName())
	}
	return bool(b), nil
}
