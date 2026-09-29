// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

// EvidenceVariable is the one CEL variable a settlement predicate sees: the
// recorded []finding.EnhancedEvidence for a bet's demonstration, in capture
// order.
const EvidenceVariable = "evidence"

// EvidenceMapType is the CEL type of one evidence item: a string-keyed map
// whose values are dyn, carrying exactly finding.EnhancedEvidence's own
// shape — "type", "title", "content", "timestamp" (see evidenceItemMap in
// evidence.go). Field access is plain CEL map dot-access (e.type, e.title),
// the same pattern internal/engine/brain/condition.go already uses for its
// "nodes" and "mission" bags — never a generated message type. "content" is
// carried as-is (JSON-normalized) for a predicate that wants to reach in
// directly, but the curated, type-safe way to read it is the helper catalog
// in functions.go: those helpers never error on an evidence item their
// operation does not apply to, so a mixed-type evidence set never trips a
// "no such key" runtime error partway through an evidence.exists(...) scan.
var EvidenceMapType = cel.MapType(cel.StringType, cel.DynType)

// EvidenceListType is the CEL type of the "evidence" variable itself.
var EvidenceListType = cel.ListType(EvidenceMapType)

// NewEnv builds the gibson-owned CEL environment a settlement predicate
// compiles and evaluates against (ADR-0031 decision 2). It declares exactly
// one variable, [EvidenceVariable], and the curated helper-function catalog
// in functions.go — nothing else. Nothing here enables cel-go's optional
// extension libraries (strings, lists, encoders, …): the environment is
// deliberately the smallest surface that can express the evidence schema
// and its curated helpers, because every addition to it is a permanent,
// version-controlled commitment (ADR-0031 decision 3) that a shipped pack
// may come to depend on.
//
// NewEnv builds a fresh *cel.Env on every call. A caller compiling more than
// one expression against the same environment (e.g. [LoadDomainPack])
// should build it once with NewEnv and reuse it via [CompileWithEnv] — a
// cel.Env is safe for concurrent Compile and Program calls.
func NewEnv() (*cel.Env, error) {
	opts := []cel.EnvOption{cel.Variable(EvidenceVariable, EvidenceListType)}
	opts = append(opts, helperFunctionOptions()...)

	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("celenv: build environment: %w", err)
	}
	return env, nil
}
