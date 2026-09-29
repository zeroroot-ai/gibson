// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"fmt"
	"math"
	"slices"
	"sort"

	"gonum.org/v1/gonum/floats"
)

// CPDToFactor builds a Factor from an artifact CPD table, mirroring
// infer.cpd_to_factor exactly.
//
// The on-disk layout is pgmpy's TabularCPD layout, kept unchanged so
// existing model artifacts (sidecar/belief/models/*.json) load byte-for-byte
// as they did: values is a 2 x prod(parentCards) matrix whose columns
// enumerate the parent assignments in the declared parent order, LAST
// PARENT VARYING FASTEST. That is exactly this package's own flat-table
// convention (Factor's doc comment) with variable as axis 0 and parents
// following in order, so no transpose is needed: the two rows of values,
// concatenated, ARE the flat table.
func CPDToFactor(variable string, values [][]float64, parents []string, parentCards []int) (Factor, error) {
	cards := parentCards
	if len(cards) == 0 {
		cards = make([]int, len(parents))
		for i := range cards {
			cards[i] = len(States)
		}
	}
	cols := 1
	for _, c := range cards {
		cols *= c
	}
	if len(values) != len(States) {
		return Factor{}, fmt.Errorf(
			"beliefvi: cpd for %q has %d row(s), expected %d", variable, len(values), len(States),
		)
	}
	for _, row := range values {
		if len(row) != cols {
			return Factor{}, fmt.Errorf(
				"beliefvi: cpd for %q has shape (%d, %d), expected (%d, %d)",
				variable, len(values), len(row), len(States), cols,
			)
		}
	}
	// Only binary parent cardinalities are representable by this package's
	// flat bit-packed table (see Factor's doc comment) — every artifact this
	// codebase ships declares evidence_card as all-2s (States has exactly
	// two members everywhere), so this is not a new restriction, just an
	// explicit check of the one infer.py's reshape([len(STATES), *cards])
	// left implicit.
	for i, c := range cards {
		if c != len(States) {
			return Factor{}, fmt.Errorf(
				"beliefvi: cpd for %q: parent %q has cardinality %d, only binary (%d) parents are supported",
				variable, parents[i], c, len(States),
			)
		}
	}

	table := make([]float64, 0, len(States)*cols)
	for _, row := range values {
		table = append(table, row...)
	}
	variables := make([]string, 0, 1+len(parents))
	variables = append(variables, variable)
	variables = append(variables, parents...)
	return NewFactor(variables, table)
}

// eliminationOrder returns a deterministic min-degree elimination order over
// every variable in factors that is not in keep, mirroring
// infer._elimination_order exactly: min-degree keeps intermediate factors
// small, and ties break on the order the variable was first seen scanning
// factors in order — a pure function of factors' own order, so the same
// factor set (in the same order) always elects the same order. Any order
// gives the same ANSWER (variable elimination is exact); this one only
// bounds the cost.
func eliminationOrder(factors []Factor, keep map[string]struct{}) []string {
	var seen []string
	seenSet := make(map[string]struct{})
	for _, f := range factors {
		for _, v := range f.Variables {
			if _, ok := seenSet[v]; !ok {
				seenSet[v] = struct{}{}
				seen = append(seen, v)
			}
		}
	}
	position := make(map[string]int, len(seen))
	for i, v := range seen {
		position[v] = i
	}

	scopes := make([]map[string]struct{}, len(factors))
	for i, f := range factors {
		s := make(map[string]struct{}, len(f.Variables))
		for _, v := range f.Variables {
			s[v] = struct{}{}
		}
		scopes[i] = s
	}

	var remaining []string
	for _, v := range seen {
		if _, ok := keep[v]; !ok {
			remaining = append(remaining, v)
		}
	}

	var order []string
	for len(remaining) > 0 {
		degree := make(map[string]int, len(remaining))
		for _, v := range remaining {
			neighbours := make(map[string]struct{})
			for _, scope := range scopes {
				if _, ok := scope[v]; ok {
					for n := range scope {
						neighbours[n] = struct{}{}
					}
				}
			}
			delete(neighbours, v)
			degree[v] = len(neighbours)
		}
		sort.Slice(remaining, func(i, j int) bool {
			vi, vj := remaining[i], remaining[j]
			if degree[vi] != degree[vj] {
				return degree[vi] < degree[vj]
			}
			return position[vi] < position[vj]
		})
		next := remaining[0]
		remaining = remaining[1:]
		order = append(order, next)

		induced := make(map[string]struct{})
		keptScopes := scopes[:0:0] // fresh backing array
		for _, scope := range scopes {
			if _, ok := scope[next]; ok {
				for n := range scope {
					induced[n] = struct{}{}
				}
				continue
			}
			keptScopes = append(keptScopes, scope)
		}
		delete(induced, next)
		scopes = keptScopes
		if len(induced) > 0 {
			scopes = append(scopes, induced)
		}
	}
	return order
}

// Query returns the exact P(variable | evidence) as a normalised
// state -> probability map, mirroring infer.query exactly (variable
// elimination: sum-product over factors, eliminating every variable except
// the one queried, then normalising).
//
// It returns an error if evidence has zero probability under the model,
// rather than a silently-normalised nonsense distribution — the same
// contract infer.query documents.
func Query(factors []Factor, variable string, evidence map[string]string) (map[string]float64, error) {
	ev := make(map[string]string, len(evidence))
	for k, v := range evidence {
		if k != variable {
			ev[k] = v
		}
	}

	reduced := make([]Factor, len(factors))
	for i, f := range factors {
		reduced[i] = f.Reduce(ev)
	}

	constant := 1.0
	working := make([]Factor, 0, len(reduced))
	for _, f := range reduced {
		if len(f.Variables) > 0 {
			working = append(working, f)
		} else {
			constant *= f.Table[0]
		}
	}
	if constant == 0.0 {
		return nil, fmt.Errorf("beliefvi: evidence %v has zero probability under this model; P(%s | evidence) is undefined", evidence, variable)
	}

	keep := map[string]struct{}{variable: {}}
	for _, v := range eliminationOrder(working, keep) {
		var involved []Factor
		var rest []Factor
		for _, f := range working {
			if f.indexOfVariable(v) != -1 {
				involved = append(involved, f)
			} else {
				rest = append(rest, f)
			}
		}
		if len(involved) == 0 {
			continue
		}
		product := involved[0]
		for _, f := range involved[1:] {
			product = product.Multiply(f)
		}
		working = append(rest, product.SumOut(v))
	}

	if len(working) == 0 {
		return nil, fmt.Errorf("beliefvi: evidence %v has zero probability under this model; P(%s | evidence) is undefined", evidence, variable)
	}
	result := working[0]
	for _, f := range working[1:] {
		result = result.Multiply(f)
	}

	table := result.expand([]string{variable})
	total := floats.Sum(table)
	if math.IsInf(total, 0) || math.IsNaN(total) || total <= 0.0 {
		return nil, fmt.Errorf("beliefvi: evidence %v has zero probability under this model; P(%s | evidence) is undefined", evidence, variable)
	}
	floats.Scale(1.0/total, table)
	out := make(map[string]float64, len(States))
	for i, s := range States {
		out[s] = table[i]
	}
	return out, nil
}

// CheckModel validates factors the way pgmpy's Model.check_model did,
// mirroring infer.check_model exactly: every declared variable needs exactly
// one CPD, every parent a CPD names must be declared, each CPD must be a
// proper conditional distribution (its variable's states sum to 1 for every
// parent assignment), and the parent relation must be acyclic.
func CheckModel(factors []Factor, variables []string) error {
	owned := make([]string, len(factors))
	for i, f := range factors {
		if len(f.Variables) == 0 {
			return fmt.Errorf("beliefvi: check model: factor %d owns no variable", i)
		}
		owned[i] = f.Variables[0]
	}

	var missing []string
	for _, v := range variables {
		if !slices.Contains(owned, v) {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("beliefvi: no cpd for declared variable(s): %v", missing)
	}
	var extra []string
	for _, v := range owned {
		if !slices.Contains(variables, v) {
			extra = append(extra, v)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("beliefvi: cpd for undeclared variable(s): %v", extra)
	}
	seen := make(map[string]struct{}, len(owned))
	for _, v := range owned {
		if _, dup := seen[v]; dup {
			return fmt.Errorf("beliefvi: more than one cpd declared for the same variable: %q", v)
		}
		seen[v] = struct{}{}
	}

	declared := make(map[string]struct{}, len(variables))
	for _, v := range variables {
		declared[v] = struct{}{}
	}
	for _, f := range factors {
		var unknown []string
		for _, parent := range f.Variables[1:] {
			if _, ok := declared[parent]; !ok {
				unknown = append(unknown, parent)
			}
		}
		if len(unknown) > 0 {
			return fmt.Errorf("beliefvi: cpd for %q names undeclared parent(s): %v", f.Variables[0], unknown)
		}

		cols := len(f.Table) / len(States)
		for col := range cols {
			sum := 0.0
			for state := range States {
				sum += f.Table[state*cols+col]
			}
			if math.Abs(sum-1.0) > 1e-9 {
				return fmt.Errorf("beliefvi: cpd for %q is not normalised: column %d sums to %v", f.Variables[0], col, sum)
			}
		}
	}

	// A cyclic parent relation is not a Bayesian network. Variable
	// elimination would still terminate on one and hand back a confident
	// number, so reject it here rather than serve a meaningless posterior.
	parents := make(map[string][]string, len(factors))
	for _, f := range factors {
		p := append([]string(nil), f.Variables[1:]...)
		sort.Strings(p)
		parents[f.Variables[0]] = p
	}
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := make(map[string]int, len(variables))
	var visit func(node string, path []string) error
	visit = func(node string, path []string) error {
		switch state[node] {
		case done:
			return nil
		case visiting:
			i := slices.Index(path, node)
			cycle := append(append([]string(nil), path[i:]...), node)
			return fmt.Errorf("beliefvi: model is cyclic: %v", cycle)
		}
		state[node] = visiting
		for _, parent := range parents[node] {
			if err := visit(parent, append(path, node)); err != nil {
				return err
			}
		}
		state[node] = done
		return nil
	}
	for _, node := range variables {
		if err := visit(node, nil); err != nil {
			return err
		}
	}
	return nil
}
