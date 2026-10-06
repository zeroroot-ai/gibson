// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fit

import (
	"slices"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// strengths.go fits the two noisy-OR strengths of a node that are not an
// enablement edge (ADR-0137, gibson#720): the strength between two variables
// of one node, and the leak of each variable. Each is a Beta posterior on the
// uninformative prior, so nobody writes a strength by hand.
//
// The fit counts the rows of the belief schema of a node type:
//   - The leak of a variable is the chance that it is true while each of its
//     parents in the node is false. The rows where each parent is false count:
//     a success when the variable is true.
//   - The strength of parent p on a variable is the chance that p alone makes
//     the variable true. The rows where p is true and each other parent is
//     false count: a success when the variable is true.
//
// A row of the trainer is the evidence of one host, so the fit reads the
// schema of the Host node type. A variable that a row does not name is false,
// as in Fit.

// InNodeKey is the key of the strength of parent on child in a node of kind.
func InNodeKey(kind, child, parent string) string {
	return kind + "/" + child + "<-" + parent
}

// LeakKey is the key of the leak of variable in a node of kind.
func LeakKey(kind, variable string) string {
	return kind + "/" + variable
}

// NodeStrengths fits the in-node strength of each declared dependency and the
// leak of each variable of schema from rows.
func NodeStrengths(rows []Row, schema ontology.NodeBeliefSchema) (inNode, leaks map[string]BetaPosterior) {
	inNode = map[string]BetaPosterior{}
	leaks = map[string]BetaPosterior{}
	for _, v := range schema.Variables {
		leak := OutcomeCount{}
		strength := make(map[string]OutcomeCount, len(v.DependsOn))
		for _, r := range rows {
			var active []string
			for _, p := range v.DependsOn {
				if r[p] {
					active = append(active, p)
				}
			}
			switch len(active) {
			case 0:
				leak = count(leak, r[v.Name])
			case 1:
				strength[active[0]] = count(strength[active[0]], r[v.Name])
			}
		}
		leaks[LeakKey(schema.NodeType, v.Name)] = posterior(leak)
		for _, p := range slices.Sorted(slices.Values(v.DependsOn)) {
			inNode[InNodeKey(schema.NodeType, v.Name, p)] = posterior(strength[p])
		}
	}
	return inNode, leaks
}

// count adds one outcome to c.
func count(c OutcomeCount, success bool) OutcomeCount {
	if success {
		c.Successes++
	} else {
		c.Failures++
	}
	return c
}

// posterior adds c to the uninformative Beta prior.
func posterior(c OutcomeCount) BetaPosterior {
	return BetaPosterior{
		Alpha: beliefvi.UninformativeBetaAlpha + c.Successes,
		Beta:  beliefvi.UninformativeBetaBeta + c.Failures,
	}
}
